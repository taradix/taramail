"""DMARC aggregate report processor.

Connects to a dedicated IMAP mailbox, fetches DMARC aggregate reports,
parses the XML, stores results in MySQL, and exposes Prometheus metrics.

Report format: https://datatracker.ietf.org/doc/html/rfc7489#section-7.2
"""

import email
import gzip
import imaplib
import io
import logging
import os
import time
import zipfile
from argparse import ArgumentParser
from datetime import UTC, datetime
from email.message import Message
from xml.etree.ElementTree import Element

from defusedxml.ElementTree import fromstring as safe_fromstring
from prometheus_client import (
    CollectorRegistry,
    Counter,
    start_http_server,
)
from sqlalchemy.exc import IntegrityError

from taramail.db import get_db_session
from taramail.logger import LoggerHandlerAction, LoggerLevelAction, setup_logger
from taramail.models import DmarcRecordModel, DmarcReportModel

logger = logging.getLogger(__name__)

registry = CollectorRegistry()

dmarc_messages_total = Counter(
    "dmarc_messages_total",
    "Total messages reported in DMARC aggregate reports",
    ["domain", "dmarc_result", "disposition"],
    registry=registry,
)
dmarc_reports_processed = Counter(
    "dmarc_reports_processed_total",
    "Number of DMARC aggregate reports successfully processed",
    registry=registry,
)
dmarc_reports_failed = Counter(
    "dmarc_reports_failed_total",
    "Number of DMARC reports that failed to parse",
    registry=registry,
)


def extract_xml_from_message(msg: Message) -> list[bytes]:
    """Extract DMARC XML content from an email message.

    Reports arrive as XML attachments, typically compressed with zip or gzip.
    """
    xml_contents: list[bytes] = []

    for part in msg.walk():
        content_type = part.get_content_type()
        filename = part.get_filename() or ""

        payload = part.get_payload(decode=True)
        if payload is None:
            continue

        if content_type == "application/zip" or filename.endswith(".zip"):
            xml_contents.extend(_extract_from_zip(payload))
        elif content_type == "application/gzip" or filename.endswith(".gz"):
            xml_contents.extend(_extract_from_gzip(payload))
        elif content_type in ("text/xml", "application/xml") or filename.endswith(".xml"):
            xml_contents.append(payload)

    return xml_contents


def _extract_from_zip(data: bytes) -> list[bytes]:
    """Extract XML files from a zip archive."""
    results: list[bytes] = []
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            for name in zf.namelist():
                if name.endswith(".xml"):
                    results.append(zf.read(name))
    except zipfile.BadZipFile:
        logger.warning("Failed to extract zip attachment")
    return results


def _extract_from_gzip(data: bytes) -> list[bytes]:
    """Extract XML content from gzip-compressed data."""
    try:
        return [gzip.decompress(data)]
    except (gzip.BadGzipFile, OSError):
        logger.warning("Failed to decompress gzip attachment")
        return []


def parse_dmarc_xml(xml_data: bytes) -> tuple[dict, list[dict]]:
    """Parse a DMARC aggregate report XML and return structured data.

    Returns a tuple of (report_metadata, records) where report_metadata is a
    dict and records is a list of dicts.
    """
    root = safe_fromstring(xml_data)

    # Handle namespace — some reports include an xmlns
    ns = ""
    if root.tag.startswith("{"):
        ns = root.tag.split("}")[0] + "}"

    # Report metadata
    metadata = root.find(f"{ns}report_metadata")
    policy_published = root.find(f"{ns}policy_published")

    report = {
        "report_id": _text(metadata, f"{ns}report_id"),
        "org_name": _text(metadata, f"{ns}org_name"),
        "org_email": _text(metadata, f"{ns}email", default=""),
        "domain": _text(policy_published, f"{ns}domain"),
        "policy": _text(policy_published, f"{ns}p", default="none"),
    }

    # Date range
    date_range = metadata.find(f"{ns}date_range")
    if date_range is not None:
        begin = _text(date_range, f"{ns}begin")
        end = _text(date_range, f"{ns}end")
        report["begin_date"] = datetime.fromtimestamp(int(begin), tz=UTC)
        report["end_date"] = datetime.fromtimestamp(int(end), tz=UTC)
    else:
        now = datetime.now(tz=UTC)
        report["begin_date"] = now
        report["end_date"] = now

    # Records
    records = []
    for record_el in root.findall(f"{ns}record"):
        row = record_el.find(f"{ns}row")
        identifiers = record_el.find(f"{ns}identifiers")
        auth_results = record_el.find(f"{ns}auth_results")
        policy_evaluated = row.find(f"{ns}policy_evaluated") if row is not None else None

        dkim_result = "none"
        spf_result = "none"
        if auth_results is not None:
            dkim_el = auth_results.find(f"{ns}dkim")
            if dkim_el is not None:
                dkim_result = _text(dkim_el, f"{ns}result", default="none")
            spf_el = auth_results.find(f"{ns}spf")
            if spf_el is not None:
                spf_result = _text(spf_el, f"{ns}result", default="none")

        disposition = "none"
        dmarc_result = "fail"
        if policy_evaluated is not None:
            disposition = _text(policy_evaluated, f"{ns}disposition", default="none")
            dkim_eval = _text(policy_evaluated, f"{ns}dkim", default="fail")
            spf_eval = _text(policy_evaluated, f"{ns}spf", default="fail")
            dmarc_result = "pass" if dkim_eval == "pass" or spf_eval == "pass" else "fail"

        records.append({
            "source_ip": _text(row, f"{ns}source_ip") if row is not None else "unknown",
            "count": int(_text(row, f"{ns}count", default="0")) if row is not None else 0,
            "disposition": disposition,
            "dkim_result": dkim_result,
            "spf_result": spf_result,
            "dmarc_result": dmarc_result,
            "header_from": _text(identifiers, f"{ns}header_from", default="") if identifiers is not None else "",
            "envelope_from": _text(identifiers, f"{ns}envelope_from", default="") if identifiers is not None else "",
        })

    return report, records


def _text(element: Element | None, tag: str, default: str = "") -> str:
    """Get text content of a child element."""
    if element is None:
        return default
    child = element.find(tag)
    if child is not None and child.text:
        return child.text.strip()
    return default


def store_report(db, report_data: dict, records_data: list[dict]) -> bool:
    """Store a parsed DMARC report and its records in the database.

    Returns True if stored successfully, False if duplicate.
    """
    report_model = DmarcReportModel(
        report_id=report_data["report_id"],
        org_name=report_data["org_name"],
        org_email=report_data["org_email"],
        domain=report_data["domain"],
        policy=report_data["policy"],
        begin_date=report_data["begin_date"],
        end_date=report_data["end_date"],
    )

    db.add(report_model)
    try:
        db.flush()
    except IntegrityError:
        db.rollback()
        logger.info("Duplicate report %s, skipping", report_data["report_id"])
        return False

    for record_data in records_data:
        record_model = DmarcRecordModel(
            report_id=report_model.id,
            **record_data,
        )
        db.add(record_model)

    db.commit()
    return True


def update_metrics(report_data: dict, records_data: list[dict]) -> None:
    """Update Prometheus counters with report data."""
    domain = report_data["domain"]
    for record in records_data:
        dmarc_messages_total.labels(
            domain=domain,
            dmarc_result=record["dmarc_result"],
            disposition=record["disposition"],
        ).inc(record["count"])


def _process_message(imap: imaplib.IMAP4, num: bytes, db) -> None:
    """Process a single IMAP message containing DMARC reports."""
    _, msg_data = imap.fetch(num, "(RFC822)")
    raw_email = msg_data[0][1]
    msg = email.message_from_bytes(raw_email)

    xml_contents = extract_xml_from_message(msg)
    if not xml_contents:
        logger.debug("Message %s has no DMARC XML attachment", num)
        imap.store(num, "+FLAGS", "\\Seen")
        return

    for xml_data in xml_contents:
        report_data, records_data = parse_dmarc_xml(xml_data)
        if store_report(db, report_data, records_data):
            update_metrics(report_data, records_data)
            dmarc_reports_processed.inc()
            logger.info(
                "Processed report %s from %s for %s (%d records)",
                report_data["report_id"],
                report_data["org_name"],
                report_data["domain"],
                len(records_data),
            )

    imap.store(num, "+FLAGS", "\\Seen")


def fetch_and_process(env=os.environ) -> None:
    """Connect to IMAP, fetch DMARC reports, parse, and store."""
    host = env.get("DMARC_IMAP_HOST", "dovecot")
    port = int(env.get("DMARC_IMAP_PORT", "993"))
    user = env.get("DMARC_IMAP_USER", "")
    password = env.get("DMARC_IMAP_PASSWORD", "")
    use_ssl = env.get("DMARC_IMAP_SSL", "true").lower() in ("true", "1", "yes")

    if not user or not password:
        logger.error("DMARC_IMAP_USER and DMARC_IMAP_PASSWORD must be set")
        return

    imap = imaplib.IMAP4_SSL(host, port) if use_ssl else imaplib.IMAP4(host, port)
    try:
        imap.login(user, password)
    except (imaplib.IMAP4.error, OSError):
        logger.exception("Failed to connect to IMAP")
        return

    try:
        imap.select("INBOX")
        _, message_nums = imap.search(None, "UNSEEN")

        if not message_nums[0]:
            logger.info("No new DMARC reports")
            return

        num_list = message_nums[0].split()
        logger.info("Found %d unread messages to process", len(num_list))

        with get_db_session() as db:
            for num in num_list:
                try:
                    _process_message(imap, num, db)
                except Exception:
                    dmarc_reports_failed.inc()
                    logger.exception("Failed to process message %s", num)

    finally:
        try:
            imap.close()
            imap.logout()
        except Exception:
            logger.debug("Error during IMAP cleanup", exc_info=True)


def main(argv=None):  # pragma: no cover
    """Entry point for the dmarc service."""
    parser = ArgumentParser()
    parser.add_argument("--log-file", action=LoggerHandlerAction)
    parser.add_argument("--log-level", action=LoggerLevelAction)
    parser.add_argument("--metrics-port", type=int, default=int(os.environ.get("DMARC_METRICS_PORT", "9199")))
    parser.add_argument("--poll-interval", type=int, default=int(os.environ.get("DMARC_POLL_INTERVAL", "3600")))
    args = parser.parse_args(argv)
    setup_logger(args.log_level, args.log_file)

    logger.info("Starting DMARC processor (poll every %ds, metrics on :%d)", args.poll_interval, args.metrics_port)
    start_http_server(args.metrics_port, registry=registry)

    while True:
        try:
            fetch_and_process()
        except Exception:
            logger.exception("Unexpected error in DMARC processing loop")
        time.sleep(args.poll_interval)
