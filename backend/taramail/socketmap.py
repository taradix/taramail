"""Postfix socketmap server for relay domain lookups.

Implements the netstring-framed socketmap protocol so Postfix on a remote
relay (taramx) can query which domains taramail accepts, eliminating manual
RELAY_DOMAINS configuration.

Protocol: https://www.postfix.org/socketmap_table.5.html
"""

import asyncio
import logging
import sys
from argparse import ArgumentParser

from sqlalchemy import select

from taramail.db import get_db_session
from taramail.logger import LoggerHandlerAction, LoggerLevelAction, setup_logger
from taramail.models import DomainModel

logger = logging.getLogger(__name__)


def lookup_relay_domain(db, key: str) -> str | None:
    """Return the domain name if active, None otherwise."""
    return db.scalar(
        select(DomainModel.domain)
        .where(DomainModel.domain == key)
        .where(DomainModel.active == True)  # noqa: E712
    )


async def read_netstring(reader: asyncio.StreamReader) -> str:
    """Read one netstring from reader, return decoded payload.

    Netstring format: ``<length>:<payload>,``
    """
    length_bytes = b""
    while True:
        byte = await reader.readexactly(1)
        if byte == b":":
            break
        length_bytes += byte
    payload = await reader.readexactly(int(length_bytes))
    await reader.readexactly(1)  # consume trailing ','
    return payload.decode()


def write_netstring(writer: asyncio.StreamWriter, data: str) -> None:
    """Write one netstring to writer.

    Netstring format: ``<length>:<payload>,``
    """
    encoded = data.encode()
    writer.write(f"{len(encoded)}:".encode() + encoded + b",")


async def handle_client(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    *,
    db,
) -> None:
    """Handle one socketmap client connection."""
    try:
        while True:
            try:
                data = await read_netstring(reader)
            except asyncio.IncompleteReadError:
                break
            name, _, key = data.partition(" ")
            if name == "relay_domains":
                result = lookup_relay_domain(db, key)
                if result:
                    write_netstring(writer, f"OK {result}")
                else:
                    write_netstring(writer, "NOTFOUND ")
            else:
                write_netstring(writer, f"PERM unknown map {name!r}")
            await writer.drain()
    except (BrokenPipeError, ConnectionResetError):
        pass
    finally:
        writer.close()
        await writer.wait_closed()


def main(argv=None):  # pragma: no cover
    sys.exit(asyncio.run(_main(argv)))


async def _main(argv=None):  # pragma: no cover
    parser = ArgumentParser()
    parser.add_argument("--bind", default="0.0.0.0")  # noqa: S104
    parser.add_argument("--port", type=int, default=10028)
    parser.add_argument("--log-file", action=LoggerHandlerAction)
    parser.add_argument("--log-level", action=LoggerLevelAction)
    args = parser.parse_args(argv)
    setup_logger(args.log_level, args.log_file)

    async def _handler(reader, writer):
        with get_db_session() as db:
            await handle_client(reader, writer, db=db)

    server = await asyncio.start_server(_handler, args.bind, args.port)
    logger.info("Socketmap listening on %s:%d", args.bind, args.port)
    async with server:
        await server.serve_forever()
