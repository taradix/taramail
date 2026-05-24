"""SQLAlchemy models."""

import re
from datetime import datetime as dt
from typing import Any

from sqlalchemy import (
    JSON,
    TIMESTAMP,
    BigInteger,
    DateTime,
    Enum,
    ForeignKey,
    Index,
    Integer,
    PrimaryKeyConstraint,
    String,
    Text,
    TextClause,
    inspect,
    text,
)
from sqlalchemy.ext.compiler import compiles
from sqlalchemy.orm import (
    Mapped,
    declarative_base,
    declarative_mixin,
    mapped_column,
)
from sqlalchemy.schema import FetchedValue
from sqlalchemy.sql import func

from taramail.units import gibi


class ReprMixin:

    def __repr__(self):
        mapper = inspect(self.__class__)
        attrs = [
            f"{n}={getattr(self, n)!r}"
            for n, c in mapper.columns.items()
        ]
        return f"<{self.__class__.__name__}({', '.join(attrs)})>"

SQLModel = declarative_base(cls=ReprMixin)


@compiles(DateTime, "sqlite")
def sqlite_datetime(element, compiler, **kw):
    """Replace CURRENT_TIMESTAMP string with function in SQLite server default."""
    server_default = kw["type_expression"].server_default
    if server_default is not None:
        arg = server_default.arg
        if isinstance(arg, TextClause) and " ON UPDATE " in arg.text:
            arg.text = re.sub(" ON UPDATE .*", "", arg.text)

    return compiler.visit_datetime(element, **kw)


@declarative_mixin
class TimestampMixin:

    created: Mapped[dt] = mapped_column(
        DateTime(timezone=True),
        server_default=func.current_timestamp(),
    )
    modified: Mapped[dt] = mapped_column(
        DateTime(timezone=True),
        server_default=text("CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP"),
        server_onupdate=FetchedValue(),
    )


class AliasModel(TimestampMixin, SQLModel):

    id: Mapped[int] = mapped_column(primary_key=True)
    address: Mapped[str] = mapped_column(String(255))
    goto: Mapped[str] = mapped_column(Text)
    domain: Mapped[str] = mapped_column(String(255))
    private_comment: Mapped[str] = mapped_column(String(160), server_default="")
    public_comment: Mapped[str] = mapped_column(String(160), server_default="")
    sogo_visible: Mapped[bool] = mapped_column(server_default="1")
    internal: Mapped[bool] = mapped_column(server_default="0")
    active: Mapped[bool] = mapped_column(server_default="1")

    __tablename__ = "alias"
    __table_args__ = (
        Index("alias_address_key", address, unique=True),
        Index("alias_domain_key", domain),
    )


class AliasDomainModel(TimestampMixin, SQLModel):

    alias_domain: Mapped[str] = mapped_column(String(255), primary_key=True)
    target_domain: Mapped[str] = mapped_column(String(255))
    active: Mapped[bool] = mapped_column(server_default="1")

    __tablename__ = "alias_domain"
    __table_args__ = (
        Index("alias_domain_active_key", active),
        Index("alias_domain_target_domain_key", target_domain),
    )


class AppPasswdModel(TimestampMixin, SQLModel):

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(255))
    mailbox: Mapped[str] = mapped_column(ForeignKey("mailbox.username", ondelete="CASCADE"))
    domain: Mapped[str] = mapped_column(String(255))
    password: Mapped[str] = mapped_column(String(255))
    imap_access: Mapped[bool] = mapped_column(server_default="1")
    smtp_access: Mapped[bool] = mapped_column(server_default="1")
    dav_access: Mapped[bool] = mapped_column(server_default="1")
    eas_access: Mapped[bool] = mapped_column(server_default="1")
    pop3_access: Mapped[bool] = mapped_column(server_default="1")
    sieve_access: Mapped[bool] = mapped_column(server_default="1")
    active: Mapped[bool] = mapped_column(server_default="1")

    __tablename__ = "app_passwd"
    __table_args__ = (
        Index("app_passwd_mailbox", mailbox),
        Index("app_passwd_password", password),
        Index("app_passwd_domain", domain),
    )


class BccMapsModel(TimestampMixin, SQLModel):

    id: Mapped[int] = mapped_column(primary_key=True)
    local_dest: Mapped[str] = mapped_column(String(255))
    bcc_dest: Mapped[str] = mapped_column(String(255))
    domain: Mapped[str] = mapped_column(String(255))
    type: Mapped[str | None] = mapped_column(Enum("sender", "rcpt"))
    active: Mapped[bool] = mapped_column(server_default="1")

    __tablename__ = "bcc_maps"
    __table_args__ = (Index("bcc_maps_local_dest_key", local_dest),)


class DomainModel(TimestampMixin, SQLModel):

    domain: Mapped[str] = mapped_column(String(255), primary_key=True)
    description: Mapped[str | None] = mapped_column(String(255))
    aliases: Mapped[int] = mapped_column(Integer, server_default="0")
    mailboxes: Mapped[int] = mapped_column(Integer, server_default="0")
    defquota: Mapped[int] = mapped_column(BigInteger, server_default=f"{3 * gibi}")
    maxquota: Mapped[int] = mapped_column(BigInteger, server_default=f"{100 * gibi}")
    quota: Mapped[int] = mapped_column(BigInteger, server_default=f"{100 * gibi}")
    relayhost: Mapped[int] = mapped_column(Integer, server_default="0")
    backupmx: Mapped[bool] = mapped_column(server_default="0")
    gal: Mapped[bool] = mapped_column(server_default="1")
    relay_all_recipients: Mapped[bool] = mapped_column(server_default="0")
    relay_unknown_only: Mapped[bool] = mapped_column(server_default="0")
    active: Mapped[bool] = mapped_column(server_default="1")

    __tablename__ = "domain"


class FilterconfModel(TimestampMixin, SQLModel):

    prefix: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    object: Mapped[str] = mapped_column(String(255), server_default="")
    option: Mapped[str] = mapped_column(String(50), server_default="")
    value: Mapped[str] = mapped_column(String(100), server_default="")

    __tablename__ = "filterconf"
    __table_args__ = (Index("filterconf_object_key", object),)  # noqa: A003


class ImapsyncModel(TimestampMixin, SQLModel):

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    user2: Mapped[str] = mapped_column(String(255))
    host1: Mapped[str] = mapped_column(String(255))
    authmech1: Mapped[str] = mapped_column(Enum("PLAIN", "LOGIN", "CRAM-MD5"), server_default="PLAIN")
    regextrans2: Mapped[str] = mapped_column(String(255), server_default="")
    authmd51: Mapped[bool] = mapped_column(server_default="0")
    domain2: Mapped[str] = mapped_column(String(255), server_default="")
    subfolder2: Mapped[str] = mapped_column(String(255), server_default="")
    user1: Mapped[str] = mapped_column(String(255))
    password1: Mapped[str] = mapped_column(String(255))
    exclude: Mapped[str] = mapped_column(String(500), server_default="")
    maxage: Mapped[int] = mapped_column(server_default="0")
    mins_interval: Mapped[int] = mapped_column(server_default="0")
    maxbytespersecond: Mapped[str] = mapped_column(String(5), server_default="0")
    port1: Mapped[int] = mapped_column()
    enc1: Mapped[str] = mapped_column(Enum("TLS", "SSL", "PLAIN"), server_default="TLS")
    delete2duplicates: Mapped[bool] = mapped_column(server_default="1")
    delete1: Mapped[bool] = mapped_column(server_default="0")
    delete2: Mapped[bool] = mapped_column(server_default="0")
    automap: Mapped[bool] = mapped_column(server_default="0")
    skipcrossduplicates: Mapped[bool] = mapped_column(server_default="0")
    custom_params: Mapped[str] = mapped_column(String(512), server_default="")
    timeout1: Mapped[int] = mapped_column(server_default="600")
    timeout2: Mapped[int] = mapped_column(server_default="600")
    subscribeall: Mapped[bool] = mapped_column(server_default="1")
    dry: Mapped[bool] = mapped_column(server_default="0")
    is_running: Mapped[bool] = mapped_column(server_default="0")
    returned_text: Mapped[str | None] = mapped_column(Text)
    last_run: Mapped[int | None] = mapped_column(TIMESTAMP)
    success: Mapped[bool | None] = mapped_column()
    exit_status: Mapped[str | None] = mapped_column(String(50))
    active: Mapped[bool] = mapped_column(server_default="0")

    __tablename__ = "imapsync"


class MailboxModel(TimestampMixin, SQLModel):

    username: Mapped[str] = mapped_column(String(255), primary_key=True)
    password: Mapped[str] = mapped_column(String(255))
    name: Mapped[str | None] = mapped_column(String(255))
    description: Mapped[str | None] = mapped_column(String(255))
    mailbox_path_prefix: Mapped[str | None] = mapped_column(String(150), server_default="/var/vmail/")
    quota: Mapped[int] = mapped_column(BigInteger)
    local_part: Mapped[str] = mapped_column(String(255))
    domain: Mapped[str] = mapped_column(String(255))
    kind: Mapped[str] = mapped_column(String(100), server_default="")
    multiple_bookings: Mapped[int] = mapped_column(Integer, server_default="-1")
    active: Mapped[bool] = mapped_column(server_default="1")

    __tablename__ = "mailbox"
    __table_args__ = (
        Index("mailbox_domain_key", domain),
        Index("mailbox_domain_local_part_key", domain, local_part, unique=True),
        Index("mailbox_kind_key", kind),
    )


class QuarantineModel(SQLModel):

    id: Mapped[int] = mapped_column(primary_key=True)
    qid: Mapped[str] = mapped_column(String(30))
    subject: Mapped[str | None] = mapped_column(String(500))
    score: Mapped[float | None] = mapped_column()
    ip: Mapped[str | None] = mapped_column(String(50))
    action: Mapped[str] = mapped_column(String(20), server_default="unknown")
    symbols: Mapped[dict[str, Any]] = mapped_column(JSON)
    fuzzy_hashes: Mapped[dict[str, Any]] = mapped_column(JSON)
    sender: Mapped[str] = mapped_column(String(255), server_default="unknown")
    rcpt: Mapped[str | None] = mapped_column(String(255))
    msg: Mapped[str | None] = mapped_column(Text)
    domain: Mapped[str | None] = mapped_column(String(255))
    notified: Mapped[bool] = mapped_column(server_default="0")
    created: Mapped[dt] = mapped_column(
        DateTime(timezone=True),
        server_default=func.current_timestamp(),
    )
    user: Mapped[str] = mapped_column(String(255), server_default="unknown")

    __tablename__ = "quarantine"


class Quota2Model(SQLModel):

    username: Mapped[str] = mapped_column(String(255), primary_key=True)
    bytes: Mapped[int] = mapped_column(BigInteger, server_default="0")
    messages: Mapped[int] = mapped_column(BigInteger, server_default="0")

    __tablename__ = "quota2"


class Quota2ReplicaModel(SQLModel):

    username: Mapped[str] = mapped_column(String(255), primary_key=True)
    bytes: Mapped[int] = mapped_column(BigInteger, server_default="0")
    messages: Mapped[int] = mapped_column(BigInteger, server_default="0")

    __tablename__ = "quota2replica"


class RecipientMapsModel(TimestampMixin, SQLModel):

    id: Mapped[int] = mapped_column(primary_key=True)
    old_dest: Mapped[str] = mapped_column(String(255))
    new_dest: Mapped[str] = mapped_column(String(255))
    active: Mapped[bool] = mapped_column(server_default="0")

    __tablename__ = "recipient_maps"
    __table_args__ = (Index("recipient_maps_old_dest_key", old_dest),)


class RelayHostsModel(SQLModel):

    id: Mapped[int] = mapped_column(primary_key=True)
    hostname: Mapped[str] = mapped_column(String(255))
    username: Mapped[str] = mapped_column(String(255))
    password: Mapped[str] = mapped_column(String(255))
    active: Mapped[bool] = mapped_column(server_default="1")

    __tablename__ = "relayhosts"
    __table_args__ = (Index("relayhosts_hostname_key", hostname),)


class SaslLogModel(SQLModel):

    app_password: Mapped[int] = mapped_column()
    service: Mapped[str] = mapped_column(String(32))
    username: Mapped[str] = mapped_column(String(255))
    real_ip: Mapped[str] = mapped_column(String(64))
    datetime: Mapped[dt] = mapped_column(
        DateTime(timezone=True),
        server_default=func.current_timestamp(),
    )

    __tablename__ = "sasl_log"
    __table_args__ = (
        PrimaryKeyConstraint(service, real_ip, username),
        Index("sasl_log_username_key", username),
        Index("sasl_log_service_key", service),
        Index("sasl_log_datetime_key", datetime),
        Index("sasl_log_real_ip_key", real_ip),
    )


class SenderAclModel(SQLModel):

    id: Mapped[int] = mapped_column(primary_key=True)
    logged_in_as: Mapped[str] = mapped_column(String(255))
    send_as: Mapped[str] = mapped_column(String(255))
    external: Mapped[bool] = mapped_column(server_default="0")

    __tablename__ = "sender_acl"


class SettingsmapModel(TimestampMixin, SQLModel):

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    desc: Mapped[str] = mapped_column(String(255))
    content: Mapped[str] = mapped_column(Text)
    active: Mapped[bool] = mapped_column(server_default="0")

    __tablename__ = "settingsmap"


class SieveFiltersModel(TimestampMixin, SQLModel):

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    username: Mapped[str] = mapped_column(ForeignKey("mailbox.username", ondelete="CASCADE"))
    script_desc: Mapped[str] = mapped_column(String(255))
    script_name: Mapped[str] = mapped_column(Enum("active", "inactive"))
    script_data: Mapped[str] = mapped_column(Text)
    filter_type: Mapped[str] = mapped_column(Enum("postfilter", "prefilter"))

    __tablename__ = "sieve_filters"
    __table_args__ = (
        Index("sieve_filters_username_key", username),
        Index("sieve_filters_script_desc_key", script_desc),
    )


class SogoStaticView(SQLModel):

    c_uid: Mapped[str] = mapped_column(String(255), primary_key=True)
    domain: Mapped[str] = mapped_column(String(255))
    c_name: Mapped[str] = mapped_column(String(255))
    c_password: Mapped[str] = mapped_column(String(255), server_default="")
    c_cn: Mapped[str | None] = mapped_column(String(255))
    c_l: Mapped[str | None] = mapped_column(String(255))
    c_o: Mapped[str | None] = mapped_column(String(255))
    c_ou: Mapped[str | None] = mapped_column(String(255))
    c_telephonenumber: Mapped[str | None] = mapped_column(String(255))
    mail: Mapped[str] = mapped_column(String(255))
    aliases: Mapped[str] = mapped_column(Text)
    ad_aliases: Mapped[str] = mapped_column(String(6144), server_default="")
    ext_acl: Mapped[str] = mapped_column(String(6144), server_default="")
    kind: Mapped[str] = mapped_column(String(100), server_default="")
    multiple_bookings: Mapped[int] = mapped_column(Integer, server_default="1")

    __tablename__ = "_sogo_static_view"
    __table_args__ = (Index("_sogo_static_view_domain_key", domain),)


class SogoAclModel(SQLModel):

    id: Mapped[int] = mapped_column(primary_key=True)
    c_folder_id: Mapped[int] = mapped_column()
    c_object: Mapped[str] = mapped_column(String(255))
    c_uid: Mapped[str] = mapped_column(String(255))
    c_role: Mapped[str] = mapped_column(String(80))

    __tablename__ = "sogo_acl"
    __table_args__ = (
        Index("sogo_acl_c_folder_id_key", c_folder_id),
        Index("sogo_acl_c_uid_key", c_uid),
    )


class SogoAlarmsFolderModel(SQLModel):

    id: Mapped[int] = mapped_column(primary_key=True)
    c_path: Mapped[str] = mapped_column(String(255))
    c_name: Mapped[str] = mapped_column(String(255))
    c_uid: Mapped[str] = mapped_column(String(255))
    c_recurrence_id: Mapped[int | None] = mapped_column()
    c_alarm_number: Mapped[int] = mapped_column()
    c_alarm_date: Mapped[int] = mapped_column()

    __tablename__ = "sogo_alarms_folder"


class SogoCacheFolderModel(SQLModel):

    c_uid: Mapped[str] = mapped_column(String(255))
    c_path: Mapped[str] = mapped_column(String(255))
    c_parent_path: Mapped[str | None] = mapped_column(String(255))
    c_type: Mapped[int] = mapped_column()
    c_creationdate: Mapped[int] = mapped_column()
    c_lastmodified: Mapped[int] = mapped_column()
    c_version: Mapped[int] = mapped_column(server_default="0")
    c_deleted: Mapped[bool] = mapped_column(server_default="0")
    c_content: Mapped[str] = mapped_column(Text)

    __tablename__ = "sogo_cache_folder"
    __table_args__ = (PrimaryKeyConstraint(c_uid, c_path),)


class SogoFolderInfoModel(SQLModel):

    c_folder_id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    c_path: Mapped[str] = mapped_column(String(255))
    c_path1: Mapped[str] = mapped_column(String(255))
    c_path2: Mapped[str | None] = mapped_column(String(255))
    c_path3: Mapped[str | None] = mapped_column(String(255))
    c_path4: Mapped[str | None] = mapped_column(String(255))
    c_foldername: Mapped[str] = mapped_column(String(255))
    c_location: Mapped[str | None] = mapped_column(String(2048))
    c_quick_location: Mapped[str | None] = mapped_column(String(2048))
    c_acl_location: Mapped[str | None] = mapped_column(String(2048))
    c_folder_type: Mapped[str] = mapped_column(String(255))

    __tablename__ = "sogo_folder_info"
    __table_args__ = (Index("sogo_folder_info_c_path_key", c_path, unique=True),)


class SogoQuickAppointmentModel(SQLModel):

    c_folder_id: Mapped[int] = mapped_column()
    c_name: Mapped[str] = mapped_column(String(255))
    c_uid: Mapped[str] = mapped_column(String(255))
    c_startdate: Mapped[int | None] = mapped_column()
    c_enddate: Mapped[int | None] = mapped_column()
    c_cycleenddate: Mapped[int | None] = mapped_column()
    c_title: Mapped[str] = mapped_column(String(1000))
    c_participants: Mapped[str | None] = mapped_column(Text)
    c_isallday: Mapped[bool | None] = mapped_column()
    c_iscycle: Mapped[bool | None] = mapped_column()
    c_cycleinfo: Mapped[str | None] = mapped_column(Text)
    c_classification: Mapped[int] = mapped_column()
    c_isopaque: Mapped[bool] = mapped_column()
    c_status: Mapped[int] = mapped_column()
    c_priority: Mapped[int | None] = mapped_column()
    c_location: Mapped[str | None] = mapped_column(String(255))
    c_orgmail: Mapped[str | None] = mapped_column(String(255))
    c_partmails: Mapped[str | None] = mapped_column(Text)
    c_partstates: Mapped[str | None] = mapped_column(Text)
    c_category: Mapped[str | None] = mapped_column(String(255))
    c_sequence: Mapped[int | None] = mapped_column()
    c_component: Mapped[str] = mapped_column(String(10))
    c_nextalarm: Mapped[int | None] = mapped_column()
    c_description: Mapped[str | None] = mapped_column(Text)

    __tablename__ = "sogo_quick_appointment"
    __table_args__ = (PrimaryKeyConstraint(c_folder_id, c_name),)


class SogoQuickContactModel(SQLModel):

    c_folder_id: Mapped[int] = mapped_column()
    c_name: Mapped[str] = mapped_column(String(255))
    c_givenname: Mapped[str | None] = mapped_column(String(255))
    c_cn: Mapped[str | None] = mapped_column(String(255))
    c_sn: Mapped[str | None] = mapped_column(String(255))
    c_screenname: Mapped[str | None] = mapped_column(String(255))
    c_l: Mapped[str | None] = mapped_column(String(255))
    c_mail: Mapped[str | None] = mapped_column(Text)
    c_o: Mapped[str | None] = mapped_column(String(255))
    c_ou: Mapped[str | None] = mapped_column(String(255))
    c_telephonenumber: Mapped[str | None] = mapped_column(String(255))
    c_categories: Mapped[str | None] = mapped_column(String(255))
    c_component: Mapped[str] = mapped_column(String(10))
    c_hascertificate: Mapped[bool] = mapped_column(server_default="0")

    __tablename__ = "sogo_quick_contact"
    __table_args__ = (PrimaryKeyConstraint(c_folder_id, c_name),)


class SogoSessionsFolderModel(SQLModel):

    c_id: Mapped[str] = mapped_column(String(255), primary_key=True)
    c_value: Mapped[str] = mapped_column(String(4096))
    c_creationdate: Mapped[int] = mapped_column()
    c_lastseen: Mapped[int] = mapped_column()

    __tablename__ = "sogo_sessions_folder"


class SogoStoreModel(SQLModel):

    c_folder_id: Mapped[int] = mapped_column()
    c_name: Mapped[str] = mapped_column(String(255), server_default="")
    c_content: Mapped[str] = mapped_column(Text)
    c_creationdate: Mapped[int] = mapped_column()
    c_lastmodified: Mapped[int] = mapped_column()
    c_version: Mapped[int] = mapped_column()
    c_deleted: Mapped[int | None] = mapped_column()

    __tablename__ = "sogo_store"
    __table_args__ = (PrimaryKeyConstraint(c_folder_id, c_name),)


class SogoAdminModel(SQLModel):

    c_key: Mapped[str] = mapped_column(String(255), primary_key=True, server_default="")
    c_content: Mapped[str] = mapped_column(Text)

    __tablename__ = "sogo_admin"


class SogoUserProfileModel(SQLModel):

    c_uid: Mapped[str] = mapped_column(String(255), primary_key=True)
    c_defaults: Mapped[str | None] = mapped_column(Text)
    c_settings: Mapped[str | None] = mapped_column(Text)

    __tablename__ = "sogo_user_profile"


class SpamaliasModel(TimestampMixin, SQLModel):

    address: Mapped[str] = mapped_column(String(255), primary_key=True)
    goto: Mapped[str] = mapped_column(Text)
    validity: Mapped[int] = mapped_column(Integer)

    __tablename__ = "spamalias"


class TlsPolicyOverrideModel(TimestampMixin, SQLModel):

    id: Mapped[int] = mapped_column(primary_key=True)
    dest: Mapped[str] = mapped_column(String(255))
    policy: Mapped[str] = mapped_column(
        Enum("none", "may", "encrypt", "dane", "dane-only", "fingerprint", "verify", "secure")
    )
    parameters: Mapped[str | None] = mapped_column(String(255), server_default="")
    active: Mapped[bool] = mapped_column(server_default="1")

    __tablename__ = "tls_policy_override"
    __table_args__ = (Index("tls_policy_override_dest_key", dest),)


class TransportsModel(SQLModel):

    id: Mapped[int] = mapped_column(primary_key=True)
    destination: Mapped[str] = mapped_column(String(255))
    nexthop: Mapped[str] = mapped_column(String(255))
    username: Mapped[str] = mapped_column(String(255), server_default="")
    password: Mapped[str] = mapped_column(String(255), server_default="")
    is_mx_based: Mapped[bool] = mapped_column(server_default="0")
    active: Mapped[bool] = mapped_column(server_default="1")

    __tablename__ = "transports"
    __table_args__ = (
        Index("transports_destination_key", destination),
        Index("transports_nexthop_key", nexthop),
    )


class UserAclModel(SQLModel):

    username: Mapped[str] = mapped_column(ForeignKey("mailbox.username", ondelete="CASCADE"), primary_key=True)
    spam_alias: Mapped[bool] = mapped_column(server_default="1")
    tls_policy: Mapped[bool] = mapped_column(server_default="1")
    spam_score: Mapped[bool] = mapped_column(server_default="1")
    spam_policy: Mapped[bool] = mapped_column(server_default="1")
    delimiter_action: Mapped[bool] = mapped_column(server_default="1")
    syncjobs: Mapped[bool] = mapped_column(server_default="0")
    eas_reset: Mapped[bool] = mapped_column(server_default="1")
    sogo_profile_reset: Mapped[bool] = mapped_column(server_default="0")
    pushover: Mapped[bool] = mapped_column(server_default="1")
    # TODO: rename quarantine to quarantine_actions
    quarantine: Mapped[bool] = mapped_column(server_default="1")
    quarantine_attachments: Mapped[bool] = mapped_column(server_default="1")
    quarantine_notification: Mapped[bool] = mapped_column(server_default="1")
    quarantine_category: Mapped[bool] = mapped_column(server_default="1")
    app_passwds: Mapped[bool] = mapped_column(server_default="1")
    pw_reset: Mapped[bool] = mapped_column(server_default="1")

    __tablename__ = "user_acl"


class DmarcReportModel(SQLModel):

    id: Mapped[int] = mapped_column(primary_key=True)
    report_id: Mapped[str] = mapped_column(String(255))
    org_name: Mapped[str] = mapped_column(String(255))
    org_email: Mapped[str] = mapped_column(String(255), server_default="")
    domain: Mapped[str] = mapped_column(String(255))
    policy: Mapped[str] = mapped_column(String(20))
    begin_date: Mapped[dt] = mapped_column(DateTime(timezone=True))
    end_date: Mapped[dt] = mapped_column(DateTime(timezone=True))
    created: Mapped[dt] = mapped_column(
        DateTime(timezone=True),
        server_default=func.current_timestamp(),
    )

    __tablename__ = "dmarc_report"
    __table_args__ = (
        Index("dmarc_report_report_id_key", report_id, unique=True),
        Index("dmarc_report_domain_key", domain),
        Index("dmarc_report_begin_date_key", begin_date),
    )


class DmarcRecordModel(SQLModel):

    id: Mapped[int] = mapped_column(primary_key=True)
    report_id: Mapped[int] = mapped_column(ForeignKey("dmarc_report.id", ondelete="CASCADE"))
    source_ip: Mapped[str] = mapped_column(String(64))
    count: Mapped[int] = mapped_column(Integer)
    disposition: Mapped[str] = mapped_column(String(20))
    dkim_result: Mapped[str] = mapped_column(String(20))
    spf_result: Mapped[str] = mapped_column(String(20))
    dmarc_result: Mapped[str] = mapped_column(String(20))
    header_from: Mapped[str] = mapped_column(String(255))
    envelope_from: Mapped[str] = mapped_column(String(255), server_default="")

    __tablename__ = "dmarc_record"
    __table_args__ = (
        Index("dmarc_record_report_id_key", report_id),
        Index("dmarc_record_source_ip_key", source_ip),
        Index("dmarc_record_header_from_key", header_from),
    )


class UserAttributesModel(SQLModel):

    username: Mapped[str] = mapped_column(ForeignKey("mailbox.username", ondelete="CASCADE"), primary_key=True)
    force_pw_update: Mapped[bool] = mapped_column(server_default="0")
    tls_enforce_in: Mapped[bool] = mapped_column(server_default="0")
    tls_enforce_out: Mapped[bool] = mapped_column(server_default="0")
    relayhost: Mapped[int] = mapped_column(server_default="0")
    sogo_access: Mapped[bool] = mapped_column(server_default="1")
    imap_access: Mapped[bool] = mapped_column(server_default="1")
    pop3_access: Mapped[bool] = mapped_column(server_default="1")
    smtp_access: Mapped[bool] = mapped_column(server_default="1")
    sieve_access: Mapped[bool] = mapped_column(server_default="1")
    quarantine_notification: Mapped[str] = mapped_column(
        Enum("never", "hourly", "daily", "weekly"), server_default="hourly"
    )
    quarantine_category: Mapped[str] = mapped_column(Enum("add_header", "reject", "all"), server_default="reject")

    __tablename__ = "user_attributes"
