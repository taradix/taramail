import re
from datetime import datetime as dt

from attrs import Factory, define, field
from pydantic import (
    BaseModel,
    EmailStr,
    Field,
    TypeAdapter,
    ValidationError,
    ValidationInfo,
    field_validator,
)
from sqlalchemy import (
    delete,
    or_,
    select,
)
from sqlalchemy.exc import NoResultFound
from sqlalchemy.sql import func

from taramail.db import DBSession
from taramail.email import is_email, join_email
from taramail.models import (
    AliasDomainModel,
    AliasModel,
    BccMapsModel,
    DomainModel,
    FilterconfModel,
    ImapsyncModel,
    MailboxModel,
    QuarantineModel,
    Quota2Model,
    Quota2ReplicaModel,
    SaslLogModel,
    SenderAclModel,
    SpamaliasModel,
    UserAclModel,
    UserAttributesModel,
)
from taramail.password import (
    PasswordPolicyManager,
    hash_password,
)
from taramail.schemas import DomainStr
from taramail.sogo import Sogo
from taramail.store import Store


class MailboxError(Exception):
    """Base exception for mailbox errors."""


class MailboxAlreadyExistsError(MailboxError):
    """Raised when a mailbox already exists."""


class MailboxNotFoundError(MailboxError):
    """Raised when a mailbox is not found."""


class MailboxValidationError(MailboxError):
    """Raised when a mailbox is invalid."""


class MailboxCreate(BaseModel):

    local_part: str = Field(..., min_length=1)
    domain: DomainStr
    password: str
    password2: str
    name: str = ""
    quota: int | None = None
    quarantine_notification: str = "hourly"
    quarantine_category: str = "reject"
    active: bool = True
    force_pw_update: bool = False
    tls_enforce_in: bool = False
    tls_enforce_out: bool = False
    relayhost: int = 0
    sogo_access: bool = True
    imap_access: bool = True
    pop3_access: bool = True
    smtp_access: bool = True
    sieve_access: bool = True
    acl_spam_alias: bool = True
    acl_tls_policy: bool = True
    acl_spam_score: bool = True
    acl_spam_policy: bool = True
    acl_delimiter_action: bool = True
    acl_syncjobs: bool = False
    acl_eas_reset: bool = True
    acl_sogo_profile_reset: bool = False
    acl_pushover: bool = True
    acl_quarantine: bool = True
    acl_quarantine_attachments: bool = True
    acl_quarantine_notification: bool = True
    acl_quarantine_category: bool = True

    @field_validator("local_part", mode="before")
    @classmethod
    def strip_and_lower(cls, v: str, info: ValidationInfo) -> str:
        v = v.lower().strip()
        if not v:
            raise ValueError(f"{info.field_name} cannot be empty or whitespace")
        return v

    @field_validator("name", mode="before")
    @classmethod
    def strip_brackets(cls, v: str, info: ValidationInfo) -> str:
        return v.lstrip("<").rstrip(">")


class MailboxDetails(BaseModel):

    username: EmailStr
    active: bool
    domain: DomainStr
    name: str
    local_part: str
    quota: int
    quota_used: int
    messages: int
    quarantine_notification: str
    quarantine_category: str
    force_pw_update: bool
    tls_enforce_in: bool
    tls_enforce_out: bool
    relayhost: int
    sogo_access: bool
    imap_access: bool
    pop3_access: bool
    smtp_access: bool
    sieve_access: bool
    last_imap_login: dt | None
    last_smtp_login: dt | None
    last_pop3_login: dt | None
    last_sso_login: dt | None
    sender_acl: list[str]
    extended_sender_acl: list[str]


class MailboxUpdate(BaseModel):

    password: str | None = None
    password2: str | None = None
    name: str | None = None
    quota: int | None = None
    quarantine_notification: str | None = None
    quarantine_category: str | None = None
    active: bool | None = None
    force_pw_update: bool | None = None
    tls_enforce_in: bool | None = None
    tls_enforce_out: bool | None = None
    relayhost: int | None = None
    sogo_access: bool | None = None
    imap_access: bool | None = None
    pop3_access: bool | None = None
    smtp_access: bool | None = None
    sieve_access: bool | None = None
    sender_acl: list[str] | None = None
    extended_sender_acl: list[str] | None = None


@define(frozen=True)
class MailboxManager:

    db: DBSession
    store: Store
    password_policy_manager: PasswordPolicyManager = field(
        default=Factory(lambda self: PasswordPolicyManager(self.store), takes_self=True),
    )
    sogo: Sogo = field(
        default=Factory(lambda self: Sogo(self.db), takes_self=True),
    )

    def get_mailbox_details(self, username: EmailStr) -> MailboxDetails:
        try:
            mailbox, quota2, attributes = self.db.execute(
                select(MailboxModel, Quota2Model, UserAttributesModel)
                .where(MailboxModel.kind == "", MailboxModel.username == username)
                .join(Quota2Model, Quota2Model.username == MailboxModel.username)
                .join(UserAttributesModel, UserAttributesModel.username == MailboxModel.username)
            ).one()
        except NoResultFound as e:
            raise MailboxNotFoundError(f"Mailbox for {username} not found") from e

        logs = self.db.execute(
            select(func.max(SaslLogModel.datetime), SaslLogModel.service)
            .where(SaslLogModel.username == username)
            .group_by(SaslLogModel.service)
        ).all()
        last_logins = {service: datetime for datetime, service in logs}

        # TODO: ratelimit

        return MailboxDetails(
            username=mailbox.username,
            active=mailbox.active,
            domain=mailbox.domain,
            name=mailbox.name,
            local_part=mailbox.local_part,
            quota=mailbox.quota,
            quota_used=quota2.bytes,
            messages=quota2.messages,
            quarantine_notification=attributes.quarantine_notification,
            quarantine_category=attributes.quarantine_category,
            force_pw_update=attributes.force_pw_update,
            tls_enforce_in=attributes.tls_enforce_in,
            tls_enforce_out=attributes.tls_enforce_out,
            relayhost=attributes.relayhost,
            sogo_access=attributes.sogo_access,
            imap_access=attributes.imap_access,
            pop3_access=attributes.pop3_access,
            smtp_access=attributes.smtp_access,
            sieve_access=attributes.sieve_access,
            last_imap_login=last_logins.get("imap"),
            last_smtp_login=last_logins.get("smtp"),
            last_pop3_login=last_logins.get("pop3"),
            last_sso_login=last_logins.get("SSO"),
            sender_acl=self._get_sender_acl(username, external=False),
            extended_sender_acl=self._get_sender_acl(username, external=True),
        )

    def get_mailboxes(self) -> list[MailboxModel]:
        return self.db.scalars(
            select(MailboxModel)
            .where(MailboxModel.active == 1)
        ).all()

    def create_mailbox(self, mailbox_create: MailboxCreate) -> MailboxModel:
        username = join_email(mailbox_create.local_part, mailbox_create.domain)
        # TODO: validate username as email
        if self.db.scalar(
            select(MailboxModel)
            .where(
                MailboxModel.kind == "",
                MailboxModel.username == username,
            )
            .limit(1)
        ):
            raise MailboxAlreadyExistsError(f"Mailbox already exists: {username}")

        name = mailbox_create.name or mailbox_create.local_part
        domain_data = self._get_domain_data(mailbox_create.domain)
        quota = mailbox_create.quota or domain_data.defquota

        mailbox_data = self._get_mailbox_data(mailbox_create.domain)
        if mailbox_data.count >= domain_data.mailboxes:
            raise MailboxValidationError(f"Max mailbox exceeded ({domain_data.mailboxes})")
        if quota > domain_data.maxquota:
            raise MailboxValidationError(f"Mailbox quota ({quota}) exceeds the domain limit ({domain_data.maxquota})")
        if mailbox_data.quota + quota > domain_data.quota:
            quota_left = domain_data.quota - mailbox_data.quota
            raise MailboxValidationError(f"Not enough quota left ({quota_left})")

        hashed_password = self._get_hashed_password(mailbox_create.password, mailbox_create.password2)

        mailbox = MailboxModel(
            username=username,
            password=hashed_password,
            name=name,
            local_part=mailbox_create.local_part,
            domain=mailbox_create.domain,
            quota=quota,
            active=mailbox_create.active,
        )
        quota2 = Quota2Model(
            username=username,
            bytes=0,
            messages=0,
        )
        quota2replica = Quota2ReplicaModel(
            username=username,
            bytes=0,
            messages=0,
        )
        alias = AliasModel(
            address=username,
            goto=username,
            domain=mailbox_create.domain,
            active=mailbox_create.active,
        )
        user_acl = UserAclModel(
            username=username,
            spam_alias=mailbox_create.acl_spam_alias,
            tls_policy=mailbox_create.acl_tls_policy,
            spam_score=mailbox_create.acl_spam_score,
            spam_policy=mailbox_create.acl_spam_policy,
            delimiter_action=mailbox_create.acl_delimiter_action,
            syncjobs=mailbox_create.acl_syncjobs,
            eas_reset=mailbox_create.acl_eas_reset,
            sogo_profile_reset=mailbox_create.acl_sogo_profile_reset,
            pushover=mailbox_create.acl_pushover,
            quarantine=mailbox_create.acl_quarantine,
            quarantine_attachments=mailbox_create.acl_quarantine_attachments,
            quarantine_notification=mailbox_create.acl_quarantine_notification,
            quarantine_category=mailbox_create.acl_quarantine_category,
        )
        user_attributes = UserAttributesModel(
            username=username,
            force_pw_update=mailbox_create.force_pw_update,
            tls_enforce_in=mailbox_create.tls_enforce_in,
            tls_enforce_out=mailbox_create.tls_enforce_out,
            sogo_access=mailbox_create.sogo_access,
            imap_access=mailbox_create.imap_access,
            pop3_access=mailbox_create.pop3_access,
            smtp_access=mailbox_create.smtp_access,
            sieve_access=mailbox_create.sieve_access,
            relayhost=mailbox_create.relayhost,
            quarantine_notification=mailbox_create.quarantine_notification,
            quarantine_category=mailbox_create.quarantine_category,
        )
        self.db.add_all([
            mailbox,
            quota2,
            quota2replica,
            alias,
            user_acl,
            user_attributes,
        ])

        # TODO: ratelimit

        self.sogo.update_static_view(username)

        return mailbox

    def update_mailbox(self, username: EmailStr, mailbox_update: MailboxUpdate) -> MailboxModel:
        details = self.get_mailbox_details(username)

        # Update mailbox values.
        mailbox = self.db.scalars(
            select(MailboxModel)
            .where(MailboxModel.username == username)
        ).one()
        if mailbox_update.name is not None:
            mailbox.name = mailbox_update.name

        if mailbox_update.active is not None:
            alias = self.db.scalars(
                select(AliasModel)
                .where(AliasModel.address == username)
            ).one()
            alias.active = mailbox_update.active
            mailbox.active = mailbox_update.active

        if mailbox_update.password:
            mailbox.password = self._get_hashed_password(
                mailbox_update.password,
                mailbox_update.password2,
            )

        if mailbox_update.quota is not None:
            # Ensure new quota is not less than current usage
            if mailbox_update.quota < details.quota_used:
                raise MailboxValidationError(
                    f"Cannot reduce quota below current usage ({details.quota_used} bytes)"
                )

            domain_data = self._get_domain_data(details.domain)
            if mailbox_update.quota > domain_data.maxquota:
                raise MailboxValidationError(
                    f"Mailbox quota ({mailbox_update.quota} bytes) exceeds the domain limit ({domain_data.maxquota} bytes)"
                )

            mailbox_data = self._get_mailbox_data(details.domain)
            # Calculate available quota after removing current mailbox
            available_quota = domain_data.quota - (mailbox_data.quota - details.quota)
            if mailbox_update.quota > available_quota:
                raise MailboxValidationError(
                    f"Not enough quota left ({available_quota} bytes)"
                )

            mailbox.quota = mailbox_update.quota

        # Update mailbox attributes.
        attributes = self.db.scalars(
            select(UserAttributesModel)
            .where(UserAttributesModel.username == username)
        ).one()
        for key, value in mailbox_update.model_dump().items():
            if value is not None and hasattr(attributes, key):
                setattr(attributes, key, value)

        self._update_sender_acl(username, mailbox_update)

        # TODO: recovery email?

        self.sogo.update_static_view(username)

        return mailbox

    def delete_mailbox(self, username: EmailStr) -> None:
        self.db.execute(delete(AliasModel).where(AliasModel.goto == username))
        # self.db.execute(delete(PushoverModel).where(PushoverModel.username == username))
        self.db.execute(delete(QuarantineModel).where(QuarantineModel.rcpt == username))
        self.db.execute(delete(Quota2Model).where(Quota2Model.username == username))
        self.db.execute(delete(Quota2ReplicaModel).where(Quota2ReplicaModel.username == username))
        self.db.execute(delete(MailboxModel).where(MailboxModel.username == username))
        self.db.execute(delete(SenderAclModel).where(
            or_(
                SenderAclModel.logged_in_as == username,
                SenderAclModel.send_as == username,
            )
        ))
        self.db.execute(delete(UserAclModel).where(UserAclModel.username == username))
        self.db.execute(delete(SpamaliasModel).where(SpamaliasModel.goto == username))
        self.db.execute(delete(ImapsyncModel).where(ImapsyncModel.user2 == username))
        self.db.execute(delete(FilterconfModel).where(FilterconfModel.object == username))
        self.db.execute(delete(BccMapsModel).where(BccMapsModel.local_dest == username))

        for alias in self.db.scalars(
            select(AliasModel)
            .where(AliasModel.goto.op("REGEXP")(f"(^|,){re.escape(username)}($|,)"))
        ).all():
            alias.goto = ",".join([a for a in alias.goto.split(",") if a != username])

        self.sogo.delete_user(username)
        self.sogo.update_static_view(username)

        self.store.hdel("RL_VALUE", username)

        # TODO: oauth

    def _get_sender_acl(self, username: EmailStr, external: bool) -> list[str]:
        return list(self.db.scalars(
            select(SenderAclModel.send_as)
            .where(
                SenderAclModel.logged_in_as == username,
                SenderAclModel.external == external,
            )
        ).all())

    def _update_sender_acl(self, username: EmailStr, mailbox_update: MailboxUpdate) -> None:
        if mailbox_update.sender_acl is not None:
            send_as = self._validate_sender_acl(username, mailbox_update.sender_acl)
            self._set_sender_acl(username, send_as, external=False)

        if mailbox_update.extended_sender_acl is not None:
            send_as = self._validate_extended_sender_acl(mailbox_update.extended_sender_acl)
            self._set_sender_acl(username, send_as, external=True)

    def _set_sender_acl(self, username: EmailStr, send_as: list[str], external: bool) -> None:
        self.db.execute(
            delete(SenderAclModel)
            .where(
                SenderAclModel.logged_in_as == username,
                SenderAclModel.external == external,
            )
        )
        self.db.add_all([
            SenderAclModel(logged_in_as=username, send_as=s, external=external)
            for s in dict.fromkeys(send_as)
        ])
        # Flush so a later delete in the same transaction sees these rows.
        self.db.flush()

    def _validate_sender_acl(self, username: EmailStr, sender_acl: list[str]) -> list[str]:
        # Like mailcow, "default" alone resets the list and "*" supersedes everything.
        sender_acl = [s.strip() for s in sender_acl if s.strip() != "default"]
        if "*" in sender_acl:
            return ["*"]

        local_domains = self._get_local_domains()
        # Aliases already pointing to the mailbox are allowed by Postfix without an ACL.
        fixed_aliases = self.db.scalars(
            select(AliasModel.address)
            .where(AliasModel.goto.op("REGEXP")(f"(^|,){re.escape(username)}($|,)"))
        ).all()
        send_as = []
        for value in sender_acl:
            if is_email(value):
                alias_domain = self.db.scalar(select(AliasModel.domain).where(AliasModel.address == value))
                if alias_domain not in local_domains:
                    raise MailboxValidationError(f"Sender ACL value {value} is invalid")
                if value not in fixed_aliases:
                    send_as.append(value)
            elif (domain := value.lstrip("@").lower()) in local_domains:
                send_as.append(f"@{domain}")
            else:
                raise MailboxValidationError(f"Sender ACL value {value} is invalid")

        return send_as

    def _validate_extended_sender_acl(self, extended_sender_acl: list[str]) -> list[str]:
        local_domains = self._get_local_domains()
        send_as = []
        for value in filter(None, map(str.strip, extended_sender_acl)):
            if is_email(value):
                domain = value.rsplit("@", 1)[1].lower()
            else:
                try:
                    domain = TypeAdapter(DomainStr).validate_python(value.lstrip("@"))
                except ValidationError as e:
                    raise MailboxValidationError(f'External sender address "{value}" is invalid') from e

            if domain in local_domains:
                raise MailboxValidationError(f'External sender "{value}" uses an invalid domain')

            send_as.append(value if is_email(value) else f"@{domain}")

        return send_as

    def _get_local_domains(self) -> set[str]:
        return set(self.db.scalars(
            select(DomainModel.domain)
            .union(select(AliasDomainModel.alias_domain))
        ).all())

    def _get_hashed_password(self, password1: str, password2: str) -> str:
        password_policy = self.password_policy_manager.get_policy()
        password_policy.validate_passwords(password1, password2)
        return hash_password(password1)

    def _get_mailbox_data(self, domain: DomainStr):
        return self.db.execute(
            select(
                func.count(MailboxModel.username).label("count"),
                func.coalesce(func.sum(MailboxModel.quota), 0).label("quota"),
            )
            .where(
                MailboxModel.kind == "",
                MailboxModel.domain == domain,
            )
        ).one()

    def _get_domain_data(self, domain: DomainStr):
        return self.db.scalars(
            select(DomainModel)
            .where(DomainModel.domain == domain)
        ).one()
