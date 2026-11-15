"""API service."""

from __future__ import annotations

import logging
import re
from base64 import b64encode
from pathlib import Path
from typing import Annotated

from fastapi import (
    Depends,
    FastAPI,
    HTTPException,
    Request,
    Response,
)
from fastapi.responses import JSONResponse
from fastapi.routing import APIRoute
from fastapi.security import (
    HTTPBasic,
    HTTPBasicCredentials,
)
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from jinja2 import (
    Environment,
    FileSystemLoader,
    select_autoescape,
)
from prometheus_client import (
    REGISTRY,
    generate_latest,
)
from prometheus_fastapi_instrumentator import Instrumentator
from pydantic import EmailStr

from taramail.alias import (
    AliasAlreadyExistsError,
    AliasCreate,
    AliasDetails,
    AliasManager,
    AliasNotFoundError,
    AliasUpdate,
    AliasValidationError,
)
from taramail.auth import (
    AuthContext,
    AuthMailboxBackend,
    AuthManager,
)
from taramail.db import db_transaction
from taramail.deps import (
    DbDep,
    MemcachedDep,
    QueueDep,
    StoreDep,
)
from taramail.dkim import (
    DKIMAlreadyExistsError,
    DKIMCreate,
    DKIMDetails,
    DKIMDuplicate,
    DKIMManager,
    DKIMNotFoundError,
)
from taramail.domain import (
    DomainAlreadyExistsError,
    DomainCreate,
    DomainDetails,
    DomainManager,
    DomainNotFoundError,
    DomainUpdate,
    DomainValidationError,
)
from taramail.forwarding_host import (
    ForwardingHostCreate,
    ForwardingHostDetails,
    ForwardingHostManager,
    ForwardingHostNotFoundError,
    ForwardingHostUpdate,
    ForwardingHostValidationError,
)
from taramail.mailbox import (
    MailboxAlreadyExistsError,
    MailboxCreate,
    MailboxDetails,
    MailboxManager,
    MailboxNotFoundError,
    MailboxUpdate,
    MailboxValidationError,
)
from taramail.password import (
    PasswordPolicy,
    PasswordPolicyManager,
    PasswordPolicyUpdate,
    PasswordValidationError,
)
from taramail.relayhost import (
    RelayHostAlreadyExistsError,
    RelayHostCreate,
    RelayHostDetails,
    RelayHostManager,
    RelayHostNotFoundError,
    RelayHostUpdate,
    RelayHostValidationError,
)
from taramail.rspamd import (
    RspamdAliasexp,
    RspamdBcc,
    RspamdMapDetails,
    RspamdMapNotFoundError,
    RspamdMaps,
    RspamdMapUpdate,
    RspamdMapValidationError,
    RspamdSettings,
)
from taramail.schemas import (
    AliasStr,
    DomainStr,
)
from taramail.sogo import Sogo
from taramail.spf import (
    DNSResolver,
    SPFResolver,
)
from taramail.transport import (
    TransportAlreadyExistsError,
    TransportCreate,
    TransportDetails,
    TransportManager,
    TransportNotFoundError,
    TransportUpdate,
    TransportValidationError,
)

logger = logging.getLogger("uvicorn")
app = FastAPI(
    docs_url="/api/swagger",
    openapi_url="/api/openapi.json",
)

env = Environment(
    loader=FileSystemLoader(Path(__file__).with_name("templates")),
    autoescape=select_autoescape(["j2"]),
)
env.filters["regex_replace"] = lambda s, p, r: re.sub(p, r, s)
templates = Jinja2Templates(env=env)


def get_alias_manager(db: DbDep, domain_manager: DomainManagerDep):
    return AliasManager(db, domain_manager)

AliasManagerDep = Annotated[AliasManager, Depends(get_alias_manager)]

def get_auth_manager(db: DbDep):
    backends = [
        AuthMailboxBackend(db)
    ]
    return AuthManager(backends)

AuthManagerDep = Annotated[AuthManager, Depends(get_auth_manager)]

def get_dkim_manager(store: StoreDep):
    return DKIMManager(store)

DKIMManagerDep = Annotated[DKIMManager, Depends(get_dkim_manager)]

def get_domain_manager(db: DbDep, store: StoreDep):
    return DomainManager(db, store)

DomainManagerDep = Annotated[DomainManager, Depends(get_domain_manager)]

def get_forwarding_host_manager(store: StoreDep):
    return ForwardingHostManager(store, SPFResolver(DNSResolver()))

ForwardingHostManagerDep = Annotated[ForwardingHostManager, Depends(get_forwarding_host_manager)]

def get_mailbox_manager(db: DbDep, password_policy_manager: PasswordPolicyManagerDep, store: StoreDep, sogo: SogoDep):
    return MailboxManager(db, store, password_policy_manager, sogo)

MailboxManagerDep = Annotated[MailboxManager, Depends(get_mailbox_manager)]

def get_password_policy_manager(store: StoreDep):
    return PasswordPolicyManager(store)

PasswordPolicyManagerDep = Annotated[PasswordPolicyManager, Depends(get_password_policy_manager)]

def get_relayhost_manager(db: DbDep):
    return RelayHostManager(db)

RelayHostManagerDep = Annotated[RelayHostManager, Depends(get_relayhost_manager)]

def get_rspamd_settings(db: DbDep):
    return RspamdSettings(db)

RspamdSettingsDep = Annotated[RspamdSettings, Depends(get_rspamd_settings)]

def get_rspamd_aliasexp(db: DbDep, store: StoreDep):
    return RspamdAliasexp(db, store)

RspamdAliasexpDep = Annotated[RspamdAliasexp, Depends(get_rspamd_aliasexp)]

def get_rspamd_bcc(db: DbDep):
    return RspamdBcc(db)

RspamdBccDep = Annotated[RspamdBcc, Depends(get_rspamd_bcc)]

def get_rspamd_maps():
    return RspamdMaps(Path("/etc/rspamd/custom"))

RspamdMapsDep = Annotated[RspamdMaps, Depends(get_rspamd_maps)]

def get_sogo(db: DbDep, memcached: MemcachedDep):
    return Sogo(db, memcached)

SogoDep = Annotated[Sogo, Depends(get_sogo)]

def get_transport_manager(db: DbDep):
    return TransportManager(db)

TransportManagerDep = Annotated[TransportManager, Depends(get_transport_manager)]


@app.get("/api/domains")
def get_domains(manager: DomainManagerDep) -> list[str]:
    return [d.domain for d in manager.get_domains()]


@app.get("/api/domains/{domain}")
def get_domain(domain: DomainStr, manager: DomainManagerDep) -> DomainDetails:
    return manager.get_domain_details(domain)


@app.post("/api/domains")
def post_domain(create: DomainCreate, manager: DomainManagerDep) -> DomainDetails:
    with db_transaction(manager.db):
        domain = manager.create_domain(create)
    return manager.get_domain_details(domain.domain)


@app.put("/api/domains/{domain}")
def put_domain(domain: DomainStr, update: DomainUpdate, manager: DomainManagerDep) -> DomainDetails:
    with db_transaction(manager.db):
        domain = manager.update_domain(domain, update)

    return manager.get_domain_details(domain.domain)


@app.delete("/api/domains/{domain}")
def delete_domain(domain: DomainStr, manager: DomainManagerDep) -> None:
    with db_transaction(manager.db):
        manager.delete_domain(domain)


@app.get("/api/mailboxes")
def get_mailboxes(manager: MailboxManagerDep) -> list[str]:
    return [m.username for m in manager.get_mailboxes()]


@app.get("/api/mailboxes/{username}")
def get_mailbox(username: EmailStr, manager: MailboxManagerDep) -> MailboxDetails:
    return manager.get_mailbox_details(username)


@app.post("/api/mailboxes")
def post_mailbox(create: MailboxCreate, manager: MailboxManagerDep) -> MailboxDetails:
    with db_transaction(manager.db):
        mailbox = manager.create_mailbox(create)
    return manager.get_mailbox_details(mailbox.username)


@app.put("/api/mailboxes/{username}")
def put_mailbox(username: EmailStr, update: MailboxUpdate, manager: MailboxManagerDep) -> MailboxDetails:
    with db_transaction(manager.db):
        mailbox = manager.update_mailbox(username, update)

    return manager.get_mailbox_details(mailbox.username)


@app.delete("/api/mailboxes/{username}")
def delete_mailbox(username: EmailStr, manager: MailboxManagerDep) -> None:
    with db_transaction(manager.db):
        manager.delete_mailbox(username)


@app.get("/api/aliases")
def get_aliases(domain: DomainStr, manager: AliasManagerDep) -> list[str]:
    return [a.address for a in manager.get_aliases(domain)]


@app.get("/api/aliases/{address}")
def get_alias(address: AliasStr, manager: AliasManagerDep) -> AliasDetails:
    return manager.get_alias_details(address)


@app.post("/api/aliases")
def post_alias(create: AliasCreate, manager: AliasManagerDep) -> AliasDetails:
    with db_transaction(manager.db):
        alias = manager.create_alias(create)
    return manager.get_alias_details(alias.address)


@app.put("/api/aliases/{address}")
def put_alias(address: AliasStr, update: AliasUpdate, manager: AliasManagerDep) -> AliasDetails:
    with db_transaction(manager.db):
        alias = manager.update_alias(address, update)

    return manager.get_alias_details(alias.address)


@app.delete("/api/aliases/{address}")
def delete_alias(address: AliasStr, manager: AliasManagerDep) -> None:
    with db_transaction(manager.db):
        manager.delete_alias(address)


@app.get("/api/forwardinghosts")
def get_forwarding_hosts(manager: ForwardingHostManagerDep) -> list[ForwardingHostDetails]:
    return manager.get_forwarding_hosts()


@app.get("/api/forwardinghosts/{host:path}")
def get_forwarding_host(host: str, manager: ForwardingHostManagerDep) -> ForwardingHostDetails:
    return manager.get_forwarding_host_details(host)


@app.post("/api/forwardinghosts")
def post_forwarding_host(create: ForwardingHostCreate, manager: ForwardingHostManagerDep) -> list[str]:
    return manager.add_forwarding_host(create)


@app.put("/api/forwardinghosts/{host:path}")
def put_forwarding_host(host: str, update: ForwardingHostUpdate, manager: ForwardingHostManagerDep) -> None:
    manager.update_forwarding_host(host, update)


@app.delete("/api/forwardinghosts/{host:path}")
def delete_forwarding_host(host: str, manager: ForwardingHostManagerDep) -> None:
    manager.delete_forwarding_host(host)


@app.get("/api/relayhosts")
def get_relayhosts(manager: RelayHostManagerDep) -> list[int]:
    return [r.id for r in manager.get_relayhosts()]


@app.get("/api/relayhosts/{relayhost_id}")
def get_relayhost(relayhost_id: int, manager: RelayHostManagerDep) -> RelayHostDetails:
    return manager.get_relayhost_details(relayhost_id)


@app.post("/api/relayhosts")
def post_relayhost(create: RelayHostCreate, manager: RelayHostManagerDep) -> RelayHostDetails:
    with db_transaction(manager.db):
        relayhost = manager.create_relayhost(create)
    return manager.get_relayhost_details(relayhost.id)


@app.put("/api/relayhosts/{relayhost_id}")
def put_relayhost(relayhost_id: int, update: RelayHostUpdate, manager: RelayHostManagerDep) -> RelayHostDetails:
    with db_transaction(manager.db):
        manager.update_relayhost(relayhost_id, update)

    return manager.get_relayhost_details(relayhost_id)


@app.delete("/api/relayhosts/{relayhost_id}")
def delete_relayhost(relayhost_id: int, manager: RelayHostManagerDep) -> None:
    with db_transaction(manager.db):
        manager.delete_relayhost(relayhost_id)


@app.get("/api/transports")
def get_transports(manager: TransportManagerDep) -> list[int]:
    return [t.id for t in manager.get_transports()]


@app.get("/api/transports/{transport_id}")
def get_transport(transport_id: int, manager: TransportManagerDep) -> TransportDetails:
    return manager.get_transport_details(transport_id)


@app.post("/api/transports")
def post_transport(create: TransportCreate, manager: TransportManagerDep) -> TransportDetails:
    with db_transaction(manager.db):
        transport = manager.create_transport(create)
    return manager.get_transport_details(transport.id)


@app.put("/api/transports/{transport_id}")
def put_transport(transport_id: int, update: TransportUpdate, manager: TransportManagerDep) -> TransportDetails:
    with db_transaction(manager.db):
        manager.update_transport(transport_id, update)

    return manager.get_transport_details(transport_id)


@app.delete("/api/transports/{transport_id}")
def delete_transport(transport_id: int, manager: TransportManagerDep) -> None:
    with db_transaction(manager.db):
        manager.delete_transport(transport_id)


@app.get("/api/dkim")
def get_dkim_keys(manager: DKIMManagerDep) -> dict[str, str]:
    return manager.get_keys()


@app.get("/api/dkim/{domain}")
def get_dkim_details(domain: DomainStr, manager: DKIMManagerDep) -> DKIMDetails:
    return manager.get_details(domain)


@app.post("/api/dkim")
def post_dkim(create: DKIMCreate, manager: DKIMManagerDep) -> DKIMDetails:
    manager.create_key(create)
    return manager.get_details(create.domain)


@app.post("/api/dkim/duplicate")
def post_dkim_duplicate(duplicate: DKIMDuplicate, manager: DKIMManagerDep) -> DKIMDetails:
    manager.duplicate_key(duplicate)
    return manager.get_details(duplicate.to_domain)


@app.delete("/api/dkim/{domain}")
def delete_dkim(domain: DomainStr, manager: DKIMManagerDep) -> None:
    manager.delete_key(domain)


@app.get("/api/password_policy")
def get_password_policy(manager: PasswordPolicyManagerDep) -> PasswordPolicy:
    return manager.get_policy()


@app.put("/api/password_policy")
def put_password_policy(policy_update: PasswordPolicyUpdate, manager: PasswordPolicyManagerDep) -> PasswordPolicy:
    return manager.update_policy(policy_update)


@app.delete("/api/password_policy")
def delete_password_policy(manager: PasswordPolicyManagerDep) -> None:
    manager.reset_policy()


@app.get("/api/rspamd/maps")
def get_rspamd_maps(maps: RspamdMapsDep) -> list[str]:
    return maps.get_maps()


@app.get("/api/rspamd/maps/{map_name}")
def get_rspamd_map(map_name: str, maps: RspamdMapsDep) -> RspamdMapDetails:
    return maps.get_map_details(map_name)


@app.put("/api/rspamd/maps/{map_name}")
def put_rspamd_map(map_name: str, update: RspamdMapUpdate, maps: RspamdMapsDep) -> RspamdMapDetails:
    return maps.update_map(map_name, update)


@app.api_route("/rspamd/settings", methods=["GET", "HEAD"], include_in_schema=False)
def get_rspamd_settings(request: Request, settings: RspamdSettingsDep) -> Response:
    return templates.TemplateResponse(request, "rspamd_settings.j2", {
        "allowed_domains_regex": settings.get_allowed_domains_regex(),
        "internal_aliases": settings.get_internal_aliases(),
        "custom_scores": settings.get_custom_scores(),
        "sogo_wl": settings.get_sogo_wl(),
        "whitelist_blocks": settings.get_blocks("whitelist_from", "whitelist_from_mime"),
        "blacklist_blocks": settings.get_blocks("blacklist_from", "blacklist_from_mime"),
    })


@app.get("/rspamd/aliasexp", include_in_schema=False)
def get_rspamd_aliasexp(request: Request, aliasexp: RspamdAliasexpDep) -> Response:
    """Expand email alias to final mailbox recipient."""
    rcpt = request.headers.get("Rcpt")
    content = aliasexp.expand_alias(rcpt)
    return Response(content=content, media_type="text/plain")


@app.get("/rspamd/bcc", include_in_schema=False)
def get_rspamd_bcc(request: Request, bcc: RspamdBccDep) -> Response:
    """Get BCC destination for recipient or sender."""
    rcpt = request.headers.get("Rcpt")
    sender = request.headers.get("From")
    content = bcc.get_bcc_dest(rcpt, sender)
    return Response(content=content, media_type="text/plain")


@app.get("/rspamd/error", include_in_schema=False)
async def get_rspamd_error(request: Request, queue: QueueDep) -> None:
    await queue.publish("F2B_CHANNEL", f"Rspamd UI: Invalid password by {request.client.host}")
    raise HTTPException(401, "Invalid password")


security = HTTPBasic(auto_error=False)

@app.get("/sogo-auth", include_in_schema=False)
def get_sogo_auth(credentials: Annotated[HTTPBasicCredentials | None, Depends(security)], manager: AuthManagerDep, request: Request, response: Response) -> None:
    if credentials:
        ip = request.headers.get("X-Real-IP", request.client.host)
        original_uri = request.headers.get("X-Original-URI", "")
        if re.match(r"^(\/SOGo|)\/dav.*", original_uri):
            service = "dav"
        elif re.match(r"/^(\/SOGo|)\/Microsoft-Server-ActiveSync.*/", original_uri):
            service = "eas"
        else:
            service = "api"

        username = credentials.username
        password = credentials.password
        context = AuthContext(ip=ip, service=service)
        if not manager.authenticate(username, password, context):
            raise HTTPException(401, "Invalid login")

        basic = b64encode(f"{username}:{password}".encode()).decode()
        response.headers["X-User"] = username
        response.headers["X-Auth"] = f"Basic {basic}"
        response.headers["X-Auth-Type"] = "Basic"
    else:
        response.headers["X-User"] = ""
        response.headers["X-Auth"] = ""
        response.headers["X-Auth-Type"] = ""


error_handlers = {
    AliasAlreadyExistsError: 409,
    AliasNotFoundError: 404,
    AliasValidationError: 400,
    DKIMAlreadyExistsError: 409,
    DKIMNotFoundError: 404,
    DomainAlreadyExistsError: 409,
    DomainNotFoundError: 404,
    DomainValidationError: 400,
    ForwardingHostNotFoundError: 404,
    ForwardingHostValidationError: 400,
    MailboxAlreadyExistsError: 409,
    MailboxNotFoundError: 404,
    MailboxValidationError: 400,
    PasswordValidationError: 400,
    RelayHostAlreadyExistsError: 409,
    RelayHostNotFoundError: 404,
    RelayHostValidationError: 400,
    RspamdMapNotFoundError: 404,
    RspamdMapValidationError: 400,
    TransportAlreadyExistsError: 409,
    TransportNotFoundError: 404,
    TransportValidationError: 400,
}

def create_error_handler(exc_class, status_code):
    async def error_handler(request: Request, exc: Exception):
        logger.warning(f"{exc_class.__name__} at {request.url}: {exc}")
        return JSONResponse(
            status_code=status_code,
            content={"error": exc_class.__name__, "detail": str(exc)},
        )
    return error_handler

for exc_type, status in error_handlers.items():
    app.exception_handler(exc_type)(create_error_handler(exc_type, status))


@app.exception_handler(Exception)
async def exception_handler(request: Request, exc: Exception):
    logger.exception(f"Unhandled exception at {request.url}")
    return JSONResponse(
        status_code=500,
        content={"error": "Unhandled exception"},
    )


Instrumentator(
    should_group_status_codes=True,
    should_ignore_untemplated=True,
    excluded_handlers=["/metrics"],
).instrument(app)

@app.get("/metrics", include_in_schema=False)
def metrics():
    return Response(content=generate_latest(REGISTRY), media_type="text/plain")


app.mount("/docs", StaticFiles(directory="./build/html", html=True, check_dir=False))

# Simplify operation IDs to use route names.
for route in app.routes:
    if isinstance(route, APIRoute):
        route.operation_id = route.name
