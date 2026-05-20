"""Unit tests for the socketmap module."""

import asyncio
import socket

from taramail.models import DomainModel
from taramail.socketmap import (
    handle_client,
    lookup_relay_domain,
    read_netstring,
    write_netstring,
)


def test_lookup_relay_domain_known(db_session, db_model, unique):
    """An active domain should be returned."""
    domain = unique("domain")
    db_model(DomainModel, domain=domain, active=True)
    assert lookup_relay_domain(db_session, domain) == domain


def test_lookup_relay_domain_unknown(db_session, unique):
    """A domain not in the database should return None."""
    assert lookup_relay_domain(db_session, unique("domain")) is None


def test_lookup_relay_domain_inactive(db_session, db_model, unique):
    """An inactive domain should return None."""
    domain = unique("domain")
    db_model(DomainModel, domain=domain, active=False)
    assert lookup_relay_domain(db_session, domain) is None


async def test_netstring_roundtrip():
    """A written netstring should be readable back to the original string."""
    data = "relay_domains example.com"

    rsock, wsock = socket.socketpair()
    server_reader, server_writer = await asyncio.open_connection(sock=rsock)
    _, client_writer = await asyncio.open_connection(sock=wsock)

    write_netstring(client_writer, data)
    await client_writer.drain()

    result = await read_netstring(server_reader)
    assert result == data

    client_writer.close()
    server_writer.close()


async def _socketmap_request(payload: str, db_session) -> str:
    """Send one socketmap request and return the decoded response."""
    rsock, wsock = socket.socketpair()
    server_reader, server_writer = await asyncio.open_connection(sock=rsock)
    client_reader, client_writer = await asyncio.open_connection(sock=wsock)

    server_task = asyncio.create_task(
        handle_client(server_reader, server_writer, db=db_session)
    )

    write_netstring(client_writer, payload)
    await client_writer.drain()
    response = await read_netstring(client_reader)

    client_writer.close()
    await server_task
    return response


async def test_handle_client_known_domain(db_model, unique, db_session):
    """handle_client should return OK for an active domain."""
    domain = unique("domain")
    db_model(DomainModel, domain=domain, active=True)
    response = await _socketmap_request(f"relay_domains {domain}", db_session)
    assert response == f"OK {domain}"


async def test_handle_client_unknown_domain(unique, db_session):
    """handle_client should return NOTFOUND for an unknown domain."""
    response = await _socketmap_request(f"relay_domains {unique('domain')}", db_session)
    assert response == "NOTFOUND "


async def test_handle_client_unknown_map(db_session):
    """handle_client should return PERM for an unknown map name."""
    response = await _socketmap_request("unknown_map example.com", db_session)
    assert response.startswith("PERM")
