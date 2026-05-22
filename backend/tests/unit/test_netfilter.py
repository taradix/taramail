"""Unit tests for the netfilter module."""

from unittest.mock import ANY, AsyncMock, Mock, patch

import pytest
from hamcrest import (
    assert_that,
    empty,
    has_item,
    has_items,
)

from taramail.netfilter import (
    Netfilter,
    NetfilterService,
    NetfilterTables,
    get_ip,
    is_ip,
    main,
    resolve_addresses,
)


def test_get_ip():
    """Getting an IP should return an IP object or None."""
    ip = get_ip("8.8.8.8")
    assert str(ip) == "8.8.8.8"


@pytest.mark.parametrize(
    "address, expected",
    [
        ("127.0.0.1", True),
        ("127.0.0.1/24", True),
        ("192.168.0.0/24", True),
        ("github.com", False),
    ],
)
def test_is_ip(address, expected):
    """Checking an address should return whether it's an IP."""
    assert is_ip(address) is expected


@pytest.mark.parametrize(
    "addresses, matches",
    [
        ([], empty()),
        (["192.168.0.1"], has_item("192.168.0.1")),
        (["localhost"], has_item("127.0.0.1")),
        (["192.168.0.1", "localhost"], has_items("192.168.0.1", "127.0.0.1")),
    ],
)
async def test_resolve_addresses(addresses, matches):
    """Resolving addresses should only return IP adresses."""
    result = await resolve_addresses(addresses)
    assert_that(result, matches)


@pytest.mark.parametrize(
    "ban_counter, net_ban_time",
    [
        (1, 3600),
        (2, 7200),
        (10, 10000),
    ],
)
def test_netfilter_calc_net_ban_time(ban_counter, net_ban_time):
    """Calculating the net ban time should return the seconds to ban for a given counter."""
    netfilter = Netfilter(None, None, None)
    result = netfilter.calc_net_ban_time(ban_counter)
    assert result == net_ban_time


def test_netfilter_tables_init_chains():
    """Initializing chains should set names with lowest priority."""
    nft = Mock(
        json_cmd=Mock(
            return_value=(
                0,
                {
                    "nftables": [
                        {"chain": {"name": "a", "table": "filter", "hook": "input", "prio": 2}},
                        {"chain": {"name": "b", "table": "filter", "hook": "input", "prio": 1}},
                    ],
                },
                None,
            )
        )
    )
    netfilter = NetfilterTables(None, None, None, nft).init_chains()
    assert netfilter.chains["filter"]["input"] == "b"


def test_netfilter_tables_get_chain_handle():
    """Getting netfilter rule handles should return a list of handles."""
    nft = Mock(
        json_cmd=Mock(
            return_value=(
                0,
                {
                    "nftables": [
                        {
                            "chain": {
                                "family": "family",
                                "table": "table",
                                "name": "name",
                                "handle": "handle",
                            },
                        },
                    ],
                },
                None,
            )
        )
    )
    netfilter = NetfilterTables(None, None, "family", nft)
    result = netfilter.get_chain_handle("table", "name")
    assert result == "handle"


def test_netfilter_tables_get_rule_handles():
    """Getting netfilter rule handles should return a list of handles."""
    nft = Mock(
        json_cmd=Mock(
            return_value=(
                0,
                {
                    "nftables": [
                        {
                            "rule": {
                                "family": "family",
                                "table": "table",
                                "chain": "chain",
                                "comment": "comment",
                                "handle": "handle",
                            },
                        },
                    ],
                },
                None,
            )
        )
    )
    netfilter = NetfilterTables(None, None, "family", nft)
    result = netfilter.get_rule_handles("table", "chain", "comment")
    assert result == ["handle"]


def test_netfilter_tables_ban():
    """Banning should insert a filter rule."""
    netfilter = NetfilterTables(None, None, "family")
    with patch.object(NetfilterTables, "insert_rule") as insert_rule:
        netfilter.ban("127.0.0.1")
        insert_rule.assert_called_once_with("filter", netfilter.name, ANY)


def test_netfilter_tables_flush_chain():
    """Flushing a netfilter chain should run a flush command."""
    nft = Mock(json_cmd=Mock(return_value=(0, None, None)))
    netfilter = NetfilterTables(None, None, "family", nft)
    netfilter.flush_chain()
    nft.json_cmd.assert_called_once_with(
        {
            "nftables": [
                {
                    "metainfo": {
                        "json_schema_version": 1,
                    },
                },
                {
                    "flush": {
                        "chain": {
                            "family": "family",
                        },
                    },
                },
            ]
        }
    )


def test_netfilter_tables_list_chains():
    """Listing netfilter chains should run a list command."""
    nft = Mock(json_cmd=Mock(return_value=(0, None, None)))
    netfilter = NetfilterTables(None, None, "family", nft)
    netfilter.list_chains()
    nft.json_cmd.assert_called_once_with(
        {
            "nftables": [
                {
                    "metainfo": {
                        "json_schema_version": 1,
                    },
                },
                {
                    "list": {
                        "chains": {
                            "family": "family",
                        },
                    },
                },
            ]
        }
    )


def test_netfilter_tables_list_table():
    """Listing a netfilter table should run a list command."""
    nft = Mock(json_cmd=Mock(return_value=(0, None, None)))
    netfilter = NetfilterTables(None, None, "family", nft)
    netfilter.list_table()
    nft.json_cmd.assert_called_once_with(
        {
            "nftables": [
                {
                    "metainfo": {
                        "json_schema_version": 1,
                    },
                },
                {
                    "list": {
                        "table": {
                            "family": "family",
                        },
                    },
                },
            ]
        }
    )


def test_netfilter_tables_delete_chain():
    """Deleting a netfilter chain should run a delete command."""
    nft = Mock(json_cmd=Mock(return_value=(0, None, None)))
    netfilter = NetfilterTables(None, None, "family", nft)
    netfilter.delete_chain("table", "name", "handle")
    nft.json_cmd.assert_called_once_with({
        "nftables": [
            {
                "metainfo": {
                    "json_schema_version": 1,
                },
            },
            {
                "delete": {
                    "chain": {
                        "family": "family",
                        "table": "table",
                        "name": "name",
                        "handle": "handle",
                    },
                },
            },
        ]
    })


def test_netfilter_tables_delete_rule():
    """Deleting a netfilter rule should run a delete command."""
    nft = Mock(json_cmd=Mock(return_value=(0, None, None)))
    netfilter = NetfilterTables(None, None, "family", nft)
    netfilter.delete_rule("table", "chain", "handle")
    nft.json_cmd.assert_called_once_with({
        "nftables": [
            {
                "metainfo": {
                    "json_schema_version": 1,
                },
            },
            {
                "delete": {
                    "rule": {
                        "family": "family",
                        "table": "table",
                        "chain": "chain",
                        "handle": "handle",
                    },
                },
            },
        ]
    })


def test_netfilter_tables_run_cmd():
    """Running a command should at least specify the JSON schema version."""
    nft = Mock(json_cmd=Mock(return_value=(0, "", {"nftables": []})))
    netfilter = NetfilterTables(None, None, None, nft)
    netfilter.run_cmd()
    nft.json_cmd.assert_called_once_with(
        {
            "nftables": [
                {
                    "metainfo": {
                        "json_schema_version": 1,
                    },
                },
            ]
        }
    )


async def test_netfilter_update_blacklist(redis_store):
    """Updating the blacklist should get from F2B_BLACKLIST."""
    redis_store.hset("F2B_BLACKLIST", "127.0.0.1", 1)
    netfilter = Netfilter(redis_store, None, None)
    assert netfilter.whitelist == set()

    with patch.object(Netfilter, "perm_ban", new_callable=AsyncMock) as perm_ban:
        await netfilter.update_blacklist()
        perm_ban.assert_called_once_with(net="127.0.0.1")

    assert netfilter.blacklist == {"127.0.0.1"}


async def test_netfilter_update_whitelist(redis_store):
    """Updating the whitelist should get from F2B_WHITELIST."""
    redis_store.hset("F2B_WHITELIST", "127.0.0.1", 1)
    netfilter = Netfilter(redis_store, None, None)
    assert netfilter.whitelist == set()

    await netfilter.update_whitelist()
    assert netfilter.whitelist == {"127.0.0.1"}


async def test_netfilter_service_snat4():
    """Calling the service snat4 should call on the ipv4 tables."""
    netfilter = Mock(lock=AsyncMock())
    service = NetfilterService(netfilter, None)

    netfilter.ipv4_tables.snat.side_effect = lambda *_: service.stop_event.set()

    await service.snat4(None, 0)

    netfilter.ipv4_tables.snat.assert_called_once()


async def test_netfilter_service_snat6():
    """Calling the service snat6 should call on the ipv6 tables."""
    netfilter = Mock(lock=AsyncMock())
    service = NetfilterService(netfilter, None)

    netfilter.ipv6_tables.snat.side_effect = lambda *_: service.stop_event.set()

    await service.snat6(None, 0)

    netfilter.ipv6_tables.snat.assert_called_once()


async def test_netfilter_service_autopurge():
    """Calling the service autopurge should autopurge the netfilter."""
    netfilter = AsyncMock()
    service = NetfilterService(netfilter, None)

    netfilter.autopurge.side_effect = lambda: service.stop_event.set()

    await service.autopurge(0)

    netfilter.autopurge.assert_called_once()


async def test_netfilter_service_whitelist():
    """Calling the service whitelist should update the netfilter whitelist."""
    netfilter = AsyncMock()
    service = NetfilterService(netfilter, None)

    netfilter.update_whitelist.side_effect = lambda: service.stop_event.set()

    await service.whitelist(0.1)

    netfilter.update_whitelist.assert_called_once()


async def test_netfilter_service_blacklist():
    """Calling the service blacklist should update the netfilter blacklist."""
    netfilter = AsyncMock()
    service = NetfilterService(netfilter, None)

    netfilter.update_blacklist.side_effect = lambda: service.stop_event.set()

    await service.blacklist(0.1)

    netfilter.update_blacklist.assert_called_once()


async def test_netfilter_service_before_exit():
    """The service should unsubscribe before exit."""
    queue = AsyncMock()
    await NetfilterService(None, queue).before_exit()
    queue.unsubscribe.assert_called_once()


async def test_netfilter_service_before_exit_clear():
    """The service should clear when asked before exit."""
    netfilter, queue = AsyncMock(), AsyncMock()
    await NetfilterService(netfilter, queue, clear_before_exit=True).before_exit()
    netfilter.clear.assert_called_once()


async def test_netfilter_service_watch(memory_queue):
    """Watching should ban when a message matches on the F2B_CHANNEL."""
    netfilter = AsyncMock()
    service = NetfilterService(netfilter, memory_queue)

    netfilter.ban.side_effect = lambda _: service.stop_event.set()
    await memory_queue.subscribe("F2B_CHANNEL")
    await memory_queue.publish(
        "F2B_CHANNEL",
        "mail UI: Invalid password for .+ by 1.2.3.4",
    )

    await service.watch()

    netfilter.ban.assert_called_once()


@patch("sys.stdout")
def test_main_help(stdout):
    """The main function should output usage when asked for --help."""
    with pytest.raises(SystemExit):
        main(["--help"])

    assert "usage" in stdout.write.call_args[0][0]
