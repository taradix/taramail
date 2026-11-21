"""Network filtering."""

import asyncio
import ipaddress
import logging
import os
import re
import signal
import sys
import time
import uuid
from argparse import ArgumentParser
from collections import defaultdict
from itertools import product

import dns.asyncresolver
import dns.exception
import dns.resolver
from attrs import define, field
from more_itertools import partition
from nftables import Nftables
from taralog import (
    LoggerHandlerAction,
    LoggerLevelAction,
    setup_logger,
)
from taraqueue.redis import RedisQueue

from taramail.store import (
    RedisStore,
)

logger = logging.getLogger(__name__)


def get_ip(address):
    ip = ipaddress.ip_address(address)
    if type(ip) is ipaddress.IPv6Address and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    if ip.is_private or ip.is_loopback:
        return None

    return ip


def is_ip(address):
    """Return whether the given address is an IP."""
    try:
        ipaddress.ip_network(address, False)
    except ValueError:
        return False
    return True


async def resolve_addresses(addresses):
    """Return IPs from a list of addresses that might be host names."""
    resolver = dns.asyncresolver.Resolver()
    hostnames, ips = map(list, partition(is_ip, addresses))
    for hostname, rdtype in product(hostnames, ["A", "AAAA"]):
        try:
            answer = await resolver.resolve(qname=hostname, rdtype=rdtype, lifetime=3)
        except dns.exception.Timeout:
            logger.info("Hostname %(hostname)s timedout on resolve", {"hostname": hostname})
            continue
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            continue
        except dns.exception.DNSException:
            logger.exception("DNS error")
            continue

        for rdata in answer:
            ips.append(rdata.to_text())

    return set(ips)


class NetfilterError(Exception):
    """Raised when an unexpected error happens."""


@define(frozen=True)
class NetfilterTables:

    name = field()
    comment = field()
    family = field()
    nft = field(factory=Nftables)
    chains = field(
        factory=lambda: {
            "filter": {
                "input": "",
                "forward": "",
            },
            "nat": {
                "postrouting": "",
            },
        }
    )

    @classmethod
    def from_current_chains(cls, name, family):
        nft = Nftables()
        nft.set_json_output(True)
        nft.set_handle_output(True)
        return cls(name, family, nft)

    def init_chains(self):
        saved_priorities = defaultdict(dict)
        kernel_ruleset = self.list_chains()
        for obj in kernel_ruleset["nftables"]:
            if chain := obj.get("chain"):
                table = chain["table"]
                hook = chain.get("hook")
                priority = chain.get("prio")

                if priority is not None and table in self.chains and hook in self.chains[table]:
                    saved_priority = saved_priorities[table].get(hook)
                    if saved_priority is None or priority < saved_priority:
                        saved_priorities[table][hook] = priority
                        self.chains[table][hook] = chain["name"]

        return self

    def insert_mail_chains(self):
        input_chain = self.chains["filter"]["input"]
        forward_chain = self.chains["filter"]["forward"]

        kernel_ruleset = self.list_table(name="filter")
        if all(obj.get("chain", {}).get("name") != self.name for obj in kernel_ruleset["nftables"]):
            self.add_chain(table="filter", name=self.name)

        input_jump_found, forward_jump_found = False, False
        for obj in kernel_ruleset["nftables"]:
            if rule := obj.get("rule"):
                if input_chain and rule["chain"] == input_chain and rule.get("comment") == self.comment:
                    input_jump_found = True
                if forward_chain and rule["chain"] == forward_chain and rule.get("comment") == self.comment:
                    forward_jump_found = True

        if input_chain and not input_jump_found:
            self.insert_mail_rule(input_chain)

        if forward_chain and not forward_jump_found:
            self.insert_mail_rule(forward_chain)

    def insert_mail_rule(self, chain: str):
        expr = [
            {
                "counter": {
                    "family": self.family,
                    "table": "filter",
                    "packets": 0,
                    "bytes": 0,
                },
            },
            {
                "jump": {
                    "target": self.name,
                },
            },
        ]

        self.insert_rule("filter", chain, expr, comment=self.comment)

    def check_chain_order(self):
        error = False

        for chain in ["input", "forward"]:
            position = self.check(chain)
            if position is None:
                continue

            if position < 0:
                logger.critical(
                    "Target not found in %(family)s %(chain)s table, restarting container to fix it...",
                    {
                        "chain": chain,
                        "family": self.family,
                    },
                )
                error = True

            elif position > 0:
                logger.critical(
                    "Target is in position %(position)s in the %(family)s %(chain)s table, restarting container to"
                    " fix it...",
                    {
                        "chain": chain,
                        "family": self.family,
                        "position": position,
                    },
                )
                error = True

        if error:
            raise NetfilterError("Chain order error, see critical logs")

    def check(self, chain: str):
        chain_name = self.chains["filter"][chain]
        if not chain_name:
            return None

        kernel_ruleset = self.list_chain(table="filter", name=chain_name)
        position = 0
        for obj in kernel_ruleset["nftables"]:
            if "rule" not in obj:
                continue
            if obj["rule"].get("comment") == self.comment:
                return position
            position += 1

        return -1

    def create_isolation_rule(self, interface: str, dports: list):
        table = "filter"
        comment_filter_drop = "mail isolation"

        # Delete old isolation rules
        handles = self.get_rule_handles(table, self.name, comment_filter_drop)
        for handle in handles:
            self.delete_rule(table, self.name, handle)

        # Insert isolation rules
        expr = [
            {
                "match": {
                    "op": "!=",
                    "left": {"meta": {"key": "iifname"}},
                    "right": interface,
                },
            },
            {
                "match": {
                    "op": "==",
                    "left": {"meta": {"key": "oifname"}},
                    "right": interface,
                },
            },
            {
                "match": {
                    "op": "==",
                    "left": {"payload": {"protocol": "tcp", "field": "dport"}},
                    "right": {"set": dports},
                }
            },
            {
                "counter": {"packets": 0, "bytes": 0},
            },
            {
                "drop": None,
            },
        ]
        self.insert_rule(table, self.name, expr, comment=comment_filter_drop)

    def clear(self):
        chain_handle = self.get_chain_handle("filter", self.name)
        if chain_handle:
            self.flush_chain(table="filter", name=self.name)

        for chain_base in [
            self.chains["filter"]["input"],
            self.chains["filter"]["forward"],
        ]:
            if not chain_base:
                continue

            for rule_handle in self.get_rule_handles("filter", chain_base, self.comment):
                self.delete_rule("filter", chain_base, rule_handle)

        if chain_handle:
            self.delete_chain("filter", self.name, chain_handle)

    def snat(self, snat_target: str, source_address: str):
        chain_name = self.chains["nat"]["postrouting"]

        # no postrouting chain, may occur if docker has ipv6 disabled.
        if not chain_name:
            return

        # Command: nft list chain <family> nat <chain_name>
        rule_position = 0
        rule_handle = None
        rule_found = False
        kernel_ruleset = self.list_chain(table="nat", name=chain_name)
        for obj in kernel_ruleset["nftables"]:
            if not obj.get("rule"):
                continue

            rule = obj["rule"]
            if rule.get("comment") != self.comment:
                rule_position += 1
                continue
            rule_found = True
            rule_handle = rule["handle"]
            break

        dest_net = ipaddress.ip_network(source_address, strict=False)
        target_net = ipaddress.ip_network(snat_target, strict=False)

        if rule_found:
            saddr_ip = rule["expr"][0]["match"]["right"]["prefix"]["addr"]
            saddr_len = int(rule["expr"][0]["match"]["right"]["prefix"]["len"])

            daddr_ip = rule["expr"][1]["match"]["right"]["prefix"]["addr"]
            daddr_len = int(rule["expr"][1]["match"]["right"]["prefix"]["len"])

            target_ip = rule["expr"][3]["snat"]["addr"]

            saddr_net = ipaddress.ip_network(f"{saddr_ip}/{saddr_len}", strict=False)
            daddr_net = ipaddress.ip_network(f"{daddr_ip}/{daddr_len}", strict=False)
            current_target_net = ipaddress.ip_network(target_ip, strict=False)

            if rule_position == 0:
                if not all([
                    dest_net == saddr_net,
                    dest_net == daddr_net,
                    target_net == current_target_net,
                ]):
                    # Position 0 , it is a mail rule , but it does not have the same parameters
                    self.delete_rule("nat", chain_name, rule_handle)
                    logger.info(
                        "Remove rule for source network %(saddr_net)s to SNAT target %(target_net)s from"
                        " %(family)s nat %(chain_name)s chain, rule does not match configured parameters",
                        {
                            "family": self.family,
                            "saddr_net": saddr_net,
                            "target_net": target_net,
                            "chain_name": chain_name,
                        },
                    )
            else:
                # Position > 0 and is mail rule
                self.delete_rule("nat", chain_name, rule_handle)
                logger.info(
                    "Remove rule for source network %(saddr_net)s to SNAT target %(target_net)s from %(family)s"
                    " nat %(chain_name)s chain, rule is at position %(rule_position)s",
                    {
                        "family": self.family,
                        "saddr_net": saddr_net,
                        "target_net": target_net,
                        "chain_name": chain_name,
                        "rule_position": rule_position,
                    },
                )

        else:
            expr = [
                {
                    "match": {
                        "op": "==",
                        "left": {
                            "payload": {
                                "protocol": self.family,
                                "field": "saddr",
                            },
                        },
                        "right": {
                            "prefix": {
                                "addr": str(dest_net.network_address),
                                "len": int(dest_net.prefixlen),
                            },
                        },
                    },
                },
                {
                    "match": {
                        "op": "!=",
                        "left": {
                            "payload": {
                                "protocol": self.family,
                                "field": "daddr",
                            },
                        },
                        "right": {
                            "prefix": {
                                "addr": str(dest_net.network_address),
                                "len": int(dest_net.prefixlen),
                            },
                        },
                    },
                },
                {
                    "snat": {
                        "addr": str(target_net.network_address),
                    },
                },
                {
                    "counter": {
                        "family": self.family,
                        "table": "nat",
                        "packets": 0,
                        "bytes": 0,
                    },
                },
            ]
            self.insert_rule("nat", chain_name, expr, comment=self.comment)
            logger.info(
                "Added %(family)s nat %(chain_name)s rule for source network %(dest_net)s to %(target_net)s",
                {
                    "family": self.family,
                    "chain_name": chain_name,
                    "dest_net": dest_net,
                    "target_net": target_net,
                },
            )

    def get_chain_handle(self, table: str, name: str):
        expected = {
            "family": self.family,
            "table": table,
            "name": name,
        }
        kernel_ruleset = self.list_chains()
        for obj in kernel_ruleset["nftables"]:
            if "chain" in obj and all(obj["chain"][k] == v for k, v in expected.items()):
                return obj["chain"]["handle"]

    def get_rule_handles(self, table: str, chain: str, comment: str):
        expected = {
            "family": self.family,
            "table": table,
            "chain": chain,
            "comment": comment,
        }
        kernel_ruleset = self.list_chain(table=table, name=chain)
        return [
            obj["rule"]["handle"]
            for obj in kernel_ruleset["nftables"]
            if "rule" in obj and all(obj["rule"].get(k) == v for k, v in expected.items())
        ]

    def ban(self, ipaddr: str):
        ipaddr_net = ipaddress.ip_network(ipaddr, strict=False)
        expr = [
            {
                "match": {
                    "op": "==",
                    "left": {
                        "payload": {
                            "protocol": self.family,
                            "field": "saddr",
                        },
                    },
                    "right": {
                        "prefix": {
                            "addr": str(ipaddr_net.network_address),
                            "len": int(ipaddr_net.prefixlen),
                        },
                    },
                },
            },
            {
                "counter": {
                    "family": self.family,
                    "table": "filter",
                    "packets": 0,
                    "bytes": 0,
                },
            },
            {"drop": "null"},
        ]

        return self.insert_rule("filter", self.name, expr)

    def unban(self, ipaddr: str):
        kernel_ruleset = self.list_chain(table="filter", name=self.name)
        for obj in kernel_ruleset["nftables"]:
            if not obj.get("rule"):
                continue

            rule = obj["rule"]["expr"][0]["match"]
            if "payload" not in rule["left"]:
                continue
            left_opt = rule["left"]["payload"]
            if left_opt["protocol"] != self.family:
                continue
            if left_opt["field"] != "saddr":
                continue

            # ip currently banned
            rule_right = rule["right"]
            if isinstance(rule_right, dict):
                current_rule_ip = rule_right["prefix"]["addr"] + "/" + str(rule_right["prefix"]["len"])
            else:
                current_rule_ip = rule_right
            current_rule_net = ipaddress.ip_network(current_rule_ip)

            # ip to unban
            candidate_net = ipaddress.ip_network(ipaddr, strict=False)
            if current_rule_net == candidate_net:
                rule_handle = obj["rule"]["handle"]
                self.delete_rule("filter", self.name, rule_handle)
                break

    def add_chain(self, **kwargs):
        return self.run_cmd({
            "add": {
                "chain": {
                    "family": self.family,
                    **kwargs,
                },
            },
        })

    def flush_chain(self, **kwargs):
        return self.run_cmd({
            "flush": {
                "chain": {
                    "family": self.family,
                    **kwargs,
                },
            },
        })

    def insert_rule(self, table: str, chain: str, expr, **kwargs):
        return self.run_cmd({
            "insert": {
                "rule": {
                    "family": self.family,
                    "table": table,
                    "chain": chain,
                    "expr": expr,
                    **kwargs,
                },
            },
        })

    def list_chain(self, **kwargs):
        return self.run_cmd({
            "list": {
                "chain": {
                    "family": self.family,
                    **kwargs,
                },
            },
        })

    def list_chains(self):
        return self.run_cmd({
            "list": {
                "chains": {
                    "family": self.family,
                },
            },
        })

    def list_table(self, **kwargs):
        return self.run_cmd({
            "list": {
                "table": {
                    "family": self.family,
                    **kwargs,
                },
            },
        })

    def delete_chain(self, table: str, name: str, handle: str):
        return self.run_cmd({
            "delete": {
                "chain": {
                    "family": self.family,
                    "table": table,
                    "name": name,
                    "handle": handle,
                },
            },
        })

    def delete_rule(self, table: str, chain: str, handle: str):
        return self.run_cmd({
            "delete": {
                "rule": {
                    "family": self.family,
                    "table": table,
                    "chain": chain,
                    "handle": handle,
                },
            },
        })

    def run_cmd(self, *obj):
        cmd = {"nftables": [{"metainfo": {"json_schema_version": 1}}, *obj]}
        logger.info("Running nft commands: %(obj)s", {"obj": obj})
        rc, output, error = self.nft.json_cmd(cmd)
        if rc != 0:
            logger.critical(
                "Nftables error for %(cmd)s: %(error)s",
                {
                    "cmd": cmd,
                    "error": error,
                },
            )
            raise NetfilterError(error)

        return output


@define
class Netfilter:

    store = field()
    ipv4_tables = field()
    ipv6_tables = field()
    bans = field(factory=dict)
    blacklist = field(factory=set)
    whitelist = field(factory=set)
    lock = field(factory=asyncio.Lock)

    @classmethod
    def from_env(cls, env=os.environ):
        store = RedisStore.from_env(env)
        name = env.get("NETFILTER_CHAIN_NAME", "MAIL")
        comment = env.get("NETFILTER_CHAIN_COMMENT", "mail")
        ipv4_tables = NetfilterTables(name, comment, "ip").init_chains()
        ipv6_tables = NetfilterTables(name, comment, "ip6").init_chains()
        return cls(store, ipv4_tables, ipv6_tables)

    @property
    def f2boptions(self):
        return {
            "ban_time": 1800,
            "max_ban_time": 10000,
            "ban_time_increment": True,
            "max_attempts": 10,
            "retry_window": 600,
            "netban_ipv4": 32,
            "netban_ipv6": 128,
            "banlist_id": str(uuid.uuid4()),
            "manage_external": 0,
        }

    def calc_net_ban_time(self, ban_counter):
        ban_time = self.f2boptions["ban_time"]
        max_ban_time = self.f2boptions["max_ban_time"]
        ban_time_increment = self.f2boptions["ban_time_increment"]
        net_ban_time = ban_time if not ban_time_increment else ban_time * 2**ban_counter
        net_ban_time = max([ban_time, min([net_ban_time, max_ban_time])])
        return net_ban_time

    async def ban(self, address):
        max_attempts = self.f2boptions["max_attempts"]
        retry_window = self.f2boptions["retry_window"]
        netban_ipv4 = f"/{self.f2boptions['netban_ipv4']}"
        netban_ipv6 = f"/{self.f2boptions['netban_ipv6']}"

        ip = get_ip(address)
        if not ip:
            return

        address = str(ip)
        self_network = ipaddress.ip_network(address)

        async with self.lock:
            whitelist = self.whitelist

        if whitelist:
            for wl_key in whitelist:
                wl_net = ipaddress.ip_network(wl_key, False)
                if wl_net.overlaps(self_network):
                    logger.info(
                        "Address %(network)s is whitelisted by rule %(rule)s",
                        {
                            "network": self_network,
                            "rule": wl_net,
                        },
                    )
                    return

        net = ipaddress.ip_network(
            (address + (netban_ipv4 if type(ip) is ipaddress.IPv4Address else netban_ipv6)), strict=False
        )
        net = str(net)
        if net not in self.bans:
            self.bans[net] = {"attempts": 0, "last_attempt": 0, "ban_counter": 0}

        current_attempt = time.time()
        if current_attempt - self.bans[net]["last_attempt"] > retry_window:
            self.bans[net]["attempts"] = 0

        self.bans[net]["attempts"] += 1
        self.bans[net]["last_attempt"] = current_attempt

        if self.bans[net]["attempts"] >= max_attempts:
            cur_time = round(time.time())
            net_ban_time = self.calc_net_ban_time(self.bans[net]["ban_counter"])
            logger.critical(
                "Banning %(net)s for %(minutes)d minutes",
                {
                    "net": net,
                    "minutes": net_ban_time / 60,
                },
            )
            if type(ip) is ipaddress.IPv4Address and self.f2boptions["manage_external"] != 1:
                async with self.lock:
                    self.ipv4_tables.ban(net)
            elif self.f2boptions["manage_external"] != 1:
                async with self.lock:
                    self.ipv6_tables.ban(net)

            self.store.hset("F2B_ACTIVE_BANS", net, cur_time + net_ban_time)
        else:
            logger.warning(
                "%(attempts)d more attempts in the next %(seconds)d seconds until %(net)s is banned",
                {
                    "attempts": max_attempts - self.bans[net]["attempts"],
                    "seconds": retry_window,
                    "net": net,
                },
            )

    async def unban(self, net):
        if net not in self.bans:
            logger.info("%(net)s is not banned, skipping unban and deleting from queue (if any)", {"net": net})
            self.store.hdel("F2B_QUEUE_UNBAN", net)
            return

        logger.info(
            "Unbanning %(net)s",
            {
                "net": net,
            },
        )
        if type(ipaddress.ip_network(net)) is ipaddress.IPv4Network:
            async with self.lock:
                self.ipv4_tables.unban(net)
        else:
            async with self.lock:
                self.ipv6_tables.unban(net)

        self.store.hdel("F2B_ACTIVE_BANS", net)
        self.store.hdel("F2B_QUEUE_UNBAN", net)
        if net in self.bans:
            self.bans[net]["attempts"] = 0
            self.bans[net]["ban_counter"] += 1

    async def perm_ban(self, net, unban=False):
        is_unbanned = False
        is_banned = False
        if type(ipaddress.ip_network(net, strict=False)) is ipaddress.IPv4Network:
            async with self.lock:
                if unban:
                    is_unbanned = self.ipv4_tables.unban(net)
                elif self.f2boptions["manage_external"] != 1:
                    is_banned = self.ipv4_tables.ban(net)
        else:
            async with self.lock:
                if unban:
                    is_unbanned = self.ipv6_tables.unban(net)
                elif self.f2boptions["manage_external"] != 1:
                    is_banned = self.ipv6_tables.ban(net)

        if is_unbanned:
            self.store.hdel("F2B_PERM_BANS", net)
            logger.critical(
                "Removed host/network %(net)s from blacklist",
                {
                    "net": net,
                },
            )
        elif is_banned:
            self.store.hset("F2B_PERM_BANS", net, round(time.time()))
            logger.critical(
                "Added host/network %(net)s to blacklist",
                {
                    "net": net,
                },
            )

    async def autopurge(self):
        max_attempts = self.f2boptions["max_attempts"]
        queue_unban = self.store.hgetall("F2B_QUEUE_UNBAN")
        if queue_unban:
            for net in queue_unban:
                await self.unban(str(net))
        for net in self.bans.copy():
            if self.bans[net]["attempts"] >= max_attempts:
                net_ban_time = self.calc_net_ban_time(self.bans[net]["ban_counter"])
                time_since_last_attempt = time.time() - self.bans[net]["last_attempt"]
                if time_since_last_attempt > net_ban_time:
                    await self.unban(net)

    async def chain_order(self):
        async with self.lock:
            self.ipv4_tables.check_chain_order()
            self.ipv6_tables.check_chain_order()

    async def update_blacklist(self):
        blacklist = set(self.store.hgetall("F2B_BLACKLIST"))
        new_blacklist = await resolve_addresses(blacklist)
        if new_blacklist != self.blacklist:
            addban = new_blacklist.difference(self.blacklist)
            delban = self.blacklist.difference(new_blacklist)
            self.blacklist = new_blacklist
            logger.info(
                "Blacklist was changed, it has %(num)s entries",
                {
                    "num": len(self.blacklist),
                },
            )
            for net in addban:
                await self.perm_ban(net=net)
            for net in delban:
                await self.perm_ban(net=net, unban=True)

    async def update_whitelist(self):
        whitelist = set(self.store.hgetall("F2B_WHITELIST"))
        new_whitelist = await resolve_addresses(whitelist)
        async with self.lock:
            if new_whitelist != self.whitelist:
                self.whitelist = new_whitelist
                logger.info(
                    "Whitelist was changed, it has %(num)s entries",
                    {
                        "num": len(self.whitelist),
                    },
                )

    async def clear(self):
        logger.info("Clearing all bans")
        for net in self.bans.copy():
            await self.unban(net)
        async with self.lock:
            self.ipv4_tables.clear()
            self.ipv6_tables.clear()
            try:
                self.store.delete("F2B_ACTIVE_BANS")
                self.store.delete("F2B_PERM_BANS")
            except Exception:
                logger.exception("Error clearing store keys F2B_ACTIVE_BANS and F2B_PERM_BANS")


@define
class NetfilterService:

    netfilter = field()
    queue = field()
    stop_event = field(factory=asyncio.Event)
    exit_code = field(default=0)
    clear_before_exit = field(default=False)

    @classmethod
    def from_env(cls, netfilter: Netfilter, env=os.environ):
        queue = RedisQueue.from_env(env)
        return cls(netfilter, queue)

    @property
    def f2bregex(self):
        return {
            1: "mail UI: Invalid password for .+ by ([0-9a-f\\.:]+)",
            2: "Rspamd UI: Invalid password by ([0-9a-f\\.:]+)",
            3: (
                "warning: .*\\[([0-9a-f\\.:]+)\\]: SASL .+ authentication failed: (?!.*Connection lost to"
                " authentication server).+"
            ),
            4: "warning: non-SMTP command from .*\\[([0-9a-f\\.:]+)]:.+",
            5: "NOQUEUE: reject: RCPT from \\[([0-9a-f\\.:]+)].+Protocol error.+",
            6: "-login: Disconnected.+ \\(auth failed, .+\\): user=.*, method=.+, rip=([0-9a-f\\.:]+),",
            7: "-login: Aborted login.+ \\(auth failed .+\\): user=.+, rip=([0-9a-f\\.:]+), lip.+",
            8: "-login: Aborted login.+ \\(tried to use disallowed .+\\): user=.+, rip=([0-9a-f\\.:]+), lip.+",
            9: "SOGo.+ Login from '([0-9a-f\\.:]+)' for user .+ might not have worked",
            10: '([0-9a-f\\.:]+) "GET \\/SOGo\\/.* HTTP.+" 403 .+',
        }

    async def watch(self):
        logger.info("Watching Redis channel F2B_CHANNEL")
        await self.queue.subscribe("F2B_CHANNEL")

        while not self.stop_event.is_set():
            try:
                while True:
                    if message := await self.queue.receive(timeout=60):
                        for rule_id, rule_regex in self.f2bregex.items():
                            if result := re.search(rule_regex, message):
                                addr = result.group(1)
                                if get_ip(addr):
                                    logger.warning(
                                        "%(addr)s matched rule id %(rule_id)s (%(data)s)",
                                        {
                                            "addr": addr,
                                            "rule_id": rule_id,
                                            "data": message,
                                        },
                                    )
                                    await self.netfilter.ban(addr)
                                    break

                    if self.stop_event.is_set():
                        break
            except Exception:
                logger.exception("Watch error")
                self.stop_event.set()
                self.exit_code = 2

    async def chain_order(self):
        while not self.stop_event.is_set():
            await asyncio.sleep(10)
            try:
                await self.netfilter.chain_order()
            except NetfilterError:
                self.stop_event.set()
                self.exit_code = 2

    async def snat4(self, snat_target, delay=10):
        while not self.stop_event.is_set():
            await asyncio.sleep(delay)
            async with self.netfilter.lock:
                self.netfilter.ipv4_tables.snat(snat_target, os.getenv("IPV4_NETWORK", "172.22.1") + ".0/24")

    async def snat6(self, snat_target, delay=10):
        while not self.stop_event.is_set():
            await asyncio.sleep(delay)
            async with self.netfilter.lock:
                self.netfilter.ipv6_tables.snat(snat_target, os.getenv("IPV6_NETWORK", "fd4d:6169:6c63:6f77::/64"))

    async def autopurge(self, delay=10):
        while not self.stop_event.is_set():
            await asyncio.sleep(delay)
            await self.netfilter.autopurge()

    async def whitelist(self, delay=60.0):
        while not self.stop_event.is_set():
            start_time = time.time()
            await self.netfilter.update_whitelist()
            await asyncio.sleep(delay - ((time.time() - start_time) % delay))

    async def blacklist(self, delay=60.0):
        while not self.stop_event.is_set():
            start_time = time.time()
            await self.netfilter.update_blacklist()
            await asyncio.sleep(delay - ((time.time() - start_time) % delay))

    def handle_sigterm(self):
        self.clear_before_exit = True
        self.stop_event.set()

    async def before_exit(self):
        if self.clear_before_exit:
            await self.netfilter.clear()
        await self.queue.unsubscribe("F2B_CHANNEL")


def main(argv=None):  # pragma: no cover
    sys.exit(asyncio.run(_main(argv)))


async def _main(argv=None):  # pragma: no cover
    parser = ArgumentParser()
    parser.add_argument(
        "--log-file",
        action=LoggerHandlerAction,
    )
    parser.add_argument(
        "--log-level",
        action=LoggerLevelAction,
    )
    args = parser.parse_args(argv)

    setup_logger(args.log_level, args.log_file)

    netfilter = Netfilter.from_env()
    await netfilter.clear()

    service = NetfilterService.from_env(netfilter)

    loop = asyncio.get_running_loop()
    loop.add_signal_handler(signal.SIGTERM, service.handle_sigterm)

    netfilter.ipv4_tables.insert_mail_chains()
    netfilter.ipv6_tables.insert_mail_chains()
    netfilter.ipv4_tables.create_isolation_rule("br-taramail", [6379])

    tasks = [
        asyncio.create_task(service.watch()),
        asyncio.create_task(service.autopurge()),
        asyncio.create_task(service.chain_order()),
        asyncio.create_task(service.blacklist()),
        asyncio.create_task(service.whitelist()),
    ]

    if snat4_ip := os.getenv("SNAT_TO_SOURCE"):
        snat4_ipo = ipaddress.ip_address(snat4_ip)
        if type(snat4_ipo) is ipaddress.IPv4Address:
            tasks.append(asyncio.create_task(service.snat4(snat4_ip)))

    if snat6_ip := os.getenv("SNAT6_TO_SOURCE"):
        snat6_ipo = ipaddress.ip_address(snat6_ip)
        if type(snat6_ipo) is ipaddress.IPv6Address:
            tasks.append(asyncio.create_task(service.snat6(snat6_ip)))

    try:
        await service.stop_event.wait()
    finally:
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        await service.before_exit()

    return service.exit_code
