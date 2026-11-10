"""Network-layer egress policy.

This is the concrete form of the promise in the threat model: the container may reach
the challenge's designated endpoints and nothing else, enforced at the network, not the
prompt. The policy is derived from the same `ScopePolicy` the in-process `egress()` gate
uses, so the two layers can never disagree. It is expressed as data (an allow-list plus
`allows()`), with iptables/nftables generators, so the enforcement logic is inspectable
and unit-tested without a live kernel."""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from ..guardrails.scope import ScopePolicy

ANY_PORT = 0  # sentinel: rule matches every port on the host
LOOPBACK = frozenset({"127.0.0.1", "::1", "localhost"})


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


@dataclass(frozen=True)
class EgressRule:
    host: str
    port: int = ANY_PORT  # 0 == any port

    def __str__(self) -> str:
        return f"{self.host}:{'*' if self.port == ANY_PORT else self.port}"


@dataclass
class EgressRuleset:
    """Default-deny: nothing is reachable unless a rule allows it (loopback aside)."""

    rules: tuple[EgressRule, ...] = ()
    allow_dns: bool = False
    allow_loopback: bool = True

    @property
    def deny_all(self) -> bool:
        return not self.rules

    def allows(self, host: str, port: int | None = None) -> bool:
        if self.allow_loopback and host in LOOPBACK:
            return True
        for r in self.rules:
            if r.host == host and (r.port == ANY_PORT or r.port == port):
                return True
        return False

    # --- rule generators (what a driver applies inside the net namespace) --- #
    def to_iptables(self, chain: str = "OUTPUT") -> list[str]:
        out = [f"-P {chain} DROP",
               f"-A {chain} -m state --state ESTABLISHED,RELATED -j ACCEPT"]
        if self.allow_loopback:
            out.append(f"-A {chain} -o lo -j ACCEPT")
        if self.allow_dns:
            out.append(f"-A {chain} -p udp --dport 53 -j ACCEPT")
            out.append(f"-A {chain} -p tcp --dport 53 -j ACCEPT")
        for r in self.rules:
            if r.port == ANY_PORT:
                out.append(f"-A {chain} -d {r.host} -j ACCEPT")
            else:
                out.append(f"-A {chain} -p tcp -d {r.host} --dport {r.port} -j ACCEPT")
        out.append(f"-A {chain} -j DROP")
        return out

    def to_nftables(self, table: str = "ctfsolver", chain: str = "egress") -> str:
        lines = [f"table inet {table} {{",
                 f"  chain {chain} {{",
                 "    type filter hook output priority 0; policy drop;",
                 "    ct state established,related accept"]
        if self.allow_loopback:
            lines.append("    oif \"lo\" accept")
        if self.allow_dns:
            lines.append("    udp dport 53 accept")
            lines.append("    tcp dport 53 accept")
        for r in self.rules:
            if r.port == ANY_PORT:
                lines.append(f"    ip daddr {r.host} accept")
            else:
                lines.append(f"    ip daddr {r.host} tcp dport {r.port} accept")
        lines += ["  }", "}"]
        return "\n".join(lines)

    def summary(self) -> str:
        return "deny-all" if self.deny_all else ", ".join(str(r) for r in self.rules)


def ruleset_from_scope(scope: ScopePolicy) -> EgressRuleset:
    """Build the egress allow-list from the authorized scope. A `host:port` opens only
    that port; a bare host opens any port; an http origin opens its host:port; DNS is
    allowed only if some target is a name rather than a bare IP."""
    rules: list[EgressRule] = []
    for hp in scope.allowed_hostports:
        host, _, port = hp.rpartition(":")
        if host and port.isdigit():
            rules.append(EgressRule(host, int(port)))
    for origin in scope.allowed_origins:
        p = urlsplit(origin)
        if p.hostname:
            port = p.port or (443 if p.scheme == "https" else 80)
            rules.append(EgressRule(p.hostname, port))
    for host in scope.allowed_hosts:
        if host in LOOPBACK:
            continue
        rules.append(EgressRule(host, ANY_PORT))
    deduped = tuple(dict.fromkeys(rules))
    allow_dns = any(not _is_ip(r.host) for r in deduped)
    return EgressRuleset(rules=deduped, allow_dns=allow_dns)
