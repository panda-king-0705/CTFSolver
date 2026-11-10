"""Scope confinement -- the first-class guardrail.

The solver may interact with the challenge's designated endpoints and *nothing else*.
This policy is the single source of truth; the sandbox consults it before any network
egress and refuses out-of-scope destinations. In production the same allow-list is
also enforced at the container's network layer, so a prompt can never talk the agent
into leaving scope.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlsplit

from ..models import Challenge


class ScopeError(PermissionError):
    """Raised when something tries to touch an endpoint outside the authorized scope."""


def _host_port_of_url(url: str) -> tuple[Optional[str], Optional[int]]:
    try:
        parts = urlsplit(url if "://" in url else "//" + url, scheme="http")
        host = parts.hostname
        port = parts.port
        if port is None and parts.scheme:
            port = {"http": 80, "https": 443}.get(parts.scheme)
        return host, port
    except ValueError:
        return None, None


def _origin(url: str) -> Optional[str]:
    parts = urlsplit(url if "://" in url else "http://" + url)
    if not parts.hostname:
        return None
    scheme = parts.scheme or "http"
    port = parts.port or {"http": 80, "https": 443}.get(scheme)
    return f"{scheme}://{parts.hostname}:{port}"


@dataclass
class ScopePolicy:
    """Default-deny allow-list. Keys may be `host`, `host:port`, a full url, or an
    opaque local-instance handle."""

    allowed_hosts: set[str] = field(default_factory=set)
    allowed_hostports: set[str] = field(default_factory=set)
    allowed_origins: set[str] = field(default_factory=set)
    allowed_handles: set[str] = field(default_factory=set)

    @classmethod
    def for_challenge(cls, challenge: Challenge) -> "ScopePolicy":
        """Build a tight allow-list. A `host:port` target authorizes ONLY that port on
        that host; a bare host (no port) authorizes any port on it; an http target
        authorizes only its exact origin. A local instance also opens loopback, since
        a container you stood up yourself binds an arbitrary local port."""
        p = cls()
        for t in challenge.targets:
            if t.kind == "tcp" and t.host:
                if t.port:
                    p.allowed_hostports.add(f"{t.host}:{t.port}")
                else:
                    p.allowed_hosts.add(t.host)
            elif t.kind == "http" and t.url:
                o = _origin(t.url)
                if o:
                    p.allowed_origins.add(o)
                h, port = _host_port_of_url(t.url)
                if h and port:
                    p.allowed_hostports.add(f"{h}:{port}")
        if challenge.local_instance:
            p.allowed_handles.add(challenge.local_instance)
            p.allowed_hosts.update({"127.0.0.1", "localhost"})
        return p

    # ------------------------------------------------------------------ #
    def is_allowed(
        self,
        *,
        host: Optional[str] = None,
        port: Optional[int] = None,
        url: Optional[str] = None,
        handle: Optional[str] = None,
    ) -> bool:
        if handle is not None:
            return handle in self.allowed_handles
        if url is not None:
            o = _origin(url)
            if o and o in self.allowed_origins:
                return True
            h, p = _host_port_of_url(url)
            host, port = h, (port or p)
        if host is None:
            return False
        if port is not None and f"{host}:{port}" in self.allowed_hostports:
            return True
        # host-only allowance covers any port on that exact host
        return host in self.allowed_hosts

    def check(
        self,
        *,
        host: Optional[str] = None,
        port: Optional[int] = None,
        url: Optional[str] = None,
        handle: Optional[str] = None,
    ) -> None:
        if not self.is_allowed(host=host, port=port, url=url, handle=handle):
            target = url or handle or (f"{host}:{port}" if port else host) or "(unknown)"
            raise ScopeError(
                f"out-of-scope endpoint refused: {target}. "
                f"authorized scope: {sorted(self.allowed_hostports | self.allowed_origins | self.allowed_handles) or sorted(self.allowed_hosts)}"
            )
