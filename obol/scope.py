"""Engagement scope helpers.

The runner is allowed to execute only against targets the operator explicitly
put in scope. This is intentionally small for the first live-run slice: exact
hosts and CIDR networks are supported, with URL/host:port normalization so
command templates can stay operator-friendly.
"""
from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlparse

_HOST_PORT_RE = re.compile(r"^([A-Za-z0-9_.-]+):(\d{1,5})$")
_IP_SCOPE_RE = re.compile(
    r"(?P<ip>(?:\d{1,3}\.){3}\d{1,3})(?P<prefix>/\d{1,2})?"
)


def normalize_target(value: str) -> str:
    """Return a normalized host/IP from URLs, host:port values, or raw strings."""
    text = str(value or "").strip().strip("[]")
    if not text:
        return ""
    if "://" in text:
        parsed = urlparse(text)
        text = parsed.hostname or ""
    match = _HOST_PORT_RE.match(text)
    if match:
        text = match.group(1)
    text = text.strip().strip(".")
    if not text:
        return ""
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        pass
    if re.match(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,252}$", text):
        return text.lower()
    return ""


def normalize_scope_entry(value: str) -> str:
    """Normalize one scope entry to how it is stored and matched.

    A genuine CIDR network is kept verbatim (``10.10.10.0/24``); anything else —
    a host, IP, URL, or ``host:port`` — is reduced to a bare host via
    :func:`normalize_target`. Returns ``""`` if the value is neither a valid
    network nor a valid host, so callers can reject it.
    """
    raw = str(value or "").strip()
    if "/" in raw:
        try:
            return str(ipaddress.ip_network(raw, strict=False))
        except ValueError:
            # Not a network — fall through to host normalization, which also
            # handles URLs like http://host/path by extracting the host.
            return normalize_target(raw)
    return normalize_target(raw)


def extract_ip_scope_entries(text: str) -> list[str]:
    """Pull only valid IP addresses/CIDRs out of pasted operator text.

    This is intentionally stricter than :func:`normalize_scope_entry`: URLs,
    labels, hostnames, ports, bullets, and scanner chatter are treated only as
    places an IP/CIDR might appear. The returned entries are canonicalized and
    de-duplicated in first-seen order.
    """
    out: list[str] = []
    seen: set[str] = set()
    for match in _IP_SCOPE_RE.finditer(str(text or "")):
        raw = match.group("ip") + (match.group("prefix") or "")
        try:
            value = (
                str(ipaddress.ip_network(raw, strict=False))
                if "/" in raw else str(ipaddress.ip_address(raw))
            )
        except ValueError:
            continue
        if value not in seen:
            seen.add(value)
            out.append(value)
    return out


def target_in_scope(target: str, scope: list[str]) -> tuple[bool, str]:
    """Return whether target is allowed, plus the matching scope entry/reason."""
    normalized = normalize_target(target)
    if not normalized:
        return False, "target is empty or invalid"
    for entry in scope:
        item = str(entry or "").strip()
        if not item:
            continue
        try:
            address = ipaddress.ip_address(normalized)
            network = ipaddress.ip_network(item, strict=False)
            if address in network:
                return True, item
        except ValueError:
            pass
        if normalize_target(item) == normalized:
            return True, item
    return False, f"{target} is not in obol scope"
