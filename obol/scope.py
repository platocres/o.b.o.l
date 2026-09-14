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
