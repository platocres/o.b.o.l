"""Evidence parser entrypoint.

The current parser core is kept in parsers_legacy so roadmap parser expansions can
layer on top without regressing the already-working nmap, LDAP, SMB, GPP, and
cracked-credential behavior.
"""
from __future__ import annotations

from .parsers_ext import parse_action_output

__all__ = ["parse_action_output"]
