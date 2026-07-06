"""
src/scope.py — authorization gate.

This is the single non-negotiable safety control in the platform: before
any HTTP request is sent to a domain, the operator must explicitly
confirm authorization for that domain, once. After confirmation, the
domain is remembered in data/authorized_targets.json so the operator is
not re-prompted on every run -- only the first time against a new
target.

This module is intentionally unaffected by "make everything automated":
full automation applies to what the LLM decides to test and how, not to
whether a domain may be attacked at all. That decision remains a human
one, made explicitly, once per domain.
"""
import json
import os
import urllib.parse
from typing import Optional

DATA_DIR = "data"
TARGETS_FILE = os.path.join(DATA_DIR, "authorized_targets.json")


class ScopeViolation(Exception):
    """Raised when an action targets a domain that has not been authorized."""
    pass


def _load() -> dict:
    if not os.path.exists(TARGETS_FILE):
        return {}
    with open(TARGETS_FILE) as f:
        return json.load(f)


def _save(data: dict) -> None:
    os.makedirs(DATA_DIR, exist_ok=True)
    with open(TARGETS_FILE, "w") as f:
        json.dump(data, f, indent=2)


def _domain(url: str) -> str:
    return urllib.parse.urlparse(url).netloc.lower()


def is_authorized(url: str) -> bool:
    return _domain(url) in _load()


def confirm_authorized(url: str, interactive: bool = True) -> bool:
    """
    Returns True if the domain is (now) authorized to test against.

    On first contact with a domain, prompts the operator to type the
    domain name back as an explicit confirmation -- cheap to do, hard to
    do by accident, which is the point.

    If interactive=False (e.g. running unattended / in a script) and the
    domain isn't already authorized, this refuses rather than assuming
    consent.
    """
    domain = _domain(url)
    if not domain:
        return False
    known = _load()
    if domain in known:
        return True
    if not interactive:
        return False

    print(f"\n[SCOPE CHECK] This run will send live test traffic to '{domain}'.")
    print("  Only proceed if you own this target or have explicit written")
    print("  authorization to test it (e.g. it is your own lab, a site you")
    print("  operate, or a purpose-built practice target).")
    typed = input(f"  Type the domain exactly ('{domain}') to confirm: ").strip().lower()
    if typed != domain:
        print("  Domain did not match -- refusing to proceed.")
        return False

    known[domain] = {"confirmed": True}
    _save(known)
    print(f"  Confirmed. '{domain}' is now authorized for future runs too.\n")
    return True


def revoke(url: str) -> None:
    """Removes a domain from the authorized list, e.g. if you're done
    testing it and want the confirmation prompt back next time."""
    known = _load()
    domain = _domain(url)
    if domain in known:
        del known[domain]
        _save(known)
