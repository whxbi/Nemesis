"""
src/scope.py — authorization gate.

Right now the agent will happily run live SQLi/XSS/credential-bruteforce
payloads against literally any URL it's given, with zero confirmation.
That's the single biggest gap in the project regardless of intent — a
typo'd target, a copy-pasted URL, or a bad LLM plan could point live
attack traffic at a domain you don't own.

This module makes the agent stop and ask, once per domain, before it ever
sends a single request there. After you confirm, that domain is
remembered in data/authorized_targets.json so you're not re-prompted on
every run — only the first time against a new target.
"""
import json
import os
import urllib.parse
from typing import Optional

DATA_DIR = "data"
TARGETS_FILE = os.path.join(DATA_DIR, "authorized_targets.json")


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
    domain name back as an explicit confirmation — cheap to do, hard to
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

    print(f"\n⚠  SCOPE CHECK: this run will send live test traffic to '{domain}'.")
    print("   Only proceed if you own this target or have explicit written")
    print("   authorization to test it (e.g. it's your own lab, a site you")
    print("   run, or a purpose-built practice target like vulnbank.org).")
    typed = input(f"   Type the domain exactly ('{domain}') to confirm: ").strip().lower()

    if typed != domain:
        print("   Domain did not match — refusing to proceed.")
        return False

    known[domain] = {"confirmed": True}
    _save(known)
    print(f"   Confirmed. '{domain}' is now authorized for future runs too.\n")
    return True


def revoke(url: str) -> None:
    """Removes a domain from the authorized list, e.g. if you're done
    testing it and want the confirmation prompt back next time."""
    known = _load()
    domain = _domain(url)
    if domain in known:
        del known[domain]
        _save(known)
