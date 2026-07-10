"""
Rotating contact/outreach messages shown below the startup banner.

Enabled by default; persists a single on/off preference in a per-user file
(``~/.pyspector/preferences.json``) so `--msg=False` needs to be passed only
once and stays off across future runs and projects.
"""

import json
import random
from pathlib import Path
from typing import Optional

import click  # type: ignore

CONTACT_EMAIL = "pyspector@biz.securitycert.it"

# Plain-text email address, no "mailto:" prefix — most terminal emulators
# auto-detect and linkify bare "user@domain" text, but won't recognize a
# "mailto:" scheme unless it's wrapped in a proper OSC 8 hyperlink escape
# (which not every terminal supports either). Plain text is the one form
# that's clickable pretty much everywhere.
_CONTACT_LINE = f"Contact Us: {CONTACT_EMAIL}"

# Dimmed so the opt-out hint reads as a quiet footnote, not a second
# call-to-action competing with the message itself.
_OPT_OUT_HINT = click.style("(you can turn off these messages with --msg=False)", dim=True)


def _msg(lead: str) -> str:
    return f"📬 {lead} {_CONTACT_LINE} {_OPT_OUT_HINT}"


CONTACT_MESSAGES = [
    _msg("Do you need more from PySpector?"),
    _msg("Does your company use PySpector and has specific needs?"),
    _msg("Want a custom solution tailored to your codebase?"),
    _msg("Need enterprise support or a dedicated SLA for PySpector?"),
    _msg("Looking to roll out PySpector across your pipeline?"),
]


def _preferences_path() -> Path:
    """Per-user preferences file, independent of the scanned project."""
    return Path.home() / ".pyspector" / "preferences.json"


def _load_preferences() -> dict:
    path = _preferences_path()
    if not path.exists():
        return {}
    try:
        with path.open("r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except (json.JSONDecodeError, OSError):
        return {}


def messages_enabled() -> bool:
    """Whether rotating contact messages should be shown. Enabled by default."""
    return bool(_load_preferences().get("show_messages", True))


def set_messages_enabled(enabled: bool) -> None:
    """Persist the on/off preference so it survives future, unrelated runs."""
    path = _preferences_path()
    prefs = _load_preferences()
    prefs["show_messages"] = enabled
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8") as f:
            json.dump(prefs, f, indent=2)
    except OSError:
        # Best-effort persistence: if the home directory isn't writable,
        # silently fall back to in-memory-only behaviour for this run
        # rather than aborting the scan over a cosmetic feature.
        pass


def random_contact_message() -> str:
    """Return one randomly chosen, ready-to-print contact message."""
    return random.choice(CONTACT_MESSAGES)


def handle_msg_flag(msg: Optional[bool]) -> None:
    """
    Apply an explicit --msg=True/False flag (if given) to the persisted
    preference, then print a rotating contact message if messages are
    currently enabled. Call once, right after printing the banner.
    """
    if msg is not None:
        set_messages_enabled(msg)

    if messages_enabled():
        click.echo(click.style(random_contact_message(), fg="cyan") + "\n")
