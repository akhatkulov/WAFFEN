"""Terminal presentation: banner, colors, bars, verdict styling.

Colour and the banner auto-disable when stdout is not a TTY (piped, redirected,
captured in tests) or when NO_COLOR is set, so machine-readable output stays clean.
"""
from __future__ import annotations

import os
import sys

_FORCE = os.environ.get("WAFFEN_FORCE_COLOR")
COLOR = bool(_FORCE) or (
    not os.environ.get("NO_COLOR")
    and hasattr(sys.stdout, "isatty") and sys.stdout.isatty()
)

_C = {
    "reset": "\033[0m", "bold": "\033[1m", "dim": "\033[2m", "italic": "\033[3m",
    "red": "\033[31m", "green": "\033[32m", "yellow": "\033[33m", "blue": "\033[34m",
    "magenta": "\033[35m", "cyan": "\033[36m", "white": "\033[37m", "gray": "\033[90m",
    "bred": "\033[91m", "bgreen": "\033[92m", "byellow": "\033[93m", "bcyan": "\033[96m",
    "bmagenta": "\033[95m",
}


def style(text, *names) -> str:
    if not COLOR or not names:
        return text
    return "".join(_C.get(n, "") for n in names) + text + _C["reset"]


# convenience shorthands
def bold(t): return style(t, "bold")
def dim(t): return style(t, "dim")
def red(t): return style(t, "bred")
def green(t): return style(t, "bgreen")
def yellow(t): return style(t, "byellow")
def cyan(t): return style(t, "bcyan")
def magenta(t): return style(t, "bmagenta")
def gray(t): return style(t, "gray")


_BANNER = r"""
 ██╗    ██╗ █████╗ ███████╗███████╗███████╗███╗   ██╗
 ██║    ██║██╔══██╗██╔════╝██╔════╝██╔════╝████╗  ██║
 ██║ █╗ ██║███████║█████╗  █████╗  █████╗  ██╔██╗ ██║
 ██║███╗██║██╔══██║██╔══╝  ██╔══╝  ██╔══╝  ██║╚██╗██║
 ╚███╔███╔╝██║  ██║██║     ██║     ███████╗██║ ╚████║
  ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝     ╚═╝     ╚══════╝╚═╝  ╚═══╝"""

_EYE = "( ◉ )"


def banner(version: str = "", *, force: bool = False) -> str:
    """The WAFFEN banner. Empty string when colour/TTY is off (keeps pipes clean),
    unless force=True (e.g. the `version` command always shows it)."""
    if not COLOR and not force:
        return ""
    art = style(_BANNER, "bred", "bold") if COLOR else _BANNER
    tag = "   WAF evasion-path finder " + _EYE + "  ·  authorized targets only"
    sub = f"   v{version}" if version else ""
    tagline = style(tag, "gray") if COLOR else tag
    subline = style(sub, "dim") if COLOR else sub
    return f"{art}\n{tagline}{('   ' + subline) if sub else ''}\n"


def rule(label: str = "", width: int = 60) -> str:
    if not label:
        return gray("─" * width)
    line = f"── {label} " + "─" * max(0, width - len(label) - 4)
    return style(line, "gray")


def bar(pct: float, width: int = 22, good_high: bool = True) -> str:
    """A proportional bar. Coloured green/yellow/red by how good `pct` is."""
    pct = max(0.0, min(100.0, pct))
    filled = int(round(width * pct / 100.0))
    good = pct >= 90 if good_high else pct <= 5
    mid = 60 <= pct < 90 if good_high else 5 < pct <= 20
    glyph = "█" * filled + "░" * (width - filled)
    if not COLOR:
        return glyph
    color = "bgreen" if good else ("byellow" if mid else "bred")
    return style(glyph, color)


def verdict(v: str) -> str:
    return {
        "BLOCKED": green("BLOCKED"),   # WAF caught it: good for the defender
        "THROUGH": yellow("THROUGH"),  # reached origin: a gap
        "DOWN": gray("DOWN"),
    }.get(v, v)


def verified_tag(exploitable, confidence) -> str:
    if exploitable is None:
        return ""
    if exploitable:
        return "  " + red(f"⚑ EXPLOITABLE {confidence:.2f}")
    return "  " + dim(f"unconfirmed {confidence:.2f}" if confidence is not None else "unconfirmed")


def ok(t): return green("✔ ") + t
def warn(t): return yellow("▲ ") + t
def info(t): return cyan("• ") + t
def bad(t): return red("✘ ") + t
