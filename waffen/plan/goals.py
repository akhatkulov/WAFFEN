"""Pre-defined attack goals for the planner."""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Goal:
    name: str
    description: str
    capability: str
    success_indicator: str
    attack_classes: list[str] = field(default_factory=list)


GOALS: dict[str, Goal] = {
    "dump_database": Goal(
        name="dump_database",
        description="Extract database contents via SQL injection",
        capability="data_extracted",
        success_indicator="data_extracted",
        attack_classes=["SQL Injection"],
    ),
    "admin_access": Goal(
        name="admin_access",
        description="Gain administrative privileges",
        capability="admin_token",
        success_indicator="admin_token",
        attack_classes=["SQL Injection", "NoSQL Injection"],
    ),
    "read_file": Goal(
        name="read_file",
        description="Read server files via LFI, SSRF, or XXE",
        capability="file_content",
        success_indicator="file_content",
        attack_classes=["Directory Traversal", "SSRF", "XXE Injection"],
    ),
    "rce": Goal(
        name="rce",
        description="Remote code execution on the server",
        capability="command_output",
        success_indicator="command_output",
        attack_classes=["Command Injection", "SSTI"],
    ),
    "xss_stored": Goal(
        name="xss_stored",
        description="Store XSS payload for other users to trigger",
        capability="payload_stored",
        success_indicator="payload_stored",
        attack_classes=["XSS Injection"],
    ),
    "account_takeover": Goal(
        name="account_takeover",
        description="Take over another user's account",
        capability="victim_session",
        success_indicator="victim_session",
        attack_classes=["SQL Injection", "XSS Injection"],
    ),
}


def list_goals() -> list[str]:
    return list(GOALS.keys())


def get_goal(name: str) -> Goal | None:
    return GOALS.get(name)
