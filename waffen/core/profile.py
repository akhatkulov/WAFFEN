"""Target profile — persist recon results and search state across sessions.

A profile stores everything WAFFEN learns about a target: calibration,
score-probe keyword maps, libinjection gap reports, partial search
findings, and which transforms have been completed. Saving after each
transform means a Ctrl-C or crash loses at most one transform's work.

Usage:
    profile = TargetProfile.create("https://t.com", "/search", "q")
    profile.set_calibration({...})
    profile.add_findings([...])
    profile.save("target.json")

    profile = TargetProfile.load("target.json")
    if profile.has_calibration(): ...
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@dataclass
class TargetProfile:
    target_url: str
    path: str = "/"
    param: str = "q"
    created: str = ""
    updated: str = ""

    fingerprint: dict | None = None
    calibration: dict | None = None
    cluster_profile: dict | None = None
    score_probe: dict = field(default_factory=dict)
    gap_reports: dict = field(default_factory=dict)

    findings: list[dict] = field(default_factory=list)
    transforms_completed: list[str] = field(default_factory=list)
    transforms_remaining: list[str] = field(default_factory=list)
    total_requests: int = 0

    # ---- constructors -------------------------------------------------------

    @classmethod
    def create(cls, target_url: str, path: str = "/", param: str = "q") -> "TargetProfile":
        now = _now()
        return cls(target_url=target_url, path=path, param=param,
                   created=now, updated=now)

    # ---- recon setters -------------------------------------------------------

    def set_fingerprint(self, data: dict):
        self.fingerprint = data
        self.updated = _now()

    def set_calibration(self, data: Any):
        if hasattr(data, "__dict__"):
            self.calibration = {k: v for k, v in data.__dict__.items()
                                if not k.startswith("_")}
        elif isinstance(data, dict):
            self.calibration = data
        self.updated = _now()

    def set_cluster_profile(self, data: Any):
        if hasattr(data, "as_dict"):
            self.cluster_profile = data.as_dict()
        elif isinstance(data, dict):
            self.cluster_profile = data
        self.updated = _now()

    def set_score_probe(self, cls: str, result: Any):
        if hasattr(result, "as_dict"):
            self.score_probe[cls] = result.as_dict()
        elif isinstance(result, dict):
            self.score_probe[cls] = result
        else:
            self.score_probe[cls] = {"raw": str(result)}
        self.updated = _now()

    def set_gap_reports(self, reports: list):
        for r in reports:
            engine = getattr(r, "engine", None) or "unknown"
            if hasattr(r, "__dict__"):
                d = {}
                for k, v in r.__dict__.items():
                    if k.startswith("_"):
                        continue
                    try:
                        json.dumps(v)
                        d[k] = v
                    except (TypeError, ValueError):
                        d[k] = str(v)
                self.gap_reports[engine] = d
            elif isinstance(r, dict):
                self.gap_reports[engine] = r
        self.updated = _now()

    # ---- search state --------------------------------------------------------

    def add_findings(self, findings: list):
        for f in findings:
            if hasattr(f, "__dict__"):
                entry = {k: v for k, v in f.__dict__.items() if not k.startswith("_")}
            elif isinstance(f, dict):
                entry = f
            else:
                entry = {"payload": str(f)}
            if entry not in self.findings:
                self.findings.append(entry)
        self.updated = _now()

    def mark_transform_done(self, name: str):
        if name not in self.transforms_completed:
            self.transforms_completed.append(name)
        if name in self.transforms_remaining:
            self.transforms_remaining.remove(name)
        self.updated = _now()

    def set_transforms_remaining(self, names: list[str]):
        self.transforms_remaining = [n for n in names
                                     if n not in self.transforms_completed]
        self.updated = _now()

    def add_requests(self, n: int):
        self.total_requests += n
        self.updated = _now()

    # ---- query helpers -------------------------------------------------------

    def has_calibration(self) -> bool:
        return self.calibration is not None

    def has_score_probe(self, cls: str = "") -> bool:
        if cls:
            return cls in self.score_probe
        return bool(self.score_probe)

    def has_gap_reports(self) -> bool:
        return bool(self.gap_reports)

    def is_transform_done(self, name: str) -> bool:
        return name in self.transforms_completed

    # ---- merge ---------------------------------------------------------------

    def merge(self, other: "TargetProfile"):
        if other.fingerprint and not self.fingerprint:
            self.fingerprint = other.fingerprint
        if other.calibration:
            self.calibration = other.calibration
        if other.cluster_profile:
            self.cluster_profile = other.cluster_profile
        for cls, data in other.score_probe.items():
            if cls not in self.score_probe:
                self.score_probe[cls] = data
        for engine, data in other.gap_reports.items():
            if engine not in self.gap_reports:
                self.gap_reports[engine] = data
        self.add_findings(other.findings)
        for t in other.transforms_completed:
            self.mark_transform_done(t)
        self.total_requests += other.total_requests
        self.updated = _now()

    # ---- persistence ---------------------------------------------------------

    def save(self, path: str):
        self.updated = _now()
        with open(path, "w") as f:
            json.dump(self._to_dict(), f, indent=2, ensure_ascii=False, default=str)

    @classmethod
    def load(cls, path: str) -> "TargetProfile":
        with open(path) as f:
            d = json.load(f)
        return cls._from_dict(d)

    def _to_dict(self) -> dict:
        return {
            "target_url": self.target_url,
            "path": self.path,
            "param": self.param,
            "created": self.created,
            "updated": self.updated,
            "fingerprint": self.fingerprint,
            "calibration": self.calibration,
            "cluster_profile": self.cluster_profile,
            "score_probe": self.score_probe,
            "gap_reports": self.gap_reports,
            "findings": self.findings,
            "transforms_completed": self.transforms_completed,
            "transforms_remaining": self.transforms_remaining,
            "total_requests": self.total_requests,
        }

    @classmethod
    def _from_dict(cls, d: dict) -> "TargetProfile":
        return cls(
            target_url=d.get("target_url", ""),
            path=d.get("path", "/"),
            param=d.get("param", "q"),
            created=d.get("created", ""),
            updated=d.get("updated", ""),
            fingerprint=d.get("fingerprint"),
            calibration=d.get("calibration"),
            cluster_profile=d.get("cluster_profile"),
            score_probe=d.get("score_probe", {}),
            gap_reports=d.get("gap_reports", {}),
            findings=d.get("findings", []),
            transforms_completed=d.get("transforms_completed", []),
            transforms_remaining=d.get("transforms_remaining", []),
            total_requests=d.get("total_requests", 0),
        )

    # ---- display -------------------------------------------------------------

    def summary(self) -> str:
        lines = [
            f"  Target:       {self.target_url}{self.path}?{self.param}=",
            f"  Created:      {self.created}",
            f"  Updated:      {self.updated}",
            f"  Requests:     {self.total_requests}",
            f"  Fingerprint:  {'yes' if self.fingerprint else 'no'}",
            f"  Calibration:  {'yes' if self.calibration else 'no'}",
            f"  Score probe:  {', '.join(self.score_probe.keys()) or 'none'}",
            f"  Gap reports:  {', '.join(self.gap_reports.keys()) or 'none'}",
            f"  Findings:     {len(self.findings)}",
            f"  Transforms:   {len(self.transforms_completed)} done"
            + (f", {len(self.transforms_remaining)} remaining"
               if self.transforms_remaining else ""),
        ]
        return "\n".join(lines)
