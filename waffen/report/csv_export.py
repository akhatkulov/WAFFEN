"""CSV export for WAFFEN findings — for spreadsheet users."""
import csv


_FIELDNAMES = [
    "attack_class", "payload", "chain", "transform", "code",
    "verified", "severity", "timestamp",
]


def write_findings_csv(findings: list, path: str):
    """Write findings to CSV."""
    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=_FIELDNAMES, extrasaction="ignore")
        writer.writeheader()
        for finding in findings:
            if isinstance(finding, dict):
                row = finding
            else:
                row = finding.as_dict() if hasattr(finding, "as_dict") else vars(finding)
            writer.writerow({
                "attack_class": row.get("attack_class", ""),
                "payload": row.get("payload", ""),
                "chain": ",".join(row.get("chain", [])) if isinstance(row.get("chain"), list) else str(row.get("chain", "")),
                "transform": row.get("transform", row.get("request_transform", "identity")),
                "code": row.get("code", ""),
                "verified": row.get("verified_exploitable", row.get("verified", False)),
                "severity": row.get("severity", ""),
                "timestamp": row.get("timestamp", ""),
            })
