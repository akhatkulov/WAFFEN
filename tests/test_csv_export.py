"""Tests for CSV export."""
import csv
import os
import tempfile

from waffen.report.csv_export import write_findings_csv


def test_write_csv_basic():
    findings = [
        {"attack_class": "SQL Injection", "payload": "' OR 1=1--",
         "chain": ["base64"], "transform": "identity", "code": "200",
         "verified_exploitable": True, "severity": "HIGH"},
    ]
    with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False) as f:
        path = f.name
    try:
        write_findings_csv(findings, path)
        with open(path) as f:
            reader = csv.DictReader(f)
            rows = list(reader)
        assert len(rows) == 1
        assert rows[0]["payload"] == "' OR 1=1--"
        assert rows[0]["attack_class"] == "SQL Injection"
        assert rows[0]["chain"] == "base64"
        assert rows[0]["verified"] == "True"
    finally:
        os.unlink(path)


def test_write_csv_empty():
    with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False) as f:
        path = f.name
    try:
        write_findings_csv([], path)
        with open(path) as f:
            reader = csv.DictReader(f)
            rows = list(reader)
        assert len(rows) == 0
    finally:
        os.unlink(path)


def test_write_csv_multiple():
    findings = [
        {"attack_class": "SQL Injection", "payload": "' OR 1=1--",
         "chain": ["base64", "url_encode"], "code": "200"},
        {"attack_class": "XSS Injection", "payload": "<script>alert(1)</script>",
         "chain": [], "code": "403"},
    ]
    with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False) as f:
        path = f.name
    try:
        write_findings_csv(findings, path)
        with open(path) as f:
            reader = csv.DictReader(f)
            rows = list(reader)
        assert len(rows) == 2
        assert rows[0]["chain"] == "base64,url_encode"
        assert rows[1]["chain"] == ""
    finally:
        os.unlink(path)


def test_csv_header_fields():
    with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False) as f:
        path = f.name
    try:
        write_findings_csv([{"payload": "test"}], path)
        with open(path) as f:
            reader = csv.reader(f)
            header = next(reader)
        assert "attack_class" in header
        assert "payload" in header
        assert "verified" in header
        assert "severity" in header
    finally:
        os.unlink(path)


def test_csv_handles_missing_fields():
    findings = [{}]
    with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False) as f:
        path = f.name
    try:
        write_findings_csv(findings, path)
        with open(path) as f:
            reader = csv.DictReader(f)
            rows = list(reader)
        assert len(rows) == 1
        assert rows[0]["payload"] == ""
    finally:
        os.unlink(path)
