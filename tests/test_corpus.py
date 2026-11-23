"""Tests for the payload corpus."""
import pytest

from waffen.kb.corpus import (
    CORPUS, corpus_for, corpus_all, corpus_stats, corpus_total,
)
from waffen.kb.seeds import seeds_for, resolve_class


class TestCorpusCompleteness:
    def test_total_at_least_3000(self):
        total = corpus_total()
        assert total >= 3000, f"corpus has {total} payloads, need >= 3000"

    def test_all_classes_present(self):
        expected = {
            "SQL Injection", "XSS Injection", "SSTI", "Command Injection",
            "Directory Traversal", "SSRF", "XXE Injection", "CRLF Injection",
            "Open Redirect", "Upload Insecure Files", "LDAP Injection", "SSI",
            "GraphQL Injection", "WebSocket Injection",
        }
        assert expected.issubset(set(CORPUS.keys()))

    @pytest.mark.parametrize("cls", list(CORPUS.keys()))
    def test_each_class_non_empty(self, cls):
        assert len(CORPUS[cls]) > 0, f"{cls} is empty"

    @pytest.mark.parametrize("cls", list(CORPUS.keys()))
    def test_no_duplicates_within_class(self, cls):
        payloads = CORPUS[cls]
        assert len(payloads) == len(set(payloads)), (
            f"{cls} has {len(payloads) - len(set(payloads))} duplicates"
        )

    @pytest.mark.parametrize("cls", list(CORPUS.keys()))
    def test_no_empty_payloads(self, cls):
        for p in CORPUS[cls]:
            assert p.strip(), f"empty payload in {cls}"


class TestCorpusAPIs:
    def test_corpus_for_sqli(self):
        payloads = corpus_for("SQL Injection")
        assert len(payloads) > 100

    def test_corpus_for_alias(self):
        payloads = corpus_for("sqli")
        assert len(payloads) > 100

    def test_corpus_for_xss(self):
        payloads = corpus_for("xss")
        assert len(payloads) > 100

    def test_corpus_for_unknown(self):
        assert corpus_for("nonexistent") == []

    def test_corpus_all_returns_dict(self):
        d = corpus_all()
        assert isinstance(d, dict)
        assert len(d) >= 14

    def test_corpus_stats(self):
        stats = corpus_stats()
        assert all(isinstance(v, int) for v in stats.values())
        assert all(v > 0 for v in stats.values())

    def test_corpus_total(self):
        total = corpus_total()
        assert total == sum(corpus_stats().values())


class TestSeedsIntegration:
    def test_seeds_for_without_corpus(self):
        base = seeds_for("sqli", include_corpus=False)
        assert len(base) < 50

    def test_seeds_for_with_corpus(self):
        full = seeds_for("sqli", include_corpus=True)
        base = seeds_for("sqli", include_corpus=False)
        assert len(full) > len(base)
        assert len(full) > 100

    def test_no_duplicates_in_merged(self):
        full = seeds_for("sqli", include_corpus=True)
        assert len(full) == len(set(full))


class TestCorpusSizeByClass:
    def test_sqli_large(self):
        assert len(corpus_for("sqli")) >= 400

    def test_xss_large(self):
        assert len(corpus_for("xss")) >= 200

    def test_ssti_reasonable(self):
        assert len(corpus_for("ssti")) >= 40

    def test_cmdi_reasonable(self):
        assert len(corpus_for("cmdi")) >= 50

    def test_traversal_reasonable(self):
        assert len(corpus_for("traversal")) >= 30

    def test_ssrf_reasonable(self):
        assert len(corpus_for("ssrf")) >= 50

    def test_xxe_reasonable(self):
        assert len(corpus_for("xxe")) >= 15


class TestCLI:
    def test_corpus_subcommand_exists(self):
        from waffen.cli import build_parser
        p = build_parser()
        args = p.parse_args(["corpus"])
        assert hasattr(args, "func")

    def test_bypass_corpus_flag_exists(self):
        from waffen.cli import build_parser
        p = build_parser()
        args = p.parse_args(["bypass", "--target", "http://x", "--class", "sqli", "--corpus"])
        assert args.corpus is True
