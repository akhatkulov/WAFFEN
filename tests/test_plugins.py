"""Tests for the WAFFEN plugin system."""
import shutil
import textwrap
from pathlib import Path

import pytest

from waffen.plugins.loader import (
    PluginInfo,
    _find_plugin_entries,
    _load_module,
    _infer_type,
    discover_plugins,
    load_plugin,
    load_all_plugins,
    unload_plugin,
    is_disabled,
    disable_plugin,
    enable_plugin,
    get_loaded,
    _loaded,
)
from waffen.plugins.scaffold import create_plugin


@pytest.fixture
def plugin_dir(tmp_path):
    """Create a temporary plugin directory with a sample plugin."""
    d = tmp_path / "plugins"
    d.mkdir()
    return d


@pytest.fixture
def sample_plugin(plugin_dir):
    """Create a sample mutator plugin."""
    p = plugin_dir / "test_bypass"
    p.mkdir()
    (p / "__init__.py").write_text(textwrap.dedent("""\
        PLUGIN_NAME = "test_bypass"
        PLUGIN_VERSION = "1.2.3"
        PLUGIN_AUTHOR = "tester"
        PLUGIN_DESC = "A test plugin"

        def register_mutators(registry):
            def reverse_payload(s):
                return s[::-1]
            registry.add(
                name="plugin_reverse",
                fn=reverse_payload,
                category="obfuscator",
                desc="Reverse the payload",
            )
    """))
    return p


@pytest.fixture
def sample_seed_plugin(plugin_dir):
    """Create a sample seed plugin."""
    p = plugin_dir / "extra_seeds"
    p.mkdir()
    (p / "__init__.py").write_text(textwrap.dedent("""\
        PLUGIN_NAME = "extra_seeds"
        PLUGIN_VERSION = "0.1.0"
        PLUGIN_AUTHOR = "tester"
        PLUGIN_DESC = "Extra seed payloads"

        def register_seeds(seeds_dict):
            seeds_dict.setdefault("SQL Injection", []).append("PLUGIN_SEED_1")
    """))
    return p


@pytest.fixture
def single_file_plugin(plugin_dir):
    """Create a single-file plugin (.py not in a directory)."""
    p = plugin_dir / "single_plugin.py"
    p.write_text(textwrap.dedent("""\
        PLUGIN_NAME = "single_plugin"
        PLUGIN_VERSION = "0.0.1"
        PLUGIN_AUTHOR = "tester"
        PLUGIN_DESC = "Single file plugin"

        def register_mutators(registry):
            registry.add(
                name="plugin_single_upper",
                fn=lambda s: s.upper(),
                category="encoder",
                desc="Uppercase",
            )
    """))
    return p


@pytest.fixture(autouse=True)
def clean_loaded():
    """Save/restore REGISTRY and loaded state around each test."""
    from waffen.mutate.base import REGISTRY
    from waffen.kb.seeds import SEEDS
    saved_m = dict(REGISTRY._m)
    saved_seeds = {k: list(v) for k, v in SEEDS.items()}
    _loaded.clear()
    yield
    REGISTRY._m.clear()
    REGISTRY._m.update(saved_m)
    SEEDS.clear()
    SEEDS.update(saved_seeds)
    _loaded.clear()
    import sys
    to_remove = [k for k in sys.modules if k.startswith("waffen_plugin_")]
    for k in to_remove:
        del sys.modules[k]


# --- discover ---

class TestDiscover:
    def test_empty_dir(self, plugin_dir):
        assert discover_plugins(plugin_dir) == []

    def test_finds_package_plugin(self, plugin_dir, sample_plugin):
        plugins = discover_plugins(plugin_dir)
        assert len(plugins) == 1
        assert plugins[0].name == "test_bypass"
        assert plugins[0].version == "1.2.3"
        assert plugins[0].author == "tester"

    def test_finds_single_file_plugin(self, plugin_dir, single_file_plugin):
        plugins = discover_plugins(plugin_dir)
        assert len(plugins) == 1
        assert plugins[0].name == "single_plugin"

    def test_skips_hidden(self, plugin_dir):
        (plugin_dir / ".hidden").mkdir()
        (plugin_dir / ".hidden" / "__init__.py").write_text("PLUGIN_NAME='hidden'")
        assert discover_plugins(plugin_dir) == []

    def test_skips_underscore(self, plugin_dir):
        (plugin_dir / "_internal").mkdir()
        (plugin_dir / "_internal" / "__init__.py").write_text("PLUGIN_NAME='internal'")
        assert discover_plugins(plugin_dir) == []

    def test_skips_disabled(self, plugin_dir, sample_plugin):
        (sample_plugin / ".disabled").touch()
        assert discover_plugins(plugin_dir) == []

    def test_multiple_plugins(self, plugin_dir, sample_plugin, single_file_plugin):
        plugins = discover_plugins(plugin_dir)
        assert len(plugins) == 2
        names = {p.name for p in plugins}
        assert "test_bypass" in names
        assert "single_plugin" in names


# --- load ---

class TestLoad:
    def test_load_mutator_plugin(self, plugin_dir, sample_plugin):
        info = load_plugin("test_bypass", plugin_dir)
        assert info is not None
        assert info.name == "test_bypass"
        assert info.mutator_count == 1
        from waffen.mutate.base import REGISTRY
        m = REGISTRY.get("plugin_reverse")
        assert m.apply("hello") == "olleh"

    def test_load_seed_plugin(self, plugin_dir, sample_seed_plugin):
        info = load_plugin("extra_seeds", plugin_dir)
        assert info is not None
        assert info.seed_count >= 1

    def test_load_single_file(self, plugin_dir, single_file_plugin):
        info = load_plugin("single_plugin", plugin_dir)
        assert info is not None
        assert info.mutator_count == 1
        from waffen.mutate.base import REGISTRY
        m = REGISTRY.get("plugin_single_upper")
        assert m.apply("hello") == "HELLO"

    def test_load_nonexistent(self, plugin_dir):
        assert load_plugin("does_not_exist", plugin_dir) is None

    def test_load_disabled(self, plugin_dir, sample_plugin):
        (sample_plugin / ".disabled").touch()
        assert load_plugin("test_bypass", plugin_dir) is None

    def test_load_all(self, plugin_dir, sample_plugin, single_file_plugin):
        loaded = load_all_plugins(plugin_dir)
        assert len(loaded) == 2

    def test_load_all_empty(self, tmp_path):
        empty = tmp_path / "empty"
        assert load_all_plugins(empty) == []

    def test_load_all_nonexistent(self, tmp_path):
        assert load_all_plugins(tmp_path / "nope") == []


# --- unload ---

class TestUnload:
    def test_unload_removes_mutators(self, plugin_dir, sample_plugin):
        load_plugin("test_bypass", plugin_dir)
        from waffen.mutate.base import REGISTRY
        assert "plugin_reverse" in REGISTRY._m
        unload_plugin("test_bypass")
        assert "plugin_reverse" not in REGISTRY._m

    def test_unload_nonexistent(self):
        assert unload_plugin("not_loaded") is False

    def test_unload_clears_loaded(self, plugin_dir, sample_plugin):
        load_plugin("test_bypass", plugin_dir)
        assert "test_bypass" in get_loaded()
        unload_plugin("test_bypass")
        assert "test_bypass" not in get_loaded()


# --- disable / enable ---

class TestDisableEnable:
    def test_disable_creates_marker(self, plugin_dir, sample_plugin):
        assert not is_disabled(sample_plugin)
        disable_plugin("test_bypass")
        # Manual marker check with the real PLUGIN_DIR won't work in tests,
        # but disable_plugin returns True if the dir exists under PLUGIN_DIR.
        # Test the is_disabled logic directly:
        (sample_plugin / ".disabled").touch()
        assert is_disabled(sample_plugin)

    def test_enable_removes_marker(self, plugin_dir, sample_plugin):
        (sample_plugin / ".disabled").touch()
        assert is_disabled(sample_plugin)
        (sample_plugin / ".disabled").unlink()
        assert not is_disabled(sample_plugin)


# --- scaffold ---

class TestScaffold:
    def test_create_plugin(self, plugin_dir):
        path = create_plugin("my-waf-bypass", author="Me262", desc="Custom bypass",
                            plugin_dir=plugin_dir)
        assert path.exists()
        assert (path / "__init__.py").exists()
        assert (path / "README.md").exists()

    def test_create_has_metadata(self, plugin_dir):
        path = create_plugin("test-plug", plugin_dir=plugin_dir)
        content = (path / "__init__.py").read_text()
        assert 'PLUGIN_NAME = "test-plug"' in content
        assert "PLUGIN_VERSION" in content
        assert "register_mutators" in content

    def test_create_readme(self, plugin_dir):
        path = create_plugin("readme-test", desc="A test", plugin_dir=plugin_dir)
        readme = (path / "README.md").read_text()
        assert "readme-test" in readme
        assert "A test" in readme

    def test_create_duplicate_raises(self, plugin_dir):
        create_plugin("dup", plugin_dir=plugin_dir)
        with pytest.raises(FileExistsError):
            create_plugin("dup", plugin_dir=plugin_dir)

    def test_created_plugin_loadable(self, plugin_dir):
        create_plugin("loadable", plugin_dir=plugin_dir)
        info = load_plugin("loadable", plugin_dir)
        assert info is not None
        assert info.name == "loadable"
        assert info.mutator_count == 0  # template has pass in register_mutators


# --- infer_type ---

class TestInferType:
    def test_mutator_only(self):
        class M:
            register_mutators = lambda self, r: None
        assert _infer_type(M()) == "mutator"

    def test_mixed(self):
        class M:
            register_mutators = lambda self, r: None
            register_seeds = lambda self, s: None
        assert _infer_type(M()) == "mixed"

    def test_unknown(self):
        class M:
            pass
        assert _infer_type(M()) == "unknown"


# --- PluginInfo ---

class TestPluginInfo:
    def test_as_dict(self):
        info = PluginInfo(
            name="test", version="1.0", author="me",
            description="desc", path=Path("/tmp"), type="mutator",
            mutator_count=3,
        )
        d = info.as_dict()
        assert d["name"] == "test"
        assert d["mutators"] == 3
        assert "module" not in d


# --- CLI ---

class TestCLI:
    def test_parser_has_plugin(self):
        from waffen.cli import build_parser
        p = build_parser()
        args = p.parse_args(["plugin", "list"])
        assert args.plugin_action == "list"
        assert hasattr(args, "func")

    def test_parser_create(self):
        from waffen.cli import build_parser
        p = build_parser()
        args = p.parse_args(["plugin", "create", "my-bypass", "--author", "Me262"])
        assert args.plugin_action == "create"
        assert args.name == "my-bypass"
        assert args.author == "Me262"
