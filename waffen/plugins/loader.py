"""Discover, load, and manage WAFFEN plugins from ~/.waffen/plugins/.

A plugin is either:
  - A directory with an ``__init__.py`` that exposes metadata constants and
    optional ``register_*`` hooks.
  - A single ``.py`` file with the same conventions.

Metadata constants (all optional, but recommended):
  PLUGIN_NAME, PLUGIN_VERSION, PLUGIN_AUTHOR, PLUGIN_DESC

Hook functions (called at load time — each receives the matching global registry):
  register_mutators(registry)   — add Mutator instances to waffen.mutate.REGISTRY
  register_transforms(transforms_list) — append RequestTransform instances
  register_seeds(seeds_dict)    — add {class: [payloads]} to waffen.kb.seeds.SEEDS
  register_sequences(seq_list)  — append AttackSequence instances

Security: plugins execute arbitrary Python. Only ``~/.waffen/plugins/`` is
scanned, so the user controls what is installed.
"""
from __future__ import annotations

import importlib.util
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

PLUGIN_DIR = Path.home() / ".waffen" / "plugins"

_DISABLED_SUFFIX = ".disabled"

_loaded: dict[str, "PluginInfo"] = {}


@dataclass
class PluginInfo:
    name: str
    version: str
    author: str
    description: str
    path: Path
    type: str  # mutator / transform / seeds / sequence / mixed
    mutator_count: int = 0
    transform_count: int = 0
    seed_count: int = 0
    sequence_count: int = 0
    module: object = None

    def as_dict(self) -> dict:
        return {
            "name": self.name,
            "version": self.version,
            "author": self.author,
            "description": self.description,
            "path": str(self.path),
            "type": self.type,
            "mutators": self.mutator_count,
            "transforms": self.transform_count,
            "seeds": self.seed_count,
            "sequences": self.sequence_count,
        }


def is_disabled(plugin_path: Path) -> bool:
    return (plugin_path / _DISABLED_SUFFIX).exists()


def disable_plugin(name: str) -> bool:
    p = PLUGIN_DIR / name
    if not p.exists():
        return False
    (p / _DISABLED_SUFFIX).touch()
    if name in _loaded:
        del _loaded[name]
    return True


def enable_plugin(name: str) -> bool:
    p = PLUGIN_DIR / name
    marker = p / _DISABLED_SUFFIX
    if marker.exists():
        marker.unlink()
        return True
    return False


def _find_plugin_entries(plugin_dir: Path) -> list[Path]:
    """Return paths to plugin packages or single .py files."""
    if not plugin_dir.is_dir():
        return []
    entries = []
    for child in sorted(plugin_dir.iterdir()):
        if child.name.startswith((".", "_")):
            continue
        if child.is_dir() and (child / "__init__.py").exists():
            entries.append(child)
        elif child.is_file() and child.suffix == ".py":
            entries.append(child)
    return entries


def _load_module(name: str, path: Path):
    """Import a module from a file path without polluting sys.modules permanently."""
    module_name = f"waffen_plugin_{name}"
    if path.is_dir():
        init = path / "__init__.py"
    else:
        init = path
    spec = importlib.util.spec_from_file_location(module_name, str(init),
                                                   submodule_search_locations=[str(path)] if path.is_dir() else None)
    if spec is None or spec.loader is None:
        return None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = mod
    spec.loader.exec_module(mod)
    return mod


def _infer_type(mod) -> str:
    hooks = []
    if hasattr(mod, "register_mutators"):
        hooks.append("mutator")
    if hasattr(mod, "register_transforms"):
        hooks.append("transform")
    if hasattr(mod, "register_seeds"):
        hooks.append("seeds")
    if hasattr(mod, "register_sequences"):
        hooks.append("sequence")
    if len(hooks) == 0:
        return "unknown"
    if len(hooks) == 1:
        return hooks[0]
    return "mixed"


def discover_plugins(plugin_dir: Path | None = None) -> list[PluginInfo]:
    """Scan the plugin directory and return info for each plugin found."""
    d = plugin_dir or PLUGIN_DIR
    entries = _find_plugin_entries(d)
    result = []
    for entry in entries:
        name = entry.stem if entry.is_file() else entry.name
        if is_disabled(entry if entry.is_dir() else entry.parent / name):
            continue
        try:
            mod = _load_module(name, entry)
        except Exception:
            continue
        if mod is None:
            continue
        info = PluginInfo(
            name=getattr(mod, "PLUGIN_NAME", name),
            version=getattr(mod, "PLUGIN_VERSION", "0.0.0"),
            author=getattr(mod, "PLUGIN_AUTHOR", "unknown"),
            description=getattr(mod, "PLUGIN_DESC", ""),
            path=entry,
            type=_infer_type(mod),
            module=mod,
        )
        result.append(info)
    return result


def load_plugin(name: str, plugin_dir: Path | None = None) -> Optional[PluginInfo]:
    """Load a single plugin by name and register its contributions."""
    d = plugin_dir or PLUGIN_DIR
    for entry in _find_plugin_entries(d):
        entry_name = entry.stem if entry.is_file() else entry.name
        if entry_name != name:
            continue
        if is_disabled(entry if entry.is_dir() else d / name):
            return None
        try:
            mod = _load_module(name, entry)
        except Exception:
            return None
        if mod is None:
            return None
        info = PluginInfo(
            name=getattr(mod, "PLUGIN_NAME", name),
            version=getattr(mod, "PLUGIN_VERSION", "0.0.0"),
            author=getattr(mod, "PLUGIN_AUTHOR", "unknown"),
            description=getattr(mod, "PLUGIN_DESC", ""),
            path=entry,
            type=_infer_type(mod),
            module=mod,
        )
        _register_hooks(info, mod)
        _loaded[name] = info
        return info
    return None


def load_all_plugins(plugin_dir: Path | None = None) -> list[PluginInfo]:
    """Load all plugins from the plugin directory."""
    d = plugin_dir or PLUGIN_DIR
    if not d.is_dir():
        return []
    loaded = []
    for entry in _find_plugin_entries(d):
        name = entry.stem if entry.is_file() else entry.name
        if name in _loaded:
            loaded.append(_loaded[name])
            continue
        info = load_plugin(name, d)
        if info is not None:
            loaded.append(info)
    return loaded


def unload_plugin(name: str) -> bool:
    """Remove a loaded plugin's contributions from registries."""
    info = _loaded.pop(name, None)
    if info is None:
        return False
    # Remove mutators contributed by this plugin
    from ..mutate.base import REGISTRY
    to_remove = [k for k, m in REGISTRY._m.items()
                 if getattr(m, "_plugin", None) == name]
    for k in to_remove:
        del REGISTRY._m[k]
    # Clean sys.modules
    mod_name = f"waffen_plugin_{name}"
    sys.modules.pop(mod_name, None)
    return True


def _register_hooks(info: PluginInfo, mod):
    """Call each register_* hook present on the module."""
    if hasattr(mod, "register_mutators"):
        from ..mutate.base import REGISTRY
        before = len(REGISTRY._m)
        mod.register_mutators(REGISTRY)
        added = len(REGISTRY._m) - before
        # tag new mutators so we can unload them
        for k, m in REGISTRY._m.items():
            if not hasattr(m, "_plugin"):
                object.__setattr__(m, "_plugin", info.name)
        info.mutator_count = added

    if hasattr(mod, "register_transforms"):
        from ..core.transforms import TRANSFORMS
        before = len(TRANSFORMS)
        mod.register_transforms(TRANSFORMS)
        info.transform_count = len(TRANSFORMS) - before

    if hasattr(mod, "register_seeds"):
        from ..kb.seeds import SEEDS
        before = sum(len(v) for v in SEEDS.values())
        mod.register_seeds(SEEDS)
        after = sum(len(v) for v in SEEDS.values())
        info.seed_count = after - before

    if hasattr(mod, "register_sequences"):
        try:
            from ..core.sequence import SEQUENCES
            before = len(SEQUENCES)
            mod.register_sequences(SEQUENCES)
            info.sequence_count = len(SEQUENCES) - before
        except ImportError:
            pass


def get_loaded() -> dict[str, PluginInfo]:
    return dict(_loaded)
