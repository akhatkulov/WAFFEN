"""WAFFEN plugin system — drop-in mutators, transforms, seeds, and sequences."""
from .loader import (
    PLUGIN_DIR,
    PluginInfo,
    discover_plugins,
    load_plugin,
    load_all_plugins,
    unload_plugin,
    is_disabled,
    disable_plugin,
    enable_plugin,
)
from .scaffold import create_plugin

__all__ = [
    "PLUGIN_DIR", "PluginInfo",
    "discover_plugins", "load_plugin", "load_all_plugins", "unload_plugin",
    "is_disabled", "disable_plugin", "enable_plugin",
    "create_plugin",
]
