"""Scaffold a new WAFFEN plugin from a template."""
from __future__ import annotations

from pathlib import Path
from .loader import PLUGIN_DIR


_INIT_TEMPLATE = '''\
"""WAFFEN plugin: {name}"""
PLUGIN_NAME = "{name}"
PLUGIN_VERSION = "1.0.0"
PLUGIN_AUTHOR = "{author}"
PLUGIN_DESC = "{desc}"


def register_mutators(registry):
    """Register custom mutators with WAFFEN's mutation registry.

    Example:
        from waffen.mutate.base import Mutator

        def my_bypass(payload):
            return payload.replace("OR", "O/**/R")

        registry.add(
            name="{name}_example",
            fn=my_bypass,
            category="obfuscator",
            desc="Example bypass mutator",
            classes={{"SQL Injection"}},
        )
    """
    pass


# Uncomment and implement as needed:
#
# def register_transforms(transforms_list):
#     """Append RequestTransform instances to the transforms list."""
#     pass
#
# def register_seeds(seeds_dict):
#     """Add seed payloads: seeds_dict["Attack Class"].extend([...])."""
#     pass
#
# def register_sequences(sequences_list):
#     """Append AttackSequence instances to the sequences list."""
#     pass
'''

_README_TEMPLATE = '''\
# {name}

WAFFEN plugin: {desc}

## Installation

Copy this directory to `~/.waffen/plugins/{name}/`.

## Usage

The plugin is loaded automatically when WAFFEN starts.

```bash
waffen plugin list          # verify it's loaded
waffen mutators             # see registered mutators
waffen bypass --target URL  # mutators are used in search
```

## Disabling

```bash
waffen plugin disable {name}
```
'''


def create_plugin(name: str, author: str = "me", desc: str = "",
                  plugin_dir: Path | None = None) -> Path:
    """Create a new plugin directory from template.

    Returns the path to the created plugin.
    """
    d = plugin_dir or PLUGIN_DIR
    target = d / name
    if target.exists():
        raise FileExistsError(f"plugin already exists: {target}")

    target.mkdir(parents=True, exist_ok=False)
    desc = desc or f"Custom WAFFEN plugin: {name}"

    init_content = _INIT_TEMPLATE.format(name=name, author=author, desc=desc)
    (target / "__init__.py").write_text(init_content)

    readme_content = _README_TEMPLATE.format(name=name, desc=desc)
    (target / "README.md").write_text(readme_content)

    return target
