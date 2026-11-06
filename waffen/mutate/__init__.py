"""Mutation engine: importing this package registers all built-in mutators."""
from .base import REGISTRY, Mutator, Registry
from . import encoders  # noqa: F401  (side effect: registers encoders)
from . import obfuscators  # noqa: F401  (side effect: registers obfuscators)
from . import sql_tamper  # noqa: F401  (side effect: registers SQLi tamper mutators)
from . import xss_context  # noqa: F401  (side effect: registers XSS context mutators)
from . import path_cmd  # noqa: F401  (side effect: registers path/cmd mutators)
from . import generic_extra  # noqa: F401  (side effect: registers generic mutators)
from . import quickwin  # noqa: F401  (side effect: registers Phase B quick-win mutators)
from . import advanced  # noqa: F401  (side effect: registers Phase B advanced mutators)

__all__ = ["REGISTRY", "Mutator", "Registry"]
