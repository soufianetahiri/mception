"""Detection engines. Each engine emits Finding objects; the dispatcher aggregates them."""

from .base import Engine, EngineResult

__all__ = ["Engine", "EngineResult"]
