"""
Recon modules registry.

Each module implements BaseModule and registers itself so the orchestrator
can dynamically load capabilities based on config.
"""

from .base import BaseModule, ModuleConfig

MODULE_REGISTRY = {}


def register_module(name: str):
    """Decorator for registering modules by name."""

    def decorator(cls):
        MODULE_REGISTRY[name] = cls
        return cls

    return decorator


__all__ = ["BaseModule", "ModuleConfig", "MODULE_REGISTRY", "register_module"]
