#!/usr/bin/env python3
"""
Dev mode helpers
----------------
Central helpers for reading the optional environment config and determining
whether development caps should be applied during a run.

These utilities are light-weight so individual scripts can opt-in without
duplicating parsing logic.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Optional

import yaml

ENV_CONFIG_DEFAULT = Path("config/environment.yml")
MODE_ENV_VAR = "TI_MODE"
CAP_ENV_VAR = "TI_DEV_MAX_TARGETS"


def load_env_settings(path: Path | None = None) -> dict:
    """
    Load the optional environment config YAML.

    Returns an empty dict if the file is missing or invalid so callers can
    treat the settings as optional.
    """
    settings_path = path or ENV_CONFIG_DEFAULT
    if not settings_path.exists():
        return {}
    try:
        with settings_path.open("r", encoding="utf-8") as fh:
            return yaml.safe_load(fh) or {}
    except Exception as exc:  # pragma: no cover - defensive
        logging.getLogger("dev_mode").warning(
            "Failed to parse %s: %s", settings_path, exc
        )
        return {}


def _env_mode_override() -> Optional[str]:
    mode = os.getenv(MODE_ENV_VAR)
    return mode.lower().strip() if mode else None


def get_mode(settings: dict | None = None) -> str:
    """
    Determine the current execution mode.

    Order of precedence:
    1. TI_MODE environment variable
    2. settings['mode'] in config/environment.yml
    3. Default to 'production'

    Returns: 'dev', 'quick', or 'production'
    """
    mode_override = _env_mode_override()
    if mode_override:
        if mode_override in ('dev', 'quick', 'production'):
            return mode_override
        logging.getLogger("dev_mode").warning(
            "Invalid mode '%s', defaulting to 'production'", mode_override
        )
        return 'production'

    settings = settings or {}
    mode = settings.get("mode")
    if isinstance(mode, str) and mode.lower() in ('dev', 'quick', 'production'):
        return mode.lower()

    return 'production'


def is_dev_mode(settings: dict | None = None) -> bool:
    """
    Determine whether dev mode caps should be active.
    Returns True if mode is 'dev', False otherwise.
    """
    return get_mode(settings) == 'dev'


def get_target_cap(settings: dict | None = None) -> Optional[int]:
    """
    Return the configured max target cap based on current mode.

    Order of precedence:
    1. TI_DEV_MAX_TARGETS environment variable.
    2. caps[mode]['max_targets'] in config/environment.yml

    Returns None for production mode (no limit).
    """
    # Check environment variable override
    try:
        env_value = os.getenv(CAP_ENV_VAR)
        if env_value:
            cap = int(env_value)
            if cap > 0:
                return cap
            logging.getLogger("dev_mode").warning(
                "Ignoring %s override '%s' (must be > 0)", CAP_ENV_VAR, env_value
            )
    except ValueError:
        logging.getLogger("dev_mode").warning(
            "Ignoring invalid %s override '%s'", CAP_ENV_VAR, os.getenv(CAP_ENV_VAR)
        )

    # Get mode
    settings = settings or {}
    mode = get_mode(settings)

    # Production mode has no cap
    if mode == 'production':
        return None

    # Get cap from config
    caps = settings.get("caps") or {}
    mode_caps = caps.get(mode) or {}

    # Try max_targets first, then legacy aliases
    for key in ("max_targets", "target_cap", "search_cap"):
        cap = mode_caps.get(key)
        if isinstance(cap, int) and cap > 0:
            return cap

    # Fallback defaults if not configured
    if mode == 'dev':
        return 100
    elif mode == 'quick':
        return 1000

    return None

