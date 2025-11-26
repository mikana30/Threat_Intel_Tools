#!/usr/bin/env python3
"""
Disk space checking utility
"""
import shutil


def check_disk_space(path: str, min_gb: int = 10) -> bool:
    """
    Check if sufficient disk space is available

    Args:
        path: Path to check disk space for
        min_gb: Minimum required space in GB

    Returns:
        True if sufficient space available

    Raises:
        IOError: If insufficient disk space
    """
    stat = shutil.disk_usage(path)
    available_gb = stat.free / (1024**3)
    if available_gb < min_gb:
        raise IOError(f"Insufficient disk space: {available_gb:.1f}GB available, need {min_gb}GB")
    return True
