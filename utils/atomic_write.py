#!/usr/bin/env python3
"""
Atomic file write utilities to prevent partial writes and race conditions
"""
import tempfile
import shutil
import json
from pathlib import Path
from typing import Dict, Any


def atomic_write_json(path: Path, data: Dict[str, Any]) -> None:
    """
    Write JSON atomically using temp + rename pattern
    
    This ensures that:
    1. The file is either fully written or not written at all (no partial writes)
    2. Readers never see a partially written state
    3. The operation is atomic at the filesystem level
    
    Args:
        path: Destination file path
        data: Dictionary to write as JSON
    """
    # Ensure path is a Path object
    if not isinstance(path, Path):
        path = Path(path)
    
    # Create parent directory if it doesn't exist
    path.parent.mkdir(parents=True, exist_ok=True)
    
    # Write to temporary file in the same directory (important for atomic rename)
    with tempfile.NamedTemporaryFile(
        mode='w',
        dir=path.parent,
        delete=False,
        suffix='.tmp',
        prefix='.tmp_'
    ) as tmp:
        json.dump(data, tmp, indent=2)
        tmp_path = tmp.name
    
    # Atomic rename (on POSIX systems, this is guaranteed atomic)
    # On Windows, this may fail if the target exists, so we handle that
    try:
        shutil.move(tmp_path, str(path))
    except Exception as e:
        # Clean up temp file if move fails
        try:
            Path(tmp_path).unlink()
        except:
            pass
        raise e


def atomic_write_text(path: Path, text: str) -> None:
    """
    Write text file atomically using temp + rename pattern
    
    Args:
        path: Destination file path
        text: Text content to write
    """
    # Ensure path is a Path object
    if not isinstance(path, Path):
        path = Path(path)
    
    # Create parent directory if it doesn't exist
    path.parent.mkdir(parents=True, exist_ok=True)
    
    # Write to temporary file
    with tempfile.NamedTemporaryFile(
        mode='w',
        dir=path.parent,
        delete=False,
        suffix='.tmp',
        prefix='.tmp_'
    ) as tmp:
        tmp.write(text)
        tmp_path = tmp.name
    
    # Atomic rename
    try:
        shutil.move(tmp_path, str(path))
    except Exception as e:
        # Clean up temp file if move fails
        try:
            Path(tmp_path).unlink()
        except:
            pass
        raise e
