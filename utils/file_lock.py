#!/usr/bin/env python3
"""
File locking utilities for safe concurrent access
"""
import portalocker
from contextlib import contextmanager
from pathlib import Path
from typing import Union


@contextmanager
def locked_file(path: Union[str, Path], mode: str = 'r', timeout: int = 30):
    """
    Context manager for file locking with timeout support

    This ensures that:
    1. Multiple processes can't write to the same file simultaneously
    2. Readers get consistent state
    3. Locks are automatically released even if exceptions occur
    4. Lock acquisition respects timeout to prevent indefinite hangs

    Usage:
        with locked_file('state.json', 'w', timeout=60) as f:
            json.dump(data, f)

    Args:
        path: File path to lock
        mode: File open mode ('r', 'w', 'a', etc.)
        timeout: Maximum seconds to wait for lock acquisition (default: 30)

    Yields:
        File handle with exclusive lock

    Raises:
        TimeoutError: If lock cannot be acquired within timeout period
    """
    # Convert to Path if needed
    if isinstance(path, str):
        path = Path(path)

    # Create parent directory if writing
    if 'w' in mode or 'a' in mode:
        path.parent.mkdir(parents=True, exist_ok=True)

    # Open file with lock
    with open(path, mode) as f:
        try:
            # Get exclusive lock with timeout
            try:
                portalocker.lock(f, portalocker.LOCK_EX, timeout=timeout)
            except portalocker.LockException as e:
                raise TimeoutError(
                    f"Failed to acquire lock on {path} within {timeout} seconds. "
                    f"Another process may be using this file."
                ) from e
            yield f
        finally:
            # Release lock (happens automatically on close, but explicit is better)
            try:
                portalocker.unlock(f)
            except:
                # Lock already released or file closed
                pass


@contextmanager
def locked_file_read(path: Union[str, Path]):
    """
    Context manager for file locking with shared read access
    
    Multiple readers can hold the lock simultaneously, but writers are blocked.
    
    Args:
        path: File path to lock
    
    Yields:
        File handle with shared lock
    """
    if isinstance(path, str):
        path = Path(path)
    
    with open(path, 'r') as f:
        try:
            # Get shared lock (multiple readers allowed)
            portalocker.lock(f, portalocker.LOCK_SH)
            yield f
        finally:
            try:
                portalocker.unlock(f)
            except:
                pass
