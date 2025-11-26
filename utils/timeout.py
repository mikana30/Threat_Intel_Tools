#!/usr/bin/env python3
"""
Timeout Context Manager
Provides a context manager for timing out operations using SIGALRM
"""

import signal
from contextlib import contextmanager


@contextmanager
def timeout(seconds):
    """
    Context manager that raises TimeoutError if operation exceeds specified seconds

    Usage:
        with timeout(10):
            # code that should complete within 10 seconds
            long_running_operation()

    Args:
        seconds: Maximum time allowed for operation

    Raises:
        TimeoutError: If operation exceeds timeout
    """
    def handler(signum, frame):
        raise TimeoutError(f"Operation timed out after {seconds}s")

    signal.signal(signal.SIGALRM, handler)
    signal.alarm(seconds)
    try:
        yield
    finally:
        signal.alarm(0)
