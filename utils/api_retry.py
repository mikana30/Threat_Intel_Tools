#!/usr/bin/env python3
"""
API retry utility with exponential backoff
"""
import time
import random
from functools import wraps


def retry_with_backoff(max_retries=3, base_delay=1):
    """
    Decorator that retries a function with exponential backoff

    Args:
        max_retries: Maximum number of retry attempts
        base_delay: Base delay in seconds (will be exponentially increased)

    Returns:
        Decorated function that retries on failure
    """
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            for attempt in range(max_retries):
                try:
                    response = func(*args, **kwargs)
                    # Check for rate limiting if response has status_code attribute
                    if hasattr(response, 'status_code') and response.status_code == 429:
                        wait_time = (2 ** attempt) * base_delay + random.uniform(0, 1)
                        time.sleep(wait_time)
                        continue
                    return response
                except Exception as e:
                    if attempt == max_retries - 1:
                        raise
                    wait_time = (2 ** attempt) * base_delay + random.uniform(0, 1)
                    time.sleep(wait_time)
            return None
        return wrapper
    return decorator
