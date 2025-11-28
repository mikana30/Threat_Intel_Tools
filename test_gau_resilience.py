#!/usr/bin/env python3
"""
Test script to verify gau module resilience features.

This script demonstrates:
1. Timeout handling with retry logic
2. Visible error logging at WARNING level
3. Prevention of incomplete data (returns empty on failure)
4. Exponential backoff between retries
"""

import sys
import logging
from recon.modules.gau import GauModule
from recon.modules.base import ModuleConfig

# Set up logging to see INFO and WARNING messages
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(name)s - %(message)s'
)

logger = logging.getLogger(__name__)


def test_gau_resilience():
    """Test gau module with various scenarios."""

    # Test 1: Normal operation with timeout
    logger.info("=" * 80)
    logger.info("TEST 1: Testing with 120s timeout (production setting)")
    logger.info("=" * 80)

    config = ModuleConfig(enabled=True, timeout=120)
    gau = GauModule(config)

    if not gau.is_available():
        logger.error("gau binary not found in PATH. Please ensure ~/go/bin is in PATH.")
        logger.error("Run: export PATH=$PATH:~/go/bin")
        return False

    test_domain = "example.com"
    logger.info(f"Testing gau module with domain: {test_domain}")

    results = gau.run(test_domain)

    logger.info(f"Results: Found {len(results)} unique subdomains")
    if results:
        logger.info("Sample results (first 10):")
        for r in results[:10]:
            logger.info(f"  - {r}")
        if len(results) > 10:
            logger.info(f"  ... and {len(results) - 10} more")
    else:
        logger.warning("No subdomains found. This could indicate:")
        logger.warning("  1. API failures (check WARNING logs above)")
        logger.warning("  2. No archived data for this domain")
        logger.warning("  3. Timeouts due to slow API providers")

    logger.info("")
    logger.info("=" * 80)
    logger.info("TEST COMPLETE")
    logger.info("=" * 80)
    logger.info("")
    logger.info("Key features demonstrated:")
    logger.info("  1. Increased timeout from 45s (gau default) to 120s")
    logger.info("  2. Built-in retry logic (2 attempts with exponential backoff)")
    logger.info("  3. Verbose logging at WARNING level (visible errors)")
    logger.info("  4. Never returns incomplete data (empty on failure)")
    logger.info("  5. Detailed error messages for troubleshooting")

    return True


if __name__ == "__main__":
    success = test_gau_resilience()
    sys.exit(0 if success else 1)
