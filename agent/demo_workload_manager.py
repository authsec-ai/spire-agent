#!/usr/bin/env python3
"""
Demo script for Workload Manager

Demonstrates:
1. Initializing workload manager
2. Fetching workload entries from ICP
3. Collecting selectors for a process
4. Matching selectors against entries
5. Requesting SVID from ICP service
"""

import asyncio
import logging
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(__file__))

from icp_agent.workload_manager import WorkloadManager

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

logger = logging.getLogger("demo")

# Configuration
TENANT_ID = "4e615215-66b4-4414-bb39-4e0c6daa8f8b"
AGENT_SPIFFE_ID = f"spiffe://{TENANT_ID}/agent/test-node-1"
ICP_SERVICE_URL = "http://localhost:8000"


async def demo_basic_flow():
    """Demonstrate basic workload attestation flow"""
    logger.info("=" * 60)
    logger.info("Workload Manager Demo")
    logger.info("=" * 60)
    logger.info("")

    # 1. Initialize workload manager
    logger.info("[Step 1] Initializing Workload Manager")
    logger.info("")

    manager = WorkloadManager(
        tenant_id=TENANT_ID,
        agent_spiffe_id=AGENT_SPIFFE_ID,
        icp_service_url=ICP_SERVICE_URL,
        logger=logger
    )

    await manager.start()
    logger.info("")

    # 2. Show cached workload entries
    logger.info("[Step 2] Cached Workload Entries")
    logger.info(f"Total entries: {len(manager.workload_entries)}")
    logger.info("")

    for i, entry in enumerate(manager.workload_entries, 1):
        logger.info(f"Entry {i}:")
        logger.info(f"  SPIFFE ID: {entry.spiffe_id}")
        logger.info(f"  Selectors: {entry.selectors}")
        logger.info("")

    # 3. Collect selectors for current process (demo)
    current_pid = os.getpid()
    logger.info(f"[Step 3] Collecting Selectors for Current Process (PID {current_pid})")
    logger.info("")

    selectors = manager.collect_selectors(current_pid)

    logger.info(f"Collected {len(selectors)} selectors:")
    for key, value in selectors.items():
        logger.info(f"  {key} = {value}")
    logger.info("")

    # 4. Try to find matching entry
    logger.info("[Step 4] Finding Matching Workload Entry")
    logger.info("")

    entry = manager.find_matching_entry(selectors)

    if entry:
        logger.info(f"✓ Found matching entry!")
        logger.info(f"  SPIFFE ID: {entry.spiffe_id}")
        logger.info(f"  Entry Selectors: {entry.selectors}")
        logger.info("")

        # 5. Request SVID
        logger.info("[Step 5] Requesting SVID from ICP Service")
        logger.info("")

        svid = await manager.attest_workload(current_pid)

        if svid:
            logger.info("✓ SVID issued successfully!")
            logger.info(f"  SPIFFE ID: {svid.spiffe_id}")
            logger.info(f"  TTL: {svid.ttl} seconds")
            logger.info(f"  Expires At: {svid.expires_at}")
            logger.info("")
            logger.info("Certificate (first 200 chars):")
            logger.info(svid.certificate[:200] + "...")
            logger.info("")
            logger.info("Private Key (first 150 chars):")
            logger.info(svid.private_key[:150] + "...")
            logger.info("")
        else:
            logger.error("✗ Failed to get SVID")

    else:
        logger.warning("✗ No matching workload entry found")
        logger.warning(f"Current selectors: {selectors}")
        logger.warning("")
        logger.warning("This is expected if:")
        logger.warning("  1. No workload entry matches current process selectors")
        logger.warning("  2. You're running outside Kubernetes")
        logger.warning("  3. No workload entries registered in ICP")
        logger.warning("")
        logger.warning("To test properly:")
        logger.warning("  1. Create a workload entry with matching selectors")
        logger.warning("  2. Run this script in a Kubernetes pod")
        logger.warning("  3. Or use test_workload_attestation.py with mock selectors")

    logger.info("")
    logger.info("=" * 60)
    logger.info("Demo Complete")
    logger.info("=" * 60)

    await manager.stop()


async def demo_manual_selectors():
    """Demonstrate with manual selectors (for testing without K8s)"""
    logger.info("=" * 60)
    logger.info("Manual Selector Matching Demo")
    logger.info("=" * 60)
    logger.info("")

    manager = WorkloadManager(
        tenant_id=TENANT_ID,
        agent_spiffe_id=AGENT_SPIFFE_ID,
        icp_service_url=ICP_SERVICE_URL,
        logger=logger
    )

    await manager.start()

    # Manually create selectors that match Service A entry
    test_selectors = {
        "k8s:ns": "default",
        "k8s:sa": "service-a",
        "k8s:pod-label:app": "barcelona-fan",
        "k8s:pod-name": "service-a-demo-123",
        "unix:uid": "1000",
        "unix:pid": str(os.getpid())
    }

    logger.info("Test selectors (manually created):")
    for key, value in test_selectors.items():
        logger.info(f"  {key} = {value}")
    logger.info("")

    # Find matching entry
    entry = manager.find_matching_entry(test_selectors)

    if entry:
        logger.info(f"✓ Found matching entry!")
        logger.info(f"  SPIFFE ID: {entry.spiffe_id}")
        logger.info("")

        # Request SVID (this will call ICP service)
        logger.info("Requesting SVID from ICP service...")
        svid = await manager.request_svid(os.getpid(), entry, test_selectors)

        if svid:
            logger.info("✓ SVID issued successfully!")
            logger.info(f"  SPIFFE ID: {svid.spiffe_id}")
            logger.info(f"  Expires: {svid.expires_at}")
        else:
            logger.error("✗ Failed to get SVID")
    else:
        logger.warning("✗ No matching entry found")

    logger.info("")
    await manager.stop()


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Workload Manager Demo")
    parser.add_argument(
        "--mode",
        choices=["basic", "manual"],
        default="basic",
        help="Demo mode: basic (auto-detect) or manual (test selectors)"
    )

    args = parser.parse_args()

    if args.mode == "basic":
        asyncio.run(demo_basic_flow())
    else:
        asyncio.run(demo_manual_selectors())
