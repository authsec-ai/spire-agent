"""
Workload Manager

Manages workload lifecycle:
1. Discovers new workloads (processes/containers/pods)
2. Collects selectors using plugins
3. Matches selectors against cached workload entries
4. Requests SVIDs from ICP service
5. Caches SVIDs for workload consumption
6. Rotates SVIDs before expiry
7. Cleans up when workloads terminate
"""

import logging
import asyncio
import httpx
from typing import Dict, List, Optional, Set
from dataclasses import dataclass, field
from datetime import datetime, timedelta
import json

from .plugins import KubernetesPlugin, UnixPlugin, DockerPlugin, SelectorPlugin


@dataclass
class WorkloadEntry:
    """Cached workload entry from ICP service"""
    id: str
    spiffe_id: str
    parent_id: str
    selectors: Dict[str, str]
    ttl: Optional[int] = None
    admin: bool = False
    downstream: bool = False


@dataclass
class WorkloadSVID:
    """Issued SVID for a workload"""
    pid: int
    spiffe_id: str
    certificate: str
    private_key: str
    trust_bundle: str
    expires_at: datetime
    ttl: int
    entry_id: str
    selectors: Dict[str, str] = field(default_factory=dict)


class WorkloadManager:
    """
    Manages workload attestation and SVID lifecycle
    """

    def __init__(
        self,
        tenant_id: str,
        agent_spiffe_id: str,
        icp_service_url: str = "https://prod.api.authsec.ai/spiresvc",
        logger: Optional[logging.Logger] = None,
        cert_lifecycle_manager = None,
        icp_client = None
    ):
        self.tenant_id = tenant_id
        self.agent_spiffe_id = agent_spiffe_id
        self.icp_service_url = icp_service_url.rstrip('/')
        self.logger = logger or logging.getLogger(__name__)
        self.cert_lifecycle_manager = cert_lifecycle_manager
        self.icp_client = icp_client

        # Workload entries cache (fetched from ICP)
        self.workload_entries: List[WorkloadEntry] = []
        self.entries_last_updated: Optional[datetime] = None

        # Active workload SVIDs (keyed by PID)
        self.workload_svids: Dict[int, WorkloadSVID] = {}

        # Tracked PIDs
        self.tracked_pids: Set[int] = set()

        # Selector plugins
        self.plugins: List[SelectorPlugin] = []
        self._initialize_plugins()

        # HTTP client for ICP service - use authenticated client from ICPClient if available
        self._fallback_http_client = None
        # When using ICPClient's mTLS client, it already has base_url set, so use relative paths
        self._use_relative_urls = False

    async def _get_http_client(self) -> httpx.AsyncClient:
        """Get the HTTP client, preferring mTLS from ICPClient."""
        if self.icp_client:
            return await self.icp_client._get_client(use_mtls=True)
        return self._fallback_http_client

    def _build_url(self, path: str) -> str:
        """Build URL for ICP service request. Uses relative path if mTLS client has base_url."""
        if self._use_relative_urls:
            return path
        return f"{self.icp_service_url}{path}"

    def _initialize_plugins(self):
        """Initialize selector collection plugins"""
        self.logger.info("Initializing selector plugins...")

        # Kubernetes plugin
        k8s_plugin = KubernetesPlugin(logger=self.logger)
        if k8s_plugin.is_available():
            self.plugins.append(k8s_plugin)
            self.logger.info("✓ Kubernetes plugin enabled")
        else:
            self.logger.info("✗ Kubernetes plugin not available")

        # Unix plugin
        unix_plugin = UnixPlugin(logger=self.logger)
        if unix_plugin.is_available():
            self.plugins.append(unix_plugin)
            self.logger.info("✓ Unix plugin enabled")
        else:
            self.logger.info("✗ Unix plugin not available")

        # Docker plugin
        docker_plugin = DockerPlugin(logger=self.logger)
        if docker_plugin.is_available():
            self.plugins.append(docker_plugin)
            self.logger.info("✓ Docker plugin enabled")
        else:
            self.logger.info("✗ Docker plugin not available")

        self.logger.info(f"Initialized {len(self.plugins)} selector plugins")

    async def start(self):
        """Start workload manager"""
        self.logger.info("Starting Workload Manager")
        self.logger.info(f"  Tenant ID: {self.tenant_id}")
        self.logger.info(f"  Agent SPIFFE ID: {self.agent_spiffe_id}")
        self.logger.info(f"  ICP Service: {self.icp_service_url}")
        self.logger.info("")

        # Initialize HTTP client - prefer mTLS client from ICPClient
        if self.icp_client:
            self._use_relative_urls = True
            self.logger.info("Will use mTLS-authenticated HTTP client from ICPClient")
        else:
            self.logger.warning("No ICPClient provided - using unauthenticated HTTP client")
            self._fallback_http_client = httpx.AsyncClient(timeout=30.0, follow_redirects=True)

        # Fetch initial workload entries
        await self.refresh_workload_entries()

        self.logger.info("Workload Manager started successfully")

    async def stop(self):
        """Stop workload manager"""
        self.logger.info("Stopping Workload Manager")
        if self._fallback_http_client:
            await self._fallback_http_client.aclose()

    async def refresh_workload_entries(self):
        """Fetch workload entries from ICP service"""
        self.logger.info("Fetching workload entries from ICP service...")

        try:
            # Use query parameters to avoid URL encoding issues with SPIFFE IDs
            url = self._build_url("/v1/entries/by-parent")
            params = {
                "tenant_id": self.tenant_id,
                "parent_id": self.agent_spiffe_id
            }

            http_client = await self._get_http_client()
            response = await http_client.get(url, params=params)

            if response.status_code == 200:
                data = response.json()
                entries = data.get('entries') or []

                self.workload_entries = [
                    WorkloadEntry(
                        id=entry['id'],
                        spiffe_id=entry['spiffe_id'],
                        parent_id=entry['parent_id'],
                        selectors=entry['selectors'],
                        ttl=entry.get('ttl'),
                        admin=entry.get('admin', False),
                        downstream=entry.get('downstream', False)
                    )
                    for entry in entries
                ]

                # Use naive UTC time consistently to avoid timezone issues
                self.entries_last_updated = datetime.now().replace(tzinfo=None)

                self.logger.info(f"✓ Loaded {len(self.workload_entries)} workload entries")

                # Log entries for debugging
                for entry in self.workload_entries:
                    self.logger.debug(f"  Entry: {entry.spiffe_id}")
                    self.logger.debug(f"    Selectors: {entry.selectors}")

            else:
                self.logger.error(f"Failed to fetch workload entries: {response.status_code}")
                self.logger.error(f"Response: {response.text}")

        except Exception as e:
            self.logger.error(f"Failed to refresh workload entries: {e}")

    async def attest_workload(self, pid: int, metadata_selectors: Optional[Dict[str, str]] = None) -> Optional[WorkloadSVID]:
        """
        Attest a workload and request SVID

        Args:
            pid: Process ID of workload
            metadata_selectors: Optional K8s selectors from gRPC metadata (sent by SDK)

        Returns:
            WorkloadSVID if successful, None otherwise
        """
        self.logger.info(f"Attesting workload PID {pid}")

        # 1. Collect selectors from all plugins
        selectors = self.collect_selectors(pid)

        # Merge K8s selectors from gRPC metadata (SDK sends these as headers).
        # Plugin-collected selectors take precedence if both exist.
        if metadata_selectors:
            merged = dict(metadata_selectors)
            merged.update(selectors)  # plugin selectors override metadata
            selectors = merged

        if not selectors:
            self.logger.warning(f"No selectors collected for PID {pid}")
            return None

        self.logger.info(f"Collected {len(selectors)} selectors for PID {pid}")
        for key, value in selectors.items():
            self.logger.debug(f"  {key} = {value}")

        # 2. Find matching workload entry
        entry = self.find_matching_entry(selectors)
        if not entry:
            self.logger.warning(f"No matching workload entry for PID {pid}")
            self.logger.warning(f"Selectors: {selectors}")
            return None

        self.logger.info(f"Found matching entry: {entry.spiffe_id}")

        # 3. Request SVID from ICP service
        svid = await self.request_svid(pid, entry, selectors)
        if not svid:
            self.logger.error(f"Failed to get SVID for PID {pid}")
            return None

        # 4. Cache SVID
        self.workload_svids[pid] = svid
        self.tracked_pids.add(pid)

        self.logger.info(f"✓ SVID issued for PID {pid}")
        self.logger.info(f"  SPIFFE ID: {svid.spiffe_id}")
        self.logger.info(f"  Expires: {svid.expires_at}")

        # 5. Register certificate with lifecycle manager for rotation tracking
        if self.cert_lifecycle_manager:
            self.cert_lifecycle_manager.register_certificate(svid)

        return svid

    def collect_selectors(self, pid: int) -> Dict[str, str]:
        """
        Collect selectors for a process using all plugins

        Args:
            pid: Process ID

        Returns:
            Combined selectors from all plugins
        """
        all_selectors = {}

        for plugin in self.plugins:
            try:
                selectors = plugin.get_selectors(pid)
                all_selectors.update(selectors)
            except Exception as e:
                self.logger.error(f"Plugin {plugin.get_plugin_name()} failed: {e}")

        return all_selectors

    def find_matching_entry(self, selectors: Dict[str, str]) -> Optional[WorkloadEntry]:
        """
        Find workload entry that matches the given selectors

        Matching logic: ALL entry selectors must be present in workload selectors

        Args:
            selectors: Workload selectors

        Returns:
            Matching entry or None
        """
        for entry in self.workload_entries:
            if self._selectors_match(entry.selectors, selectors):
                return entry

        return None

    def _selectors_match(self, entry_selectors: Dict[str, str], workload_selectors: Dict[str, str]) -> bool:
        """
        Check if workload selectors match entry selectors

        Args:
            entry_selectors: Required selectors from workload entry
            workload_selectors: Actual selectors collected from workload

        Returns:
            True if ALL entry selectors are present in workload selectors
        """
        for key, value in entry_selectors.items():
            if key not in workload_selectors or workload_selectors[key] != value:
                return False
        return True

    async def request_svid(
        self,
        pid: int,
        entry: WorkloadEntry,
        selectors: Dict[str, str]
    ) -> Optional[WorkloadSVID]:
        """
        Request SVID from ICP service

        Args:
            pid: Process ID
            entry: Matching workload entry
            selectors: Workload selectors

        Returns:
            WorkloadSVID if successful
        """
        try:
            url = self._build_url("/v1/workload/attest")

            request_data = {
                "tenant_id": self.tenant_id,
                "agent_id": self.agent_spiffe_id,
                "selectors": selectors
            }

            self.logger.debug(f"Requesting SVID from {url}")

            http_client = await self._get_http_client()
            response = await http_client.post(url, json=request_data)

            if response.status_code == 200:
                data = response.json()

                # Parse expires_at
                expires_at = datetime.fromisoformat(data['expires_at'].replace('Z', '+00:00'))

                svid = WorkloadSVID(
                    pid=pid,
                    spiffe_id=data['spiffe_id'],
                    certificate=data['certificate'],
                    private_key=data['private_key'],
                    trust_bundle=data['trust_bundle'],
                    expires_at=expires_at,
                    ttl=data['ttl'],
                    entry_id=entry.id,
                    selectors=selectors
                )

                return svid

            else:
                self.logger.error(f"SVID request failed: {response.status_code}")
                self.logger.error(f"Response: {response.text}")
                return None

        except Exception as e:
            self.logger.error(f"Failed to request SVID: {e}")
            return None

    def get_svid(self, pid: int) -> Optional[WorkloadSVID]:
        """
        Get cached SVID for a workload

        Args:
            pid: Process ID

        Returns:
            WorkloadSVID if available
        """
        return self.workload_svids.get(pid)

    def is_svid_expired(self, svid: WorkloadSVID) -> bool:
        """Check if SVID is expired or about to expire"""
        # Consider expired if less than 10% of TTL remaining
        # Strip timezone info if present to ensure naive datetime comparison
        expires_at = svid.expires_at
        if expires_at.tzinfo is not None:
            expires_at = expires_at.replace(tzinfo=None)
        # Use naive UTC datetime for comparison to avoid deprecation warning
        now_utc = datetime.now().replace(tzinfo=None) if datetime.now().tzinfo else datetime.now()
        time_remaining = expires_at - now_utc
        ttl_threshold = timedelta(seconds=svid.ttl * 0.1)
        return time_remaining < ttl_threshold

    async def rotate_expired_svids(self):
        """Rotate SVIDs that are about to expire"""
        for pid, svid in list(self.workload_svids.items()):
            if self.is_svid_expired(svid):
                self.logger.info(f"Rotating SVID for PID {pid} (expiring soon)")
                new_svid = await self.attest_workload(pid)
                if not new_svid:
                    self.logger.error(f"Failed to rotate SVID for PID {pid}")

    def cleanup_workload(self, pid: int):
        """
        Clean up resources for a terminated workload

        Args:
            pid: Process ID
        """
        if pid in self.workload_svids:
            svid = self.workload_svids.pop(pid)
            self.logger.info(f"Cleaned up SVID for terminated workload PID {pid}")
            self.logger.info(f"  SPIFFE ID: {svid.spiffe_id}")

        if pid in self.tracked_pids:
            self.tracked_pids.remove(pid)
