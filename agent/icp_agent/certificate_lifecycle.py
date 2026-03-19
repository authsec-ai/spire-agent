"""
Certificate Lifecycle Manager

Manages the complete lifecycle of workload certificates:
1. Issuance - Request and cache certificates
2. Renewal - Proactive renewal before expiry
3. Rotation - Automatic rotation with notification
4. Revocation - Handle certificate revocation
5. Monitoring - Track certificate health and expiry

Epic 8 - SPIRE-70, SPIRE-71
"""

import asyncio
import logging
import os
import signal
from typing import Optional, Dict, List, Callable, Set
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum


class CertificateStatus(Enum):
    """Certificate lifecycle status"""
    ACTIVE = "active"
    EXPIRING_SOON = "expiring_soon"
    EXPIRED = "expired"
    REVOKED = "revoked"
    ROTATION_IN_PROGRESS = "rotation_in_progress"


@dataclass
class CertificateMetrics:
    """Metrics for certificate lifecycle tracking"""
    total_issued: int = 0
    total_rotated: int = 0
    total_expired: int = 0
    total_revoked: int = 0
    rotation_failures: int = 0
    average_rotation_time_ms: float = 0.0
    active_certificates: int = 0


@dataclass
class CertificateInfo:
    """Enhanced certificate information with lifecycle data"""
    pid: int
    spiffe_id: str
    certificate: str
    private_key: str
    trust_bundle: str
    issued_at: datetime
    expires_at: datetime
    ttl: int
    serial_number: Optional[str] = None
    status: CertificateStatus = CertificateStatus.ACTIVE
    rotation_count: int = 0
    last_rotation: Optional[datetime] = None
    rotation_scheduled: bool = False


class CertificateLifecycleManager:
    """
    Manages complete certificate lifecycle with proactive rotation
    """

    def __init__(
        self,
        workload_manager,
        rotation_threshold: float = 0.1,  # Rotate at 10% TTL remaining
        check_interval: int = 30,  # Check every 30 seconds
        logger: Optional[logging.Logger] = None
    ):
        self.workload_manager = workload_manager
        self.rotation_threshold = rotation_threshold
        self.check_interval = check_interval
        self.logger = logger or logging.getLogger(__name__)

        # Certificate tracking
        self.certificates: Dict[int, CertificateInfo] = {}
        self.revoked_serials: Set[str] = set()

        # Rotation callbacks
        self.rotation_callbacks: List[Callable] = []

        # Metrics
        self.metrics = CertificateMetrics()

        # Background tasks
        self.rotation_task: Optional[asyncio.Task] = None
        self.monitoring_task: Optional[asyncio.Task] = None
        self.running = False

    async def start(self):
        """Start certificate lifecycle management"""
        self.logger.info("Starting Certificate Lifecycle Manager")
        self.logger.info(f"  Rotation Threshold: {self.rotation_threshold * 100}% TTL")
        self.logger.info(f"  Check Interval: {self.check_interval}s")

        self.running = True

        # Start background tasks
        self.rotation_task = asyncio.create_task(self._rotation_loop())
        self.monitoring_task = asyncio.create_task(self._monitoring_loop())

        self.logger.info("✓ Certificate Lifecycle Manager started")

    async def stop(self):
        """Stop certificate lifecycle management"""
        self.logger.info("Stopping Certificate Lifecycle Manager")
        self.running = False

        if self.rotation_task:
            self.rotation_task.cancel()
            try:
                await self.rotation_task
            except asyncio.CancelledError:
                pass

        if self.monitoring_task:
            self.monitoring_task.cancel()
            try:
                await self.monitoring_task
            except asyncio.CancelledError:
                pass

        self.logger.info("✓ Certificate Lifecycle Manager stopped")

    def register_certificate(self, svid) -> CertificateInfo:
        """
        Register a newly issued certificate for lifecycle management

        Args:
            svid: WorkloadSVID from workload manager

        Returns:
            CertificateInfo with lifecycle tracking
        """
        cert_info = CertificateInfo(
            pid=svid.pid,
            spiffe_id=svid.spiffe_id,
            certificate=svid.certificate,
            private_key=svid.private_key,
            trust_bundle=svid.trust_bundle,
            issued_at=datetime.now(),
            expires_at=svid.expires_at,
            ttl=svid.ttl,
            status=CertificateStatus.ACTIVE
        )

        self.certificates[svid.pid] = cert_info
        self.metrics.total_issued += 1
        self.metrics.active_certificates = len(self.certificates)

        self.logger.info(f"Registered certificate for PID {svid.pid}")
        self.logger.info(f"  SPIFFE ID: {svid.spiffe_id}")
        self.logger.info(f"  Expires: {svid.expires_at}")
        self.logger.info(f"  TTL: {svid.ttl}s")

        return cert_info

    def get_certificate(self, pid: int) -> Optional[CertificateInfo]:
        """Get certificate info for a PID"""
        return self.certificates.get(pid)

    def get_status(self, pid: int) -> Optional[CertificateStatus]:
        """Get certificate status for a PID"""
        cert = self.certificates.get(pid)
        return cert.status if cert else None

    def is_expiring_soon(self, cert_info: CertificateInfo) -> bool:
        """Check if certificate is expiring soon"""
        # Strip timezone info if present to ensure naive datetime comparison
        expires_at = cert_info.expires_at
        if expires_at.tzinfo is not None:
            expires_at = expires_at.replace(tzinfo=None)
        # Use naive UTC datetime for comparison to avoid deprecation warning
        now_utc = datetime.now().replace(tzinfo=None) if datetime.now().tzinfo else datetime.now()

        time_remaining = expires_at - now_utc
        ttl_threshold = timedelta(seconds=cert_info.ttl * self.rotation_threshold)
        return time_remaining < ttl_threshold

    def is_expired(self, cert_info: CertificateInfo) -> bool:
        """Check if certificate has expired"""
        # Strip timezone info if present to ensure naive datetime comparison
        expires_at = cert_info.expires_at
        if expires_at.tzinfo is not None:
            expires_at = expires_at.replace(tzinfo=None)
        # Use naive UTC datetime for comparison to avoid deprecation warning
        now_utc = datetime.now().replace(tzinfo=None) if datetime.now().tzinfo else datetime.now()

        return now_utc >= expires_at

    def is_process_running(self, pid: int) -> bool:
        """
        Check if a process with the given PID is still running.

        Args:
            pid: Process ID to check

        Returns:
            True if process exists, False otherwise
        """
        try:
            # Sending signal 0 checks if process exists without sending a signal
            os.kill(pid, 0)
            return True
        except ProcessLookupError:
            # Process doesn't exist
            return False
        except (PermissionError, OSError):
            # Can't check (permission denied, or other error)
            # Assume process is still running to be safe
            return True

    def should_rotate(self, cert_info: CertificateInfo) -> bool:
        """
        Determine if certificate should be rotated

        Returns True if:
        - Certificate is expiring soon
        - Certificate is not already being rotated
        - Certificate is not revoked
        """
        if cert_info.status == CertificateStatus.REVOKED:
            return False

        if cert_info.status == CertificateStatus.ROTATION_IN_PROGRESS:
            return False

        if self.is_expired(cert_info):
            cert_info.status = CertificateStatus.EXPIRED
            return True

        if self.is_expiring_soon(cert_info):
            cert_info.status = CertificateStatus.EXPIRING_SOON
            return True

        return False

    async def rotate_certificate(self, pid: int) -> bool:
        """
        Rotate certificate for a workload

        Args:
            pid: Process ID

        Returns:
            True if rotation successful
        """
        cert_info = self.certificates.get(pid)
        if not cert_info:
            self.logger.warning(f"No certificate found for PID {pid}")
            return False

        self.logger.info(f"Rotating certificate for PID {pid}")
        self.logger.info(f"  Current SPIFFE ID: {cert_info.spiffe_id}")
        self.logger.info(f"  Expires at: {cert_info.expires_at}")

        # Mark as rotation in progress
        old_status = cert_info.status
        cert_info.status = CertificateStatus.ROTATION_IN_PROGRESS

        rotation_start = datetime.now()

        try:
            # Request new SVID from workload manager
            new_svid = await self.workload_manager.attest_workload(pid)

            if not new_svid:
                self.logger.error(f"Failed to rotate certificate for PID {pid}")
                cert_info.status = old_status
                self.metrics.rotation_failures += 1
                return False

            # Update certificate info
            cert_info.certificate = new_svid.certificate
            cert_info.private_key = new_svid.private_key
            cert_info.trust_bundle = new_svid.trust_bundle
            cert_info.expires_at = new_svid.expires_at
            cert_info.ttl = new_svid.ttl
            cert_info.status = CertificateStatus.ACTIVE
            cert_info.rotation_count += 1
            cert_info.last_rotation = datetime.now()
            cert_info.rotation_scheduled = False

            # Update metrics
            rotation_time = (datetime.now() - rotation_start).total_seconds() * 1000
            self.metrics.total_rotated += 1

            # Update average rotation time
            if self.metrics.average_rotation_time_ms == 0:
                self.metrics.average_rotation_time_ms = rotation_time
            else:
                self.metrics.average_rotation_time_ms = (
                    self.metrics.average_rotation_time_ms * 0.9 + rotation_time * 0.1
                )

            self.logger.info(f"✓ Certificate rotated for PID {pid}")
            self.logger.info(f"  New expires at: {cert_info.expires_at}")
            self.logger.info(f"  Rotation count: {cert_info.rotation_count}")
            self.logger.info(f"  Rotation time: {rotation_time:.2f}ms")

            # Notify callbacks
            await self._notify_rotation(pid, cert_info)

            return True

        except Exception as e:
            self.logger.error(f"Error rotating certificate for PID {pid}: {e}")
            cert_info.status = old_status
            self.metrics.rotation_failures += 1
            return False

    async def revoke_certificate(self, pid: int, serial_number: Optional[str] = None):
        """
        Revoke a certificate

        Args:
            pid: Process ID
            serial_number: Optional serial number for revocation list
        """
        cert_info = self.certificates.get(pid)
        if not cert_info:
            self.logger.warning(f"No certificate found for PID {pid}")
            return

        self.logger.info(f"Revoking certificate for PID {pid}")
        self.logger.info(f"  SPIFFE ID: {cert_info.spiffe_id}")

        cert_info.status = CertificateStatus.REVOKED

        if serial_number:
            self.revoked_serials.add(serial_number)

        self.metrics.total_revoked += 1
        self.metrics.active_certificates = len([
            c for c in self.certificates.values()
            if c.status not in [CertificateStatus.REVOKED, CertificateStatus.EXPIRED]
        ])

        self.logger.info(f"✓ Certificate revoked for PID {pid}")

    def cleanup_certificate(self, pid: int):
        """Remove certificate from tracking"""
        if pid in self.certificates:
            cert_info = self.certificates.pop(pid)
            self.logger.info(f"Cleaned up certificate for PID {pid}")
            self.logger.info(f"  SPIFFE ID: {cert_info.spiffe_id}")
            self.logger.info(f"  Total rotations: {cert_info.rotation_count}")

            self.metrics.active_certificates = len(self.certificates)

    def add_rotation_callback(self, callback: Callable):
        """
        Add callback to be notified when certificate is rotated

        Callback signature: async def callback(pid: int, cert_info: CertificateInfo)
        """
        self.rotation_callbacks.append(callback)

    async def _notify_rotation(self, pid: int, cert_info: CertificateInfo):
        """Notify all rotation callbacks"""
        for callback in self.rotation_callbacks:
            try:
                await callback(pid, cert_info)
            except Exception as e:
                self.logger.error(f"Error in rotation callback: {e}")

    async def _rotation_loop(self):
        """Background task to check and rotate expiring certificates"""
        self.logger.info("Certificate rotation loop started")

        while self.running:
            try:
                await asyncio.sleep(self.check_interval)

                if not self.running:
                    break

                # Check all certificates for rotation or cleanup
                pids_to_remove = []
                for pid, cert_info in list(self.certificates.items()):
                    # FEATURE: Check if process is still running (handles graceful shutdown)
                    if not self.is_process_running(pid):
                        self.logger.info(f"Process PID {pid} no longer running, cleaning up")
                        self.logger.info(f"  SPIFFE ID: {cert_info.spiffe_id}")
                        pids_to_remove.append(pid)
                        continue

                    # Proceed with rotation check only if process is alive
                    if self.should_rotate(cert_info):
                        if not cert_info.rotation_scheduled:
                            cert_info.rotation_scheduled = True
                            self.logger.info(f"Scheduling rotation for PID {pid}")

                            # Rotate in background
                            asyncio.create_task(self.rotate_certificate(pid))

                # Clean up certificates for dead processes
                for pid in pids_to_remove:
                    removed_cert = self.certificates.pop(pid, None)
                    if removed_cert:
                        self.metrics.active_certificates = len(self.certificates)
                        # Also clean up in workload manager
                        if self.workload_manager:
                            self.workload_manager.cleanup_workload(pid)

            except asyncio.CancelledError:
                break
            except Exception as e:
                self.logger.error(f"Error in rotation loop: {e}")

        self.logger.info("Certificate rotation loop stopped")

    async def _monitoring_loop(self):
        """Background task to monitor certificate health"""
        self.logger.info("Certificate monitoring loop started")

        while self.running:
            try:
                await asyncio.sleep(60)  # Monitor every minute

                if not self.running:
                    break

                # Log health metrics
                self.logger.debug("Certificate Health Metrics:")
                self.logger.debug(f"  Total Issued: {self.metrics.total_issued}")
                self.logger.debug(f"  Total Rotated: {self.metrics.total_rotated}")
                self.logger.debug(f"  Active Certificates: {self.metrics.active_certificates}")
                self.logger.debug(f"  Rotation Failures: {self.metrics.rotation_failures}")
                self.logger.debug(f"  Avg Rotation Time: {self.metrics.average_rotation_time_ms:.2f}ms")

                # Check for expired certificates
                expired_count = 0
                for pid, cert_info in self.certificates.items():
                    if self.is_expired(cert_info) and cert_info.status != CertificateStatus.EXPIRED:
                        cert_info.status = CertificateStatus.EXPIRED
                        expired_count += 1
                        self.metrics.total_expired += 1
                        self.logger.warning(f"Certificate expired for PID {pid}")

                if expired_count > 0:
                    self.logger.warning(f"Found {expired_count} expired certificate(s)")

            except asyncio.CancelledError:
                break
            except Exception as e:
                self.logger.error(f"Error in monitoring loop: {e}")

        self.logger.info("Certificate monitoring loop stopped")

    def get_metrics(self) -> CertificateMetrics:
        """Get current lifecycle metrics"""
        return self.metrics

    def get_certificates_by_status(self, status: CertificateStatus) -> List[CertificateInfo]:
        """Get all certificates with a specific status"""
        return [
            cert for cert in self.certificates.values()
            if cert.status == status
        ]

    def get_expiring_certificates(self, hours: int = 24) -> List[CertificateInfo]:
        """Get certificates expiring within specified hours"""
        threshold = datetime.now() + timedelta(hours=hours)
        return [
            cert for cert in self.certificates.values()
            if cert.expires_at <= threshold and cert.status == CertificateStatus.ACTIVE
        ]
