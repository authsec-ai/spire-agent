"""
Unix process attestation validator.

Collects Unix-specific attestation evidence including:
- Process ID (PID)
- User ID (UID)
- Group ID (GID)
- Process path
- Command line
"""

import os
import platform
from pathlib import Path
from typing import Dict, Any, Optional

import structlog

# Import Unix-specific modules only on Unix systems
try:
    import pwd
    import grp
    HAS_PWD = True
except ImportError:
    HAS_PWD = False

from .base import AttestationValidator
from icp_agent.config import UnixAttestationConfig


logger = structlog.get_logger(__name__)


class UnixValidator(AttestationValidator):
    """Unix process attestation validator."""

    def __init__(self, config: UnixAttestationConfig):
        """
        Initialize Unix validator.

        Args:
            config: Unix attestation configuration
        """
        super().__init__(config)
        self.config: UnixAttestationConfig = config

    async def validate_environment(self) -> bool:
        """
        Validate that we're running on a Unix system (or Windows fallback).

        Returns:
            True if environment is valid, False otherwise
        """
        # Check for /proc filesystem (Linux/Unix)
        if Path("/proc").exists():
            logger.info("Unix environment validated (/proc exists)")
            return True

        # Windows fallback - allow Unix attestation on Windows for development
        if platform.system() == "Windows":
            logger.info("Windows environment detected, using Unix attestation fallback mode")
            return True

        logger.warning("Unable to validate Unix/Windows environment")
        return False

    async def collect_evidence(self) -> Dict[str, Any]:
        """
        Collect Unix process attestation evidence.

        Returns:
            Dictionary containing:
            - pid: Process ID
            - uid: User ID
            - gid: Group ID
            - username: Username
            - groupname: Group name
            - exe_path: Executable path
            - cmdline: Command line
            - hostname: System hostname

        Raises:
            ValueError: If unable to collect evidence
        """
        logger.info("Collecting Unix attestation evidence")

        evidence = {}

        # Get process information
        pid = os.getpid()
        evidence["pid"] = pid

        # Get user information (Unix only)
        if HAS_PWD:
            try:
                uid = os.getuid()
                evidence["uid"] = uid

                user_info = pwd.getpwuid(uid)
                evidence["username"] = user_info.pw_name
            except (KeyError, AttributeError) as e:
                logger.warning("Unable to get username", error=str(e))
        else:
            # Windows fallback
            evidence["username"] = os.getenv("USERNAME", "unknown")

        # Get group information (Unix only)
        if HAS_PWD:
            try:
                gid = os.getgid()
                evidence["gid"] = gid

                group_info = grp.getgrgid(gid)
                evidence["groupname"] = group_info.gr_name
            except (KeyError, AttributeError) as e:
                logger.warning("Unable to get groupname", error=str(e))
        else:
            # Windows - use domain/workgroup
            evidence["groupname"] = os.getenv("USERDOMAIN", "unknown")

        # Get executable path
        exe_path = self._get_exe_path(pid)
        if exe_path:
            evidence["exe_path"] = exe_path

        # Get command line
        cmdline = self._get_cmdline(pid)
        if cmdline:
            evidence["cmdline"] = cmdline

        # Get hostname
        import socket
        evidence["hostname"] = socket.gethostname()

        # Get parent process information (optional)
        ppid = os.getppid()
        evidence["ppid"] = ppid

        parent_exe = self._get_exe_path(ppid)
        if parent_exe:
            evidence["parent_exe"] = parent_exe

        logger.info(
            "Unix attestation evidence collected",
            pid=pid,
            uid=evidence.get("uid", "N/A"),
            username=evidence.get("username", "unknown"),
        )

        return evidence

    def _get_exe_path(self, pid: int) -> Optional[str]:
        """
        Get executable path for a process.

        Args:
            pid: Process ID

        Returns:
            Executable path or None if not found
        """
        exe_link = Path(f"/proc/{pid}/exe")
        try:
            if exe_link.exists():
                return str(exe_link.resolve())
        except Exception as e:
            logger.debug("Failed to read exe path", pid=pid, error=str(e))

        return None

    def _get_cmdline(self, pid: int) -> Optional[str]:
        """
        Get command line for a process.

        Args:
            pid: Process ID

        Returns:
            Command line string or None if not found
        """
        cmdline_path = Path(f"/proc/{pid}/cmdline")
        try:
            if cmdline_path.exists():
                with open(cmdline_path, "r") as f:
                    # cmdline uses null bytes as separators
                    cmdline = f.read().replace("\x00", " ").strip()
                    return cmdline
        except Exception as e:
            logger.debug("Failed to read cmdline", pid=pid, error=str(e))

        return None

    def get_node_selectors(self) -> Dict[str, str]:
        """
        Get node selectors from Unix environment.

        Returns:
            Dictionary of node selectors (unix:uid, unix:username, unix:hostname, etc.)
        """
        selectors = {}

        if HAS_PWD:
            try:
                selectors["unix:uid"] = str(os.getuid())
                selectors["unix:gid"] = str(os.getgid())

                user_info = pwd.getpwuid(os.getuid())
                selectors["unix:username"] = user_info.pw_name

                group_info = grp.getgrgid(os.getgid())
                selectors["unix:groupname"] = group_info.gr_name
            except (KeyError, AttributeError):
                pass
        else:
            # Windows fallback
            selectors["unix:username"] = os.getenv("USERNAME", "unknown")
            selectors["unix:groupname"] = os.getenv("USERDOMAIN", "unknown")

        import socket
        selectors["unix:hostname"] = socket.gethostname()

        if exe_path := self._get_exe_path(os.getpid()):
            selectors["unix:exe"] = exe_path

        return selectors
