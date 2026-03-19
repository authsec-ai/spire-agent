"""
Unix Selector Plugin

Collects selectors from Unix process metadata:
- unix:uid (user ID)
- unix:gid (group ID)
- unix:path (executable path)
- unix:process (process name)
- unix:pid (process ID)
- unix:sha256 (SHA256 hash of executable)
"""

import os
import hashlib
import logging
from typing import Dict, Optional
from .base import SelectorPlugin


class UnixPlugin(SelectorPlugin):
    """
    Unix selector plugin

    Reads process information from /proc filesystem
    """

    def __init__(self, logger: Optional[logging.Logger] = None):
        super().__init__(logger)

    def is_available(self) -> bool:
        """Check if /proc filesystem is available"""
        return os.path.exists('/proc')

    def get_plugin_name(self) -> str:
        """Get plugin name"""
        return "unix"

    def get_selectors(self, pid: int) -> Dict[str, str]:
        """
        Collect Unix selectors for a process

        Args:
            pid: Process ID

        Returns:
            Dictionary of selectors
        """
        if not self.is_available():
            self.logger.debug("Unix plugin not available (/proc not found)")
            return {}

        selectors = {}

        try:
            # Get process status (UID, GID)
            status = self._read_proc_status(pid)
            if status:
                if 'Uid' in status:
                    # Uid line format: "Uid:	1000	1000	1000	1000"
                    # We want the real UID (first value)
                    uid = status['Uid'].split()[0]
                    selectors['unix:uid'] = uid

                if 'Gid' in status:
                    # Gid line format: "Gid:	1000	1000	1000	1000"
                    # We want the real GID (first value)
                    gid = status['Gid'].split()[0]
                    selectors['unix:gid'] = gid

            # Get executable path
            exe_path = self._get_executable_path(pid)
            if exe_path:
                selectors['unix:path'] = exe_path

                # Calculate SHA256 of executable (for integrity verification)
                sha256 = self._calculate_file_hash(exe_path)
                if sha256:
                    selectors['unix:sha256'] = sha256

            # Get process name (from comm or cmdline)
            process_name = self._get_process_name(pid)
            if process_name:
                selectors['unix:process'] = process_name

            # Add PID as selector (useful for debugging)
            selectors['unix:pid'] = str(pid)

            self.logger.info(f"Collected {len(selectors)} Unix selectors for PID {pid}")

        except Exception as e:
            self.logger.error(f"Failed to collect Unix selectors: {e}")

        return selectors

    def _read_proc_status(self, pid: int) -> Optional[Dict[str, str]]:
        """
        Read /proc/<pid>/status

        Args:
            pid: Process ID

        Returns:
            Dictionary of status fields
        """
        status_path = f"/proc/{pid}/status"

        try:
            if not os.path.exists(status_path):
                return None

            status = {}
            with open(status_path, 'r') as f:
                for line in f:
                    if ':' in line:
                        key, value = line.split(':', 1)
                        status[key.strip()] = value.strip()

            return status

        except Exception as e:
            self.logger.debug(f"Could not read {status_path}: {e}")
            return None

    def _get_executable_path(self, pid: int) -> Optional[str]:
        """
        Get executable path from /proc/<pid>/exe

        Args:
            pid: Process ID

        Returns:
            Executable path or None
        """
        exe_link = f"/proc/{pid}/exe"

        try:
            if os.path.exists(exe_link):
                # /proc/<pid>/exe is a symlink to the actual executable
                return os.readlink(exe_link)

        except Exception as e:
            self.logger.debug(f"Could not read executable path for PID {pid}: {e}")

        return None

    def _get_process_name(self, pid: int) -> Optional[str]:
        """
        Get process name from /proc/<pid>/comm or cmdline

        Args:
            pid: Process ID

        Returns:
            Process name or None
        """
        # First try /proc/<pid>/comm (contains just the process name)
        comm_path = f"/proc/{pid}/comm"
        try:
            if os.path.exists(comm_path):
                with open(comm_path, 'r') as f:
                    process_name = f.read().strip()
                    if process_name:
                        return process_name
        except Exception as e:
            self.logger.debug(f"Could not read comm for PID {pid}: {e}")

        # Fallback: try /proc/<pid>/cmdline (contains full command with args)
        cmdline_path = f"/proc/{pid}/cmdline"
        try:
            if os.path.exists(cmdline_path):
                with open(cmdline_path, 'r') as f:
                    # cmdline is null-separated, first element is the command
                    cmdline = f.read()
                    if cmdline:
                        # Extract first argument (the executable)
                        cmd = cmdline.split('\x00')[0]
                        # Get just the basename if it's a path
                        if '/' in cmd:
                            return os.path.basename(cmd)
                        return cmd
        except Exception as e:
            self.logger.debug(f"Could not read cmdline for PID {pid}: {e}")

        return None

    def _calculate_file_hash(self, file_path: str) -> Optional[str]:
        """
        Calculate SHA256 hash of a file

        Args:
            file_path: Path to file

        Returns:
            SHA256 hash (hex) or None
        """
        try:
            if not os.path.exists(file_path):
                return None

            sha256_hash = hashlib.sha256()

            with open(file_path, 'rb') as f:
                # Read in chunks to handle large files
                for chunk in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(chunk)

            return sha256_hash.hexdigest()

        except Exception as e:
            self.logger.debug(f"Could not calculate hash for {file_path}: {e}")
            return None

    def get_username(self, uid: int) -> Optional[str]:
        """
        Get username from UID

        Args:
            uid: User ID

        Returns:
            Username or None
        """
        try:
            import pwd
            return pwd.getpwuid(uid).pw_name
        except Exception as e:
            self.logger.debug(f"Could not get username for UID {uid}: {e}")
            return None

    def get_groupname(self, gid: int) -> Optional[str]:
        """
        Get group name from GID

        Args:
            gid: Group ID

        Returns:
            Group name or None
        """
        try:
            import grp
            return grp.getgrgid(gid).gr_name
        except Exception as e:
            self.logger.debug(f"Could not get group name for GID {gid}: {e}")
            return None
