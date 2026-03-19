"""
Kubernetes Selector Plugin

Collects selectors from Kubernetes pod metadata:
- k8s:ns (namespace)
- k8s:sa (service account)
- k8s:pod-name
- k8s:pod-uid
- k8s:pod-label:* (pod labels)
- k8s:pod-image (container image)
- k8s:pod-image-id (image ID)
- k8s:node-name
- k8s:pod-owner-* (owner references: deployment, statefulset, daemonset, replicaset)
"""

import os
import re
import logging
from typing import Dict, Optional
from kubernetes import client, config
from kubernetes.client.rest import ApiException
from .base import SelectorPlugin


class KubernetesPlugin(SelectorPlugin):
    """
    Kubernetes selector plugin

    Queries Kubernetes API to get pod metadata for a given process.
    """

    def __init__(self, logger: Optional[logging.Logger] = None):
        super().__init__(logger)
        self.k8s_client = None
        self._initialize_client()

    def _initialize_client(self):
        """Initialize Kubernetes client"""
        try:
            # Try in-cluster configuration first
            config.load_incluster_config()
            self.logger.info("Loaded in-cluster Kubernetes configuration")
        except config.ConfigException:
            try:
                # Fall back to kubeconfig
                config.load_kube_config()
                self.logger.info("Loaded Kubernetes configuration from kubeconfig")
            except config.ConfigException as e:
                self.logger.warning(f"Could not load Kubernetes configuration: {e}")
                return

        self.k8s_client = client.CoreV1Api()

    def is_available(self) -> bool:
        """Check if Kubernetes API is available"""
        return self.k8s_client is not None

    def get_plugin_name(self) -> str:
        """Get plugin name"""
        return "kubernetes"

    def get_selectors(self, pid: int) -> Dict[str, str]:
        """
        Collect Kubernetes selectors for a process

        Args:
            pid: Process ID

        Returns:
            Dictionary of selectors
        """
        if not self.is_available():
            self.logger.debug("Kubernetes plugin not available")
            return {}

        selectors = {}

        try:
            # Get pod info from process cgroup (method 1)
            pod_uid = self._get_pod_uid_from_cgroup(pid)
            if not pod_uid:
                # Fall back to environment variables (method 2)
                pod_uid = self._get_pod_uid_from_env(pid)

            if not pod_uid:
                self.logger.debug(f"Could not determine pod UID for PID {pid}")
                return {}

            # Get pod details from Kubernetes API
            pod = self._get_pod_by_uid(pod_uid)
            if not pod:
                self.logger.warning(f"Could not find pod with UID {pod_uid}")
                return {}

            # Extract selectors from pod
            selectors = self._extract_selectors(pod)

            self.logger.info(f"Collected {len(selectors)} Kubernetes selectors for PID {pid}")

        except Exception as e:
            self.logger.error(f"Failed to collect Kubernetes selectors: {e}")

        return selectors

    def _get_pod_uid_from_cgroup(self, pid: int) -> Optional[str]:
        """
        Extract pod UID from process cgroup

        Kubernetes sets cgroup paths depending on runtime and cgroup version:

        Docker/containerd (cgroups v1):
        - /kubepods/besteffort/pod<pod-uid>/<container-id>
        - /kubepods/burstable/pod<pod-uid>/<container-id>
        - /kubepods/pod<pod-uid>/<container-id>

        containerd (cgroups v2):
        - /kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-pod<pod-uid>.slice/<container>
        - /kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod<pod-uid>.slice/<container>

        CRI-O:
        - /kubepods.slice/kubepods-pod<pod_uid>.slice/crio-<container-id>.scope
        """
        try:
            cgroup_path = f"/proc/{pid}/cgroup"
            if not os.path.exists(cgroup_path):
                return None

            with open(cgroup_path, 'r') as f:
                for line in f:
                    if 'kubepods' not in line:
                        continue

                    # Pattern 1: cgroups v1 format (Docker, containerd)
                    # Example: 0::/kubepods/besteffort/pod1234-5678-9abc-def0/...
                    match = re.search(r'/kubepods(?:/[^/]+)?/pod([a-f0-9-]+)', line)
                    if match:
                        pod_uid = match.group(1).replace('_', '-')
                        self.logger.debug(f"Extracted pod UID from cgroups v1: {pod_uid}")
                        return pod_uid

                    # Pattern 2: cgroups v2 systemd format (containerd, CRI-O)
                    # Example: 0::/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-pod1234_5678_9abc_def0.slice/...
                    match = re.search(r'pod([a-f0-9_-]+)\.slice', line)
                    if match:
                        pod_uid = match.group(1).replace('_', '-')
                        self.logger.debug(f"Extracted pod UID from cgroups v2: {pod_uid}")
                        return pod_uid

            self.logger.debug(f"No kubepods cgroup found for PID {pid}")

        except Exception as e:
            self.logger.debug(f"Could not read cgroup for PID {pid}: {e}")

        return None

    def _get_pod_uid_from_env(self, pid: int) -> Optional[str]:
        """
        Extract pod UID from process environment variables

        Fallback method if cgroup parsing fails
        """
        try:
            # Read environment variables from /proc/<pid>/environ
            environ_path = f"/proc/{pid}/environ"
            if not os.path.exists(environ_path):
                return None

            with open(environ_path, 'rb') as f:
                environ_data = f.read().decode('utf-8', errors='ignore')

            # Split by null bytes
            env_vars = environ_data.split('\x00')

            for var in env_vars:
                if var.startswith('POD_UID='):
                    return var.split('=', 1)[1]

        except Exception as e:
            self.logger.debug(f"Could not read environ for PID {pid}: {e}")

        return None

    def _get_pod_by_uid(self, pod_uid: str) -> Optional[client.V1Pod]:
        """
        Get pod object from Kubernetes API by UID

        Args:
            pod_uid: Pod UID

        Returns:
            Pod object or None
        """
        try:
            # List all pods and find by UID
            pods = self.k8s_client.list_pod_for_all_namespaces(
                field_selector=f"metadata.uid={pod_uid}"
            )

            if pods.items:
                return pods.items[0]

        except ApiException as e:
            self.logger.error(f"Kubernetes API error: {e}")

        return None

    def _extract_selectors(self, pod: client.V1Pod) -> Dict[str, str]:
        """
        Extract selectors from pod metadata

        Args:
            pod: Kubernetes pod object

        Returns:
            Dictionary of selectors
        """
        selectors = {}

        # Namespace
        if pod.metadata.namespace:
            selectors['k8s:ns'] = pod.metadata.namespace

        # Service Account
        if pod.spec.service_account_name:
            selectors['k8s:sa'] = pod.spec.service_account_name

        # Pod Name
        if pod.metadata.name:
            selectors['k8s:pod-name'] = pod.metadata.name

        # Pod UID
        if pod.metadata.uid:
            selectors['k8s:pod-uid'] = pod.metadata.uid

        # Node Name
        if pod.spec.node_name:
            selectors['k8s:node-name'] = pod.spec.node_name

        # Pod Labels
        if pod.metadata.labels:
            for key, value in pod.metadata.labels.items():
                # Format: k8s:pod-label:<label-key>
                selector_key = f'k8s:pod-label:{key}'
                selectors[selector_key] = value

        # Container Image and Image ID (from first container)
        if pod.status and pod.status.container_statuses:
            first_container = pod.status.container_statuses[0]
            if first_container.image:
                selectors['k8s:pod-image'] = first_container.image
            if first_container.image_id:
                # Remove docker-pullable:// or other prefixes
                image_id = first_container.image_id
                if '://' in image_id:
                    image_id = image_id.split('://', 1)[1]
                selectors['k8s:pod-image-id'] = image_id

        # Owner References (Deployment, StatefulSet, DaemonSet, ReplicaSet, Job)
        if pod.metadata.owner_references:
            for owner in pod.metadata.owner_references:
                kind = owner.kind.lower()
                name = owner.name

                # Add owner reference as selector
                # Example: k8s:pod-owner-deployment:my-deployment
                selector_key = f'k8s:pod-owner-{kind}'
                selectors[selector_key] = name

                # For ReplicaSet, try to extract parent Deployment name
                if kind == 'replicaset':
                    # ReplicaSet names are usually: <deployment>-<hash>
                    # Extract deployment name by removing last segment
                    deployment_name = '-'.join(name.rsplit('-', 1)[:-1])
                    if deployment_name:
                        selectors['k8s:pod-owner-deployment'] = deployment_name

        return selectors
