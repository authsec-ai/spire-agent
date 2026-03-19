# SPIRE Agent

SPIFFE-compatible workload identity agent by [AuthSec](https://authsec.ai). Runs as a Kubernetes DaemonSet and provides cryptographic identities (X.509 and JWT SVIDs) to your workloads for mTLS and authorization.

## Quick Start

### Helm (recommended)

```bash
helm install spire-agent ./charts/spire-agent \
  --namespace spire --create-namespace \
  --set tenantId="YOUR-TENANT-UUID"
```

One command. Creates namespace, RBAC, config, and DaemonSet.

### Raw manifests

```bash
# 1. Download the manifest
curl -sO https://raw.githubusercontent.com/authsec-ai/spire-agent/main/manifests/spire-agent-daemonset.yaml

# 2. Edit the ConfigMap — set your tenant_id and cluster_name
#    Look for "your-tenant-uuid-here" and "production"

# 3. Apply
kubectl apply -f spire-agent-daemonset.yaml
```

## Verify

```bash
# One Running pod per node
kubectl get pods -n spire -l app=spire-agent

# Check logs
kubectl logs -n spire -l app=spire-agent --tail=20
```

You should see:
```
{"event": "Agent startup completed successfully", ...}
{"event": "Agent SVID renewal successful", "spiffe_id": "spiffe://YOUR-TENANT-UUID/agent/...", ...}
{"event": "✓ gRPC Workload API Server started", ...}
```

## Workload Integration

Install the [AuthSec SDK](https://github.com/authsec-ai/sdk-authsec) in your service:

```bash
pip install git+https://github.com/authsec-ai/sdk-authsec.git#subdirectory=packages/python-sdk
```

```python
from AuthSec_SDK import QuickStartSVID

svid = await QuickStartSVID.initialize(
    socket_path="/run/spire/sockets/agent.sock"
)

# You now have:
# - svid.spiffe_id            → your workload identity
# - svid.cert_file_path       → mTLS cert (auto-renewed)
# - svid.key_file_path        → mTLS key
# - svid.ca_file_path         → CA bundle
# - svid.validate_jwt_svid()  → validate incoming JWT-SVIDs
# - svid.fetch_jwt_svid()     → get a JWT-SVID for outbound calls
```

Mount the agent socket in your workload Deployment:

```yaml
spec:
  template:
    spec:
      serviceAccountName: my-service  # Must match workload entry selectors
      containers:
        - name: my-service
          env:
            - name: SPIFFE_ENDPOINT_SOCKET
              value: "/run/spire/sockets/agent.sock"
          volumeMounts:
            - name: spire-agent-socket
              mountPath: /run/spire/sockets
              readOnly: true
      volumes:
        - name: spire-agent-socket
          hostPath:
            path: /run/spire/sockets
            type: Directory
```

## Helm Values

| Value | Default | Description |
|---|---|---|
| `tenantId` | **(required)** | Tenant UUID from AuthSec |
| `clusterName` | `production` | Cluster name (multi-cluster setups) |
| `image.repository` | `docker-repo-public.authsec.ai/spire-agent` | Agent image |
| `image.tag` | `latest` | Image tag |
| `logging.level` | `info` | `debug`, `info`, `warning`, `error` |
| `resources.requests.memory` | `256Mi` | Memory request |
| `resources.limits.memory` | `512Mi` | Memory limit |
| `nodeSelector` | `{}` | Target specific nodes |

## How It Works

```
Your App  →  SDK  →  Unix Socket  →  ICP Agent  →  ICP Service (AuthSec Cloud)
                                       (local)       (prod.api.authsec.ai)
```

- Your workloads talk to the agent via a **local Unix socket** — no network calls from your code
- The agent handles node attestation, workload attestation, cert issuance, and rotation
- Certificates auto-renew — no restarts needed
- Only outbound HTTPS to `prod.api.authsec.ai:443` — no inbound ports required

## Network Requirements

| Source | Destination | Port | Purpose |
|---|---|---|---|
| ICP Agent | `prod.api.authsec.ai` | 443/HTTPS | Attestation, SVID issuance |
| ICP Agent | Kubernetes API | 443/HTTPS | TokenReview, pod metadata |

## Documentation

- [Full Integration Guide](docs/INTEGRATION_GUIDE.md) — step-by-step with examples, troubleshooting, FAQ
- [AuthSec SDK](https://github.com/authsec-ai/sdk-authsec) — Python SDK for workload identity

## Support

For integration help, contact the AuthSec team and include agent logs:

```bash
kubectl logs -n spire -l app=icp-agent --tail=100
```
