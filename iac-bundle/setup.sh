#!/bin/bash
# setup.sh
#
# One-click deployment of the full test environment:
#   1. kind cluster (control-plane + worker)
#   2. Cilium CNI (with Hubble enabled)
#   3. Falco + Falco Sidekick (webhook output -> remediation engine)
#   4. Custom Falco rules (SUID etc.)
#   5. The deliberately vulnerable app (command-injection log viewer)
#   6. RBAC for the remediation engine (least-privilege ServiceAccount)
#
# Requirements: kind, kubectl, helm, docker -- all on PATH.
#
# Usage:
#   bash setup.sh
#
# After this completes, start the remediation engine separately:
#   cd remediation-engine && python3 remediation_engine.py
# (not included here since it runs on the host, not in-cluster, per the
#  current architecture -- Falcosidekick posts to http://172.17.0.1:5001)

set -euo pipefail

CLUSTER_NAME="security-cluster"
KIND_CONFIG="$(dirname "$0")/kind-config.yaml"
VULN_APP_DIR="$(dirname "$0")/vulnerable-app"
K8S_DIR="$(dirname "$0")/k8s"
FALCO_RULES_DIR="$(dirname "$0")/falco-rules"

log() { echo -e "\n=== $1 ===\n"; }

# ---------------------------------------------------------------------
# 1. Cluster
# ---------------------------------------------------------------------
log "Creating kind cluster: $CLUSTER_NAME"
if kind get clusters | grep -qx "$CLUSTER_NAME"; then
    echo "Cluster $CLUSTER_NAME already exists -- skipping creation."
else
    kind create cluster --name "$CLUSTER_NAME" --config "$KIND_CONFIG"
fi
kubectl cluster-info --context "kind-$CLUSTER_NAME"

# ---------------------------------------------------------------------
# 2. Cilium (CNI + Hubble)
# ---------------------------------------------------------------------
log "Installing Cilium"
helm repo add cilium https://helm.cilium.io/ 2>/dev/null || true
helm repo update cilium
helm upgrade --install cilium cilium/cilium \
    --namespace kube-system \
    --set hubble.enabled=true \
    --set hubble.relay.enabled=true \
    --set hubble.ui.enabled=true \
    --wait --timeout 5m

# ---------------------------------------------------------------------
# 3. Falco + Falco Sidekick
# ---------------------------------------------------------------------
log "Installing Falco (+ Sidekick, webhook -> host:5001)"
helm repo add falcosecurity https://falcosecurity.github.io/charts 2>/dev/null || true
helm repo update falcosecurity
kubectl create namespace falco --dry-run=client -o yaml | kubectl apply -f -

helm upgrade --install falco falcosecurity/falco \
    --namespace falco \
    --set falcosidekick.enabled=true \
    --set falcosidekick.config.webhook.address="http://172.17.0.1:5001/falco-alerts" \
    --set tty=true \
    --wait --timeout 5m

# ---------------------------------------------------------------------
# 4. Custom Falco rules
# ---------------------------------------------------------------------
if [ -f "$FALCO_RULES_DIR/custom-rules.yaml" ]; then
    log "Applying custom Falco rules"
    kubectl create configmap falco-custom-rules \
        --namespace falco \
        --from-file="$FALCO_RULES_DIR/custom-rules.yaml" \
        --dry-run=client -o yaml | kubectl apply -f -
    echo "NOTE: mount this ConfigMap into the Falco DaemonSet's rules volume"
    echo "if not already wired via the helm values -- see falco-rules/README.md"
fi

# ---------------------------------------------------------------------
# 5. Vulnerable app
# ---------------------------------------------------------------------
log "Building and loading the vulnerable app image"
docker build -t vulnerable-log-viewer:local "$VULN_APP_DIR"
kind load docker-image vulnerable-log-viewer:local --name "$CLUSTER_NAME"

log "Deploying the vulnerable app"
kubectl apply -f "$K8S_DIR/vulnerable-app.yaml"
kubectl wait --for=condition=Available deployment/vulnerable-log-viewer --timeout=90s

# ---------------------------------------------------------------------
# 6. Remediation engine RBAC
# ---------------------------------------------------------------------
if [ -f "$K8S_DIR/rbac.yaml" ]; then
    log "Applying remediation engine RBAC (least-privilege ServiceAccount)"
    kubectl apply -f "$K8S_DIR/rbac.yaml"
fi

log "Done."
echo "Cluster: kind-$CLUSTER_NAME"
echo "Vulnerable app: kubectl port-forward svc/vulnerable-log-viewer 8080:8080"
echo "  then try:  curl 'http://localhost:8080/search?q=x;%20cat%20/etc/shadow'"
echo "Next: start the remediation engine on the host (python3 remediation_engine.py)"
echo "      and the dashboard, then run generate_dataset_v6.sh for a demo session."
