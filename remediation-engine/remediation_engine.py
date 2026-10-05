"""
remediation_engine.py

The autonomous remediation engine for the project.

Flow:
  1. Receives Falco alerts via webhook (same pattern as webhook-receiver/app.py)
  2. Buffers recent events per pod in a rolling time window (matches the
     120-second window used during model training)
  3. On each new event, recomputes that pod's current-window features
     using the SAME features.py module the training notebook imports --
     this is what prevents train/serve schema skew.
  4. Scores the window with the trained Isolation Forest model
  5. Applies tiered decision logic:
       score above WARNING_THRESHOLD  -> log only
       score below WARNING_THRESHOLD  -> isolate (CiliumNetworkPolicy)
       score below CRITICAL_THRESHOLD -> kill the pod
  6. Executes the action via the Kubernetes API
  7. Logs every decision (event -> score -> action) to remediation_log.jsonl
     for the benchmark deliverable

Run:
  source venv/bin/activate
  python3 remediation_engine.py
"""

from flask import Flask, request
import json
import time
from datetime import datetime, timezone
from collections import defaultdict, deque
import warnings
from sklearn.exceptions import DataConversionWarning
warnings.filterwarnings("ignore", message="X has feature names")

import joblib
import numpy as np
import pandas as pd
from kubernetes import client, config

# ---------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------

from features import extract_features, prune_window, FEATURE_COLUMNS

WINDOW_SECONDS = 120          # must match the window size used in training
REMEDIATION_LOG = "remediation_log.jsonl"

# Thresholds now loaded from model_config.json (written by train_model.ipynb),
# since the model is a supervised classifier (predict_proba, range 0-1) --
# NOT an IsolationForest decision_function (unbounded score) anymore.
with open("model_config.json") as f:
    _cfg = json.load(f)
WARNING_PROBA = _cfg["warning_proba"]     # proba >= this -> isolate
CRITICAL_PROBA = _cfg["critical_proba"]   # proba >= this -> kill
assert _cfg["feature_columns"] == FEATURE_COLUMNS, \
    "model_config.json feature order does not match features.py -- retrain or fix schema"

# Namespaces that host cluster infrastructure / our own security tooling.
# These are NEVER remediated automatically, regardless of score -- isolating
# or killing Cilium, CoreDNS, Falco itself, or the monitoring stack would
# destabilize the cluster. This is standard practice for any real autonomous
# remediation system: infrastructure/control-plane namespaces are excluded
# by policy, not left to the model's judgment.
EXCLUDED_NAMESPACES = {
    "kube-system", "kube-public", "kube-node-lease",
    "falco", "falco-ui", "monitoring", "local-path-storage",
}

# Priorities below this are not counted toward the anomaly score at all.
# "Informational" and "Debug" events (e.g. routine pod-creation noise like
# "Launch Sensitive Mount Container") fire on essentially every pod and
# caused false-positive cluster-wide isolation when included -- see
# incident log. Only Notice and above contribute to detection.
MIN_SCORABLE_PRIORITY = {"Notice", "Warning", "Error", "Critical"}

# --- Circuit breaker -----------------------------------------------------
# Deployment/ReplicaSet-managed pods get a NEW pod name every time they are
# killed and respawned. Without tracking this, a Deployment whose normal
# startup behavior scores as anomalous triggers an infinite kill->respawn
# loop (observed empirically: metadata-db and build-code-deployment were
# killed and respawned repeatedly within seconds). The circuit breaker
# tracks actions per WORKLOAD (pod name with the trailing random suffix
# stripped) rather than per exact pod name, and halts further automatic
# action on that workload once a threshold is exceeded within a time window.
import re

CIRCUIT_BREAKER_MAX_ACTIONS = 2        # max kill/isolate actions per workload...
CIRCUIT_BREAKER_WINDOW_SECONDS = 300   # ...within this many seconds
CIRCUIT_BREAKER_COOLDOWN_SECONDS = 10  # after tripping, auto-recover after this long
                                        # NOTE: set short for active development/testing.
                                        # Recommend raising back to 60-120s+ before final
                                        # demo/benchmark -- a short cooldown weakens
                                        # protection against a genuine sustained
                                        # kill-respawn loop (it would still occur, just
                                        # throttled to once per cooldown window rather
                                        # than fully prevented).
workload_action_history = defaultdict(deque)  # workload_key -> deque of timestamps
tripped_breakers = {}  # workload_key -> time.time() when it tripped


def get_workload_name(pod_name):
    """Strips Kubernetes-generated suffixes to identify the underlying
    Deployment/ReplicaSet/Job, e.g. 'metadata-db-5748699756-k7856' ->
    'metadata-db'. Falls back to the raw pod name if no pattern matches
    (e.g. manually created pods like test-pod)."""
    m = re.match(r"^(.*)-[a-f0-9]{8,10}-[a-z0-9]{5}$", pod_name)
    if m:
        return m.group(1)
    m = re.match(r"^(.*)-[a-z0-9]{5}$", pod_name)
    if m:
        return m.group(1)
    return pod_name


def circuit_breaker_check(workload_key):
    """Returns True if it's safe to act, False if the breaker is tripped.

    Cooldown-based auto-recovery ("half-open" state, as in Hystrix/Polly):
    once tripped, blocks automatic action for CIRCUIT_BREAKER_COOLDOWN_SECONDS,
    then allows one action through to test whether the issue resolved.
    Manual reset via /breakers/reset remains available for immediate recovery.
    """
    if workload_key in tripped_breakers:
        tripped_at = tripped_breakers[workload_key]
        if (time.time() - tripped_at) < CIRCUIT_BREAKER_COOLDOWN_SECONDS:
            return False
        print(f"  -> Circuit breaker for '{workload_key}' auto-recovered after "
              f"{CIRCUIT_BREAKER_COOLDOWN_SECONDS}s cooldown.")
        del tripped_breakers[workload_key]
        workload_action_history[workload_key].clear()

    now = time.time()
    history = workload_action_history[workload_key]
    while history and (now - history[0]) > CIRCUIT_BREAKER_WINDOW_SECONDS:
        history.popleft()

    if len(history) >= CIRCUIT_BREAKER_MAX_ACTIONS:
        tripped_breakers[workload_key] = time.time()
        print(f"  !! CIRCUIT BREAKER TRIPPED for workload '{workload_key}' -- "
              f"{len(history)} actions in {CIRCUIT_BREAKER_WINDOW_SECONDS}s. "
              f"Auto-recovers in {CIRCUIT_BREAKER_COOLDOWN_SECONDS}s, or reset manually.")
        return False

    return True


def circuit_breaker_record(workload_key):
    workload_action_history[workload_key].append(time.time())


# ---------------------------------------------------------------------
# Load model + scaler
# ---------------------------------------------------------------------

print("Loading trained model and scaler...")
model = joblib.load("model.pkl")          
scaler = joblib.load("feature_scaler.pkl")
print(f"Model loaded successfully ({_cfg['model_type']}).")

# ---------------------------------------------------------------------
# Load Kubernetes client
# ---------------------------------------------------------------------

try:
    config.load_incluster_config()
    print("Loaded in-cluster Kubernetes config.")
except Exception:
    config.load_kube_config()
    print("Loaded local kubeconfig.")

core_v1 = client.CoreV1Api()
custom_api = client.CustomObjectsApi()
networking_v1 = client.NetworkingV1Api()


event_buffers = defaultdict(deque)


already_isolated = set()
already_killed = set()

app = Flask(__name__)


def get_pod_age_seconds(pod_name, namespace):
    try:
        pod = core_v1.read_namespaced_pod(pod_name, namespace)
        start = pod.status.start_time
        if start is None:
            return 0
        return (datetime.now(timezone.utc) - start).total_seconds()
    except Exception:
        return 0


def score_window(features_dict):
    """Runs the feature row through the scaler + classifier.
    Returns attack_proba in [0,1] (was an unbounded IsolationForest score before)."""
    X = pd.DataFrame([[features_dict[col] for col in FEATURE_COLUMNS]], columns=FEATURE_COLUMNS)
    X_scaled = scaler.transform(X)
    proba = model.predict_proba(X_scaled)[0][1]  # P(class == attack)
    return proba


def log_remediation_action(pod_name, namespace, proba, action, features_dict, alert):
    record = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "pod_name": pod_name,
        "namespace": namespace,
        "attack_proba": round(float(proba), 4),
        "action": action,
        "features": features_dict,
        "triggering_rule": alert.get("rule"),
        "triggering_priority": alert.get("priority"),
        "mitre_tags": alert.get("tags", []),
    }
    with open(REMEDIATION_LOG, "a") as f:
        f.write(json.dumps(record) + "\n")
    print(f"[{record['timestamp']}] {pod_name} | attack_proba={proba:.4f} | action={action}")


def isolate_pod(pod_name, namespace):
    """Applies a CiliumNetworkPolicy denying all ingress/egress for the
    targeted pod. Enforced directly by Cilium's eBPF dataplane."""
    policy_name = f"quarantine-{pod_name}"[:63]
    body = {
        "apiVersion": "cilium.io/v2",
        "kind": "CiliumNetworkPolicy",
        "metadata": {"name": policy_name, "namespace": namespace},
        "spec": {
            "endpointSelector": {"matchLabels": {"run": pod_name}},
            "ingress": [{}],
            "egress": [{}],
        },
    }
    try:
        custom_api.create_namespaced_custom_object(
            group="cilium.io", version="v2", namespace=namespace,
            plural="ciliumnetworkpolicies", body=body,
        )
        print(f"  -> CiliumNetworkPolicy '{policy_name}' applied. Pod isolated (eBPF-enforced).")
        return True
    except client.exceptions.ApiException as e:
        if e.status == 409:
            print(f"  -> CiliumNetworkPolicy '{policy_name}' already exists. Skipping.")
            return True
        print(f"  -> ERROR applying CiliumNetworkPolicy: {e}")
        return False


def kill_pod(pod_name, namespace):
    """Deletes the pod entirely, and cleans up any quarantine policy
    left behind from a prior isolate action on the same pod."""
    policy_name = f"quarantine-{pod_name}"[:63]
    try:
        custom_api.delete_namespaced_custom_object(
            group="cilium.io", version="v2", namespace=namespace,
            plural="ciliumnetworkpolicies", name=policy_name,
        )
        print(f"  -> Cleaned up orphaned CiliumNetworkPolicy '{policy_name}'.")
    except client.exceptions.ApiException:
        pass

    try:
        core_v1.delete_namespaced_pod(name=pod_name, namespace=namespace)
        print(f"  -> Pod '{pod_name}' deleted.")
        return True
    except client.exceptions.ApiException as e:
        if e.status == 404:
            print(f"  -> Pod '{pod_name}' already gone.")
            return True
        print(f"  -> ERROR deleting pod: {e}")
        return False


def decide_and_act(pod_name, namespace, container_id, proba, features_dict, alert):
    instance_key = (namespace, pod_name, container_id)
    workload_key = (namespace, get_workload_name(pod_name))

    # NOTE: direction flipped vs the old IsolationForest logic -- proba is
    # P(attack), so HIGHER means worse (opposite of the old decision_function score).
    if proba >= CRITICAL_PROBA:
        if not circuit_breaker_check(workload_key):
            action = "kill_blocked_circuit_breaker"
        elif instance_key not in already_killed:
            action = "kill"
            kill_pod(pod_name, namespace)
            already_killed.add(instance_key)
            circuit_breaker_record(workload_key)
        else:
            action = "kill_skipped_already_done"

    elif proba >= WARNING_PROBA:
        if not circuit_breaker_check(workload_key):
            action = "isolate_blocked_circuit_breaker"
        elif instance_key not in already_isolated:
            action = "isolate"
            isolate_pod(pod_name, namespace)
            already_isolated.add(instance_key)
            circuit_breaker_record(workload_key)
        else:
            action = "isolate_skipped_already_done"

    else:
        action = "log_only"

    log_remediation_action(pod_name, namespace, proba, action, features_dict, alert)
    return action


@app.route("/falco-alerts", methods=["POST"])
def receive_alert():
    alert = request.get_json()

    fields = alert.get("output_fields", {})
    pod_name = fields.get("k8s.pod.name")
    namespace = fields.get("k8s.ns.name") or "default"
    container_id = fields.get("container.id") or "unknown"
    rule = alert.get("rule")
    priority = alert.get("priority")

    if not pod_name:
        return {"status": "skipped_no_pod"}, 200

    if namespace in EXCLUDED_NAMESPACES:
        return {"status": "skipped_excluded_namespace"}, 200

    if priority not in MIN_SCORABLE_PRIORITY:
        return {"status": "skipped_low_priority"}, 200

    pod_key = (namespace, pod_name)
    now = time.time()
    event_buffers[pod_key].append((now, rule, priority))
    event_buffers[pod_key] = deque(prune_window(list(event_buffers[pod_key]), now))

    pod_age = get_pod_age_seconds(pod_name, namespace)
    features = extract_features(list(event_buffers[pod_key]), pod_age_seconds=pod_age)
    proba = score_window(features)  # schema now matches model_config.json -- no bypass needed

    action = decide_and_act(pod_name, namespace, container_id, proba, features, alert)

    return {"status": "processed", "attack_proba": float(proba), "action": action}, 200


@app.route("/breakers", methods=["GET"])
def list_breakers():
    now = time.time()
    result = []
    for (ns, wl), tripped_at in tripped_breakers.items():
        remaining = max(0, CIRCUIT_BREAKER_COOLDOWN_SECONDS - (now - tripped_at))
        result.append({"namespace": ns, "workload": wl, "auto_recovers_in_seconds": round(remaining)})
    return {"tripped": result}, 200


@app.route("/breakers/reset", methods=["POST"])
def reset_breaker():
    data = request.get_json() or {}
    namespace = data.get("namespace")
    workload = data.get("workload")
    key = (namespace, workload)
    if key in tripped_breakers:
        del tripped_breakers[key]
        workload_action_history[key].clear()
        return {"status": f"breaker reset for {namespace}/{workload}"}, 200
    return {"status": "breaker was not tripped"}, 200


if __name__ == "__main__":
    print(f"Remediation engine listening on :5001")
    print(f"Model: {_cfg['model_type']} | Thresholds: WARNING_PROBA={WARNING_PROBA}, CRITICAL_PROBA={CRITICAL_PROBA}")
    app.run(host="0.0.0.0", port=5001)
