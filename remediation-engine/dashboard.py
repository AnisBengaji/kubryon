"""
dashboard.py

Real-time monitoring dashboard for the autonomous Kubernetes remediation
system. Flask + Jinja templates (templates/, static/) -- Tailwind CSS,
Alpine.js and Chart.js loaded via CDN (no build step required), D3 for
the cluster topology graph.

Two pages:
  /          -- live incident feed + charts (Falco -> remediation engine -> LLM report)
  /topology  -- dedicated cluster topology view (read-only K8s API + D3)

Reads directly from the JSONL files already produced by
remediation_engine.py and incident_summarizer.py, plus a live
Kubernetes API read for cluster topology.

This is a read-only reporting/visualization layer -- no cluster write
access, no influence on detection or remediation decisions.

Run:
  source venv/bin/activate
  pip install flask kubernetes
  python3 dashboard.py

Then open http://localhost:8080 in a browser.
"""

from flask import Flask, jsonify, render_template
import json
import os
from datetime import datetime, timezone

REMEDIATION_LOG = "remediation_log.jsonl"
SUMMARY_LOG = "incident_reports.jsonl"
RESOURCE_LOG = "resource_alerts.jsonl"  # optional, only used if present

app = Flask(__name__)


def load_jsonl(path):
    if not os.path.exists(path):
        return []
    records = []
    with open(path) as f:
        for line in f:
            if line.strip():
                try:
                    records.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    return records


def record_id(record):
    return f"{record.get('timestamp')}::{record.get('pod_name')}"


def build_incident_view():
    actions = load_jsonl(REMEDIATION_LOG)
    summaries = load_jsonl(SUMMARY_LOG)
    resource_alerts = load_jsonl(RESOURCE_LOG)

    summary_by_id = {s.get("source_id"): s for s in summaries}

    incidents = []
    for record in actions:
        rid = record_id(record)
        summary_entry = summary_by_id.get(rid)
        tags = record.get("mitre_tags", []) or []
        mitre = [t for t in tags if t.startswith("T") and t[1:].split(".")[0].isdigit()]

        incidents.append({
            "id": rid,
            "timestamp": record.get("timestamp"),
            "pod_name": record.get("pod_name"),
            "namespace": record.get("namespace"),
            "anomaly_score": record.get("anomaly_score"),
            "action": record.get("action"),
            "triggering_rule": record.get("triggering_rule"),
            "triggering_priority": record.get("triggering_priority"),
            "mitre_tags": mitre,
            "summary": summary_entry.get("report") if summary_entry else None,
            "verified": summary_entry.get("verified") if summary_entry else None,
            "source": "falco",
        })

    for record in resource_alerts:
        fields = record.get("output_fields", {})
        incidents.append({
            "id": record.get("uuid"),
            "timestamp": record.get("time"),
            "pod_name": fields.get("k8s.pod.name"),
            "namespace": fields.get("k8s.ns.name"),
            "anomaly_score": None,
            "action": "resource_alert",
            "triggering_rule": record.get("rule"),
            "triggering_priority": record.get("priority"),
            "mitre_tags": [],
            "summary": record.get("output"),
            "verified": None,
            "source": "resource_monitor",
        })

    incidents.sort(key=lambda x: x["timestamp"] or "", reverse=True)
    return incidents


@app.route("/api/incidents")
def api_incidents():
    incidents = build_incident_view()
    actionable = [i for i in incidents if i["action"] not in ("log_only", "skipped_not_monitored", "skipped_low_priority", "skipped_excluded_namespace", "skipped_no_pod")]

    rule_counts = {}
    for i in incidents:
        rule = i.get("triggering_rule") or "unknown"
        rule_counts[rule] = rule_counts.get(rule, 0) + 1
    top_rules = sorted(rule_counts.items(), key=lambda kv: -kv[1])[:8]

    stats = {
        "total_events": len(incidents),
        "killed": sum(1 for i in incidents if i["action"] == "kill"),
        "isolated": sum(1 for i in incidents if i["action"] == "isolate"),
        "resource_alerts": sum(1 for i in incidents if i["source"] == "resource_monitor"),
        "circuit_breaker_blocks": sum(1 for i in incidents if "circuit_breaker" in (i["action"] or "")),
        "pods_affected": len(set(i["pod_name"] for i in actionable if i["pod_name"])),
        "top_rules": [{"rule": r, "count": c} for r, c in top_rules],
    }
    return jsonify({"incidents": actionable[:200], "stats": stats, "server_time": datetime.now(timezone.utc).isoformat()})


@app.route("/api/health")
def api_health():
    return jsonify({
        "components": [
            {"name": "Anomaly Detector", "state": "operational"},
            {"name": "Remediation Engine", "state": "operational"},
            {"name": "Circuit Breaker", "state": "armed"},
            {"name": "Incident Summarizer", "state": "operational"},
        ],
        "server_time": datetime.now(timezone.utc).isoformat(),
    })


# ---------------------------------------------------------------------
# Cluster topology (read-only Kubernetes API access)
# ---------------------------------------------------------------------
_k8s_ready = False
try:
    from kubernetes import client as k8s_client, config as k8s_config
    try:
        k8s_config.load_incluster_config()
    except Exception:
        k8s_config.load_kube_config()
    _core_v1 = k8s_client.CoreV1Api()
    _custom_api = k8s_client.CustomObjectsApi()
    _k8s_ready = True
    print("Cluster topology: Kubernetes API access ready.")
except Exception as e:
    print(f"Cluster topology disabled -- could not load Kubernetes config: {e}")


def build_topology():
    if not _k8s_ready:
        return {"nodes": [], "namespaces": [], "available": False}

    isolated_pods = set()
    try:
        policies = _custom_api.list_cluster_custom_object(
            group="cilium.io", version="v2", plural="ciliumnetworkpolicies"
        )
        for item in policies.get("items", []):
            name = item.get("metadata", {}).get("name", "")
            ns = item.get("metadata", {}).get("namespace", "default")
            if name.startswith("quarantine-"):
                pod_name = name[len("quarantine-"):]
                isolated_pods.add((ns, pod_name))
    except Exception as e:
        print(f"Topology: could not list CiliumNetworkPolicies: {e}")

    nodes = []
    try:
        pods = _core_v1.list_pod_for_all_namespaces()
        for pod in pods.items:
            ns = pod.metadata.namespace
            name = pod.metadata.name
            phase = pod.status.phase or "Unknown"
            ip = pod.status.pod_ip or ""
            owner_kind = ""
            if pod.metadata.owner_references:
                owner_kind = pod.metadata.owner_references[0].kind
            nodes.append({
                "id": f"{ns}/{name}",
                "name": name,
                "namespace": ns,
                "ip": ip,
                "phase": phase,
                "owner_kind": owner_kind,
                "isolated": (ns, name) in isolated_pods,
            })
    except Exception as e:
        print(f"Topology: could not list pods: {e}")
        return {"nodes": [], "namespaces": [], "available": False}

    namespaces = sorted(set(n["namespace"] for n in nodes))
    return {"nodes": nodes, "namespaces": namespaces, "available": True}


@app.route("/api/topology")
def api_topology():
    return jsonify(build_topology())


@app.route("/")
def index():
    return render_template("index.html", active_page="overview")


@app.route("/topology")
def topology_page():
    return render_template("topology.html", active_page="topology")


if __name__ == "__main__":
    print("Dashboard running at http://localhost:8080")
    app.run(host="0.0.0.0", port=8080)
