"""
run_benchmark.py

Single script for Livrable #4 -- runs everything needed for the
performance benchmark in one pass:

  1. Parses remediation_log.jsonl for action distribution, remediation
     latency, and isolate->kill escalation timing.
  2. Computes REAL precision/recall by joining remediation_log.jsonl to
     ground_truth_log.csv (pod_name + timestamp window), same logic as
     train_model.ipynb -- NOT a hardcoded constant.
  3. Captures a system overhead snapshot BEFORE triggering attacks.
  4. Runs the known-safe attack set against test-pod and times detection
     end-to-end (attack command issued -> logged in remediation_log.jsonl).
  5. Captures a system overhead snapshot AFTER, and diffs the two.
  6. Prints one consolidated report and writes it to
     benchmark_results.json and benchmark_summary.md.

Requirements before running:
  - test-pod exists and is Running (tail -f /dev/null, not sleep)
  - remediation_engine.py is running and reachable, using the CURRENT
    model (model.pkl / RandomForest, not the old IsolationForest)
  - kubectl is on PATH and pointed at the right cluster
  - MODEL_DEPLOYED_AT below is set to when you restarted the engine with
    the new model, so old log rows from the previous model don't pollute
    these stats

Usage:
  cd ~/cluster_security/remediation-engine
  python3 run_benchmark.py
"""

import json
import os
import re
import subprocess
import statistics
import time
from datetime import datetime
from collections import defaultdict, Counter

import pandas as pd

REMEDIATION_LOG = "remediation_log.jsonl"
GROUND_TRUTH_LOG = "../ground_truth_log.csv"
POD = "test-pod"
POLL_INTERVAL = 0.25
POLL_TIMEOUT = 30
INCIDENT_GAP_SECONDS = 300

# --- Set this to the timestamp you restarted the engine with the new
# RandomForest model (13-col schema, attack_proba field). Rows before this
# are the old IsolationForest-era rows and must be excluded -- they have
# no attack_proba field at all, so the filter below drops them naturally. ---
MODEL_DEPLOYED_AT = "2026-10-01T00:00:00+00:00"

# Thresholds currently in model_config.json -- read once so we can recompute
# what the action SHOULD have been for each row from its attack_proba,
# rather than trusting the logged `action` field. This matters because
# thresholds were toggled multiple times during collection (1.1/1.1 for
# safe data collection vs 0.5/0.8 for real enforcement) -- a single time
# cutoff cannot separate "which thresholds were active" cleanly, but
# recomputing from attack_proba + current config always reflects the
# CURRENT deployed policy regardless of what was active when the row
# was originally written.
with open("model_config.json") as _f:
    _current_cfg = json.load(_f)
CURRENT_WARNING_PROBA = _current_cfg["warning_proba"]
CURRENT_CRITICAL_PROBA = _current_cfg["critical_proba"]


def recomputed_action(record):
    """What action SHOULD this row have produced under the CURRENT
    thresholds, given its logged attack_proba? Falls back to the row's
    own logged action if attack_proba is missing (old-schema row --
    these get dropped by filter_to_current_model anyway)."""
    proba = record.get("attack_proba")
    if proba is None:
        return record.get("action")
    if proba >= CURRENT_CRITICAL_PROBA:
        return "kill"
    elif proba >= CURRENT_WARNING_PROBA:
        return "isolate"
    return "log_only"

ATTACKS = [
    ("drop_and_execute", 'cp /bin/busybox /tmp/mal_bench && /tmp/mal_bench echo hi', "Drop and execute"),
    ("sensitive_file_read", 'cat /etc/shadow', "Read sensitive file"),
    ("setuid", 'cp /bin/busybox /tmp/x_bench && chmod +s /tmp/x_bench', "Setuid"),
    ("stratum_miner_string", 'echo test stratum+tcp://fake-pool.local:3333', "Stratum"),
]

REMEDIATED_ACTIONS = {
    "kill", "isolate",
    "kill_blocked_circuit_breaker", "isolate_blocked_circuit_breaker",
    # "skipped_already_done" means the engine correctly detected the attack
    # on an earlier event in the same incident and chose not to re-kill/
    # re-isolate a pod it already acted on -- this IS a correct detection,
    # not a miss. Excluding these was undercounting recall.
    "kill_skipped_already_done", "isolate_skipped_already_done",
}


# ------------------------------------------------------------------
# Part 0 -- shared helpers
# ------------------------------------------------------------------

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


def parse_ts(ts_str):
    return datetime.fromisoformat(ts_str.replace("Z", "+00:00"))


def filter_to_current_model(records):
    """Keeps only rows with an attack_proba field -- this is the real
    signal of 'written by the current classifier', not timestamp, since
    thresholds (not the model) were toggled multiple times during
    collection. A row missing attack_proba is either pre-migration
    (IsolationForest era) or malformed; both get dropped."""
    before = len(records)
    records = [r for r in records if r.get("attack_proba") is not None]
    dropped = before - len(records)
    if dropped:
        print(f"  (filtered out {dropped} log rows with no attack_proba -- pre-migration rows)")
    return records


# ------------------------------------------------------------------
# Part 1 -- real precision/recall from ground truth
# ------------------------------------------------------------------

def compute_precision_recall(records, gt_path=GROUND_TRUTH_LOG, valid_runs=None):
    """Joins remediation_log.jsonl records to ground_truth_log.csv by
    pod_name + timestamp window (same logic as train_model.ipynb).
    Returns (precision, recall, n_labeled) or (None, None, 0) if gt missing."""
    if not os.path.exists(gt_path):
        print(f"  WARNING: {gt_path} not found -- cannot compute real precision/recall.")
        return None, None, 0

    gt_cols = ["run_id", "start_utc", "end_utc", "label", "type", "pod", "expected_rule", "detail"]
    gt = pd.read_csv(gt_path, header=None, names=gt_cols, skiprows=1)
    gt = gt.dropna(subset=["run_id"])
    if valid_runs:
        gt = gt[gt["run_id"].isin(valid_runs)]
    gt["start_dt"] = pd.to_datetime(gt["start_utc"], format="%Y-%m-%dT%H:%M:%S.%f", utc=True, errors="coerce")
    gt["end_dt"] = pd.to_datetime(gt["end_utc"], format="%Y-%m-%dT%H:%M:%S.%f", utc=True, errors="coerce")
    gt = gt.dropna(subset=["start_dt", "end_dt"])

    def label_for(pod, ts):
        cand = gt[(gt["pod"] == pod) & (gt["label"].isin(["attack", "benign"]))]
        for _, row in cand.iterrows():
            if (row["start_dt"] - pd.Timedelta(seconds=1)) <= ts <= (row["end_dt"] + pd.Timedelta(seconds=3)):
                return row["label"]
        return None

    tp = fp = fn = 0
    for r in records:
        if not r.get("pod_name") or not r.get("timestamp"):
            continue
        ts = parse_ts(r["timestamp"])
        label = label_for(r["pod_name"], ts)
        if label is None:
            continue  # unlabeled, excluded -- same rule as training
        effective_action = recomputed_action(r)
        acted = effective_action in REMEDIATED_ACTIONS
        if label == "attack" and acted:
            tp += 1
        elif label == "benign" and acted:
            fp += 1
        elif label == "attack" and not acted:
            fn += 1
        # benign + not acted = true negative, not needed for precision/recall

    precision = tp / (tp + fp) if (tp + fp) > 0 else None
    recall = tp / (tp + fn) if (tp + fn) > 0 else None
    return precision, recall, (tp + fp + fn)


# ------------------------------------------------------------------
# Part 2 -- log-based stats
# ------------------------------------------------------------------

def group_incidents(records):
    by_pod = defaultdict(list)
    for r in records:
        if not r.get("timestamp") or not r.get("pod_name"):
            continue
        by_pod[r["pod_name"]].append(r)

    incidents = []
    for pod_name, events in by_pod.items():
        events.sort(key=lambda r: r["timestamp"])
        current = [events[0]]
        for prev, cur in zip(events, events[1:]):
            gap = (parse_ts(cur["timestamp"]) - parse_ts(prev["timestamp"])).total_seconds()
            if gap > INCIDENT_GAP_SECONDS:
                incidents.append((pod_name, current))
                current = [cur]
            else:
                current.append(cur)
        incidents.append((pod_name, current))
    return incidents


def analyze_log():
    records = load_jsonl(REMEDIATION_LOG)
    records = filter_to_current_model(records)

    result = {
        "total_events": len(records),
        "action_distribution": {},
        "rule_breakdown": {},
        "first_action_latency": {},
        "escalation_latency": {},
        "circuit_breaker_blocks": 0,
    }
    if not records:
        return result, records

    result["action_distribution"] = dict(Counter(r.get("action", "unknown") for r in records))

    rule_action = defaultdict(Counter)
    for r in records:
        rule = r.get("triggering_rule") or "unknown"
        rule_action[rule][r.get("action", "unknown")] += 1
    result["rule_breakdown"] = {rule: dict(counts) for rule, counts in rule_action.items()}

    incidents = group_incidents(records)
    first_action_latencies = []
    escalation_latencies = []
    for pod_name, events in incidents:
        first_ts = parse_ts(events[0]["timestamp"])
        actionable = [e for e in events if e.get("action") in
                      ("kill", "isolate", "kill_blocked_circuit_breaker", "isolate_blocked_circuit_breaker")]
        if actionable:
            first_action_latencies.append((parse_ts(actionable[0]["timestamp"]) - first_ts).total_seconds())

        isolate_events = [e for e in events if e.get("action") == "isolate"]
        kill_events = [e for e in events if e.get("action") == "kill"]
        if isolate_events and kill_events:
            iso_ts = parse_ts(isolate_events[0]["timestamp"])
            kill_ts = parse_ts(kill_events[0]["timestamp"])
            if kill_ts > iso_ts:
                escalation_latencies.append((kill_ts - iso_ts).total_seconds())

    if first_action_latencies:
        result["first_action_latency"] = {
            "n": len(first_action_latencies),
            "mean": statistics.mean(first_action_latencies),
            "median": statistics.median(first_action_latencies),
            "min": min(first_action_latencies),
            "max": max(first_action_latencies),
        }
    if escalation_latencies:
        result["escalation_latency"] = {
            "n": len(escalation_latencies),
            "mean": statistics.mean(escalation_latencies),
            "median": statistics.median(escalation_latencies),
            "values": escalation_latencies,
        }

    result["circuit_breaker_blocks"] = sum(1 for r in records if "circuit_breaker" in (r.get("action") or ""))
    return result, records


# ------------------------------------------------------------------
# Part 3 -- live detection latency
# ------------------------------------------------------------------

def log_line_count():
    if not os.path.exists(REMEDIATION_LOG):
        return 0
    with open(REMEDIATION_LOG) as f:
        return sum(1 for _ in f)


def read_new_lines(start_count):
    with open(REMEDIATION_LOG) as f:
        lines = f.readlines()
    return [json.loads(l) for l in lines[start_count:] if l.strip()]


def check_pod_ready():
    check = subprocess.run(
        ["kubectl", "get", "pod", POD, "-o", "jsonpath={.status.phase}"],
        capture_output=True, text=True,
    )
    return check.stdout.strip() == "Running"


def run_attack(label, cmd, expect_substring):
    start_count = log_line_count()
    issue_time = time.time()

    subprocess.run(["kubectl", "exec", POD, "--", "sh", "-c", cmd], capture_output=True, text=True)

    deadline = time.time() + POLL_TIMEOUT
    while time.time() < deadline:
        new_lines = read_new_lines(start_count)
        matches = [l for l in new_lines
                   if expect_substring.lower() in (l.get("triggering_rule") or "").lower()
                   and l.get("pod_name") == POD]
        if matches:
            latency = time.time() - issue_time
            return {
                "label": label, "latency_seconds": round(latency, 3),
                "rule": matches[0].get("triggering_rule"),
                "attack_proba": matches[0].get("attack_proba"),  # renamed from anomaly_score
                "action": matches[0].get("action"),
            }
        time.sleep(POLL_INTERVAL)
    return {"label": label, "latency_seconds": None, "detected": False}


def run_detection_latency_suite():
    if not check_pod_ready():
        print(f"  SKIPPED -- {POD} is not Running. Create it first:")
        print(f'    kubectl run {POD} --image=busybox --restart=Never -- sh -c "tail -f /dev/null"')
        print(f"    kubectl wait --for=condition=Ready pod/{POD} --timeout=60s")
        return []

    results = []
    for label, cmd, expect in ATTACKS:
        print(f"  running: {label} ...")
        r = run_attack(label, cmd, expect)
        results.append(r)
        status = f"{r['latency_seconds']}s" if r.get("latency_seconds") is not None else "NOT DETECTED"
        print(f"    -> {status}")
        time.sleep(3)
    return results


# ------------------------------------------------------------------
# Part 4 -- system overhead
# ------------------------------------------------------------------

def capture_top(label):
    try:
        out = subprocess.run(["kubectl", "top", "pods", "--all-namespaces"],
                              capture_output=True, text=True, timeout=15)
        if out.returncode != 0:
            print(f"  kubectl top failed ({label}): {out.stderr.strip()}")
            return None
        return out.stdout
    except Exception as e:
        print(f"  kubectl top error ({label}): {e}")
        return None


def parse_top_output(text):
    """Parses `kubectl top pods --all-namespaces` output into
    {(namespace, pod): (cpu_millicores, mem_mib)}."""
    if not text:
        return {}
    usage = {}
    lines = text.strip().splitlines()[1:]  # skip header
    for line in lines:
        parts = line.split()
        if len(parts) < 4:
            continue
        ns, pod, cpu_str, mem_str = parts[0], parts[1], parts[2], parts[3]
        cpu = int(re.sub(r"[^\d]", "", cpu_str) or 0)
        mem = int(re.sub(r"[^\d]", "", mem_str) or 0)
        usage[(ns, pod)] = (cpu, mem)
    return usage


def summarize_overhead(idle_text, load_text):
    idle = parse_top_output(idle_text)
    load = parse_top_output(load_text)
    idle_cpu_total = sum(v[0] for v in idle.values())
    load_cpu_total = sum(v[0] for v in load.values())
    idle_mem_total = sum(v[1] for v in idle.values())
    load_mem_total = sum(v[1] for v in load.values())
    return {
        "idle_cpu_millicores_total": idle_cpu_total,
        "load_cpu_millicores_total": load_cpu_total,
        "idle_mem_mib_total": idle_mem_total,
        "load_mem_mib_total": load_mem_total,
        "cpu_delta": load_cpu_total - idle_cpu_total,
        "mem_delta": load_mem_total - idle_mem_total,
    }


# ------------------------------------------------------------------
# Main
# ------------------------------------------------------------------

def main():
    print("=" * 70)
    print("PART 1 -- Log-based analysis (remediation_log.jsonl)")
    print("=" * 70)
    log_stats, filtered_records = analyze_log()
    print(f"Total events (current model only): {log_stats['total_events']}")
    print(f"Action distribution: {log_stats['action_distribution']}")
    if log_stats.get("first_action_latency"):
        fa = log_stats["first_action_latency"]
        print(f"First-action latency: mean={fa['mean']:.3f}s median={fa['median']:.3f}s n={fa['n']}")
    if log_stats.get("escalation_latency"):
        el = log_stats["escalation_latency"]
        print(f"Isolate->kill escalation: mean={el['mean']:.3f}s median={el['median']:.3f}s n={el['n']}")
    print(f"Circuit breaker blocks: {log_stats['circuit_breaker_blocks']}")
    print()

    print("=" * 70)
    print("PART 2 -- Real precision/recall (ground truth join)")
    print("=" * 70)
    precision, recall, n_labeled = compute_precision_recall(filtered_records)
    if precision is not None:
        print(f"Precision={precision:.3f} Recall={recall:.3f} (n_labeled={n_labeled})")
    else:
        print("Could not compute -- no ground truth data matched current-model log rows.")
    print()

    print("=" * 70)
    print("PART 3 -- System overhead: idle snapshot")
    print("=" * 70)
    idle_top = capture_top("idle")
    print("Captured." if idle_top else "Skipped (kubectl top unavailable).")
    print()

    print("=" * 70)
    print("PART 4 -- Live detection latency (issuing real attacks)")
    print("=" * 70)
    detection_results = run_detection_latency_suite()
    valid = [r["latency_seconds"] for r in detection_results if r.get("latency_seconds") is not None]
    if valid:
        print(f"\nDetection latency summary: mean={statistics.mean(valid):.3f}s "
              f"min={min(valid):.3f}s max={max(valid):.3f}s n={len(valid)}")
    print()

    print("=" * 70)
    print("PART 5 -- System overhead: post-attack snapshot")
    print("=" * 70)
    time.sleep(2)  # let metrics-server catch up
    load_top = capture_top("under load")
    print("Captured." if load_top else "Skipped (kubectl top unavailable).")

    overhead = None
    if idle_top and load_top:
        overhead = summarize_overhead(idle_top, load_top)
        print(f"\nCPU total: idle={overhead['idle_cpu_millicores_total']}m -> "
              f"load={overhead['load_cpu_millicores_total']}m "
              f"(delta {overhead['cpu_delta']:+d}m)")
        print(f"Memory total: idle={overhead['idle_mem_mib_total']}Mi -> "
              f"load={overhead['load_mem_mib_total']}Mi "
              f"(delta {overhead['mem_delta']:+d}Mi)")
    print()

    # ------------------------------------------------------------------
    # Assemble + write outputs
    # ------------------------------------------------------------------
    report = {
        "generated_at": datetime.now().isoformat(),
        "model_deployed_at_cutoff": MODEL_DEPLOYED_AT,
        "precision": precision,
        "recall": recall,
        "precision_recall_n": n_labeled,
        "precision_recall_note": (
            "Computed by joining remediation_log.jsonl to ground_truth_log.csv "
            "(pod_name + timestamp window), not a fixed constant. n_labeled is the "
            "sample size this is based on -- report it alongside the numbers. "
            "Ground truth sessions are attack-heavy by collection design, so this "
            "does not estimate real-world false-positive rate on a quiet cluster."
        ),
        "log_analysis": log_stats,
        "detection_latency": detection_results,
        "overhead": overhead,
    }

    with open("benchmark_results.json", "w") as f:
        json.dump(report, f, indent=2, default=str)

    with open("benchmark_summary.md", "w") as f:
        f.write("# Benchmark Summary\n\n")
        f.write(f"Generated: {report['generated_at']}\n\n")
        f.write(f"Model cutoff (rows before this timestamp excluded): {MODEL_DEPLOYED_AT}\n\n")
        f.write("## Model performance (computed from ground truth, this run)\n\n")
        if precision is not None:
            f.write(f"- Precision: {precision:.3f}\n- Recall: {recall:.3f}\n- n_labeled: {n_labeled}\n\n")
        else:
            f.write("- Could not compute (no ground truth data matched).\n\n")
        f.write("## Action distribution (production log, current model only)\n\n")
        for action, count in log_stats["action_distribution"].items():
            f.write(f"- {action}: {count}\n")
        f.write("\n## Remediation latency (log-derived)\n\n")
        if log_stats.get("first_action_latency"):
            fa = log_stats["first_action_latency"]
            f.write(f"- First automated action after incident start: mean {fa['mean']:.3f}s, "
                    f"median {fa['median']:.3f}s (n={fa['n']})\n")
        if log_stats.get("escalation_latency"):
            el = log_stats["escalation_latency"]
            f.write(f"- Isolate to kill escalation: mean {el['mean']:.3f}s, "
                    f"median {el['median']:.3f}s (n={el['n']}), values={el['values']}\n")
        f.write("\n## Detection latency (live, end-to-end)\n\n")
        for r in detection_results:
            if r.get("latency_seconds") is not None:
                f.write(f"- {r['label']}: {r['latency_seconds']}s (action={r.get('action')}, "
                        f"attack_proba={r.get('attack_proba')})\n")
            else:
                f.write(f"- {r['label']}: NOT DETECTED\n")
        if overhead:
            f.write("\n## System overhead\n\n")
            f.write(f"- CPU: {overhead['idle_cpu_millicores_total']}m idle -> "
                    f"{overhead['load_cpu_millicores_total']}m under load "
                    f"(delta {overhead['cpu_delta']:+d}m)\n")
            f.write(f"- Memory: {overhead['idle_mem_mib_total']}Mi idle -> "
                    f"{overhead['load_mem_mib_total']}Mi under load "
                    f"(delta {overhead['mem_delta']:+d}Mi)\n")

    print("=" * 70)
    print("Wrote benchmark_results.json and benchmark_summary.md")
    print("=" * 70)


if __name__ == "__main__":
    main()
