"""
resource_monitor.py

Detects DoS / resource-exhaustion attacks that Falco's syscall-based
detection cannot see (confirmed empirically: Falco stays silent during
CPU/memory exhaustion attacks, even with incubating+sandbox rules enabled).

Approach: poll the Kubernetes metrics API periodically, maintain a rolling
per-pod baseline (mean + std dev), and flag anomalies using a z-score
threshold. This catches both sudden spikes AND gradual resource creep,
which a fixed static threshold would miss.

Output format deliberately mirrors Falco's alert JSON structure
(rule / priority / output_fields with k8s.pod.name etc.) so it can be
concatenated with falco_alerts.jsonl and processed by the exact same
cleaning + windowing pipeline in the feature engineering notebook.

Guardrails added after an initial run flooded alerts on nearly every pod
in the cluster, including control-plane components:
  1. EXCLUDED_NAMESPACES -- never baseline/alert on cluster infrastructure,
     same convention as remediation_engine.py.
  2. MIN_CPU_STD / MIN_MEM_STD -- a floor on the standard deviation used
     in the z-score denominator. Steady-state pods have near-zero natural
     variance, so trivial noise (a few KB of memory churn) divided by a
     near-zero std produced z-scores in the hundreds (observed: z=215 for
     a 1% memory move). The floor prevents that amplification.
  3. CONFIRM_BREACHES -- require N consecutive breaching samples before
     alerting, so a single noisy poll can't trigger an alert on its own.
"""

from kubernetes import client, config
import time
import json
import statistics
from datetime import datetime, timezone
from collections import defaultdict, deque

LOG_FILE = "resource_alerts.jsonl"
POLL_INTERVAL = 10          # seconds between polls
BASELINE_WINDOW = 12        # number of samples used to compute rolling baseline (~2 min at 10s interval)
Z_SCORE_WARNING = 2.5       # standard deviations above baseline -> Warning
Z_SCORE_CRITICAL = 4.0      # standard deviations above baseline -> Critical
MIN_SAMPLES_BEFORE_ALERTING = 6   # don't alert until we have a real baseline
MIN_CPU_STD = 5.0           # millicores -- floor so trivial CPU noise can't fake a huge z-score
MIN_MEM_STD = 5.0           # MiB -- same floor for memory
CONFIRM_BREACHES = 2        # consecutive breaching samples required before alerting

EXCLUDED_NAMESPACES = {
    "kube-system", "kube-public", "kube-node-lease",
    "falco", "falco-ui", "monitoring", "local-path-storage",
}

config.load_kube_config()
custom_api = client.CustomObjectsApi()

# rolling history per (namespace, pod_name) -> deque of (cpu_millicores, memory_mib)
history = defaultdict(lambda: deque(maxlen=BASELINE_WINDOW))

# consecutive-breach counters per (namespace, pod_name), reset to 0 whenever
# a poll does NOT breach the z-score threshold
consecutive_breaches = defaultdict(int)


def parse_cpu(cpu_str):
    if cpu_str.endswith("n"):
        return int(cpu_str[:-1]) / 1_000_000
    if cpu_str.endswith("u"):
        return int(cpu_str[:-1]) / 1_000
    if cpu_str.endswith("m"):
        return int(cpu_str[:-1])
    return float(cpu_str) * 1000


def parse_memory(mem_str):
    if mem_str.endswith("Ki"):
        return int(mem_str[:-2]) / 1024
    if mem_str.endswith("Mi"):
        return int(mem_str[:-2])
    if mem_str.endswith("Gi"):
        return int(mem_str[:-2]) * 1024
    return int(mem_str) / (1024 * 1024)


def get_pod_metrics():
    try:
        metrics = custom_api.list_cluster_custom_object(
            group="metrics.k8s.io", version="v1beta1", plural="pods"
        )
        return metrics.get("items", [])
    except Exception as e:
        print(f"[monitor] Error fetching metrics: {e}")
        return []


def make_falco_style_event(rule, priority, pod_name, namespace, output_msg, extra_fields=None):
    """Builds an event dict shaped like a Falco alert so it merges with falco_alerts.jsonl."""
    now = datetime.now(timezone.utc).isoformat()
    fields = {
        "k8s.pod.name": pod_name,
        "k8s.ns.name": namespace,
        "container.id": None,
        "proc.name": None,
    }
    if extra_fields:
        fields.update(extra_fields)

    return {
        "uuid": f"resmon-{pod_name}-{int(time.time()*1000)}",
        "output": output_msg,
        "priority": priority,
        "rule": rule,
        "time": now,
        "output_fields": fields,
        "source": "resource_monitor",
        "tags": ["resource_exhaustion", "dos", "synthetic"],
        "hostname": "resource-monitor",
    }


def check_anomaly(pod_key, cpu, mem):
    samples = history[pod_key]
    if len(samples) < MIN_SAMPLES_BEFORE_ALERTING:
        return None  # not enough baseline yet

    cpu_values = [s[0] for s in samples]
    mem_values = [s[1] for s in samples]

    cpu_mean = statistics.mean(cpu_values)
    cpu_std = max(statistics.pstdev(cpu_values), MIN_CPU_STD)
    mem_mean = statistics.mean(mem_values)
    mem_std = max(statistics.pstdev(mem_values), MIN_MEM_STD)

    cpu_z = (cpu - cpu_mean) / cpu_std
    mem_z = (mem - mem_mean) / mem_std

    max_z = max(cpu_z, mem_z)
    metric = "CPU" if cpu_z >= mem_z else "Memory"
    value = cpu if metric == "CPU" else mem
    baseline = cpu_mean if metric == "CPU" else mem_mean

    if max_z >= Z_SCORE_CRITICAL:
        return ("Critical", metric, value, baseline, max_z)
    elif max_z >= Z_SCORE_WARNING:
        return ("Warning", metric, value, baseline, max_z)
    return None


def main():
    print(f"Starting resource-based DoS monitor (poll every {POLL_INTERVAL}s)...")
    print(f"Baseline window: {BASELINE_WINDOW} samples | "
          f"Warning z>={Z_SCORE_WARNING} | Critical z>={Z_SCORE_CRITICAL} | "
          f"confirm={CONFIRM_BREACHES} consecutive samples")

    while True:
        pods = get_pod_metrics()
        for pod in pods:
            pod_name = pod["metadata"]["name"]
            namespace = pod["metadata"]["namespace"]

            if namespace in EXCLUDED_NAMESPACES:
                continue

            pod_key = (namespace, pod_name)

            total_cpu = 0
            total_mem = 0
            for container in pod.get("containers", []):
                total_cpu += parse_cpu(container["usage"]["cpu"])
                total_mem += parse_memory(container["usage"]["memory"])

            result = check_anomaly(pod_key, total_cpu, total_mem)

            if result:
                consecutive_breaches[pod_key] += 1
            else:
                consecutive_breaches[pod_key] = 0

            if result and consecutive_breaches[pod_key] >= CONFIRM_BREACHES:
                priority, metric, value, baseline, z = result
                msg = (f"Resource anomaly detected | pod={pod_name} namespace={namespace} "
                       f"metric={metric} current={value:.1f} baseline={baseline:.1f} z_score={z:.2f} "
                       f"(confirmed over {consecutive_breaches[pod_key]} consecutive samples)")

                event = make_falco_style_event(
                    rule=f"Abnormal {metric} usage (resource exhaustion)",
                    priority=priority,
                    pod_name=pod_name,
                    namespace=namespace,
                    output_msg=msg,
                    extra_fields={
                        "resmon.metric": metric,
                        "resmon.value": round(value, 2),
                        "resmon.baseline": round(baseline, 2),
                        "resmon.z_score": round(z, 2),
                        "resmon.confirmed_samples": consecutive_breaches[pod_key],
                    },
                )

                with open(LOG_FILE, "a") as f:
                    f.write(json.dumps(event) + "\n")

                print(f"[{datetime.now().strftime('%H:%M:%S')}] {priority} | {pod_name} | "
                      f"{metric}={value:.1f} (baseline {baseline:.1f}, z={z:.2f}, "
                      f"confirmed x{consecutive_breaches[pod_key]})")

            # update rolling history AFTER checking, so the anomalous sample
            # doesn't immediately get absorbed into its own baseline
            history[pod_key].append((total_cpu, total_mem))

        time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    main()
