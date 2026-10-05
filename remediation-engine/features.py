"""
features.py

Single source of truth for feature extraction, imported by BOTH:
  - the training notebook (batch, event-anchored windows over historical alerts)
  - remediation_engine.py (live, trailing window per incoming event)

Keeping one copy prevents train/serve skew.
"""

from collections import Counter

WINDOW_SECONDS = 120

# Rule name -> feature flag. Includes both the custom AND stock rule names
# for SUID (the custom rule never fires in practice; the stock one does).
KNOWN_RULES = {
    "Terminal shell in container": "terminal_shell_in_container",
    "Drop and execute new binary in container": "drop_and_execute_new_binary_in",
    "Read sensitive file untrusted": "read_sensitive_file_untrusted",
    "Suspicious SUID bit set": "suspicious_suid_bit_set",
    "Set Setuid or Setgid bit": "suspicious_suid_bit_set",  # same flag, real trigger
    "Contact K8S API Server From Container": "contact_k8s_api_server_from_co",
    "Write below root": "write_below_root",
    "Delete or rename shell history": "delete_or_rename_shell_history",
    "Modify Shell Configuration File": "modify_shell_config",
    "Read ssh information": "read_ssh_information",
    "Launch Ingress Remote File Copy Tools in Container": "remote_file_copy_tools",
    "Launch Package Management Process in Container": "package_mgmt_process",
    "Potential Local Privilege Escalation via Environment Variables Misuse": "env_var_privesc",
}
RULE_FLAG_COLUMNS = sorted(set(KNOWN_RULES.values()))

PRIORITY_WEIGHT = {
    "Critical": 4, "Error": 3, "Warning": 2, "Notice": 1, "Informational": 0, "Debug": 0
}

FEATURE_COLUMNS = [
    "event_count", "critical_count", "distinct_rules",
    "max_priority_weight", "avg_priority_weight",
    "pod_age_seconds",
] + RULE_FLAG_COLUMNS


def extract_features(events, pod_age_seconds=None):
    """
    events: list of (timestamp, rule, priority) tuples already pruned to the
            120s trailing window (caller's responsibility -- both the engine's
            live buffer and the notebook's per-alert lookback must prune the
            same way before calling this).
    pod_age_seconds: seconds since the pod's container started, at the time
            of the triggering event. Pass None if unknown (engine will fall
            back to 0, which is conservative -- treats unknown as "new pod").

    Returns a dict with every key in FEATURE_COLUMNS, always in the same
    order/shape regardless of input, so a DataFrame built from many of
    these dicts is guaranteed schema-consistent between training and serving.
    """
    event_count = len(events)

    row = {col: 0 for col in FEATURE_COLUMNS}
    row["pod_age_seconds"] = pod_age_seconds if pod_age_seconds is not None else 0

    if event_count == 0:
        return row

    priorities = [e[2] for e in events]
    rules = [e[1] for e in events]
    weights = [PRIORITY_WEIGHT.get(p, 0) for p in priorities]
    rule_counts = Counter(rules)

    row["event_count"] = event_count
    row["critical_count"] = sum(1 for p in priorities if p == "Critical")
    row["distinct_rules"] = len(set(rules))
    row["max_priority_weight"] = max(weights)
    row["avg_priority_weight"] = sum(weights) / len(weights)

    for rule_name, flag_col in KNOWN_RULES.items():
        if rule_counts.get(rule_name, 0) > 0:
            row[flag_col] = 1  # presence flag; dedup handled by using a set of rule names

    return row


def prune_window(events, now_ts):
    """events: list of (ts, rule, priority). Returns only those within
    WINDOW_SECONDS of now_ts. Use this identically in both notebook
    (per-alert lookback) and engine (live buffer) to avoid skew."""
    return [e for e in events if (now_ts - e[0]) <= WINDOW_SECONDS]
