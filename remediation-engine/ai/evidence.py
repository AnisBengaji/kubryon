"""
Kubryon Analyst - Behavioral Evidence Layer

Converts raw remediation-engine features into human-readable,
security-oriented evidence.

This module is deterministic.
It does NOT use the LLM and does NOT make security decisions.
"""

FEATURE_DEFINITIONS = {
    # Execution
    "terminal_shell_in_container": {
        "domain": "execution",
        "label": "Container shell activity",
    },
    "drop_and_execute_new_binary_in": {
        "domain": "execution",
        "label": "New binary dropped and executed",
    },
    "rule__drop_and_execute_new_binary_in_container": {
        "domain": "execution",
        "label": "New binary dropped and executed",
    },
    "rule__launch_package_management_process_in_con": {
        "domain": "execution",
        "label": "Package-management process execution",
    },

    # Credential access
    "read_sensitive_file_untrusted": {
        "domain": "credential_access",
        "label": "Sensitive file access",
    },
    "rule__read_sensitive_file_untrusted": {
        "domain": "credential_access",
        "label": "Sensitive file access",
    },
    "rule__read_ssh_information": {
        "domain": "credential_access",
        "label": "SSH information access",
    },

    # Privilege escalation
    "suspicious_suid_bit_set": {
        "domain": "privilege_escalation",
        "label": "Suspicious SUID/SGID activity",
    },
    "rule__set_setuid_or_setgid_bit": {
        "domain": "privilege_escalation",
        "label": "SUID/SGID modification",
    },
    "rule__change_namespace_privileges_via_unshare": {
        "domain": "privilege_escalation",
        "label": "Namespace privilege manipulation",
    },
    "rule__change_thread_namespace": {
        "domain": "privilege_escalation",
        "label": "Thread namespace manipulation",
    },
    "rule__launch_privileged_container": {
        "domain": "privilege_escalation",
        "label": "Privileged container launch",
    },
    "rule__launch_sensitive_mount_container": {
        "domain": "privilege_escalation",
        "label": "Sensitive host mount",
    },

    # Kubernetes
    "contact_k8s_api_server_from_co": {
        "domain": "kubernetes",
        "label": "Kubernetes API access",
    },
    "rule__contact_k8s_api_server_from_container": {
        "domain": "kubernetes",
        "label": "Kubernetes API access",
    },

    # Filesystem / defense evasion
    "rule__write_below_root": {
        "domain": "filesystem",
        "label": "Filesystem write below root",
    },
    "rule__delete_or_rename_shell_history": {
        "domain": "defense_evasion",
        "label": "Shell history deletion or modification",
    },

    # Network
    "rule__launch_ingress_remote_file_copy_tools_in": {
        "domain": "network",
        "label": "Remote file-copy tooling",
    },
    "rule__system_procs_network_activity": {
        "domain": "network",
        "label": "System/network activity",
    },

    # MITRE behavioral dimensions
    "mitre_collection": {
        "domain": "mitre",
        "label": "Collection activity",
    },
    "mitre_command_and_control": {
        "domain": "mitre",
        "label": "Command and Control activity",
    },
    "mitre_credential_access": {
        "domain": "mitre",
        "label": "Credential Access activity",
    },
    "mitre_defense_evasion": {
        "domain": "mitre",
        "label": "Defense Evasion activity",
    },
    "mitre_discovery": {
        "domain": "mitre",
        "label": "Discovery activity",
    },
    "mitre_execution": {
        "domain": "mitre",
        "label": "Execution activity",
    },
    "mitre_persistence": {
        "domain": "mitre",
        "label": "Persistence activity",
    },
    "mitre_privilege_escalation": {
        "domain": "mitre",
        "label": "Privilege Escalation activity",
    },
}


def build_behavioral_evidence(features):
    """
    Convert raw binary security features into normalized evidence.

    Only explicitly mapped behavioral features are interpreted here.
    Statistical features such as event_count and anomaly_score are
    handled separately.
    """

    observed = []
    not_observed = []

    seen_observed_labels = set()
    seen_not_observed_labels = set()

    for feature_name, definition in FEATURE_DEFINITIONS.items():

        value = features.get(feature_name, 0)

        try:
            is_active = float(value) > 0
        except (TypeError, ValueError):
            is_active = False

        label = definition["label"]

        if is_active:
            if label not in seen_observed_labels:
                observed.append({
                    "domain": definition["domain"],
                    "label": label,
                    "feature": feature_name,
                })

                seen_observed_labels.add(label)

        else:
            if (
                label not in seen_observed_labels
                and label not in seen_not_observed_labels
            ):
                not_observed.append({
                    "domain": definition["domain"],
                    "label": label,
                    "feature": feature_name,
                })

                seen_not_observed_labels.add(label)

    return {
        "observed": observed,
        "not_observed": not_observed,
    }


def build_detection_statistics(features):
    """
    Extract statistical detection context without interpreting it.
    """

    return {
        "event_count": features.get("event_count"),
        "critical_count": features.get("critical_count"),
        "error_count": features.get("error_count"),
        "distinct_rules": features.get("distinct_rules"),
        "distinct_mitre_tactics": features.get(
            "distinct_mitre_tactics"
        ),
        "max_priority_weight": features.get(
            "max_priority_weight"
        ),
        "avg_priority_weight": features.get(
            "avg_priority_weight"
        ),
    }


def build_evidence_context(features):
    """
    Return the complete normalized evidence context.
    """

    return {
        "behavioral_evidence": build_behavioral_evidence(
            features
        ),
        "detection_statistics": build_detection_statistics(
            features
        ),
    }
    
def format_evidence_for_llm(evidence_context):
    """
    Convert normalized evidence into a deterministic text representation
    suitable for inclusion in an LLM prompt.
    """

    behavioral = evidence_context["behavioral_evidence"]
    stats = evidence_context["detection_statistics"]

    lines = []

    lines.append("BEHAVIORAL EVIDENCE")
    lines.append("=" * 50)

    # Observed behaviors
    lines.append("")
    lines.append("Observed behaviors:")

    if behavioral["observed"]:
        for item in behavioral["observed"]:
            lines.append(
                f"- {item['label']} "
                f"(domain: {item['domain']}; "
                f"source feature: {item['feature']})"
            )
    else:
        lines.append("- None explicitly observed")

    # Not observed behaviors
    lines.append("")
    lines.append("Not observed in this detection window:")

    if behavioral["not_observed"]:
        for item in behavioral["not_observed"]:
            lines.append(
                f"- {item['label']} "
                f"(domain: {item['domain']})"
            )
    else:
        lines.append("- None available")

    # Detection statistics
    lines.append("")
    lines.append("DETECTION STATISTICS")
    lines.append("=" * 50)

    statistic_labels = {
        "event_count": "Events",
        "critical_count": "Critical events",
        "error_count": "Error events",
        "distinct_rules": "Distinct rules",
        "distinct_mitre_tactics": "Distinct MITRE tactics",
        "max_priority_weight": "Maximum priority weight",
        "avg_priority_weight": "Average priority weight",
    }

    for key, label in statistic_labels.items():
        value = stats.get(key)

        if value is None:
            value_text = "Not available"
        else:
            value_text = str(value)

        lines.append(f"- {label}: {value_text}")

    return "\n".join(lines)
