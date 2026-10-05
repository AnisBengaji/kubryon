"""
knowledge_base.py

Local knowledge base for the incident summarizer's retrieval step.
Three curated corpora, each retrieved by exact key lookup:

  1. FALCO_RULE_DOCS   -- what each Falco rule actually detects and why
  2. MITRE_DOCS        -- ATT&CK technique descriptions for tags seen in this project
  3. REMEDIATION_GUIDE -- internal policy text explaining what each automated
                          action means and what a human should do next

Design note: this corpus is small and well-structured (a bounded set of
known Falco rules and MITRE techniques), so exact key-based retrieval is
used rather than embedding/vector search. This is more precise and fully
deterministic for this use case -- no similarity search is needed when
every possible query (a rule name, a technique ID) has exactly one
correct document. Semantic/vector retrieval would be a reasonable
extension if the corpus grew large or unstructured (e.g. free-text
runbooks), noted here as a possible future direction.
"""

FALCO_RULE_DOCS = {
    "Terminal shell in container": (
        "Detects when an interactive shell (e.g. sh, bash) is spawned inside a "
        "container with an attached terminal. Legitimate use includes debugging "
        "via 'kubectl exec'; malicious use includes an attacker gaining "
        "interactive access after exploiting a vulnerability."
    ),
    "Read sensitive file untrusted": (
        "Detects a process reading a sensitive system file (e.g. /etc/shadow, "
        "/etc/passwd) from a program not on Falco's trusted binary list. "
        "Commonly associated with credential harvesting."
    ),
    "Drop and execute new binary in container": (
        "Detects execution of a binary whose on-disk content changed after the "
        "container image was built (an 'upper layer' write), suggesting a file "
        "was written and then run at runtime rather than shipped in the image. "
        "Associated with malware staging, but also triggers on legitimate "
        "runtime operations such as package installation or first-time-mount "
        "helpers -- always cross-check container start time and process lineage."
    ),
    "Suspicious SUID bit set": (
        "Custom rule (not part of Falco's default set) detecting a chmod "
        "operation that sets the SUID bit on a binary. This is a classic Linux "
        "privilege-escalation technique: an attacker sets SUID on a binary they "
        "control so it executes with the file owner's (often root) privileges "
        "regardless of who runs it."
    ),
    "Set Setuid or Setgid bit": (
        "Falco's official (incubating-tier) equivalent detection for SUID/SGID "
        "bit changes via chmod, covering the same privilege-escalation pattern "
        "with broader syscall coverage than the project's custom rule."
    ),
    "Contact K8S API Server From Container": (
        "Detects a container process making a direct network connection to the "
        "Kubernetes API server. Legitimate for K8s-native tooling; suspicious "
        "for an application pod that has no operational reason to talk to the "
        "control plane -- often indicates an attacker using a pod's mounted "
        "ServiceAccount token to enumerate or attack the cluster."
    ),
    "Launch Package Management Process in Container": (
        "Detects a package manager (apt-get, yum, apk, etc.) running inside a "
        "container. Rarely needed at runtime in a properly built image; often "
        "indicates an attacker installing additional tooling post-compromise."
    ),
    "Write below root": (
        "Detects a write operation to a file directly under '/' or '/root'. "
        "Sensitive location; legitimate application behavior almost never "
        "writes here, making this a strong signal of tampering or persistence."
    ),
    "Directory traversal monitored file read": (
        "Detects file reads using path traversal patterns (e.g. '../') that "
        "reach outside an expected directory scope, potentially exposing files "
        "not meant to be accessible."
    ),
    "Change thread namespace": (
        "Detects a process changing Linux namespaces via setns(). Namespace "
        "manipulation is a core technique in container escape attempts, though "
        "it also occurs during normal container/pod initialization."
    ),
    "Change namespace privileges via unshare": (
        "Detects use of the 'unshare' syscall/command to create new namespaces "
        "for a process. Can indicate an attempt to escape container isolation "
        "boundaries."
    ),
    "Potential Local Privilege Escalation via Environment Variables Misuse": (
        "Detects processes launched with environment variables known to be "
        "abused for privilege escalation (e.g. GLIBC_TUNABLES against "
        "vulnerable glibc versions)."
    ),
    "Modify Shell Configuration File": (
        "Detects writes to shell startup/config files (.bashrc, .bash_history, "
        "etc.), a common persistence technique -- planting commands that run "
        "automatically on future shell sessions."
    ),
    "Delete or rename shell history": (
        "Detects deletion or renaming of shell history files, a common "
        "anti-forensics technique used to hide an attacker's command history."
    ),
    "Clear Log Activities": (
        "Detects truncation or clearing of system log files, another "
        "anti-forensics technique aimed at erasing evidence of an intrusion."
    ),
    "Read ssh information": (
        "Detects access to SSH-related files (keys, known_hosts, config), "
        "which may indicate credential theft or lateral-movement preparation."
    ),
    "Launch Sensitive Mount Container": (
        "Detects a container starting with a sensitive host-path mount. Note: "
        "this frequently fires as routine noise during normal pod "
        "initialization and should be cross-referenced with container start "
        "time before treating as suspicious."
    ),
    "Launch Ingress Remote File Copy Tools in Container": (
        "Detects remote file-copy utilities (rsync, scp, sftp) running inside "
        "a container, which can indicate data exfiltration."
    ),
    "Unexpected UDP Traffic": (
        "Detects UDP network connections that do not match expected traffic "
        "patterns for the workload, potentially indicating exfiltration or "
        "command-and-control communication."
    ),
     "Detect crypto miners using the Stratum protocol": (
        "Detects processes launched with command-line arguments referencing "
        "the Stratum mining protocol (stratum+tcp/ssl), used by cryptocurrency "
        "miners to connect to a mining pool. A Falco sandbox-tier rule that "
        "matches on command-line content, so it can be bypassed by obfuscating "
        "the connection string -- catches unsophisticated or "
        "default-configuration miner deployments rather than sophisticated ones."
    ),
}

MITRE_DOCS = {
    "T1059": (
        "Command and Scripting Interpreter (Execution). Adversaries abuse "
        "command and script interpreters to execute commands, scripts, or "
        "binaries. This is one of the most common initial-access-to-execution "
        "techniques observed after a successful compromise."
    ),
    "T1555": (
        "Credentials from Password Stores (Credential Access). Adversaries "
        "search for and extract credentials stored on a system, including "
        "system credential files, aiming to obtain valid account access."
    ),
    "T1548": (
        "Abuse Elevation Control Mechanism (Privilege Escalation). Adversaries "
        "circumvent mechanisms designed to control elevation of privileges to "
        "gain higher-level permissions on a system."
    ),
    "T1548.001": (
        "Abuse Elevation Control Mechanism: Setuid and Setgid (Privilege "
        "Escalation). A specific sub-technique where an adversary abuses the "
        "configuration of setuid/setgid bits on binaries to run with elevated "
        "privileges."
    ),
    "T1610": (
        "Deploy Container (Execution/Defense Evasion). Adversaries deploy a "
        "container into an environment to facilitate execution or evade "
        "detection, potentially leveraging containers with sensitive mounts "
        "or elevated privileges."
    ),
    "T1611": (
        "Escape to Host (Privilege Escalation). Adversaries break out of a "
        "container to gain access to the underlying host system, often via "
        "namespace or capability abuse."
    ),
    "T1565": (
        "Data Manipulation (Impact). Adversaries insert, delete, or manipulate "
        "data to influence business or operational processes, or manipulate "
        "data at rest, in transit, or during processing to affect downstream "
        "outputs. In the context of unexpected API server contact, this "
        "technique tag can also reflect reconnaissance/probing behavior "
        "against cluster-internal data flows."
    ),
    "T1546.004": (
        "Event Triggered Execution: Unix Shell Configuration Modification "
        "(Persistence/Privilege Escalation). Adversaries insert commands into "
        "shell configuration files so they execute automatically when a new "
        "shell session starts."
    ),
    "T1070": (
        "Indicator Removal (Defense Evasion). Adversaries delete or modify "
        "artifacts (logs, command history) generated within a system to "
        "remove evidence of their activity."
    ),
    "T1496": (
        "Resource Hijacking (Impact). Adversaries leverage compromised system "
        "resources -- CPU, GPU, network bandwidth, cloud billing -- for their "
        "own purposes, most commonly cryptocurrency mining, at the cost of the "
        "legitimate workload's performance and the victim's compute spend."
    ),
    "TA0003": "Tactic: Persistence -- techniques adversaries use to maintain access across restarts, credential changes, and other interruptions.",
    "TA0004": "Tactic: Privilege Escalation -- techniques adversaries use to gain higher-level permissions.",
    "TA0011": "Tactic: Exfiltration -- techniques adversaries use to steal data from a network.",
}

REMEDIATION_GUIDE = {
    "kill": (
        "Policy: KILL is triggered when the anomaly score falls below the "
        "critical threshold, indicating high-confidence malicious activity. "
        "The affected pod is deleted immediately via the Kubernetes API to "
        "stop the process. Recommended follow-up: preserve any available logs "
        "before the replacement pod (if Deployment-managed) overwrites recent "
        "history; review whether the workload's base image needs patching."
    ),
    "isolate": (
        "Policy: ISOLATE is triggered when the anomaly score crosses the "
        "warning threshold but not the critical threshold. A Kubernetes "
        "NetworkPolicy is applied to block all ingress/egress traffic for the "
        "pod, containing the potential threat while preserving the pod and "
        "its filesystem state for forensic inspection. Recommended follow-up: "
        "manually inspect the pod (kubectl exec, kubectl logs) before deciding "
        "whether to remove isolation or escalate to termination."
    ),
    "kill_blocked_circuit_breaker": (
        "Policy: automatic action was BLOCKED by the circuit breaker after "
        "repeated actions against this workload within the configured time "
        "window. This is a safety mechanism preventing an infinite "
        "kill-respawn loop against a Deployment/ReplicaSet-managed workload. "
        "Recommended follow-up: manual investigation is required before "
        "resetting the breaker via the /breakers/reset endpoint."
    ),
    "isolate_blocked_circuit_breaker": (
        "Policy: automatic isolation was BLOCKED by the circuit breaker. "
        "Recommended follow-up: manual investigation required before resetting "
        "via /breakers/reset."
    ),
}

DEFAULT_RULE_DOC = "No curated description available for this Falco rule."
DEFAULT_MITRE_DOC = "No curated description available for this MITRE ATT&CK identifier."
DEFAULT_REMEDIATION_DOC = "No specific remediation policy text available for this action."


def retrieve_rule_doc(rule_name):
    return FALCO_RULE_DOCS.get(rule_name, DEFAULT_RULE_DOC)


def retrieve_mitre_docs(technique_ids):
    """Given a list of MITRE technique/tactic identifiers, return their
    descriptions. Falls back gracefully for unknown IDs rather than
    fabricating a description."""
    docs = []
    for tid in technique_ids:
        docs.append((tid, MITRE_DOCS.get(tid, DEFAULT_MITRE_DOC)))
    return docs


def retrieve_remediation_doc(action):
    return REMEDIATION_GUIDE.get(action, DEFAULT_REMEDIATION_DOC)
