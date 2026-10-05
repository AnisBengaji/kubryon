"""
incident_summarizer.py

Generates SOC-style incident reports from the remediation engine's action
log, using a local LLM (Ollama) grounded with retrieved context -- a
lightweight RAG pipeline.

Pipeline per incident:
  1. Read the structured remediation_log.jsonl record
  2. RETRIEVE: look up the triggering Falco rule's description, the
     relevant MITRE ATT&CK technique description(s), and the internal
     remediation policy text for the action taken -- all from
     knowledge_base.py, via exact key lookup (see that file's docstring
     for why exact lookup rather than vector search is used here)
  3. Build a structured prompt containing the incident's raw facts PLUS
     the retrieved context
  4. Call the local LLM to fill in a fixed SOC incident report template
  5. Verify the action word is stated correctly (post-generation check)
  6. Write the report to incident_reports.jsonl

This is DELIBERATELY downstream of and has zero influence on detection,
scoring, or remediation decisions -- see project design notes.

Usage:
  python3 incident_summarizer.py            # batch mode
  python3 incident_summarizer.py --watch    # poll for new incidents every 10s
"""

import json
import time
import sys
import os
import requests

from knowledge_base import retrieve_rule_doc, retrieve_mitre_docs, retrieve_remediation_doc

REMEDIATION_LOG = "remediation_log.jsonl"
REPORT_LOG = "incident_reports.jsonl"

SUMMARIZABLE_ACTIONS = {"isolate", "kill", "kill_blocked_circuit_breaker", "isolate_blocked_circuit_breaker"}

# Local Ollama instance running on the host machine (reached from the VM
# over the network). See project notes for host-side setup.
OLLAMA_URL = "http://172.16.208.1:11434/api/generate"
OLLAMA_MODEL = "llama3.2:3b"

RISK_LEVEL_BY_ACTION = {
    "kill": "High",
    "isolate": "Medium",
    "kill_blocked_circuit_breaker": "High (action blocked -- manual review required)",
    "isolate_blocked_circuit_breaker": "Medium (action blocked -- manual review required)",
}


def extract_mitre_ids(record):
    tags = record.get("mitre_tags", []) or []
    return [t for t in tags if t.startswith("T") or t.startswith("TA")]


def build_prompt(record):
    features = record.get("features", {})
    action = record.get("action")
    rule = record.get("triggering_rule")
    mitre_ids = extract_mitre_ids(record)

    # --- retrieval step -------------------------------------------------
    rule_doc = retrieve_rule_doc(rule)
    mitre_docs = retrieve_mitre_docs(mitre_ids)
    remediation_doc = retrieve_remediation_doc(action)
    risk_level = RISK_LEVEL_BY_ACTION.get(action, "Unknown")

    mitre_doc_text = "\n".join(f"  - {tid}: {desc}" for tid, desc in mitre_docs) or "  - none available"

    # --- prompt -----------------------------------------------------------
    return f"""You are a SOC (Security Operations Center) analyst assistant. Fill in the incident report template below using ONLY the facts and retrieved knowledge provided. Do not invent details, causes, or explanations not present in the data below. If a field has no data, write "Not available".

CRITICAL: The exact action taken was "{action}". Use this exact word in the report -- do not paraphrase or substitute a different action.

=== RAW INCIDENT DATA ===
Timestamp: {record.get('timestamp')}
Pod: {record.get('pod_name')}
Namespace: {record.get('namespace')}
Falco rule: {rule}
Priority: {record.get('triggering_priority')}
Events observed in detection window: {features.get('event_count')}
Critical-priority events: {features.get('critical_count')}
Distinct rule types triggered: {features.get('distinct_rules')}
Anomaly score: {record.get('anomaly_score')}
Action taken: {action}
Risk level: {risk_level}

=== RETRIEVED KNOWLEDGE (use this to inform your analysis, do not contradict it) ===
Falco rule description: {rule_doc}

MITRE ATT&CK reference(s):
{mitre_doc_text}

Internal remediation policy for action "{action}": {remediation_doc}

=== OUTPUT FORMAT (fill in every field, keep it factual and concise) ===
======================================================
INCIDENT REPORT
======================================================
Time: <timestamp>

Affected Workload
  Pod: <pod>
  Namespace: <namespace>

Detection
  Falco Rule: <rule>
  Priority: <priority>
  Observed Events: <event count>
  MITRE ATT&CK Technique(s): <ids>
  Tactic Context: <one line, based on retrieved MITRE knowledge>

ML Analysis
  Model: Isolation Forest
  Anomaly Score: <score>

Decision
  Risk Level: <risk level>
  Automatic Action: <action, must match exactly>
  Reason: <one line, based on score vs. threshold>

Analyst Briefing
  <2-4 sentences: what the rule detects (from retrieved knowledge), what
  the MITRE technique means (from retrieved knowledge), and why this
  action was taken. Ground every claim in the data and retrieved
  knowledge above -- do not speculate beyond it.>

Recommended Investigation
  <2-4 bullet points, informed by the retrieved remediation policy text>
======================================================

Write the completed report now:"""


def call_llm(prompt):
    try:
        response = requests.post(
            OLLAMA_URL,
            json={"model": OLLAMA_MODEL, "prompt": prompt, "stream": False},
            timeout=45,
        )
        response.raise_for_status()
        return response.json().get("response", "").strip()
    except requests.exceptions.ConnectionError:
        return "[LLM unavailable: Ollama not reachable. Check host is running 'ollama serve'.]"
    except Exception as e:
        return f"[LLM generation failed: {e}]"


def verify_action_word(report_text, action):
    if action.lower() not in report_text.lower():
        return False, f"[WARNING: report does not clearly state action '{action}' -- needs manual review]\n\n{report_text}"
    return True, report_text


def already_processed_ids():
    if not os.path.exists(REPORT_LOG):
        return set()
    ids = set()
    with open(REPORT_LOG) as f:
        for line in f:
            if line.strip():
                ids.add(json.loads(line).get("source_id"))
    return ids


def record_id(record):
    return f"{record.get('timestamp')}::{record.get('pod_name')}"


def process_new_incidents():
    if not os.path.exists(REMEDIATION_LOG):
        print(f"{REMEDIATION_LOG} not found. Nothing to process yet.")
        return

    done = already_processed_ids()
    new_count = 0

    with open(REMEDIATION_LOG) as f:
        for line in f:
            if not line.strip():
                continue
            record = json.loads(line)

            if record.get("action") not in SUMMARIZABLE_ACTIONS:
                continue

            rid = record_id(record)
            if rid in done:
                continue

            prompt = build_prompt(record)
            raw_report = call_llm(prompt)
            is_verified, report_text = verify_action_word(raw_report, record.get("action"))

            report_record = {
                "source_id": rid,
                "pod_name": record.get("pod_name"),
                "namespace": record.get("namespace"),
                "action": record.get("action"),
                "anomaly_score": record.get("anomaly_score"),
                "mitre_ids": extract_mitre_ids(record),
                "report": report_text,
                "verified": is_verified,
            }

            with open(REPORT_LOG, "a") as out:
                out.write(json.dumps(report_record) + "\n")

            print(report_text)
            print()
            new_count += 1

    print(f"Processed {new_count} new incident(s).")


def watch_mode():
    print("Watching remediation_log.jsonl for new incidents (Ctrl+C to stop)...")
    while True:
        process_new_incidents()
        time.sleep(10)


if __name__ == "__main__":
    if "--watch" in sys.argv:
        watch_mode()
    else:
        process_new_incidents()
