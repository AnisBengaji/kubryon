# Kubryon Dashboard — ready folder

This folder is a drop-in Flask dashboard frontend for the Kubryon runtime-security project.

## What changed
- Reworked the visual language around a professional enterprise SOC / SIEM console.
- Kept the Flask backend contract unchanged.
- Uses your existing `/api/incidents`, `/api/health`, and `/api/topology` endpoints.
- Dashboard presents the real Kubryon pipeline: Falco telemetry → anomaly assessment → kill/isolate response → incident reporting.
- Keeps the existing D3 Kubernetes topology page and routes it through the new common shell.
- No fake threat score, no fabricated telemetry, and no AI-centric visual treatment.

## Install
Copy:
- `templates/base.html`
- `templates/index.html`
- `templates/topology.html`
- `static/kubryon.css`
- `static/kubryon.js`

into the corresponding directories of your existing Flask dashboard.

Your current `dashboard.py` can remain unchanged.

## Public reference
The visual/functional direction was informed by the open-source CyberShield SIEM dashboard, which uses a SOC dashboard, anomaly detection, MITRE mapping, topology visualization and automated response concepts. The implementation here is adapted to your existing Flask/Jinja architecture rather than copied into React. Source: https://github.com/MDsalmanhyder/Cyber-Security-Threat-Detection-Dashboard
