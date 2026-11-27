# Windows Threat Detection Library

Sigma detection rules for Windows attacker techniques, each mapped to MITRE ATT&CK, documented, and tested against telemetry from a lab VM.

> **Status: in progress.** No detections have been tested yet. This section is updated as each rule is validated.

## Layout

- `detections/` – one folder per detection: Sigma rule, documentation, test events
- `lab/` – how the lab VM is built and configured (Azure, Sysmon, audit policy, simulations)
- `evidence/` – results of validation runs against lab telemetry
- `tests/` – automated tests run in CI
- `scripts/` – helper scripts
- `docs/` – architecture, telemetry requirements, testing methodology
