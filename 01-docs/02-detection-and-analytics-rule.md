# Detection and Analytics Rule

## Overview

This document explains how Microsoft Sentinel was configured to detect ransomware-like impact activity and generate an incident.

The attack simulation steps are documented separately in:

```text
docs/01-attack-simulation.md
```

This file focuses only on Sentinel detection engineering, analytics rule configuration, entity mapping, and automated triage.

---

## Detection Strategy

The lab used Windows Security Events collected in Microsoft Sentinel.

The main detection focused on ransomware-like impact behavior, where command-line activity showed file extension modification and ransom note creation.

| Detection Area | Event ID | Purpose |
|---|---|---|
| Failed logon monitoring | 4625 | Identify brute-force attempts |
| Successful logon validation | 4624 | Confirm successful authentication |
| Process creation monitoring | 4688 | Detect command execution and impact activity |

---

## Main Detection Logic

The final analytics rule was created for ransomware-like impact activity.

### Detection Indicators

| Indicator | Description |
|---|---|
| `Ransomware-Simulation-Lab` | Lab folder used during impact activity |
| `.locked` | File extension used to represent impacted files |
| `ransom-note` | Ransom note file created during impact phase |
| `cmd.exe` | Process used to execute the activity |

---

## Analytics Rule Query

```kql
SecurityEvent
| where TimeGenerated > ago(1h)
| where EventID == 4688
| where CommandLine has_any ("Ransomware-Simulation-Lab", ".locked", "ransom-note", "ransom-note2")
| project TimeGenerated, Computer, Account, NewProcessName, CommandLine, ParentProcessName
```

---

## Analytics Rule Configuration

| Setting | Value |
|---|---|
| Rule Name | Ransomware-Like Impact Activity Detected |
| Rule Type | Scheduled query rule |
| Severity | High |
| MITRE Tactics | Execution, Impact |
| Query Frequency | Every 5 minutes |
| Lookup Period | Last 1 hour |
| Alert Threshold | Greater than 0 |
| Incident Creation | Enabled |
| Grouping | Enabled / Default |

---

## Entity Mapping

Entity mapping was configured to make investigation easier in Microsoft Sentinel.

| Entity | Field |
|---|---|
| Account | Account |
| Host | Computer |
| Process | NewProcessName |

### Purpose of Entity Mapping

Entity mapping helps Sentinel identify important investigation objects such as the affected user, affected host, and process involved in the incident.

---

## Incident Generation

The analytics rule generated a high-severity incident when ransomware-like impact activity matched the detection logic.

The incident provided visibility into:

| Incident Detail | Value |
|---|---|
| Alert Name | Ransomware-Like Impact Activity Detected |
| Severity | High |
| Affected Host | SOC-WIN01 |
| Affected User | SOC-WIN01\azureuser |
| Process | cmd.exe |

---

## Automation Rule

A Microsoft Sentinel automation rule was configured for initial triage.

| Setting | Value |
|---|---|
| Automation Rule Name | AR-Ransomware-Initial-Triage |
| Trigger | When incident is created |
| Condition | Analytics rule name equals Ransomware-Like Impact Activity Detected |
| Actions | Assign owner, update incident status, add tags |

---

## Tags Applied

```text
Ransomware-Simulation
SOC-L1
Initial-Response
High-Severity
Project-2
```

---

## Detection Outcome

The analytics rule successfully detected ransomware-like impact behavior and generated a Microsoft Sentinel incident.

The automation rule then performed initial triage by assigning ownership, updating the incident status, and applying relevant tags.

---

## Summary

This phase demonstrates how Microsoft Sentinel can convert endpoint telemetry into an actionable SOC incident using KQL, analytics rules, entity mapping, and automation rules.
