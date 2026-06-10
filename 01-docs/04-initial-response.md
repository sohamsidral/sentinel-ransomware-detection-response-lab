# Initial Response

## Overview

This document explains the initial response actions performed after validating the ransomware-like incident in Microsoft Sentinel.

This phase focuses on automated triage, containment action, and escalation preparation.

---

## Response Flow

```text
Incident Generated
     ↓
Automated Triage
     ↓
SOC Investigation
     ↓
IOC Collection
     ↓
Initial Response
     ↓
Test User Disabled
     ↓
Escalation Preparation
```

---

## Automated Initial Triage

A Microsoft Sentinel automation rule was configured to perform initial triage when the incident was created.

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

## Initial Response Action

After investigation and IOC collection, the test account used during the simulation was disabled.

### Command Used

```cmd
net user ransomwaretest /active:no
```

### Verification Command

```cmd
net user ransomwaretest
```

### Expected Result

```text
Account active               No
```

---

## Response Summary

| Response Action | Status |
|---|---|
| Incident owner assigned | Completed |
| Incident status updated | Completed |
| Incident tags applied | Completed |
| IOC collection completed | Completed |
| Test user disabled | Completed |
| Incident prepared for escalation | Completed |

---

## Containment Summary

The initial containment action focused on disabling the test user account associated with the simulation.

| Item | Value |
|---|---|
| Disabled Account | ransomwaretest |
| Response Type | Initial containment |
| Method | Local Windows user disable command |
| Verification | Account active status changed to No |

---

## Escalation Summary

After initial containment, the incident was prepared for escalation to L2 or Incident Response team.

```text
Ransomware-like activity was detected on SOC-WIN01.

Observed behavior included discovery, persistence, privilege checking, credential discovery, and ransomware-style impact activity.

Initial response was performed by disabling the test user account.

Collected IoCs included host, user, process, event ID, file path, file extension, and ransom note.
```

---

## Outcome

The initial response phase demonstrated how a SOC analyst can validate an incident, collect evidence, perform containment, and prepare the incident for escalation.
