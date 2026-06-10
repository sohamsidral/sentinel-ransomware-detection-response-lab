# MITRE ATT&CK Mapping

## Overview

This document maps the simulated attack activities from the Microsoft Sentinel ransomware detection and response lab to MITRE ATT&CK tactics.

The mapping helps explain how each activity fits into a SOC investigation workflow.

---

## MITRE ATT&CK Summary

| Phase | Activity | MITRE Tactic |
|---|---|---|
| Initial Access | Brute-force login attempts | Credential Access / Initial Access Attempt |
| Authentication | Successful login | Initial Access |
| Execution | Command execution using cmd.exe | Execution |
| Discovery | User, system, and network enumeration | Discovery |
| Persistence | Scheduled task creation | Persistence |
| Privilege Checking | User privilege and group checks | Discovery |
| Credential Discovery | Saved credential and user profile discovery | Credential Access |
| Impact | File extension modification | Impact |
| Impact | Ransom note creation | Impact |

---

## Brute-Force Login Attempts

| Field | Details |
|---|---|
| Activity | Multiple failed login attempts |
| Event ID | 4625 |
| Tactic | Credential Access |
| SOC Relevance | Indicates possible password guessing or brute-force behavior |

---

## Successful Login

| Field | Details |
|---|---|
| Activity | Successful authentication |
| Event ID | 4624 |
| Tactic | Initial Access |
| SOC Relevance | Helps validate whether access occurred after failed login attempts |

---

## Command Execution

| Field | Details |
|---|---|
| Activity | Windows command-line execution |
| Process | cmd.exe |
| Event ID | 4688 |
| Tactic | Execution |
| SOC Relevance | Shows command execution on the endpoint |

---

## Discovery

| Field | Details |
|---|---|
| Activity | System, user, and network enumeration |
| Commands | whoami, hostname, ipconfig, net user, net localgroup, systeminfo |
| Event ID | 4688 |
| Tactic | Discovery |
| SOC Relevance | Helps identify enumeration of users, groups, system details, and network configuration |

---

## Persistence

| Field | Details |
|---|---|
| Activity | Scheduled task creation |
| Command | schtasks |
| Event ID | 4688 |
| Tactic | Persistence |
| SOC Relevance | Scheduled tasks can be used to maintain access or execute commands repeatedly |

---

## Privilege Checking

| Field | Details |
|---|---|
| Activity | User privilege and group checks |
| Commands | whoami /priv, whoami /groups, net localgroup administrators |
| Event ID | 4688 |
| Tactic | Discovery |
| SOC Relevance | Helps identify privilege and administrator group enumeration |

---

## Credential Discovery

| Field | Details |
|---|---|
| Activity | Saved credential and user profile discovery |
| Commands | cmdkey /list, net user, dir C:\Users |
| Event ID | 4688 |
| Tactic | Credential Access |
| SOC Relevance | Indicates possible credential or user profile discovery behavior |

---

## Ransomware-like Impact

| Field | Details |
|---|---|
| Activity | File extension modification and ransom note creation |
| Process | cmd.exe |
| Event ID | 4688 |
| Tactic | Impact |
| SOC Relevance | Indicates ransomware-style impact behavior |

---

## Final Attack Chain Mapping

```text
Credential Access / Initial Access
        ↓
Execution
        ↓
Discovery
        ↓
Persistence
        ↓
Credential Discovery
        ↓
Impact
        ↓
Response
```

---

## Summary

This MITRE ATT&CK mapping shows how the simulated activity followed a realistic attack chain and how each stage was detected and investigated using Microsoft Sentinel.
