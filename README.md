# Microsoft Sentinel Ransomware Detection & Response Lab

## Project Overview

This project demonstrates an end-to-end SOC workflow for detecting, investigating, and responding to ransomware-like activity using Microsoft Sentinel.

The lab includes brute-force login attempts, successful logins, discovery commands, persistence simulation, credential discovery, ransomware-style impact activity, Sentinel analytics rule creation, incident generation, automated triage, IOC collection, and initial response.

---

## Lab Environment

| Component      | Details                                                               |
| -------------- | --------------------------------------------------------------------- |
| SIEM           | Microsoft Sentinel                                                    |
| Cloud Platform | Microsoft Azure                                                       |
| Resource Group | RG-SOC-LAB                                                            |
| Workspace      | LAW-SOC-LAB                                                           |
| Endpoint       | SOC-WIN01                                                             |
| Log Source     | Windows Security Events                                               |
| Main Event IDs | 4625 - Failed Logon, 4624 - Successful Logon, 4688 - Process Creation |

---

## Attack Flow

```text
Brute-force Login Attempts
     ↓
Successful Login
     ↓
Execution
     ↓
Discovery
     ↓
Persistence
     ↓
Privilege Checking
     ↓
Credential Discovery
     ↓
Ransomware-like Impact
     ↓
Detection
     ↓
Investigation
     ↓
Initial Response
```

---

## Detection & Response Summary

| Stage          | Implementation                                                         |
| -------------- | ---------------------------------------------------------------------- |
| Initial Access | Brute-force login simulation using failed logons                       |
| Authentication | Successful login validation using Event ID 4624                        |
| Detection      | KQL queries using Windows Security Events                              |
| Analytics Rule | High severity Sentinel rule for ransomware-like impact                 |
| Incident       | Sentinel incident generated from analytics rule                        |
| Automation     | Incident owner, status, and tags updated using automation rule         |
| Investigation  | Host, user, process, command line, file path, and ransom note reviewed |
| Response       | Test user account disabled as initial containment action               |

---

## Key KQL Detections

### Brute-Force Login Detection

```kql
SecurityEvent
| where EventID == 4625
| summarize FailedAttempts=count() by Account, Computer, IpAddress
| where FailedAttempts >= 5
| order by FailedAttempts desc
```

### Successful Login Detection

```kql
SecurityEvent
| where EventID == 4624
| project TimeGenerated, Computer, Account, IpAddress, LogonType
| order by TimeGenerated desc
```

### Ransomware Impact Detection

```kql
SecurityEvent
| where EventID == 4688
| where CommandLine has_any ("Ransomware-Simulation-Lab", ".locked", "ransom-note")
| project TimeGenerated, Computer, Account, NewProcessName, CommandLine, ParentProcessName
```

---

## Indicators Collected

| IOC Type           | Value                         |
| ------------------ | ----------------------------- |
| Host               | SOC-WIN01                     |
| User               | SOC-WIN01\azureuser           |
| Process            | cmd.exe                       |
| Event ID           | 4688                          |
| File Path          | C:\Ransomware-Simulation-Lab2 |
| File Extension     | .locked                       |
| Ransom Note        | ransom-note2.txt              |
| Disabled Test User | ransomwaretest                |

---

## MITRE ATT&CK Mapping

| Activity                      | Tactic            |
| ----------------------------- | ----------------- |
| Brute-force login attempts    | Credential Access |
| Successful authentication     | Initial Access    |
| Command execution             | Execution         |
| System and user enumeration   | Discovery         |
| Scheduled task creation       | Persistence       |
| Credential discovery commands | Credential Access |
| File extension modification   | Impact            |
| Ransom note creation          | Impact            |

---

## Skills Demonstrated

- Microsoft Sentinel monitoring
- KQL detection engineering
- Windows Security Event analysis
- Event ID 4624, 4625, and 4688 investigation
- Brute-force attack detection
- Successful login validation
- Analytics rule creation
- Incident triage and investigation
- Sentinel automation rule configuration
- IOC collection
- MITRE ATT&CK mapping
- SOC L1 response workflow

---

## Final Outcome

```text
Attack Simulation → Detection → Incident Creation → Automated Triage → Investigation → Initial Response
```

This project demonstrates a practical SOC Analyst workflow using Microsoft Sentinel.
