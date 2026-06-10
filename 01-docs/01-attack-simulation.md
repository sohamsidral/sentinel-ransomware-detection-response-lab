# Attack Simulation

## Overview

This document explains the attack simulation performed in the Microsoft Sentinel ransomware detection and response lab.

This file focuses only on the attacker-side activity performed on the Windows endpoint. Detection logic, KQL queries, analytics rule configuration, and automation rule details are documented separately in:

```text
docs/02-detection-and-analytics-rule.md
```

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
```

---

## Phase 1: Brute-Force Login Simulation

Multiple failed login attempts were generated against the Windows VM to simulate brute-force activity.

### Purpose

This phase represents an attacker attempting to guess valid credentials.

### Evidence Generated

| Evidence | Description |
|---|---|
| Failed logons | Multiple failed authentication attempts |
| Event ID | 4625 |
| Log Source | Windows Security Events |

---

## Phase 2: Successful Login Validation

After the failed login attempts, a successful login was reviewed to represent access to the system.

### Purpose

This phase represents successful access after authentication activity.

### Evidence Generated

| Evidence | Description |
|---|---|
| Successful logon | Valid login to SOC-WIN01 |
| Event ID | 4624 |
| Log Source | Windows Security Events |

---

## Phase 3: Discovery Simulation

Discovery commands were executed to collect information about the system, user, network, and local groups.

### Purpose

Attackers commonly run discovery commands after gaining access to understand the environment.

### Commands Executed

```cmd
whoami
hostname
ipconfig /all
net user
net localgroup
systeminfo
```

### What This Simulates

| Command | Purpose |
|---|---|
| `whoami` | Identifies current user |
| `hostname` | Identifies system name |
| `ipconfig /all` | Reviews network configuration |
| `net user` | Lists local user accounts |
| `net localgroup` | Lists local groups |
| `systeminfo` | Collects system information |

---

## Phase 4: Persistence Simulation

A scheduled task was created to simulate persistence.

### Purpose

Scheduled tasks are commonly used to maintain access or execute commands repeatedly.

### Command Executed

```cmd
schtasks /create /tn "UpdaterCheck" /tr "notepad.exe" /sc minute /mo 30 /f
```

### What This Simulates

| Item | Description |
|---|---|
| Task Name | UpdaterCheck |
| Action | Opens Notepad |
| Frequency | Every 30 minutes |
| Persistence Method | Scheduled task |

---

## Phase 5: Privilege Checking Simulation

Privilege and group membership checks were performed.

### Purpose

Attackers often check privileges to understand what actions can be performed on the host.

### Commands Executed

```cmd
whoami /priv
whoami /groups
net localgroup administrators
```

### What This Simulates

| Command | Purpose |
|---|---|
| `whoami /priv` | Checks assigned privileges |
| `whoami /groups` | Checks group membership |
| `net localgroup administrators` | Lists local administrators |

---

## Phase 6: Credential Discovery Simulation

Credential and user profile discovery commands were executed.

### Purpose

Attackers may look for saved credentials, local users, and user profile folders during credential discovery.

### Commands Executed

```cmd
cmdkey /list
net user
dir C:\Users
```

### What This Simulates

| Command | Purpose |
|---|---|
| `cmdkey /list` | Lists saved credentials |
| `net user` | Lists local user accounts |
| `dir C:\Users` | Lists user profile directories |

---

## Phase 7: Ransomware-like Impact Simulation

Ransomware-like impact behavior was simulated by creating test files, changing file extensions, and creating a ransom note.

### Purpose

This phase represents the impact stage of ransomware-like activity.

### Command Executed

```cmd
cmd.exe /c "mkdir C:\Ransomware-Simulation-Lab2 && cd C:\Ransomware-Simulation-Lab2 && echo test > file1.txt && echo test > file2.txt && ren *.txt *.locked && echo This is a safe ransomware simulation > ransom-note2.txt"
```

### What This Simulates

| Activity | Description |
|---|---|
| Test file creation | Creates files in a lab folder |
| File extension change | Renames `.txt` files to `.locked` |
| Ransom note creation | Creates `ransom-note2.txt` |
| Process execution | Executes activity through `cmd.exe` |

### Evidence Collected

| Evidence | Value |
|---|---|
| File Path | `C:\Ransomware-Simulation-Lab2` |
| File Extension | `.locked` |
| Ransom Note | `ransom-note2.txt` |
| Process | `cmd.exe` |

---

## Summary

This attack simulation created a complete chain of endpoint activity that could be detected, investigated, and responded to using Microsoft Sentinel.
