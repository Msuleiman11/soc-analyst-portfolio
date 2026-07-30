# SOC205 - Malicious Macro Executed

**Platform:** LetsDefend | **Alert ID:** 231 | **Host:** Jayne (172.16.17.198)
**Event time:** 28 February 2024, 08:42
**Verdict:** True Positive - macro executed, second-stage download failed (HTTP 404)
**Severity:** Medium

## Summary

A macro-enabled Word document, `edit1-invoice.docm`, was executed on host
Jayne from the user's Downloads folder. On execution the macro launched
PowerShell, which resolved and attempted to download a second-stage
executable from an external server. The download request returned HTTP 404,
so the payload was not retrieved.

The macro executed and its intent is confirmed malicious, but the
second-stage delivery failed. There is no evidence of a downloaded payload
running on this host.

## Evidence

| Artifact | Value | Finding |
|---|---|---|
| File name | `edit1-invoice.docm` | Macro-enabled Word document (`.docm`). The "invoice" theme is a common lure. |
| File path | `C:\Users\LetsDefend\Downloads\edit1-invoice.docm` | Downloaded by the user, consistent with an email or web delivery vector. |
| SHA256 | `1a819d18c9a9de4f81829c4cd55a17f767443c22f9b30ca953866827e5d96fb0` | 28/63 vendors on VirusTotal classify as malicious. |
| AV/EDR action | Detected | Flagged, but the document still executed. |
| Spawned process | `powershell.exe` | A Word document spawning PowerShell is the core indicator - Office applications have no legitimate reason to launch a script interpreter. |

## Execution chain

The macro's behaviour is reconstructed from two Sysmon-sourced log entries.

**DNS query (Sysmon Event ID 22)**

| Field | Value |
|---|---|
| Process | `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` |
| Type | DNS Query |
| QueryName | www.greyhathacker.net |
| QueryResult | 92.204.221.16 |
| Username | Jayne |
| UtcTime | 2023-02-28 08:42:51 |

PowerShell - launched by the macro - resolved an external domain. The
domain name itself is a strong indicator, and the query returned a valid IP,
so name resolution succeeded and PowerShell had a live address to contact.

**HTTP request (network log)**

| Field | Value |
|---|---|
| Request | http://www.greyhathacker.net/tools/messbox.exe |
| Method | GET |
| HTTP code | 404 |
| Device action | Permitted |
| Process | powershell.exe |

PowerShell then attempted to download an executable, `messbox.exe`, from the
resolved host. Two details decide the verdict:

- **Device action: Permitted.** The outbound request was not blocked by any
  network control. Had the file existed, it would have been retrieved.
- **HTTP code: 404.** The server returned Not Found. The payload was not on
  the server at request time, so nothing was downloaded.

The compromise attempt was therefore successful up to the point of
second-stage retrieval, and failed only because the payload was absent from
the attacker's server - not because a control stopped it.

## Analysis

This is a macro-based loader. The document uses an invoice lure to induce
execution; on running, the macro invokes PowerShell to pull a second-stage
binary from an external host. This is a standard initial-access-to-loader
pattern.

The execution succeeded: the macro ran, PowerShell ran, DNS resolved, and
the outbound request left the host uninhibited. The chain broke only at
delivery, because the server returned 404. This is an attacker-side failure
(payload removed, taken down, or the sample is stale), not a defensive win -
the "Permitted" device action shows nothing on this network would have
stopped a successful download.

The practical consequence: intent and initial execution are confirmed, but
there is no second-stage payload to analyse or contain on this host, because
none was retrieved.

## MITRE ATT&CK

| Technique | ID | Evidence |
|---|---|---|
| Phishing (assessed) | T1566.001 | Invoice-themed `.docm` in Downloads; delivery vector not directly in evidence |
| User Execution: Malicious File | T1204.002 | Macro executed from the document |
| Command and Scripting Interpreter: PowerShell | T1059.001 | Word spawned PowerShell |
| Ingress Tool Transfer (attempted) | T1105 | GET for `messbox.exe`, failed at 404 |

## What I could not establish

- Whether the macro performed any other action before the failed download -
  persistence, additional C2, or local changes. The two logs show the
  download attempt only.
- The delivery vector. The Downloads path and invoice lure strongly suggest
  email, but no email artifact is in the evidence, so T1566.001 is assessed
  rather than confirmed.
- Whether the same document reached other hosts.
- Whether a retry occurred later, when the payload might have been available.

## Response actions

1. Quarantine `edit1-invoice.docm` and add the SHA256 to the endpoint blocklist
2. Block the domain www.greyhathacker.net and the IP 92.204.221.16 at the
   perimeter - the download failed this time, but a retry could succeed if
   the payload is restored
3. Review PowerShell activity on Jayne after 08:42:51 for any other outbound
   attempts or persistence created by the macro
4. Confirm whether the document reached other users and sweep for the hash
5. Investigate the delivery vector - if email, identify and remove any other
   copies from mailboxes

## Tuning notes

The macro was detected but still executed, so detection did not translate to
prevention. Higher-value opportunities:

1. **Office applications spawning script interpreters.** `winword.exe`
   spawning `powershell.exe` has almost no legitimate use and is the highest-
   fidelity signal in this whole chain. It fires at execution, before any
   network activity.
2. **PowerShell making outbound connections to newly resolved external
   domains.** Would catch the download attempt regardless of the HTTP result -
   note that this alert's own detection is arguably too dependent on the
   404; a payload served successfully would have progressed further with the
   same early indicators available to catch it sooner.
3. **Macro-enabled documents (`.docm`) executing from user Downloads.** Useful
   as an enrichment signal rather than a standalone alert.

The broader control gap is that the outbound request was permitted. Blocking
executable downloads (`.exe`) over HTTP from user workstations, or forcing
them through an inspecting proxy, would have stopped delivery even if the
payload had been present.
