# soc-analyst-portfolio

Documented security alert investigations, written up as working analyst
reports. All analysis is performed in training environments (LetsDefend).

## Format

Each investigation follows the same structure: alert summary, attack
chain reconstruction, evidence, verdict reasoning, MITRE ATT&CK mapping,
findings I withdrew and why, what I could not establish, response
actions, and detection tuning recommendations.

Wrong turns are kept in the write-ups rather than deleted. Knowing why
an initial read didn't hold is part of the analysis.

## Investigations

| # | Investigation | Verdict | Key techniques |
|---|---|---|---|
| 01 | [CVE-2024-49138 CLFS Privilege Escalation](investigations/01-cve-2024-49138-privilege-escalation.md) | True Positive | T1068, T1036.005, T1059.001 |
| 02 | [SOC205 - Malicious Macro Executed](investigations/02-soc205-malicious-macro.md) | True Positive | T1204.002, T1059.001, T1105 |
| 03 | [SOC326 - Impersonating Domain Phishing](investigations/03-soc326-impersonating-domain-phishing.md) | True Positive | T1583.001, T1566.002, T1204.001 |

## About

Cybersecurity graduate (BSc, University of Bedfordshire) working toward
a SOC analyst role. eJPTv2 certified, Security+ in progress.

[LinkedIn](https://www.linkedin.com/in/mohammad-suleiman-367a23201/) · suleiman.mohammad1@outlook.com
