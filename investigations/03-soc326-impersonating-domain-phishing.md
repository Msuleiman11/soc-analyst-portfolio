# SOC326 - Impersonating Domain MX Record Change Detected

**Platform:** LetsDefend | **Alert ID:** 304
**Alert time:** 17 September 2024, 12:05
**Verdict:** [your call]
**Severity:** [your call]

## Summary
[3-4 sentences. What the CTI feed warned about, what happened next,
and how far it got. End on the impact.]

## Timeline
| Time | Event | Source |
|---|---|---|
| 17 Sep 12:05 | [CTI alert] | |
| 18 Sep 08:00 | [phish delivered] | |
| 18 Sep 13:32 | [first connection] | |
| 18 Sep 13:32 | [second connection] | |

## The warning
[What a CTI feed is doing here. Why an MX record change on a typosquat
matters — what it enables that a parked domain doesn't. Name the
typosquat and the character substitution.]

## The phishing email
[Sender, recipient, subject, lure. What made it credible. The plaintext
fallback URL, and the HTTP-not-HTTPS detail. Device action.]

## User interaction
[Mateo's host, the destination IP, both connections. Be precise about
what the second connection is *consistent with* versus what you can
actually prove from a connection log.]

## Key finding
[The one that matters: the SOC was told which domain, 20 hours before.
Say what that means.]

## Infrastructure
[45.33.23.183 doing double duty. Why that IP is the more durable IOC.]

## Out of scope
[The RDP traffic. One short paragraph, then leave it.]

## MITRE ATT&CK
| Technique | ID | Evidence |
|---|---|---|
[T1583.001 Acquire Infrastructure: Domains, T1566.002 Phishing: Spearphishing Link,
T1204.001 User Execution: Malicious Link — check each fits before you use it]

## What I could not establish
[Sandbox unavailable. Whether credentials were entered. Whether the page
was harvesting or malware. Anything after 13:32.]

## Response actions
[Ordered by urgency. Think: what's the first thing you do if you assume
credentials are gone?]

## Tuning notes
[The control gap isn't detection here — the alert fired correctly.
What should have happened between 12:05 on the 17th and 08:00 on the 18th?]
