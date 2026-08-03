# SOC326 - Impersonating Domain MX Record Change Detected

**Platform:** LetsDefend | **Alert ID:** 304
**Alert time:** 17 September 2024, 12:05
**Verdict:** True Positive - phishing delivered and user interaction confirmed
**Severity:** High

## Summary

A threat intelligence feed notified the SOC that an impersonating domain,
letsdefwnd[.]io, had changed its MX record - indicating the domain had been
configured to send and receive mail.

Twenty hours later, a phishing email was delivered from that exact domain to
an internal user. The user clicked the embedded link, and the outbound
connection was allowed.

The domain was named in an alert the day before the attack. No blocking
action was taken in the intervening period.

## Timeline

| Time | Event | Source |
|---|---|---|
| 17 Sep, 12:05 | CTI feed alerts SOC to MX record change on letsdefwnd[.]io | Email to soc@letsdefend.io |
| 18 Sep, 08:00 | Phishing email delivered from voucher@letsdefwnd[.]io to mateo@letsdefend.io. Action: Allowed | Email Security |
| 18 Sep, 13:32:13 | Connection from 172.16.17.162 to 45.33.23.183:443, user Mateo. Action: Allowed | Network log |
| 18 Sep, 13:32 | Second connection to same destination, different source port | Network log |

![Email Security showing both messages 20 hours apart](Images/Screenshot%202026-08-03%20204412.png)

## The warning

The initial alert was not an attack. It was a Digital Risk Protection feed
reporting on infrastructure - the sender was no-reply@cti-report.io and the
recipient was the SOC mailbox, not an end user.

The domain flagged was letsdefwnd[.]io against the legitimate
letsdefend[.]io. The substitution replaces the "e" with a "w", which sit
adjacent on a QWERTY keyboard. This is a typosquat designed around a
plausible typing error rather than a random string.

The significance is the MX record specifically. Registering a lookalike
domain is trivial and most squatted domains sit parked indefinitely. An MX
record is the DNS record that directs mail delivery for a domain, so adding
one means the operator has deliberately stood up mail infrastructure. That
moves the domain from dormant to operational, and enables it both to receive
misdirected mail and to send mail impersonating the organisation.

The alert was correctly classified as high risk. It was a warning that an
attacker had completed a setup step.

## The phishing email

Delivered at 08:00 the following morning.

| Field | Value |
|---|---|
| From | voucher@letsdefwnd[.]io |
| To | mateo@letsdefend.io |
| Subject | Congratulations! You've Won a Voucher |
| Action | Allowed |

The email reproduces LetsDefend branding, including the logo and colour
scheme, and addresses the recipient by first name. The lure is a voucher
claim with a "Claim Your Voucher" button and a limited-time framing to
create urgency.

Below the button, the email includes a plaintext fallback URL:
http://letsdefwnd.io/

Two observations. The fallback URL defeats any control that only rewrites or
inspects hyperlinks, since a user can copy and paste it manually. And the
link is HTTP rather than HTTPS, which is a minor tell but inconsistent with
a legitimate corporate communication.

![Phishing email impersonating LetsDefend branding](Images/Screenshot%202026-08-03%20204317.png)

The email was targeted rather than bulk. A search of Email Security across
the period returned only this message and the CTI alert.

## User interaction

At 13:32 on 18 September, host 172.16.17.162 connected outbound to
45.33.23.183 on port 443. The log records the user as Mateo and the URL as
letsdefwnd[.]io. Device action was Allowed.

A second connection to the same destination followed from a different source
port.

![Network log showing the allowed outbound connection from Mateo's host](Images/Screenshot%202026-08-03%20204647.png)

What this establishes: the user clicked the link, the connection completed,
and no control blocked it.

What it does not establish: whether credentials were entered. The second
connection is consistent with a form submission following an initial page
load, but a connection log records only that traffic occurred - not its
content. Without the request body or a sandbox analysis of the landing page,
credential submission is a reasonable concern rather than a demonstrated
fact.

Given that distinction, the correct response is to assume compromise. The
cost of resetting credentials that were never stolen is trivial; the cost of
leaving stolen credentials active is not.

## Key finding

The SOC was told the name of this domain twenty hours before it was used.

The intelligence was accurate, specific, actionable, and correctly rated
high risk. It named the exact domain that would go on to send the phishing
email. In the intervening period the domain was not blocked at the mail
gateway or the proxy, and both the email and the subsequent web connection
were allowed.

This is not a detection failure. Every control that was supposed to observe
this activity did so. The gap is between receiving intelligence and acting
on it.

## Infrastructure

45.33.23.183 appears twice in the evidence - as the SMTP source of the
phishing email at 08:00, and as the destination of the user's web connection
at 13:32. The same host sent the mail and served the landing page.

That makes the IP a more durable indicator than the domain. A registered
domain is cheap and easily replaced; hosting infrastructure is more often
reused across campaigns. Blocking the domain alone would leave the operator
free to register another typosquat against the same server.

## Out of scope

Three connections from 146.70.202.86 to 172.16.17.128 on port 3389 appear at
04:57, 04:58 and 04:59 on 17 September. This is external traffic to RDP on a
different internal host, unrelated to the phishing chain by source,
destination and timing.

Noted here because repeated external RDP connection attempts warrant their
own investigation, but excluded from this one to avoid conflating two
separate issues.

## Console inconsistency

The network log displays the two connections at "01:32 PM" and "01:32 AM",
while the raw log field for the first reads 2024-09-18 13:32:13. The events
are seconds apart on the same afternoon; the AM/PM rendering in the summary
view is unreliable. I have used the raw log timestamp throughout.

## MITRE ATT&CK

| Technique | ID | Evidence |
|---|---|---|
| Acquire Infrastructure: Domains | T1583.001 | Typosquat domain registered and MX record configured |
| Phishing: Spearphishing Link | T1566.002 | Branded email with embedded link to attacker-controlled domain |
| User Execution: Malicious Link | T1204.001 | Confirmed outbound connection from the recipient's host |

## What I could not establish

- The nature of the landing page. Sandbox analysis was unavailable, so
  whether the site was credential harvesting or malware delivery is unknown.
  This determines whether the priority response is credential rotation or
  host examination.
- Whether credentials were submitted. See the reasoning above.
- No activity from Mateo's host after 13:32 appears in the available logs,
  but absence here is only as reliable as the logging coverage.
- Whether any outbound mail has been sent to letsdefwnd[.]io by staff
  mistyping the internal domain, which would represent data exposure
  independent of this phishing attempt.

## Response actions

1. Reset Mateo's credentials and invalidate active sessions. Treat as
   compromised pending evidence otherwise.
2. Block letsdefwnd[.]io at the mail gateway and web proxy.
3. Block 45.33.23.183, which covers both the mail and web infrastructure.
4. Examine Mateo's host for any payload delivered by the landing page.
5. Search outbound mail logs for messages sent to letsdefwnd[.]io - misdirected
   internal mail to an attacker-controlled MX is a data exposure route that
   exists independently of this phishing email.
6. Check for further recipients of mail from the domain across the estate.
7. Identify and pre-emptively block other plausible typosquat variants of the
   organisation's domain.
8. Review DMARC, SPF and DKIM policy, and consider external-sender warning
   banners on inbound mail.

## Tuning notes

The detection worked. The CTI feed identified the domain, correctly assessed
it as high risk, and delivered the alert to the SOC twenty hours before it
was used. No rule change would have improved that.

The gap is procedural. There is no evident process for converting a
domain-impersonation alert into a block. Improvements, in order of value:

1. **Automatic blocklisting of impersonating domains on receipt of a CTI
   alert.** A confirmed typosquat with an active MX record has no legitimate
   business use, so blocking carries near-zero false positive cost. This
   single change would have prevented the entire incident.
2. **Alert on inbound mail from domains with low Levenshtein distance to the
   organisation's own domain.** Catches typosquats generally, including ones
   no CTI feed has reported yet.
3. **Extract and evaluate plaintext URLs in message bodies, not only
   hyperlinks.** The fallback URL in this email would bypass link-rewriting
   controls entirely.
4. **Alert on first-time outbound connections to recently registered
   domains.** A final layer for cases where the mail control is bypassed.

The broader point is that this incident was preventable with information the
organisation already held. Detection produced the right answer and nothing
downstream consumed it.
