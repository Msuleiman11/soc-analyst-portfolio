
# Wazuh SOC Home Lab

Building a working SIEM from scratch, monitoring a live endpoint, and investigating the detections that came out of it.

---

## The lab

![Lab architecture](../images/wazuh-lab-architecture.png)

Three machines, all on the same home network so they can see each other:

| | | |
|---|---|---|
| **Host machine** | `192.168.0.105` | Windows 11 running VirtualBox. This is where I ran the attacks from, and where I opened the dashboard. |
| **Wazuh server** | `192.168.0.102` | Wazuh 4.14.7 OVA. Manager, indexer and dashboard in one appliance. This is the SIEM. |
| **Monitored endpoint** | `192.168.0.109` | Ubuntu 24.04.4 LTS running the Wazuh agent and an SSH server. This is the machine being watched, and the machine being attacked. |

The agent collects logs and file changes and forwards them to the server over TCP 1514. The server decides what those events mean and what severity to give them. I reach the dashboard from the host over HTTPS.

That split matters and it's worth stating up front: **the agent collects, the manager decides.** Nothing on the Ubuntu box has an opinion about whether an event is suspicious. All of that logic lives on the server.

---

## Getting there

The original plan was a Windows endpoint. I wanted Windows event logs and eventually Sysmon, because that's what most environments actually run.

That didn't happen. I lost several hours to a Windows 11 VM that would boot to a black screen and nothing else. I worked through the graphics controller, EFI, TPM, memory allocation, and eventually a completely fresh VM with the unattended installer disabled. Still black.

At some point I decided the operating system wasn't the point of the exercise. The point was to have something generating logs that Wazuh could watch. Ubuntu installed in about twenty minutes and I got on with it.

I'd still like Windows telemetry in here eventually, but not at the cost of another evening staring at a blank window.

**Screenshot: both machines pinging each other**
`![Connectivity between VMs](../images/ping-connectivity.png)`

That ping is the first thing worth checking and the thing I'd check first if anything broke later. Both VMs are on bridged adapters, so they're real devices on the home network rather than hidden behind NAT. Without that, none of the rest works.

**Screenshot: deploy new agent wizard**
`![Agent deployment configuration](../images/agent-deploy-wizard.png)`

**Screenshot: agent showing active**
`![Agent connected](../images/agent-active.png)`

Agent 001, Ubuntu 24.04.4, active. That's the platform up and something reporting into it.

---

## Detection 1 — SSH brute force

### What I wanted to see

Ubuntu Desktop doesn't ship with an SSH server, so I installed one. That gave the box a service worth attacking, and gave me a realistic thing to detect: someone trying to guess their way in.

### Generating the attack

From the Windows host:

```bash
for i in {1..10}; do ssh -o StrictHostKeyChecking=no -o PreferredAuthentications=password -o PubkeyAuthentication=no fakeuser@192.168.0.109 exit; done
```

Ten attempts against a username that doesn't exist, run from a different machine. Running it from the host rather than from the Ubuntu box itself matters — I wanted the source IP in the alerts to be genuinely external to the endpoint, the way it would be in a real intrusion.

**Screenshot: Threat Hunting dashboard**
`![Threat Hunting dashboard](../images/threat-hunting-dashboard.png)`

The MITRE panel picked it up immediately — Password Guessing and SSH.

### What fired first

**Rule 5710 — "sshd: Attempt to login using a non-existent user", level 5.**

**Screenshot: 5710 alert detail**
`![Rule 5710 alert](../images/alert-5710.png)`

The useful fields:

- `full_log` — the raw auth.log line: *Failed password for invalid user fakeuser from 192.168.0.105*
- `data.srcip` — 192.168.0.105, the host machine
- `rule.mitre.id` — T1110.001 and T1021.004, Password Guessing and SSH
- `rule.level` — 5

Level 5 is low, and it should be. One failed login is a person mistyping their password. On its own it means almost nothing.

### What fired next

**Rule 5712 — "sshd: brute force trying to get access to the system", level 10.**

**Screenshot: repeated alerts in the events list**
`![Repeated authentication failures](../images/repeated-failures.png)`

**Screenshot: 5712 brute force alert**
`![Rule 5712 brute force](../images/alert-5712.png)`

This is the interesting one:

- `rule.frequency` — 8. That's the threshold: eight failures inside the window.
- `previous_output` — the individual events that made up the pattern, listed out in the alert itself
- `rule.mitre.id` — T1110, Brute Force
- `rule.level` — 10

Same events. Different conclusion.

That's the part worth dwelling on. Fifteen level-5 alerts are noise — you'd never chase them individually and you shouldn't. But eight of them in two minutes from one source is an attack, and the correlation rule says so with a severity that would actually get someone's attention.

That gap between an event and an incident is the whole job, and watching it happen on something I'd built made it land in a way that reading about it hadn't.

### What slowed me down

I couldn't find the 5712 alert at first. I'd applied an "Authentication failure" filter to the events view, and 5712 sits in a different rule group, so my own filter was hiding the thing I was looking for. I had to search for the rule ID directly.

Worth remembering: a filter that makes the noise manageable can also hide the alert that matters.

---

## Detection 2 — File Integrity Monitoring

### The idea

Brute force detection watches a service. File integrity monitoring watches data. I wanted something that would tell me if a file changed, and prove that it had changed rather than just that someone had touched it.

### Setting it up

Created a directory and put something in it worth protecting:

```bash
sudo mkdir -p /opt/customer-records
echo "account: 4417 balance: 200" | sudo tee /opt/customer-records/accounts.txt
```

Then opened the agent's configuration file:

```bash
sudo nano /var/ossec/etc/ossec.conf
```

This is the agent's main config — the single place that defines what that machine collects and forwards. Inside it, the `<syscheck>` block controls file integrity monitoring: which directories to watch, how often, and which attributes to check.

**Screenshot: syscheck block before editing**
`![Default syscheck configuration](../images/syscheck-before.png)`

By default it watches system directories like `/etc`, `/usr/bin` and `/boot` on a twelve-hour schedule. I added my own:

```xml
<directories check_all="yes" realtime="yes">/opt/customer-records</directories>
```

`realtime="yes"` means alerts fire on change rather than waiting for the next scheduled scan. `check_all="yes"` watches size, permissions, ownership and a content hash.

**Screenshot: syscheck block with my directory added**
`![Custom directory added](../images/syscheck-after.png)`

### Then it broke

The agent wouldn't restart.

**Screenshot: agent restart failure**
`![Agent failed to start](../images/agent-restart-error.png)`

`journalctl` only told me the process had exited with status 1, which wasn't much help. Testing the config directly was more useful:

```bash
sudo /var/ossec/bin/wazuh-agentd -t
```

```
ERROR: (1226): Error reading XML file 'etc/ossec.conf': (line 0).
```

Line 0 meant the parser had failed immediately rather than choking on a specific structural problem, which suggested a malformed character rather than a missing tag. I checked what I'd actually written:

```bash
sudo grep -n "customer-records" /var/ossec/etc/ossec.conf | cat -A
```

```
111:    <directories check_all="yes" realtime"yes">/opt/customer-records</directories>$
```

There it is. `realtime"yes"` instead of `realtime="yes"`. A missing equals sign.

Fixed it in place rather than reopening the editor:

```bash
sudo sed -i '111s/realtime"yes"/realtime="yes"/' /var/ossec/etc/ossec.conf
```

Config test came back silent, agent restarted, service active.

**One character took the endpoint offline entirely.** For the duration, that machine was sending nothing — no auth logs, no file changes, nothing. If this had been a real host, it would have gone dark and the only sign would have been an agent showing disconnected on the dashboard.

That's a genuinely useful thing to have experienced rather than read about. It's also why the config test exists, and why I'd run it before restarting anything in future.

### Triggering the alerts

Three different kinds of change:

```bash
echo "account: 4417 balance: 999999" | sudo tee /opt/customer-records/accounts.txt
sudo touch /opt/customer-records/passwords.txt
sudo rm /opt/customer-records/passwords.txt
```

A modification, an addition, a deletion.

**Screenshot: syscheck events**
`![File integrity events](../images/syscheck-events.png)`

All three came through:

| Rule | Description | Level |
|---|---|---|
| 550 | Integrity checksum changed | 7 |
| 553 | File deleted | 7 |
| 554 | File added to the system | 5 |

Note the severity split. Modifying or deleting an existing file is level 7; adding a new one is level 5. Wazuh treats changing something that was already there as more significant than creating something new, which is a reasonable default — most attacks alter or destroy existing data rather than simply adding to it.

**Screenshot: event details**
`![FIM alert detail](../images/fim-alert-detail.png)`

**Screenshot: full log showing the modification**
`![File modification full log](../images/fim-full-log.png)`

The fields that matter here are the before and after hashes. FIM computes a checksum of each watched file, so when the file changes you get both values in the alert. That's the difference between knowing a file was touched and proving its contents are different — a timestamp can be changed trivially, a content hash can't.

---

## What this actually taught me

**The agent collects, the manager decides.** Nothing on the endpoint has an opinion about severity. Every judgement — level 5 versus level 10, brute force versus a mistyped password — happens on the server against its rule set. That separation is how any SIEM works and it's much clearer having configured both ends.

**Correlation is where detection gets useful.** Individual events are almost worthless. The 5710 to 5712 escalation is the whole point: a rule that recognises a pattern in events that are individually unremarkable.

**Defaults are a starting position, not an answer.** Wazuh watches `/etc` and `/boot` out of the box. It has no idea `/opt/customer-records` exists or that I care about it. Detection coverage is something you decide and configure, not something you receive.

**Config is fragile and worth testing.** One missing character silenced an endpoint. `wazuh-agentd -t` before a restart costs two seconds.

**My own filters hid an alert from me.** The 5712 hunt was a small thing but a real lesson — the view you build to reduce noise can also remove the thing you're hunting for.

---

## What I'd do next

**Write a custom rule.** Everything above uses Wazuh's built-in detections. Someone else decided eight failures in two minutes is a brute force, and that a changed file is level 7. The next step is deciding something myself and writing the rule for it — for instance, escalating any change in `/opt/customer-records` above the generic FIM severity, on the basis that this specific data matters more than a routine file change. That moves from operating detections to building them.

**Get Windows telemetry in.** Event 4625 and Sysmon are what most environments actually run, and it's the gap in this lab.

**Add Suricata** for network-layer detection alongside the host-based rules.

---

## Environment

| | |
|---|---|
| Hypervisor | VirtualBox on Windows 11 |
| SIEM | Wazuh 4.14.7 (OVA), 8 GB RAM |
| Endpoint | Ubuntu 24.04.4 LTS, Wazuh agent 001 |
| Network | Bridged, 192.168.0.0/24 |
| Detections | Rules 5710, 5712, 550, 553, 554 |
| MITRE techniques | T1110, T1110.001, T1021.004 |
