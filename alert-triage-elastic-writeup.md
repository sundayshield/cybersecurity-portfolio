# Alert Triage with Elastic — TryHackMe Write-Up

| Field          | Details                                              |
|----------------|------------------------------------------------------|
| **Author**     | Linus Yohanna                                        |
| **Date**       | July 2025                                            |
| **Platform**   | TryHackMe                                            |
| **Category**   | SOC / Alert Triage / SIEM                            |
| **Tool**       | Elastic Stack / Kibana (KQL)                         |
| **Status**     | ✅ Completed                                         |

---

## 📌 Objective

Perform structured alert triage using the Elastic Stack (Kibana) — investigating web request anomalies, administrative access events, and privilege escalation activity using KQL (Kibana Query Language) to reach evidence-backed verdicts.

---

## 🛠️ Tools & Technologies

- Elastic Stack (Elasticsearch + Kibana)
- KQL — Kibana Query Language
- Web logs (`weblogs` index)
- Windows Event Logs (winlog)

---

## 🔄 Splunk vs Elastic — Key Differences

| Aspect | Splunk (SPL) | Elastic (KQL) |
|--------|-------------|---------------|
| Value matching | `field=value` | `field:value` |
| AND logic | `AND` (uppercase) or chaining | `and` (lowercase) |
| Time filtering | `earliest=` / `latest=` or UI picker | `@timestamp >= "YYYY-MM-DDThh:mm:ss"` |
| Interface | Search bar + dashboard | Kibana Discover + dashboards |
| Query style | Pipe-based transformations | Filter-based with KQL |

> Both platforms serve the same investigative purpose. The underlying analyst thinking is identical — only the syntax and interface differ.

---

## 🔍 Investigation 1 — Suspicious Web Requests

**Alert type:** Anomalous HTTP activity from a flagged IP address (`203.0.113.55`)

### Step 1: Identify POST request activity

```kql
_index:weblogs and client.ip:203.0.113.55 and http.request.method:POST
```

Returned POST requests from the flagged IP — potential data submission or web shell interaction.

### Step 2: Check for GET requests to suspicious file

```kql
_index:weblogs and client.ip:203.0.113.55 and http.request.method:GET and errorEE.aspx
```

GET requests to `errorEE.aspx` — a suspicious filename consistent with a disguised web shell (attackers often name shells to blend in with error pages).

**Verdict:** ✅ True Positive — Flagged IP interacting with a likely web shell via both POST and GET methods.

---

## 🔍 Investigation 2 — Unauthorized Administrative Access

**Alert type:** Administrator account login outside expected parameters

```kql
@timestamp >= "2025-07-20T05:11:22" and winlog.event_id:4624 and host.name:winserv2019.some.corp and winlog.event_data.TargetUserName:Administrator
```

- **Event ID 4624** = Successful logon
- Filtered to the specific timestamp, host, and Administrator account
- Confirmed a successful login to a production server under the Administrator account at a suspicious time

**Verdict:** ✅ True Positive — Unauthorized administrative access confirmed.

---

## 🔍 Investigation 3 — New User Account Creation

**Alert type:** New account created on a Windows host shortly after the admin access event

```kql
@timestamp >= "2025-07-20T05:13:10.000" and winlog.event.code:4720
```

- **Event Code 4720** = User account created
- Timestamp placed this event approximately 2 minutes after the admin login — consistent with an attacker establishing persistence immediately after gaining access

**Verdict:** ✅ True Positive — Persistence via account creation confirmed. Part of the same attack chain.

---

## 🔍 Investigation 4 — Privilege Escalation via Unusual Command Line

**Alert type:** Suspicious process spawned by `cmd.exe` under the Administrator account

```kql
@timestamp >= "2025-07-20T05:13:15" and process.parent.name:cmd.exe and user.name:Administrator
```

- Queried for processes with `cmd.exe` as parent, running as Administrator
- Returned unusual command-line execution consistent with post-exploitation activity

**Verdict:** ✅ True Positive — Privilege escalation and lateral activity confirmed via command-line analysis.

---

## 🔗 Full Attack Chain Reconstructed

```
Suspicious web request (POST to web shell)
        ↓
GET request confirming web shell execution (errorEE.aspx)
        ↓
Administrator account login (Event ID 4624) — 05:11:22
        ↓
New user account created (Event Code 4720) — 05:13:10
        ↓
Unusual cmd.exe process under Administrator — 05:13:15
```

All four alerts connected into a single, coherent intrusion sequence.

---

## 🧩 Challenges

**KQL syntax adjustment:** Coming from SPL, the shift from `=` to `:` and from pipe-based to filter-based queries required deliberate adjustment. Small syntax differences produce very different results.

**Timestamp-anchored querying:** Learning to anchor queries with `@timestamp >=` to isolate activity within the incident window — rather than searching across all logs — was essential for reducing noise and keeping the investigation focused.

---

## 💡 Key Learnings

1. The triage mindset is platform-agnostic. Whether in Splunk or Elastic, the process is identical: understand the alert, build targeted queries, document evidence, reach a verdict.
2. Timestamps are anchors. In a live investigation, pinning your queries to the incident window prevents you from drowning in unrelated events.
3. Attack chains reveal themselves across multiple Event IDs. No single event tells the whole story — the sequence does.
4. `errorEE.aspx` is a naming pattern worth knowing — attackers disguise web shells as system error pages to avoid detection.
5. Two minutes between admin login and account creation is not a coincidence. Correlation of timing is as important as correlation of fields.

---

## 🌍 Real-World Application

Alert triage in Elastic mirrors exactly what a SOC analyst does in organizations running the Elastic Security stack (widely used in enterprise environments). The skill of pivoting between log sources, chaining event IDs across a timeline, and building a documented verdict from raw logs is foundational to incident response. This room demonstrated that platform fluency in both Splunk and Elastic is a meaningful differentiator for a working analyst.

---

## ➡️ Next Steps

- [ ] Practice building Elastic detection rules to automate alert firing on these patterns
- [ ] Study MITRE ATT&CK: T1078 (Valid Accounts), T1136 (Create Account), T1059 (Command and Scripting Interpreter)
- [ ] Explore Elastic's built-in threat detection rules and how to tune them

---

*Linus Yohanna | Actively exploring the cyber space and building threat intelligence, one layer at a time.*
