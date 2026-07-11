# Alert Triage with Splunk — TryHackMe Write-Up

| Field          | Details                                              |
|----------------|------------------------------------------------------|
| **Author**     | Linus Yohanna                                        |
| **Date**       | July 2025                                            |
| **Platform**   | TryHackMe                                            |
| **Category**   | SOC / Alert Triage / SIEM                            |
| **Tool**       | Splunk (SPL)                                         |
| **Status**     | ✅ Completed                                         |

---

## 📌 Objective

Develop structured alert triage skills using Splunk — investigating real alerts across Linux, Windows, and web log sources to determine whether each represents a true positive, false positive, or requires escalation.

---

## 🛠️ Tools & Technologies

- Splunk SIEM (SPL — Splunk Processing Language)
- Linux authentication logs (`linux-alert` index)
- Windows Event Logs (`win-alert` index)
- Web application logs (`web-alert` index)

---

## 🔬 Triage Methodology

When an alert fires, the process is:

1. **Understand the alert** — What is it telling you? What behaviour triggered it?
2. **Identify the alert type** — Brute force? Privilege escalation? Persistence? Web threat?
3. **Narrow the scope** — Use the alert details (user, IP, timestamp, host) to build targeted queries
4. **Investigate** — Query the relevant log source with precision
5. **Reach a verdict** — True positive, false positive, or escalate with documented evidence

> The alert tells you *what* to look for. Your investigation determines *what actually happened*.

---

## 🔍 Investigation 1 — Brute Force + Privilege Escalation (Linux)

**Alert type:** Multiple failed authentication attempts against a user account

### Step 1: Confirm brute force activity

```spl
index="linux-alert" user="john.smith"
| search "Failed password"
```

High volume of `Failed password` entries confirmed a brute force attempt against `john.smith`.

### Step 2: Check for privilege escalation

```spl
index="linux-alert"
| search "su"
```

`su` activity detected — indicating an attempt (or success) in switching to a higher-privilege account following the brute force.

### Step 3: Check for persistence via account creation

```spl
index="linux-alert"
| search "added"
```

A new user account was added to the system — a classic attacker persistence move after gaining access.

**Verdict:** ✅ True Positive — Brute force → privilege escalation → account creation. Full attack chain confirmed across Linux logs.

---

## 🔍 Investigation 2 — Scheduled Task Creation (Windows)

**Alert type:** Suspicious scheduled task registered on a Windows host

```spl
index="win-alert" EventCode=4698 AssessmentTaskOne
| table _time EventCode user_name host Task_Name Message
```

- **EventCode 4698** = A scheduled task was created
- Filtered to the specific task name to confirm it matched the suspicious activity in the alert
- Returned the creating user, host, task name, and full message for documentation

**Verdict:** ✅ True Positive — Unauthorized scheduled task confirmed as a persistence mechanism.

---

## 🔍 Investigation 3 — Potential Web Shell Upload

**Alert type:** Suspicious POST requests to unusual file paths from a flagged IP

```spl
index=web-alert 171.251.232.40 useragent!="Mozilla/5.0 (Hydra)"
| table _time clientip useragent uri_path referer referer_domain method status
```

- Filtered to the source IP identified in the alert
- Excluded the known Hydra scanner user agent to isolate other suspicious activity
- Revealed POST requests to executable file paths returning 200 OK — web shell behaviour

**Verdict:** ✅ True Positive — Web shell upload activity confirmed from flagged IP.

---

## 🧩 Challenges

**Building precise filters:** The hardest part was constructing queries specific enough to surface the right events without returning thousands of unrelated logs. Too broad = noise. Too narrow = missing evidence.

**Interpreting log fields:** Understanding what each field value means in context — not just that a field exists, but what its value *tells you about the attack* — required deliberate attention.

---

## 💡 Key Learnings

1. Read the alert carefully before opening a single query. The alert defines your investigation scope.
2. Every triage must end with a documented verdict — not a guess, a conclusion supported by evidence.
3. Privilege escalation almost always follows initial access. When you see brute force, keep looking.
4. EventCode 4698 is a high-value Windows detection signal — scheduled task creation is a primary attacker persistence method.
5. Excluding known noise (e.g. Hydra user agent) from queries surfaces the signal faster.

---

## 🌍 Real-World Application

Tier 1 SOC analysts perform alert triage every shift. The workflow here — read alert → query logs → build evidence → reach verdict — is the same process used in live SOC environments. Not every alert is a true positive, but no alert should be closed without investigation. Documentation of findings is what enables incident responders to act.

---

## ➡️ Next Steps

- [ ] Practice writing Splunk correlation searches to chain related events automatically
- [ ] Study MITRE ATT&CK mappings: T1110 (Brute Force), T1053 (Scheduled Task), T1505.003 (Web Shell)
- [ ] Explore Splunk alert thresholds and tuning to reduce false positive volume

---

*Linus Yohanna | Actively exploring the cyber space and building threat intelligence, one layer at a time.*
