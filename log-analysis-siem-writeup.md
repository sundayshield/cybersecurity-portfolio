# Log Analysis with SIEM — TryHackMe Write-Up

| Field          | Details                                              |
|----------------|------------------------------------------------------|
| **Author**     | Linus Yohanna                                        |
| **Date**       | July 2025                                            |
| **Platform**   | TryHackMe                                            |
| **Category**   | SIEM / Log Analysis / Threat Detection               |
| **Room Type**  | Guided — Tasks + Practical Questions                 |
| **Status**     | ✅ Completed                                         |

---

## 📌 Objective

Develop practical log analysis skills using a SIEM platform, covering the benefits of centralized log management, identifying and distinguishing log source types, and performing hands-on threat detection across Windows, Linux, and web application environments using structured query filters.

---

## 🛠️ Tools & Technologies

- Splunk (SIEM platform — in-browser)
- Sysmon (Windows process and network telemetry)
- Windows Event Logs (Security + System channels)
- Linux `auth.log` and system logs
- Web application access logs
- SPL (Splunk Processing Language) for log querying

---

## 📚 Part 1 — Why SIEM? Core Benefits

Before querying a single log, the room established *why* SIEM exists. Three pillars:

### Centralization
Every log from every source — endpoints, network devices, web servers — is collected into one platform. An analyst no longer needs to SSH into individual machines or open log files manually. Everything is searchable from a single interface.

> Without centralization, investigating a single incident could mean hunting across dozens of separate files on dozens of machines. SIEM eliminates that entirely.

### Correlation
SIEM doesn't just store events — it links them. Correlation is the ability to connect separate events across different sources and timelines into a single coherent picture.

**Example:** A remote login event (network log) + a privilege escalation event (auth log) + a new scheduled task created (system log) = a likely intrusion sequence. Individually, each event might look unremarkable. Correlated, they tell a story.

### Historical Events
SIEM stores past events for forensic investigation. When an incident is discovered, analysts need to trace back in time — sometimes days or weeks — to find the initial point of compromise. Historical log retention makes that possible.

---

## 📂 Part 2 — Log Sources Overview

| Log Source Type | Origin | Examples of What It Captures |
|-----------------|--------|------------------------------|
| **Host-Based** | Individual devices (endpoints) | Login attempts, process execution, file changes |
| **Network-Based** | Network devices and traffic | Port scans, unusual external connections, traffic anomalies |
| **Web-Based** | Web application servers | HTTP requests, SQL injection attempts, web shell access |

### Host-Based — Key Use Case
Detecting brute force against a local system: multiple failed login attempts from a single source in a short window, followed (or not) by a successful authentication.

### Network-Based — Key Use Case
Detecting port scanning: a single external IP sending connection requests across many ports in rapid succession — a reconnaissance pattern before an attack.

### Web-Based — Key Use Case
Detecting web shell exploitation: HTTP POST requests to unexpected `.php`, `.asp`, or `.jsp` file paths that return 200 OK status codes — indicating an attacker has uploaded and is executing server-side scripts.

---

## 🪟 Part 3 — Windows Log Analysis

Two primary data sources were used: **Sysmon** and **Windows Event Logs**.

---

### 3A — Sysmon Analysis

Sysmon provides granular telemetry on Windows process activity and network connections. Event Codes are the key to filtering precisely.

#### Event Code 1 — Process Creation (Malicious Process Execution)

Any time a process launches on a Windows machine, Sysmon logs it with Event Code 1. This is essential for detecting malware execution, suspicious scripts, or attacker tools running on an endpoint.

```spl
index=win-101 EventCode=1
| table _time ComputerName ParentUser ParentImage ParentCommandLine Image CommandLine
```

**What to look for:** Unusual `ParentImage` → `CommandLine` relationships. For example: `Word.exe` spawning `cmd.exe` or `PowerShell.exe` — a classic macro-based malware execution pattern.

---

#### Event Code 3 — Network Connection

Logs every outbound or inbound network connection initiated by a process. Used to detect C2 (command-and-control) beaconing, lateral movement, or data exfiltration.

```spl
index=win-101 EventCode=3
| table _time ComputerName Image DestinationIp DestinationPort
```

**What to look for:** A process that has no business making network connections (e.g. `notepad.exe`, `calc.exe`) establishing an outbound connection to an external IP.

---

### 3B — Windows Event Log Analysis

#### Windows Security Logs — Account Activity

| Event Code | Meaning | Analyst Use |
|------------|---------|-------------|
| `4720` | New user account created | Detect unauthorized account creation — persistence mechanism |
| `4722` | User account enabled | An attacker may re-enable a disabled account to regain access |

#### Windows System Logs — Service Activity

| Event Code | Meaning | Analyst Use |
|------------|---------|-------------|
| `7036` | Service started or stopped | Baseline changes — detect unexpected service starts |
| `7045` | New service installed | Attackers install services (malware, RATs) as persistence; also covers scheduled tasks |

> **Key insight:** Event Code 7045 is a high-value detection signal. Legitimate software rarely installs new Windows services silently. An unexpected 7045 event — especially for a service with a random or suspicious name — warrants immediate investigation.

---

## 🐧 Part 4 — Linux Log Analysis

Two primary log sources were analyzed: `auth.log` and system logs.

---

### 4A — auth.log

Captures all authentication activity: SSH logins, `sudo` usage, `su` (switch user) commands, and PAM events.

#### Detecting Brute Force / Login Attempts

```spl
index=linux source="auth.log" process=sshd
| search "Accepted password" OR "Failed password"
```

**What to look for:** A high volume of `Failed password` entries from a single IP in a short timeframe, followed by a single `Accepted password` — the signature of a successful brute force attack.

#### Detecting Privilege Escalation

```spl
index=linux source="auth.log" *su*
| sort + _time
```

**What to look for:** A standard user account suddenly using `su` or `sudo` to gain root-level privileges — especially if the account has no business requiring elevated access, or if this activity occurs at an unusual hour.

---

### 4B — System Logs — Persistence Mechanisms

System logs capture scheduled tasks (cron jobs) and service registrations — two of the most common attacker persistence techniques on Linux.

**What to look for in cron entries:**

Any cron job referencing executable file types that shouldn't appear in a scheduled context:

```
.sh  |  .py  |  .pl  |  .rb  |  bash  |  nc  |  python  |  perl  |  ruby
```

A cron job calling `nc` (netcat) or a reverse shell script is a major red flag — attackers use these to maintain persistent remote access even if their initial entry point is patched.

---

## 🌐 Part 5 — Web Application Log Analysis

Three threat scenarios were covered, each with a distinct log signature.

---

### 5A — Brute Force (HTTP POST)

**Signature:** Hundreds of POST requests to a login endpoint from a single IP within minutes.

**Real case observed:** 160 login attempts to `/wp-login.php` within a 5-minute window from one IP.

```spl
index=* method=POST uri_path="/wp-login.php"
| bin _time span=5m
| stats values(referer_domain) as referer_domain
        values(status) as status
        values(useragent) as UserAgent
        values(uri_path) as uri_path
        count by clientip _time
| where count > 25
| table referer_domain clientip UserAgent uri_path count status
```

**Tool identified in investigation:** WPScan — a WordPress vulnerability scanner used by the attacker to conduct the brute force.

---

### 5B — Web Shell Detection

**Signature:** POST or GET requests to executable script file extensions (`.php`, `.asp`, `.jsp`, etc.) returning HTTP 200 — meaning the server successfully executed the uploaded file.

```spl
index=*
| search status=200 AND uri_path IN (*.php, *.phtm, *.asp, *.aspx, *.jsp, *.exe)
          AND (method=POST OR method=GET)
| stats values(status) as status
        values(useragent) as UserAgent
        values(method) as method
        values(uri) as uri
        values(clientip) as clientip
        count by referer_domain
| where count > 2
| table referer_domain count method status clientip UserAgent uri
```

**What to look for:** File paths with unusual names, scripts in directories that shouldn't contain executable files, and POST requests returning 200 to `.php` or `.asp` files that weren't part of the legitimate application.

---

### 5C — DDoS Detection

**Signature:** An overwhelming volume of requests to a specific endpoint from one or few IPs, causing 503 (Service Unavailable) responses — the server is collapsing under load.

**Real case observed:** Over 100,000 requests from a single IP within a 10-minute window.

```spl
index=* status=503
| bin _time span=10m
| stats values(referer_domain) as referer_domain
        values(status) as status
        values(useragent) as UserAgent
        values(uri_path) as uri_path
        count by clientip _time
| where count > 100000
| table _time referer_domain clientip UserAgent uri_path count status
```

**Distinction from normal traffic:** Legitimate users produce varied IPs, varied user agents, varied URI paths, and spread-out timing. DDoS traffic shows: one or few IPs, identical or rotated user agents, same URI path, and request counts that are orders of magnitude beyond normal.

---

## 🔍 Part 6 — Hands-On Investigation Summary

The room included a practical investigation component. Key findings from log queries:

| Investigation Task | Method Used | Finding |
|--------------------|-------------|---------|
| Identify DDoS source IP | `status=503` + count threshold | Single IP with 100k+ requests in 10 min |
| Identify URI with highest requests | Web log analysis | Login/admin endpoint targeted |
| Identify attacker tool | UserAgent field analysis | **WPScan** detected in brute force logs |
| Confirm SSH account creation | `auth.log` + "Accepted password" | Remote-SSH account successfully authenticated |
| Detect privilege escalation | `auth.log` + `*su*` | Account escalated to root via `su` |
| Count failed login attempts before success | Failed/Accepted pattern | Number of failed attempts before breach confirmed |
| Identify C2 connection IP | Sysmon `EventCode=3` | Destination IP of suspicious outbound connection found |
| Identify initiating process | Sysmon `EventCode=1` | Process responsible for malicious execution identified |
| Retrieve MD5 hash for threat research | Sysmon process logs | Hash extracted for VirusTotal lookup |
| Detect scheduled task creation | Windows `EventCode=7045` | Persistence mechanism via new service/task confirmed |

---

## 🧩 Challenges & How I Solved Them

**Challenge 1: Volume and variety of Event Codes**
Windows Event Codes number in the hundreds. Knowing which ones matter — and what each one reveals — felt overwhelming at first.

**Resolution:** Focused on understanding the *category* each code belongs to (account activity, service activity, process activity) rather than memorizing individual codes. That framework makes it easier to know where to look when a specific behavior is suspected.

**Challenge 2: SPL filter construction**
Building accurate Splunk queries across different log sources required understanding both the SPL syntax and the specific field names available in each log type.

**Resolution:** Worked through each filter methodically, starting with the broadest search, then adding field filters, then stats and thresholds. Understanding *why* each line exists in a query is more valuable than memorizing the query itself.

---

## 💡 Key Learnings

1. **Logs give you direction.** Every attack leaves a trail — logs are that trail. The analyst's job is to follow it back to the root cause. Logs aren't the answer; they're the map.

2. **Logs are noisy, not useless.** Raw logs are overwhelming. But properly filtered and structured, they surface exactly what you need. The skill isn't reading logs — it's knowing how to query them.

3. **Filtering precision determines investigation quality.** A poorly constructed query drowns you in irrelevant data. A precise one surfaces the one event that matters. The filter is as important as the finding.

4. **Know your source before you search.** Whether you're hunting in `auth.log`, Windows Security logs, or web access logs — each has its own structure, field names, and threat patterns. Knowing which log to search is half the work.

5. **You don't need to memorize every filter — you need to understand every problem.** The right filter follows naturally once you understand what behavior you're looking for. Pattern recognition and analytical thinking outweigh memorization.

---

## 🌍 Real-World Application

A Tier 1 SOC analyst spends a significant portion of every shift reading and querying logs. This room reflects that reality directly.

What separates an effective analyst from an overwhelmed one isn't how many Event Codes they've memorized — it's whether they can define the problem first, then construct the right query to surface it. An analyst who understands that `auth.log` is the right place to look for privilege escalation, or that `EventCode=1` surfaces process creation, can investigate efficiently even in an unfamiliar environment.

The skills built in this room — log source identification, targeted SPL querying, threat pattern recognition across Windows, Linux, and web layers — map directly to the daily workflow of a blue team analyst performing alert triage, threat hunting, and incident investigation.

---

## ➡️ Next Steps

- [ ] Practice more complex SPL queries — joins, lookups, subsearches
- [ ] Explore Splunk alert creation — automate detection of the patterns studied here
- [ ] Study MITRE ATT&CK mappings for each technique observed (brute force = T1110, scheduled task = T1053, web shell = T1505.003)
- [ ] Complete a hands-on incident response room that builds on these log analysis skills

---

## 📎 References

- [TryHackMe — Log Analysis with SIEM](https://tryhackme.com)
- [Splunk SPL Documentation](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference)
- [Sysmon Event IDs Reference — Microsoft](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
- [Windows Security Event IDs — Microsoft](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/appendix-l--events-to-monitor)
- [MITRE ATT&CK — Persistence Techniques](https://attack.mitre.org/tactics/TA0003/)

---

*Linus Yohanna | Actively exploring the cyber space and building threat intelligence, one layer at a time.*
