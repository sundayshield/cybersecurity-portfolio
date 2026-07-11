# Benign — TryHackMe Challenge Write-Up

| Field          | Details                                              |
|----------------|------------------------------------------------------|
| **Author**     | Linus Yohanna                                        |
| **Date**       | July 2025                                            |
| **Platform**   | TryHackMe                                            |
| **Category**   | SOC Challenge / Threat Hunting / Insider Threat      |
| **Tool**       | Splunk (SPL)                                         |
| **Difficulty** | Medium                                               |
| **Status**     | ✅ Completed                                         |

---

## 📌 Scenario

An alert flagged suspicious activity originating from the **HR department**. The challenge: investigate Windows process execution logs to identify a compromised host, trace attacker activity, and expose a sophisticated impersonation technique used to create a deceptive user account designed to blend into the organization.

---

## 🛠️ Tools Used

- Splunk (SPL)
- Windows Event Logs (`win_eventlogs` index)
- Process execution analysis (Event ID 4688)
- Keyword-based hunting (`schtasks`, `certutil`)

---

## 🔬 Investigation Walkthrough

### Step 1: Scope the Investigation — March 2022

```spl
index=win_eventlogs EventCode=4688 earliest="2022-03-01" latest="2022-03-31"
```

- **Event ID 4688** = A new process was created
- Narrowed to March 2022 to contain the investigation to the confirmed incident window
- Established baseline process execution volume for the period

---

### Step 2: Review Usernames — Identify Imposter Account

Pulled all unique usernames from process execution logs during the incident window:

```spl
index=win_eventlogs EventCode=4688 earliest="2022-03-01" latest="2022-03-31"
| stats count by user
```

**Critical finding:** A username nearly identical to a legitimate Marketing department user was present.

- Legitimate account: **Amelia** (Marketing)
- Attacker-created account: **Ame1ia** (lowercase `l` replaced with `1`, `i` replaced with `l`)

> This is a **character substitution impersonation attack** — a deliberate technique where attackers create accounts visually indistinguishable from legitimate ones at a glance. In a busy SOC or IT environment, `Amelia` and `Ame1ia` look identical without careful inspection.

---

### Step 3: Detect Scheduled Task Creation — Persistence

```spl
index=win_eventlogs earliest="2022-03-01" latest="2022-03-31"
| search "schtasks"
```

- `schtasks` keyword identified in process command lines
- The compromised user (HR — **Chris**) was running scheduled tasks — a persistence mechanism to ensure continued access even after reboots or session termination

---

### Step 4: Detect Payload Download via certutil

```spl
index=win_eventlogs earliest="2022-03-01" latest="2022-03-31"
| search "certutil"
```

**`certutil`** is a legitimate Windows certificate management tool — but it is widely abused by attackers to download files from the internet because:
- It is a native Windows binary (Living Off the Land — LOLBin)
- It can bypass certain security controls that block conventional download tools
- Security products that whitelist system binaries may not flag it

The query confirmed `certutil` was used to download an executable payload from a third-party site onto the compromised host.

---

### Step 5: Identify the Payload and Third-Party Site

From the `certutil` process execution logs, extracted:
- The **third-party hosting site** used to deliver the payload
- The **filename** of the downloaded executable

---

## 🔗 Full Attack Chain — Reconstructed

```
Chris (HR Department) — compromised host
        ↓
Attacker creates persistence via scheduled tasks (schtasks)
        ↓
Attacker creates fake user account:
  Legitimate: Amelia (Marketing)
  Fake:       Ame1ia — character substitution impersonation
        ↓
Attacker downloads executable payload using certutil
  (LOLBin abuse — bypasses security controls)
        ↓
Payload delivered from third-party file-sharing site
        ↓
Executable deployed — full attacker foothold established
```

---

## 🏁 Verdict

**True Positive — Compromised Host with Active Attacker Activity**

The infected host originated from the HR department — user **Chris**. The attacker used Chris's access to:

1. Establish persistence via scheduled tasks
2. Create a deceptive impersonator account (`Ame1ia`) designed to blend into the Marketing department
3. Download a malicious executable using `certutil` to bypass security controls

The "benign" in the challenge name refers to how the activity appeared on the surface — a Windows binary (`certutil`) performing what looks like a routine task. The malicious intent only becomes clear through full log investigation.

---

## 🧩 Challenges

**Spotting the impersonation:** The character substitution attack (`l` → `1`, `i` → `l`) is genuinely easy to miss at speed. It requires careful, deliberate review of usernames — not a quick scan.

**Understanding certutil abuse:** Recognizing `certutil` as a legitimate tool being weaponized — rather than flagging it as obviously malicious — required understanding the concept of Living Off the Land Binaries (LOLBins). The tool itself isn't the threat; the context of its use is.

---

## 💡 Key Learnings

1. **Know your departments and their users.** Threat intelligence starts with knowing what normal looks like. An analyst who knows Marketing uses `Amelia` catches `Ame1ia` immediately. One who doesn't may miss it entirely.
2. **Character substitution is a real and dangerous technique.** Attackers rely on human visual pattern matching being imprecise. `0` vs `O`, `1` vs `l`, `rn` vs `m` — these are active tradecraft.
3. **LOLBins are a primary evasion technique.** `certutil`, `mshta`, `regsvr32`, `wmic` — native Windows tools used maliciously. Knowing which legitimate binaries are commonly abused is essential analyst knowledge.
4. **Keyword searches are powerful pivots.** Searching for `schtasks` and `certutil` across process logs surfaces attacker behaviour quickly when you know what to hunt for.
5. **Don't guess — build evidence.** The answer to every investigation question must be supported by a specific log entry, timestamp, or field value. In a real SOC, you give facts to incident responders, not assumptions.

---

## 🌍 Real-World Application

This challenge reflects two of the most underappreciated threats in real environments: **insider threat scenarios** (or compromised internal accounts) and **LOLBin abuse**. Both are hard to detect precisely because they involve legitimate-looking activity from trusted systems.

The impersonation technique documented here has been used in real APT campaigns and business email compromise (BEC) attacks. An analyst who understands this technique, knows to carefully read usernames, and knows which native binaries are commonly weaponized is a significantly more effective defender.

---

## 📎 References

- [MITRE ATT&CK — T1036: Masquerading](https://attack.mitre.org/techniques/T1036/)
- [MITRE ATT&CK — T1053: Scheduled Task/Job](https://attack.mitre.org/techniques/T1053/)
- [MITRE ATT&CK — T1218: System Binary Proxy Execution (certutil)](https://attack.mitre.org/techniques/T1218/)
- [LOLBAS Project — certutil](https://lolbas-project.github.io/lolbas/Binaries/Certutil/)

---

*Linus Yohanna | Actively exploring the cyber space and building threat intelligence, one layer at a time.*
