# ItsyBitsy — TryHackMe Challenge Write-Up

| Field          | Details                                              |
|----------------|------------------------------------------------------|
| **Author**     | Linus Yohanna                                        |
| **Date**       | July 2025                                            |
| **Platform**   | TryHackMe                                            |
| **Category**   | SOC Challenge / Threat Hunting / C2 Detection        |
| **Tool**       | Elastic Stack / Kibana (KQL)                         |
| **Difficulty** | Medium                                               |
| **Status**     | ✅ Completed                                         |

---

## 📌 Scenario

A user in the HR department (identified as **BROWN**) triggered a suspicious activity alert. The investigation objective: determine whether BROWN's machine was involved in Command and Control (C2) communication — an attacker maintaining a persistent, covert channel to a compromised endpoint.

---

## 🛠️ Tools Used

- Elastic Stack / Kibana
- KQL (Kibana Query Language)
- Network/web log analysis
- File-sharing site traffic analysis

---

## 🔬 Investigation Walkthrough

### Step 1: Scope the Investigation — March 2022

The first action was narrowing the investigation to the confirmed incident timeframe: **March 2022**. Searching across all time creates noise. A scoped time window keeps the investigation surgical.

```kql
@timestamp >= "2022-03-01T00:00:00" and @timestamp <= "2022-03-31T23:59:59"
```

Confirmed log volume for the period and established the baseline for the investigation.

---

### Step 2: Identify the Consistent External IP

C2 communication has a signature: **repeated, consistent connections to the same external IP** over time. Legitimate user traffic is varied. C2 beaconing is rhythmic and repetitive.

Queried network logs for BROWN's machine and identified a single external IP making repeated contact — the likely C2 server.

---

### Step 3: Identify the Binary Used

From the consistent IP, drilled down to identify **what process or binary** on BROWN's machine was initiating the outbound connection. This revealed the tool the attacker had deployed to maintain the C2 channel.

---

### Step 4: Trace the Download Source

Pivoted from the binary to identify **where it was downloaded from** — narrowed to a specific file-sharing site. This is a common attacker delivery method: hosting malicious payloads on legitimate-looking file-sharing platforms to avoid URL blocklists.

---

### Step 5: Retrieve the Full Download URL

Extracted the complete URI from the logs — the exact URL used to deliver the payload to BROWN's machine.

---

### Step 6: Access the URI — Identify the File and Secret Code

Accessed the URL to identify the file associated with the download and retrieve the embedded secret code, confirming the nature of the payload.

---

## 🔗 Attack Chain — Reconstructed

```
BROWN (HR) machine initiates outbound connection
        ↓
Repeated contact with consistent external IP — C2 beacon pattern
        ↓
Binary identified — attacker's tool deployed on endpoint
        ↓
Binary traced to file-sharing site — delivery mechanism confirmed
        ↓
Full download URL recovered from logs
        ↓
File and secret code identified — C2 payload confirmed
```

---

## 🏁 Verdict

**True Positive — Active C2 Communication Confirmed**

BROWN's machine in the HR department had been compromised. An attacker deployed a binary via a file-sharing platform and established a Command and Control channel, maintaining covert persistent access to the endpoint. The full delivery chain — from download source to running payload — was traced and documented through log analysis.

---

## 🧩 Challenges

**Identifying the C2 pattern in noisy network logs:** C2 beaconing can look like regular traffic at first glance. The tell is consistency — same destination IP, regular intervals, same process initiating the connection. Training the eye to spot repetition in network logs is a skill built through deliberate investigation.

---

## 💡 Key Learnings

1. **C2 communication hides in repetition.** Normal user traffic is varied. Beaconing is rhythmic. Counting connection frequency by destination IP is a fast way to surface C2 candidates.
2. **File-sharing sites are a common delivery vector.** Attackers use them because they're trusted domains — URL filters often whitelist them. Looking past the domain to the specific URI is essential.
3. **Scope your time window first.** Every investigation should start with narrowing to the incident period. Broad searches waste time and dilute findings.
4. **The binary tells you the capability.** Identifying what was downloaded tells you what the attacker can do — keylogging, screen capture, reverse shell, data exfiltration. The file is the threat profile.

---

## 🌍 Real-World Application

C2 detection is one of the most critical functions of a SOC. Attackers who establish C2 channels can maintain long-term persistent access, exfiltrate data slowly, and move laterally across a network — all while remaining under detection thresholds. This challenge mirrors the investigation a Tier 2 analyst would conduct when escalated a suspected C2 alert: scope the timeframe, identify the beaconing pattern, trace the payload, and document the full chain for incident response.

---

## 📎 References

- [MITRE ATT&CK — T1071: Application Layer Protocol (C2)](https://attack.mitre.org/techniques/T1071/)
- [MITRE ATT&CK — T1105: Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105/)

---

*Linus Yohanna | Actively exploring the cyber space and building threat intelligence, one layer at a time.*
