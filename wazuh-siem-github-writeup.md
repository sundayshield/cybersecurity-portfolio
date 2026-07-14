# Wazuh SIEM Setup, VirusTotal Integration & Active Response

> **Platform:** TS Academy (Practical Lab) · **Category:** SIEM / EDR · **Environment:** Local VMs · **Status:** ✅ Completed

---

## Table of Contents

- [Objective](#objective)
- [Environment](#environment)
- [Phase 1 — Server Setup](#phase-1--server-setup-kali-linux)
- [Phase 2 — Agent Enrollment](#phase-2--agent-enrollment-ubuntu)
- [Phase 3 — VirusTotal Integration](#phase-3--virustotal-integration)
- [Phase 4 — Real-Time FIM Configuration](#phase-4--real-time-file-integrity-monitoring-fim)
- [Phase 5 — Malware Simulation](#phase-5--malware-simulation--eicar-test-file)
- [Phase 6 — Active Response](#phase-6--active-response--automated-threat-removal)
- [Key Findings](#key-findings)
- [Challenges](#challenges--how-i-solved-them)
- [Key Learnings](#key-learnings)
- [Real-World Application](#real-world-application)
- [Next Steps](#next-steps)
- [References](#references)

---

## Objective

Deploy a fully functional Wazuh SIEM environment from scratch, enroll an endpoint agent, integrate VirusTotal for real-time malware intelligence, configure real-time file integrity monitoring, and implement automated active response to neutralize detected threats — simulating a functional SOC detection and response pipeline.

---

## Environment

| Role | OS | Purpose |
|------|----|---------|
| Wazuh Server | Kali Linux | SIEM manager, dashboard, alerting |
| Wazuh Agent | Ubuntu | Monitored endpoint |

- **Deployment:** Local VMs (not cloud-based)
- **Wazuh Version:** Latest stable (6.x)
- **Network:** Agent connected to server via local IP

### Tools & Technologies

| Tool | Purpose |
|------|---------|
| Wazuh SIEM (Manager + Agent + Dashboard) | Core SIEM platform |
| VirusTotal API | Threat intelligence integration |
| EICAR test file (`eicar.com`) | Malware simulation |
| Bash (`remove-threat.sh`) | Active response scripting |
| `curl` | Package download and malware simulation |
| `ossec.conf` | Wazuh main configuration file |

---

## Phase 1 — Server Setup (Kali Linux)

Prepare the Kali Linux machine to host the Wazuh manager.

```bash
# Step 1: Update the system
sudo apt update && sudo apt upgrade -y

# Step 2: Install curl
sudo apt install curl -y

# Step 3: Download and install Wazuh manager
curl -sO https://packages.wazuh.com/4.x/wazuh-install.sh
sudo bash ./wazuh-install.sh -a
```

After installation, Wazuh automatically generates login credentials. Access the dashboard via:

```
https://[SERVER-IP]
```

---

## Phase 2 — Agent Enrollment (Ubuntu)

From the Wazuh dashboard, navigate to **Deploy Agent** and configure:

| Field | Value |
|-------|-------|
| Package Type | DEB |
| Architecture | AMD64 |
| Server Address | [Kali Linux local IP] |
| Agent Name | [Custom label for Ubuntu VM] |

The dashboard generates an enrollment script. Execute it on the Ubuntu machine:

```bash
# Run on Ubuntu agent
sudo WAZUH_MANAGER='[SERVER-IP]' WAZUH_AGENT_NAME='[AGENT-NAME]' \
  apt-get install wazuh-agent

# Enable and start the agent service
sudo systemctl daemon-reload
sudo systemctl enable wazuh-agent
sudo systemctl start wazuh-agent
```

✅ **Confirmation:** Ubuntu agent appears as **Active** on the Wazuh dashboard.

---

## Phase 3 — VirusTotal Integration

Integrate the VirusTotal API so every detected file hash is automatically cross-referenced against 70+ antivirus engines.

**Step 1:** Create a free account at [virustotal.com](https://virustotal.com) and retrieve your API key.

**Step 2:** Edit the Wazuh manager configuration file:

```bash
sudo nano /var/ossec/etc/ossec.conf
```

**Step 3:** Add the integration block inside `<ossec_config>`:

```xml
<integration>
  <name>virustotal</name>
  <api_key>YOUR_VIRUSTOTAL_API_KEY</api_key>
  <rule_id>550, 554</rule_id>
  <alert_format>json</alert_format>
</integration>
```

> **How it works:** When Wazuh's FIM detects a new or modified file, it extracts the file hash and submits it to VirusTotal. VirusTotal returns a verdict — clean or malicious — with a direct link to the full scan report.

---

## Phase 4 — Real-Time File Integrity Monitoring (FIM)

Configure Wazuh to monitor the filesystem in real-time with a 2-minute scan frequency.

**File:** `/var/ossec/etc/ossec.conf`

```xml
<syscheck>

  <!-- Default is 43200 seconds (12 hours). Set to 120 seconds (2 minutes) for testing -->
  <frequency>120</frequency>

  <!-- Enable real-time monitoring on critical directories -->
  <directories realtime="yes">/root</directories>
  <directories realtime="yes">/home</directories>
  <directories realtime="yes">/tmp</directories>

</syscheck>
```

> **Note:** `frequency` is in seconds. `realtime="yes"` enables event-driven monitoring — changes are detected instantly rather than waiting for the next scheduled scan.

Restart the manager to apply changes:

```bash
sudo systemctl restart wazuh-manager
```

---

## Phase 5 — Malware Simulation — EICAR Test File

Download the EICAR test file to the Ubuntu agent to validate the full detection pipeline:

```bash
curl -Lo /root/eicar.com https://secure.eicar.org/eicar.com
```

**What happened:**

- Wazuh FIM detected the new file in `/root` immediately (real-time active)
- File hash submitted to VirusTotal automatically
- Alert fired on the Wazuh dashboard — file flagged as malicious
- Alert included a direct VirusTotal link with full scan verdict

**Detection chain confirmed:**

```
File dropped → FIM detects → Hash submitted → VirusTotal flags → Alert fires
```

---

## Phase 6 — Active Response — Automated Threat Removal

Build an automated response that removes confirmed malicious files without manual intervention.

### Step 1 — Write the Removal Script (Ubuntu Agent)

```bash
sudo nano /var/ossec/active-response/bin/remove-threat.sh
```

```bash
#!/bin/bash
# remove-threat.sh
# Removes files flagged as malicious by Wazuh + VirusTotal

LOCAL=`dirname $0`
cd $LOCAL
cd ../
PWD=`pwd`

read INPUT_JSON
FILENAME=$(echo $INPUT_JSON | python3 -c \
  'import sys, json; data = json.load(sys.stdin); \
   print(data["parameters"]["alert"]["syscheck"]["path"])')

echo "$(date '+%Y/%m/%d %H:%M:%S') Removing threat: $FILENAME" \
  >> ${PWD}/logs/active-responses.log

rm -f "$FILENAME"

if [ $? -eq 0 ]; then
  echo "$(date '+%Y/%m/%d %H:%M:%S') Successfully removed: $FILENAME" \
    >> ${PWD}/logs/active-responses.log
else
  echo "$(date '+%Y/%m/%d %H:%M:%S') Failed to remove: $FILENAME" \
    >> ${PWD}/logs/active-responses.log
fi
```

### Step 2 — Set Permissions

```bash
# Make executable
sudo chmod 750 /var/ossec/active-response/bin/remove-threat.sh

# Set correct ownership
sudo chown root:wazuh /var/ossec/active-response/bin/remove-threat.sh
```

### Step 3 — Register Command and Active Response in `ossec.conf`

```xml
<!-- Define the command -->
<command>
  <name>remove-threat</name>
  <executable>remove-threat.sh</executable>
  <timeout_allowed>no</timeout_allowed>
</command>

<!-- Bind to VirusTotal positive verdict rule -->
<active-response>
  <command>remove-threat</command>
  <location>local</location>
  <rules_id>87105</rules_id>
</active-response>
```

> **Rule 87105** fires when VirusTotal returns a positive malware verdict. Binding the response to this rule ensures the script only triggers on confirmed threats.

Restart to apply:

```bash
sudo systemctl restart wazuh-manager
```

**End-to-end response chain:**

```
File dropped → FIM detects → VirusTotal flags → Rule 87105 fires → remove-threat.sh executes → File deleted
```

---

## Key Findings

| Finding | Result |
|---------|--------|
| Wazuh server + agent connection | ✅ Fully connected and communicating |
| VirusTotal integration | ✅ Hashes submitted, verdicts returned on detection |
| EICAR malware detection | ✅ Flagged immediately with VirusTotal link in alert |
| Active response | ✅ Malicious file automatically removed on rule trigger |
| Real-time FIM | ✅ File changes detected without delay |

---

## Challenges & How I Solved Them

**Challenge 1 — Kali Linux VM performance**

The Wazuh server failed to run properly on initial setup. Root cause: insufficient CPU allocation.

**Resolution:** Increased VM CPU allocation to 4 cores. Server stabilized and dashboard became accessible.

---

**Challenge 2 — Navigating `ossec.conf`**

The configuration file is large and densely structured. Locating the correct sections (`<syscheck>`, `<integration>`, `<active-response>`) and understanding the syntax hierarchy required deliberate effort.

**Resolution:** Studied the file structure carefully before editing. Established a habit of restarting the manager after every change to validate syntax — a single misconfiguration stops the entire service.

---

## Key Learnings

1. **Alerts are only as good as your rules.** Wazuh only flags what it has rules for. Keeping detection rules current is an active, ongoing responsibility — not a one-time setup.

2. **Configuration precision is non-negotiable.** A single syntax error in `ossec.conf` can bring the entire Wazuh manager down. Methodical editing and post-change restarts are essential discipline.

3. **Hash-based threat intelligence is a force multiplier.** Submitting file hashes to VirusTotal and receiving verdicts from 70+ engines in real time turns a raw file system alert into actionable intelligence instantly.

4. **Detection without response is incomplete.** Automating the removal of confirmed threats closes the loop. A SOC doesn't just observe — it responds.

5. **Real-time monitoring and scheduled scans are fundamentally different.** Understanding `realtime="yes"` vs. `frequency` clarifies how FIM actually works — and why real-time detection speed matters in a live environment.

---

## Real-World Application

This lab mirrors a core function in real SOC environments: deploying and maintaining endpoint monitoring infrastructure. Wazuh is used by security teams globally as an open-source SIEM and EDR platform, particularly in organizations building cost-effective detection capabilities.

The VirusTotal integration replicates how SOC analysts perform **automated indicator enrichment** — converting raw file detections into threat intelligence without manual lookups. The active response pipeline demonstrates **automated containment**, a key component of modern incident response playbooks.

A junior SOC analyst or security engineer is expected to enroll agents, tune FIM policies, interpret SIEM alerts, and escalate or automate responses — all of which this lab covers directly.

---

## Next Steps

- [ ] Explore Wazuh's built-in rule set and write custom detection rules
- [ ] Test active response against more sophisticated malware samples
- [ ] Integrate a Windows VM as a second agent for cross-platform monitoring comparison
- [ ] Explore Wazuh's MITRE ATT&CK mapping for detected alerts
- [ ] Investigate log aggregation — forwarding system logs into Wazuh for broader visibility

---

## References

- [Wazuh Official Documentation](https://documentation.wazuh.com)
- [VirusTotal API Documentation](https://developers.virustotal.com/reference)
- [EICAR Test File](https://www.eicar.org/download-anti-malware-testfile/)
- [Wazuh Active Response Documentation](https://documentation.wazuh.com/current/user-manual/capabilities/active-response/)
- Wazuh Rule 87105 — VirusTotal: File marked as malicious

---

*Linus Yohanna | Actively exploring the cyber space and building threat intelligence, one layer at a time.*
