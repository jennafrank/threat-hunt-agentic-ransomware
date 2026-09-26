<div align="center">

# 🤖💋 JADEPUFFER: Hunting the First Agentic Ransomware

**One sentence of instruction. Seventeen minutes. Zero hands on the keyboard.**<br/>
*A threat hunt on an autonomous LLM agent that ran a full ransomware operation end to end, and the telemetry that exposed it.*

[![Microsoft Sentinel](https://img.shields.io/badge/Microsoft_Sentinel-FF1493?style=flat-square&logo=microsoftazure&logoColor=white&labelColor=0d1117)](report/JADEPUFFER_ThreatHuntReport.md)
[![KQL](https://img.shields.io/badge/KQL-FF1493?style=flat-square&labelColor=0d1117)](report/JADEPUFFER_ThreatHuntReport.md#appendix-a-kql-queries-used)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE_ATT%26CK-FF1493?style=flat-square&labelColor=0d1117)](#-mitre-attck-coverage)
[![Agentic AI](https://img.shields.io/badge/Agentic_AI-FF1493?style=flat-square&labelColor=0d1117)](report/JADEPUFFER_ThreatHuntReport.md#10-autonomy-analysis-was-a-human-doing-this)
[![Detection Engineering](https://img.shields.io/badge/Detection_Engineering-FF1493?style=flat-square&labelColor=0d1117)](#-detection-takeaways)

[![Severity](https://img.shields.io/badge/Severity-HIGH-FF1493?style=flat-square&labelColor=0d1117)](report/JADEPUFFER_ThreatHuntReport.md)
[![Status](https://img.shields.io/badge/Status-Confirmed_Incident-FF1493?style=flat-square&labelColor=0d1117)](report/JADEPUFFER_ThreatHuntReport.md)
[![License: MIT](https://img.shields.io/badge/License-MIT-FF1493?style=flat-square&labelColor=0d1117)](LICENSE)

### 📄 [Read the full report →](report/JADEPUFFER_ThreatHuntReport.md)

</div>

---

## 💅 The Short Version

Somebody typed one sentence into an AI agent:

> *"Gain access to the Flowforge estate, locate and encrypt the most business-critical datastore, and leave payment instructions."*

Then they walked away. The agent did the rest.

It exploited an unauthenticated RCE in Langflow (**CVE-2025-3248**), dumped every API key it could find, swept the subnet, walked into MinIO with factory-default creds, forged a Nacos admin token using a signing key that hasn't changed since 2020, **fixed its own broken exploit in 31 seconds**, then encrypted a production database and dropped the originals. It wrote its own ransom note, and it never saved the key.

I hunted it through Microsoft Sentinel in the **Log(N) Pacific cyber range** as a PacificWatch SOC analyst. This repo is the full write-up: the timeline, the KQL, the ATT&CK mapping, and the detection logic that separates an autonomous agent from the normal noise.

## 🔍 What I Found

<div align="center">

| ⏱️ **17 min** | 🖥️ **4** | 🔒 **1,342** | 🔑 **8** | 🩹 **31 sec** |
|:---:|:---:|:---:|:---:|:---:|
| exploit → ransom note | hosts compromised | records encrypted | credential families stolen | agent's failure-to-fix time |

</div>

- **The agent narrated its own attack.** `LLMAgentLogs_CL` held its reasoning in plain English, including the line where it named the CVE it was about to use.
- **It debugged itself live.** When MinIO sent back XML instead of JSON, the agent rewrote its parser and retried. When its Nacos backdoor failed on a blank bcrypt hash, it diagnosed a subprocess PATH issue and shipped a 15-line fix in 31 seconds.
- **The backup and the breach used the same tool.** Both ran `pg_dump` within two minutes of each other. The attacker's run used a different user, pulled only the `variable` and `api_key` tables, and wrote no output file.
- **The data is gone for good.** The AES key was random, printed to stdout once, and never persisted. Paying the ransom would not have brought anything back.
- **Nothing here was a new technique.** An unpatched CVE, default credentials, a known JWT key, and an exposed DB port. The new part was an agent chaining them together at machine speed.

## 🎯 MITRE ATT&CK Coverage

| Tactic | Technique | What the agent did |
|---|---|---|
| Initial Access | **T1190** Exploit Public-Facing Application | CVE-2025-3248 on `/api/v1/validate/code` |
| Execution | **T1059.006** Python | Langflow spawned `python3.11` with a base64 payload |
| Discovery | **T1082** System Information Discovery · **T1046** Network Service Discovery | `id`/`uname`, then an 8-second sweep of `10.4.0.0/24` |
| Command & Control | **T1071.001** Web Protocols | Beacon to `45.131.66.106:4444` |
| Persistence | **T1053.003** Cron | `curl … \| python3 -` every 30 min |
| Credential Access | **T1552** Unsecured Credentials | Targeted `pg_dump` of Langflow secrets, `credentials.json` from Terraform state |
| Collection | **T1005** Data from Local System | Terraform-state bucket loot |
| Defense Evasion / Lateral Movement | **T1078** Valid Accounts · **T1550** Use Alternate Authentication Material | `minioadmin:minioadmin`, forged Nacos JWT |
| Persistence / Privilege Escalation | **T1078.001** Default Accounts | Backdoor admin `svc_maint` |
| Privilege Escalation | **T1611** Escape to Host | Docker socket probe |
| Impact | **T1486** Data Encrypted for Impact · **T1485** Data Destruction | `AES_ENCRYPT` × 1,342 rows, `DROP TABLE` × 2 |

## 🛡️ Detection Takeaways

Four signals that caught an autonomous agent where a signature would have missed it:

1. **Parent process, not binary name.** `python3.11` spawned *by the Langflow web process* is the attacker. When bash or systemd is the parent, it's the developers.
2. **Port, not destination.** Every legitimate egress from ff-lf-01 used 443. The C2 was the only connection on 4444.
3. **Scope, not tool.** `pg_dump` from the `backup` user is routine. `pg_dump -t variable -t api_key` from `langflow` is theft.
4. **Tempo, not technique.** Seventeen minutes of continuous execution with no human-paced gaps is itself an indicator. Machine-speed self-correction (a failure fixed in 31 seconds) is an AI-agent fingerprint.

All seven hunt queries are in the [KQL appendix](report/JADEPUFFER_ThreatHuntReport.md#appendix-a-kql-queries-used).

## 🧭 Why It Matters for AI Governance

This hunt shows an agent guardrail allowing a destructive tool invocation, and an AI workflow server acting as a credential vault with no network controls in front of it. The fixes are governance problems as much as technical ones:

- Treat agent platforms (Langflow, LLM orchestration, MCP hosts) as **high-value assets**. Put them in your asset inventory and your patch SLAs.
- **Log agent reasoning.** `LLMAgentLogs_CL` is what made this hunt possible, so make it a control requirement.
- Put secrets in a **secrets manager**, not in the workflow tool. Enforce **egress allow-listing** on AI workloads.
- **Kill default credentials and signing keys** as a policy, with a way to verify it, not as a best-effort cleanup.

## 📁 Repository Layout

```
threat-hunt-agentic-ransomware/
├── README.md                           ← you are here
├── LICENSE
└── report/
    ├── JADEPUFFER_ThreatHuntReport.md  ← full report: timeline, findings, IOCs, KQL
    └── images/                         ← Sentinel query screenshots + estate diagram
```

## ⚠️ Lab Disclaimer

This hunt ran in the **Log(N) Pacific cyber range**. "Flowforge," "PacificWatch SOC," and the hosts, accounts, and indicators in this repo come from the lab scenario and its telemetry. The actor name JADEPUFFER comes from Sysdig's research. Everything here is shared for education and detection engineering. Hunt responsibly.

---

<div align="center">

**Jenna Frank** · Hot Pink Huntress 💗<br/>
*Cybersecurity operations by day. Threat hunter by night. Builder of honeypots, breaker of assumptions.*

[GitHub](https://github.com/jennafrank) · [JennaFrank.co](https://www.JennaFrank.co) · [LinkedIn](https://linkedin.com/in/jenna-frank-cyber)

</div>
