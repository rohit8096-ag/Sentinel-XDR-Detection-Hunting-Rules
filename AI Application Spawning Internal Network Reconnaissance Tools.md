# *AI Application Spawning Internal Network Reconnaissance Tools*

#### Description
This detection identifies instances where Generative AI desktop applications, coding assistants or CLI agents (e.g.. Claude, Copilot, Gemini, Aider, Goose) spawn active network scanning and fuzzing utilities (e.g.. Nmap, Nuclei, Gobuster, Masscan, FFuF) that subsequently probe private internal networks. Through Indirect Prompt Injection, malicious workspace files or unrestricted tool-execution permissions, an attacker can leverage an AI process to map internal network subnets, discover active services and perform lateral movement reconnaissance.

#### MITRE ATT&CK
| Technique ID | Title | Link |
| --- | --- | --- |
| T1046    | Network Service Discovery| https://attack.mitre.org/techniques/T1046/|
| T1018    | Remote System Discovery  | https://attack.mitre.org/techniques/T1018/|


#### MITRE ATLAS (AI Threat Framework)
| Technique ID | Title | Link |
| --- | --- | --- |
| AML.T0116     | Execution via LLM Agent                      | https://atlas.mitre.org/techniques/AML.T0116/     |
| AML.T0085.001 | Unauthorized / Unrestricted Tool Execution   | https://atlas.mitre.org/techniques/AML.T0085.001/ |
| AML.T0043     | Operational Environment Reconnaissance       | https://atlas.mitre.org/techniques/AML.T0043/     |
| AML.T0006     | Active Scanning                              | https://atlas.mitre.org/techniques/AML.T0006/     |



#### Sentinel

```KQL
let AITools = dynamic([
    "claude", "claude.exe", "codex", "codex.exe", "gemini", "gemini.exe",
    "grok", "grok.exe", "qwen-code", "qwen-code.exe", "qoder", "qoder.exe",
    "kimi", "kimi.exe", "kimi-code", "kimi-code.exe", "aider", "aider.exe",
    "goose", "goose.exe", "hermes", "hermes.exe", "openclaw", "openclaw.exe",
    "opencode", "opencode.exe", "cline", "cline.exe", "amp", "amp.exe",
    "augment", "augment.exe", "kilo", "kilo.exe", "kiro", "kiro.exe",
    "trae", "trae.exe", "droid", "droid.exe", "nanocoder", "nanocoder.exe",
    "pi", "pi.exe", "omp", "omp.exe", "iflow", "iflow.exe",
    "antigravity", "antigravity.exe", "copilot", "copilot.exe"
]);
let ReconTools = dynamic([
    "nmap", "nmap.exe", "masscan", "masscan.exe", "rustscan", "rustscan.exe",
    "naabu", "naabu.exe", "nuclei", "nuclei.exe", "httpx", "httpx.exe",
    "ffuf", "ffuf.exe", "gobuster", "gobuster.exe", "feroxbuster", "feroxbuster.exe",
    "sqlmap", "sqlmap.exe", "nikto", "nikto.exe"
]);
let AIRecon = DeviceProcessEvents
| where Timestamp > ago(2h)
| extend Proc = tolower(FileName)
| where Proc in~ (AITools)
| project AITime = Timestamp, DeviceId, DeviceName, AIProcess = Proc, AIProcessId = ProcessId
| join kind=inner (
    DeviceProcessEvents
    | where Timestamp > ago(2h)
    | extend Proc = tolower(FileName)
    | where Proc in~ (ReconTools)
    | project ReconTime = Timestamp, DeviceId, ReconProcess = Proc, ReconProcessId = ProcessId, ParentProcessId = InitiatingProcessId, ReconCommandLine = ProcessCommandLine
) on DeviceId
| where ParentProcessId == AIProcessId
| where ReconTime between (AITime .. AITime + 30m)
| project DeviceId, DeviceName, AITime, ReconTime, AIProcess, ReconProcess, ReconProcessId, ReconCommandLine,AIProcessId;
DeviceNetworkEvents
| where Timestamp > ago(2h)
| where RemoteIPType == "Private"
| extend NetworkProcess = tolower(InitiatingProcessFileName)
| where NetworkProcess in~ (ReconTools)
| project Timestamp, DeviceId, RemoteIP, RemotePort, ActionType, InitiatingProcessId, NetworkProcess
| join kind=inner AIRecon on DeviceId
| where InitiatingProcessId == ReconProcessId
| where NetworkProcess == ReconProcess
| where Timestamp between (ReconTime .. ReconTime + 30m)
| summarize
    FirstAITime = min(AITime),
    LastReconTime = max(ReconTime),
    ReconSessions = dcount(ReconProcessId),
    ReconTargets = dcount(RemoteIP),
    ReconPorts = dcount(RemotePort),
    Attempts = count(),
    FailedConnections = countif(ActionType == "ConnectionFailed"),
    SuccessfulConnections = countif(ActionType == "ConnectionSuccess"),
    ReconCommands = make_set(ReconCommandLine, 20),
    SampleTargets = make_set(strcat(RemoteIP, ":", tostring(RemotePort)), 20)
    by DeviceName, DeviceId, AIProcess, ReconProcess
| where ReconTargets >= 2
```

## Importance
| Impact Level | False Positive Rate    | Data Source    |
| ---  | --- | --- |
| 🔴 High | Low  |Microsoft Defender for Endpoint (DeviceProcessEvents, DeviceNetworkEvents) |

#### Investigation Steps
1. Verify Process Hierarchy: Confirm that the AI binary (AIProcess) directly spawned the recon tool (ReconProcess) by inspecting InitiatingProcessId and parent process trees.
2. Inspect Command Lines: Examine ReconCommands (e.g. nmap -sS, nuclei -t) to evaluate targeted subnets, ports or scanning templates being executed.
3. Review AI Workspace & Prompt Context: Inspect recently modified workspace files, untrusted repositories or prompt histories processed by the AI application for indirect prompt injection vectors.
4. Assess Network Scope: Analyze SampleTargets and SuccessfulConnections to determine whether sensitive private subnets, active host IPs or internal services were successfully probed.

#### Recommendations
1. Terminate Rogue Process Trees: Immediately terminate the process tree and isolate the affected endpoint if unauthorized internal scanning is validated.
2. Restrict AI Execution Policies: Implement WDAC or AppLocker policies to prevent local AI process binaries from launching network diagnostic utilities.
3. Sandbox AI Developer Environments: Enforce containerized environments (e.g. Devcontainers) to isolate LLM tool execution from raw local host interfaces and internal subnets.

#### Author 
- **Name: Rohit Ashok**
- **Github: https://github.com/rohit8096-ag**
- **LinkedIn: https://linkedin.com/in/rohit-ashokgoud-5b77a0188**