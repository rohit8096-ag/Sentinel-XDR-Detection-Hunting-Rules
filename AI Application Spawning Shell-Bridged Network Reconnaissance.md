# *AI Application Spawning Shell-Bridged Network Reconnaissance*

#### Description
This detection identifies indirect, shell-bridged process chains where Generative AI desktop applications, coding assistants or CLI agents (e.g.. Claude, Copilot, Gemini..etc) launch command interpreters or script hosts (e.g.. PowerShell, CMD, Bash, Python, Node.js), which subsequently execute network scanning utilities (e.g.. Nmap, Masscan, Nuclei, Gobuster) against private internal networks. Detecting this 3-tier process lineage (AI Agent -> Shell Interpreter -> Scanner) catches sophisticated Indirect Prompt Injection attacks and unauthorized tool executions where an AI process uses an intermediary shell to evade basic parent-child rules.

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
let ShellTools = dynamic([
    "powershell.exe", "pwsh.exe", "cmd.exe",
    "bash", "sh", "zsh",
    "python.exe", "python", "python3",
    "node.exe", "node", "perl.exe", "ruby.exe"
]);
let Scanners = dynamic([
    "nmap", "nmap.exe", "masscan", "masscan.exe", "rustscan", "rustscan.exe",
    "naabu", "naabu.exe", "nuclei", "nuclei.exe", "httpx", "httpx.exe",
    "ffuf", "ffuf.exe", "gobuster", "gobuster.exe", "feroxbuster", "feroxbuster.exe",
    "sqlmap", "sqlmap.exe", "nikto", "nikto.exe"
]);
let AgentBridgedScans = DeviceProcessEvents
| where Timestamp > ago(2h)
| extend proc = tolower(FileName)
| where proc in~ (AITools)
| project AgentStart = Timestamp, DeviceId, DeviceName, AgentProc = proc, AgentPid = ProcessId
| join kind=inner (
    DeviceProcessEvents
    | where Timestamp > ago(2h)
    | extend proc = tolower(FileName)
    | where proc in~ (ShellTools)
    | project ShellStart = Timestamp, DeviceId, ShellProc = proc, ShellPid = ProcessId, ShellParentPid = InitiatingProcessId, ShellCmd = ProcessCommandLine
) on DeviceId
| where ShellParentPid == AgentPid
| where ShellStart between (AgentStart .. AgentStart + 30m)
| join kind=inner (
    DeviceProcessEvents
    | where Timestamp > ago(2h)
    | extend proc = tolower(FileName)
    | where proc in~ (Scanners)
    | project ScanStart = Timestamp, DeviceId, ScanProc = proc, ScanPid = ProcessId, ScanParentPid = InitiatingProcessId, ScanCmd = ProcessCommandLine
) on DeviceId
| where ScanParentPid == ShellPid
| where ScanStart between (ShellStart .. ShellStart + 30m)
| project DeviceId, DeviceName, AgentStart, ShellStart, ScanStart, AgentProc, ShellProc, ScanProc, ScanPid, ShellCmd, ScanCmd;
DeviceNetworkEvents
| where Timestamp > ago(2h)
| where RemoteIPType == "Private"
| extend netProc = tolower(InitiatingProcessFileName)
| where netProc in~ (Scanners)
| project Timestamp, DeviceId, RemoteIP, RemotePort, ActionType, InitiatingProcessId, netProc
| join kind=inner AgentBridgedScans on DeviceId
| where InitiatingProcessId == ScanPid
| where netProc == ScanProc
| where Timestamp between (ScanStart .. ScanStart + 30m)
| summarize
    FirstSeen = min(AgentStart),
    LastSeen = max(ScanStart),
    ScanRuns = dcount(ScanPid),
    UniqueHosts = dcount(RemoteIP),
    UniquePorts = dcount(RemotePort),
    TotalConnections = count(),
    FailedConnections = countif(ActionType == "ConnectionFailed"),
    SuccessConnections = countif(ActionType == "ConnectionSuccess"),
    ShellsUsed = make_set(ShellProc, 10),
    Commands = make_set(ScanCmd, 20),
    TargetSample = make_set(strcat(RemoteIP, ":", tostring(RemotePort)), 20)
    by DeviceName, DeviceId, AgentProc, ScanProc
| where UniqueHosts >= 2
```

## Importance
| Impact Level | False Positive Rate    | Data Source    |
| ---  | --- | --- |
| 🔴 High | Low  |Microsoft Defender for Endpoint (DeviceProcessEvents, DeviceNetworkEvents) |

#### Investigation Steps
1. Verify 3-Tier Process Lineage: Validate that the AI application (AgentProc) spawned an intermediate shell (ShellProc), which then launched the network scanner (ScanProc).
2. Analyze Execution Commands: Inspect ShellCmd and Commands to review flags, target subnets and scripts passed down through the shell interpreter.
3. Review AI Agent Context & Inputs: Check active developer workspace files, code repositories or chat prompt history for untrusted content or Indirect Prompt Injection vectors.
4. Assess Network Probing Scope: Analyze TargetSample, SuccessConnections and UniqueHosts to quantify internal network exposure and identify reached host services.

#### Recommendations
1. Isolate Endpoint & Kill Process Chain: Immediately terminate the process tree (Agent -> Shell -> Scanner) and isolate the device if unauthorized internal scanning is confirmed.
2. Block Shell Invocation from AI Applications: Implement application control rules (WDAC/AppLocker) to restrict AI process binaries from spawning interactive command shells (powershell.exe, cmd.exe, bash).
3. Enforce Isolated Sandboxing: Mandate devcontainer or virtualized sandbox isolation for AI developer tools to decouple tool execution from physical host interfaces and private corporate networks.

#### Author 
- **Name: Rohit Ashok**
- **Github: https://github.com/rohit8096-ag**
- **LinkedIn: https://linkedin.com/in/rohit-ashokgoud-5b77a0188**