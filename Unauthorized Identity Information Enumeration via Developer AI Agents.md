# *Unauthorized Identity Information Enumeration via Developer AI Agents*

#### Description
This detection identifies instances where local AI developer tools, CLI agents or autonomous agent frameworks (e.g.. Claude CLI, Copilot, Cline, Aider, OpenClaw, Hermes, Qwen-Code) execute commands or spawn subprocesses performing Active Directory and local identity discovery. Attackers leveraging compromised AI agent contexts, indirect prompt injection or malicious developer agent plugins can direct these tools to map domain users, group memberships and administrative privileges (get-adgroup, get-aduser, net group, whoami /groups, dsquery). This query detects host-level identity discovery originating directly from AI execution engines before privilege escalation or lateral movement takes place.

#### MITRE ATT&CK
| Technique ID | Title | Link |
| --- | --- | --- |
|T1087.002	|Account Discovery: Domain Account	            |https://attack.mitre.org/techniques/T1087/002/|
|T1069.002	|Permission Groups Discovery: Domain Groups	    |https://attack.mitre.org/techniques/T1069/002/|
|T1059.001	|Command and Scripting Interpreter: PowerShell	|https://attack.mitre.org/techniques/T1059/001/|


#### MITRE ATLAS (AI Threat Framework)
| Technique ID | Title | Link |
| --- | --- | --- |
|AML.T0087	|Gather Victim Identity Information	    |https://atlas.mitre.org/techniques/AML.T0087/|
|AML.T0043	|Operational Environment Reconnaissance	|https://atlas.mitre.org/techniques/AML.T0043/|
|AML.T0040	|Execution / Agent Abuse	            |https://atlas.mitre.org/techniques/AML.T0040/|



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
let IdentityDiscovery = dynamic([
    "get-adgroup","get-adgroupmember","get-adprincipalgroupmembership","get-aduser",
    "get-netgroup","get-domaingroup","get-domaingroupmember","get-netuser","get-domainuser",
    "net group","net localgroup","net user","whoami /groups","whoami /all",
    "dsquery group","dsquery user","dsget group"]);
DeviceProcessEvents
| where Timestamp > ago(1h)
| where InitiatingProcessFileName has_any (AITools) or InitiatingProcessParentFileName has_any (AITools)
| where tolower(ProcessCommandLine) has_any (IdentityDiscovery)
| extend AITool = case(
    InitiatingProcessFileName has_any (AITools), InitiatingProcessFileName,
    InitiatingProcessParentFileName has_any (AITools), InitiatingProcessParentFileName,
    "Unknown"
)
| summarize DiscoveryCmds = count(), DistinctCmds = dcount(ProcessCommandLine), Cmds = make_set(ProcessCommandLine, 20),FirstSeen = min(Timestamp),LastSeen = max(Timestamp)by DeviceName, AccountName, AccountDomain, AITool
```

## Importance
| Impact Level | False Positive Rate    | Data Source    |
| ---  | --- | --- |
| 🔴 High | Low  |Microsoft Defender for Endpoint (DeviceProcessEvents) |

#### Investigation Steps
1. Analyze Subprocess Execution: Review Cmds spawned by AITool on DeviceName to determine whether the commands reflect intentional developer administrative tasks or automated, suspicious reconnaissance patterns.
2. Inspect AI Agent Logs & Prompts: Review recent prompt history, workspace files or task logs associated with the detected AITool (e.g. Cline, Copilot, Aider, OpenClaw) to identify potential indirect prompt injection vectors or unapproved automation scripts.
3. Evaluate Account Context: Assess AccountName and AccountDomain to verify whether the account holds elevated domain privileges or sensitive access that could be abused following discovery.
4. Correlate Downstream Activity: Pivoting to DeviceProcessEvents and DeviceNetworkEvents around FirstSeen to detect subsequent privileged actions, Kerberoasting requests, or lateral movement attempts.

#### Recommendations
1. Restrict Agent Execution Privileges: Implement strict process isolation and execution sandboxing for developer AI CLI tools and autonomous agents to prevent them from executing system discovery commands (net.exe, dsquery, Active Directory PowerShell modules).
2. Apply Endpoint Application Control: Deploy AppLocker or Windows Defender Application Control (WDAC) policies to restrict unauthorized or unmanaged AI agent binaries from executing within enterprise developer environments.
3. Enforce Least Privilege for Developer Accounts: Ensure developer workstations and service accounts running local AI agent frameworks do not hold Domain Admin or excessive Active Directory enumeration rights.

#### Author 
- **Name: Rohit Ashok**
- **Github: https://github.com/rohit8096-ag**
- **LinkedIn: https://linkedin.com/in/rohit-ashokgoud-5b77a0188**