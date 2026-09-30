# *Microsoft Graph Reconnaissance Spawned by AI Coding Assistants*

#### Description
This detection looks for local AI tools and coding assistants such as Claude CLI, Copilot, Cline, Aider, OpenClaw, Hermes and Qwen-Code making requests to Microsoft Graph (graph.microsoft.com) or starting processes that access it.

An attacker could abuse an AI tool through a malicious prompt, extension or stolen login session to gather information from Entra ID. This could include checking users, groups, roles, applications and service principals.

The detection helps to identify the activity from the device before the attacker can use the collected information for further access or privilege escalation.


#### MITRE ATT&CK
| Technique ID | Title | Link |
| --- | --- | --- |
|T1087.004	|Account Discovery: Cloud Account	            |https://attack.mitre.org/techniques/T1087/004/|
|T1069.003	|Permission Groups Discovery: Cloud Groups      |https://attack.mitre.org/techniques/T1069/003/|


#### MITRE ATLAS (AI Threat Framework)
| Technique ID | Title | Link |
| --- | --- | --- |
|AML.T0087	|Gather Victim Identity Information	    |https://atlas.mitre.org/techniques/AML.T0087/|
|AML.T0043	|Operational Environment Reconnaissance	|https://atlas.mitre.org/techniques/AML.T0043/|
|AML.T0087	|Gather Victim Identity Information	    |https://atlas.mitre.org/techniques/AML.T0087/|



#### Sentinel

```KQL
let lookback = 1d;
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
let GraphDiscoveryComm = @"(?i)/(users|groups|servicePrincipals|directoryObjects|memberOf|contacts|directoryRoles|applications|roleManagement)(/|\?|$)";
DeviceProcessEvents
| where Timestamp > ago(lookback)
| where InitiatingProcessFileName in~ (AITools) or InitiatingProcessParentFileName in~ (AITools)
| where ProcessCommandLine contains "graph.microsoft.com"   
| where ProcessCommandLine matches regex GraphDiscoveryComm
| extend MatchedResource = extract(GraphDiscoveryComm, 1, ProcessCommandLine)
| extend Session = bin(Timestamp, 30m)
| summarize
    CommandCount      = count(),
    DistinctResources = dcount(tolower(MatchedResource)),
    MatchedResources  = make_set(tolower(MatchedResource), 20),
    Commands          = make_set(ProcessCommandLine, 30),
    AIToolChain       = make_set(coalesce(InitiatingProcessParentFileName, InitiatingProcessFileName), 5),
    StartTime         = min(Timestamp),
    EndTime           = max(Timestamp)
    by DeviceId, DeviceName, AccountName, AccountDomain,Session
| where DistinctResources >= 2
```

## Importance
| Impact Level | False Positive Rate    | Data Source    |
| ---  | --- | --- |
| 🔴 High | Low  |Microsoft Defender for Endpoint (DeviceProcessEvents) |

#### Investigation Steps
1. Check Microsoft Graph API activity: Review MatchedResources and Commands to see which Entra ID objects were accessed, such as /roleManagement, /servicePrincipals or /users.
2. Check the AI tool activity: Review the device activity, workspace projects, prompt history and agent extension logs for tools such as Copilot, Cline or OpenClaw. Check whether the activity could have been triggered by prompt injection or unauthorized commands.
3. Check the user session and tokens: Review active PowerShell or CLI sessions and available OAuth tokens to determine whether the AI tool used an existing Connect-MgGraph or Azure CLI session belonging to the user.
4. Check Entra ID activity: Review AADNonInteractiveUserSignInLogs and AuditLogs to confirm whether the user performed unusual or high-privilege Microsoft Graph API actions from the affected device or IP address.

#### Recommendations
1. Restrict Microsoft Graph PowerShell access: Use Conditional Access to limit Microsoft Graph PowerShell and CLI authentication to approved privileged access workstations (PAWs).
2. Require user approval for AI agents: Configure AI CLI tools and agent extensions to require user confirmation before executing CLI commands or making network/API requests to production cloud resources.
3. Control AI agent applications: Use AppLocker or Windows Defender Application Control (WDAC) to control which AI agent applications can run and prevent unauthorized tools from launching elevated PowerShell or other privileged processes.

#### Author 
- **Name: Rohit Ashok**
- **Github: https://github.com/rohit8096-ag**
- **LinkedIn: https://linkedin.com/in/rohit-ashokgoud-5b77a0188**