# *Cloud IAM and Multi-Cloud Identity Reconnaissance via Developer AI Agents*

#### Description
This detection looks for cases where local AI tools such as Cursor, Claude CLI, Windsurf, Aider, Cline, Ollama, VS Code or ChatGPT start running commands to discover cloud identities and permissions.

An attacker could abuse an AI coding agent through prompt injection or a malicious plugin and use it to run cloud management commands such as `az`, `aws`, `gcloud`, or Microsoft Graph/PowerShell. These commands can be used to identify users, service principals, roles, access keys and permission assignments.

The detection focuses on cloud IAM reconnaissance coming from AI-related process activity on an endpoint. This can help identify suspicious activity before the attacker moves on to privilege escalation or attempts to access cloud resources.


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
|AML.T0087	|Gather Victim Identity Information	    |https://atlas.mitre.org/techniques/AML.T0087/|



#### Sentinel

```KQL
let lookback = 30d;
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
let CliTerms = dynamic([
    "az", "aws", "gcloud",
    "get-mg", "get-azuread", "get-msol", "get-az"
]);
let HighSignal = dynamic([
    "get-account-authorization-details",
    "get-account-summary",
    "get-iam-policy",
    "role assignment list",
    "role definition list",
    "list-access-keys"
]);
let DiscoveryCommands= strcat(
    @"(?i)(az ad (user|group|sp|app) (list|show)|",
    @"az role (assignment|definition) list|",
    @"get-mg(user|group|groupmember|directoryobject|serviceprincipal|application|directoryrole)|",
    @"get-azuread(user|group|serviceprincipal|application)|",
    @"get-msol(user|role|group)|",
    @"get-az(aduser|adgroup|roleassignment)|",
    @"aws iam (list-(users|groups|roles|policies|access-keys)|get-account-authorization-details|get-account-summary)|",
    @"aws (organizations list-accounts|identitystore list-users)|",
    @"gcloud (identity groups|iam (service-accounts list|roles list)|projects get-iam-policy|organizations list))"
);
DeviceProcessEvents
| where Timestamp > ago(lookback)
| where InitiatingProcessFileName in (AITools) or InitiatingProcessParentFileName in (AITools)
| where ProcessCommandLine has_any (CliTerms)   
| where ProcessCommandLine matches regex DiscoveryCommands
| extend HighSignalHit = ProcessCommandLine has_any (HighSignal)
| extend MatchedPatterns = extract(DiscoveryCommands, 0, ProcessCommandLine) 
| summarize
    CommandCount = count(),
    DistinctCommands = dcount(tolower(ProcessCommandLine)),
    HighSignalHits = countif(HighSignalHit),
    MatchedPatterns  = make_set(tolower(MatchedPatterns), 30),
    Commands = make_set(ProcessCommandLine, 20),
    AIToolChain = make_set(coalesce(InitiatingProcessParentFileName,InitiatingProcessFileName), 5),
    StartTime = min(Timestamp),
    EndTime = max(Timestamp)
    by DeviceId, DeviceName, AccountName, AccountDomain
| where DistinctCommands >= 2 or HighSignalHits >= 1 //Add condition according to your Environment
```

## Importance
| Impact Level | False Positive Rate    | Data Source    |
| ---  | --- | --- |
| 🔴 High | Low  |Microsoft Defender for Endpoint (DeviceProcessEvents) |

#### Investigation Steps
1. Analyze Command History: Inspect the Commands array executed by the AI tool process chain (AIToolChain) to identify whether the cloud IAM requests target high-privilege Azure Entra ID, AWS IAM or GCP IAM roles.
2. Review AI Workspace Context: Check open project folders, recent developer prompts, extension logs or workspace files in tools like Cursor, VS Code or Windsurf to determine if indirect prompt injection or malicious agent instructions triggered the commands.
3. Verify Cloud Credential Access: Check if the host holds cached CLI credentials (~/.aws/credentials, ~/.azure/azureProfile.json, ~/.config/gcloud/credentials.db) or OAuth tokens accessible to the developer context.
4. Correlate Cloud Audit Telemetry: Pivot to Microsoft Entra ID (AuditLogs), AWS CloudTrail (AWSCloudTrail) or GCP Audit logs (GCP_AuditLogs) for AccountName to check if discovered roles/keys were subsequently used for privilege escalation or resource modification.

#### Recommendations
1. Implement Scoped Developer CLI Roles: Enforce strictly scoped IAM policies and temporary, short-lived session tokens for developer workstations to prevent broad cloud identity enumeration.
2. Isolate AI Tool Shell Permissions: Restrict AI extension and agent processes from executing unrestricted CLI commands without explicit human-in-the-loop authorization.
3. Deploy Host Application Controls: Utilize WDAC / AppLocker policies and Microsoft Defender for Endpoint process controls to limit unapproved AI agents from invoking cloud administrative tools.

#### Author 
- **Name: Rohit Ashok**
- **Github: https://github.com/rohit8096-ag**
- **LinkedIn: https://linkedin.com/in/rohit-ashokgoud-5b77a0188**
