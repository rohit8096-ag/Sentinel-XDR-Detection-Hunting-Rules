# *GenAI Process Accessing Sensitive Files*

#### Description
This detection identifies instances where Generative AI desktop applications or CLI tools attempt to create, modify, rename or delete sensitive local credential files, SSH host keys, browser state databases or shell profile configurations (.bashrc, .zshrc). Through Indirect Prompt Injection or tool-use exploits, malicious instructions can force an AI agent to establish persistence by modifying user shell startup files or harvest stored access tokens.

#### MITRE ATT&CK
| Technique ID | Title | Link |
| --- | --- | --- |
| T1552.001 | Unsecured Credentials: Credentials In Files | https://attack.mitre.org/techniques/T1552/001/ |
| T1546.004 | Unix Shell Configuration Modification       | https://attack.mitre.org/techniques/T1546/004/ |
| T1059.004 | Command and Scripting Interpreter:Unix Shell| https://attack.mitre.org/techniques/T1059/004/|

#### MITRE ATLAS (AI Threat Framework)
| Technique ID | Title | Link |
| --- | --- | --- |
| AML.T0051.001 | Indirect Prompt Injection                  | https://atlas.mitre.org/techniques/AML.T0051.001/ |
| AML.T0055     | Insecure Output Handling                   | https://atlas.mitre.org/techniques/AML.T0055/     |
| AML.T0085     | LLM Agent Tool Execution                   | https://atlas.mitre.org/techniques/AML.T0085/     |
| AML.T0085.001 | Unauthorized / Unrestricted Tool Execution | https://atlas.mitre.org/techniques/AML.T0085.001/ |


#### Sentinel

```KQL
let GenAIProcesses = dynamic([
    "ollama",
    "textgen",
    "text-generation-webui",
    "oobabooga",
    "lmstudio", 
    "lm studio",
    "claude",
    "cursor",
    "copilot",
    "codex",
    "jan",
    "gpt4all",
    "gemini-cli", 
    "gemini",
    "genaiscript",
    "grok",
    "qwen",
    "koboldcpp",
    "llama-server", 
    "llama-cli",
    "windsurf",
    "zed",
    "opencode",
    "goose"
]);
let ShellConfigFiles = dynamic([
    ".bashrc",
    ".bash_profile",
    ".zshrc",
    ".zshenv",
    ".zprofile",
    ".profile",
    ".bash_logout"
]);
let CredentialFiles = dynamic([
    "logins.json",
    "Login Data",
    "Local State",
    "signons.sqlite",
    "Cookies",
    "cookies.sqlite",
    "Cookies.binarycookies",
    "login.keychain-db",
    "System.keychain",
    "credentials.db",
    "credentials",
    "access_tokens.db",
    "accessTokens.json",
    "azureProfile.json",
    "RDCMan.settings",
    "known_hosts",
    "KeePass.config.xml",
    "Unattended.xml"
]);
let GenAIAppNames = dynamic(["Claude","Cursor","Windsurf","Jan","LM Studio","GPT4All","Gemini"]);
DeviceFileEvents
| where ActionType in ("FileRenamed", "FileCreated", "FileModified", "FileDeleted")
| where InitiatingProcessFileName has_any (GenAIProcesses)
| where FileName in~ (CredentialFiles) or FileName in~ (ShellConfigFiles) or FileName matches regex @"(?i)^key.*\.db$"
| where not ( FileName in~ ("Cookies", "Local State", "Login Data") and FolderPath has_any (GenAIAppNames)
        and (
        FolderPath matches regex @"(?i)\\AppData\\(Local|Roaming)\\[^\\]+\\"
        or
        FolderPath matches regex @"(?i)\\AppData\\Local\\Packages\\[^\\]+\\LocalCache\\Roaming\\[^\\]+\\"
        or FolderPath matches regex @"(?i)/Library/Application Support/[^/]+/"
        or FolderPath matches regex @"(?i)/\.config/[^/]+/"
        or FolderPath matches regex @"(?i)/\.local/share/[^/]+/"
    )
)
| project Timestamp,DeviceName,ActionType,FileName,FolderPath,InitiatingProcessFileName,InitiatingProcessCommandLine,InitiatingProcessAccountName, ReportId
```

## Importance
| Impact Level | False Positive Rate    | Data Source    |
| ---  | --- | --- |
| 🔴 High | Low  | Defender for Endpoint (DeviceFileEvents) |

#### Investigation Steps
1. Verify Modification Type: Check ActionType and FileName. Modifications to .zshrc or .bashrc suggest persistence attempts, while access to accessTokens.json or credentials.db points to credential theft.
2. Review Prompt & Workspace Context: Inspect the workspace directory and recent files processed by the AI process (InitiatingProcessFileName) for malicious context, untrusted repositories or prompt injection triggers.
3. Inspect File Diff / Content: If the file was modified, determine what lines were added or removed (e.g., rogue export statements, reverse shell aliases, or cleared logs).
4. Correlate Process Activity: Cross-reference ReportId with DeviceProcessEvents to inspect any child commands spawned by the AI tool immediately after the file event.

#### Recommendations
1. Isolate Affected Host: If shell configurations were modified with unauthorized network endpoints or aliases, isolate the machine for forensic review.
2. Revoke Active Tokens: Immediately invalidate any cloud session tokens or SSH key pairs contained within the accessed target path.
3. Enforce Workspace Sandboxing: Configure developer AI tools to run inside containerized dev environments (e.g Docker / Devcontainers) without direct host filesystem access.

#### Author 
- **Name: Rohit Ashok**
- **Github: https://github.com/rohit8096-ag**
- **LinkedIn: https://linkedin.com/in/rohit-ashokgoud-5b77a0188**