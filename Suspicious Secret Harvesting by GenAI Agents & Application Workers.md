# *Suspicious Secret Harvesting by GenAI Agents & Application Workers*

#### Description
This detection identifies instances where Generative AI tools (e.g Claude, Cursor, Aider, Ollama, Copilot) or background application runtimes (e.g Gunicorn, Uvicorn, Celery, Python, Node) execute commands targeting high-value system credentials, cloud service account tokens, SSH keys or application configuration secrets. This activity is frequently leveraged in Indirect Prompt Injection attacks, Local File Inclusion (LFI) or Remote Code Execution (RCE) scenarios to exfiltrate credentials and pivot across cloud environments.

#### MITRE ATT&CK Technique(s)
| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1552.001 | Unsecured Credentials: Credentials In Files |https://attack.mitre.org/techniques/T1552/001/ |
| T1552.004 | Unsecured Credentials: Private Keys | https://attack.mitre.org/techniques/T1552/004/        |
| T1059     | Command and Scripting Interpreter   | https://attack.mitre.org/techniques/T1059/            |
| T1059.    | Exploit Public-Facing Application   | https://attack.mitre.org/techniques/T1190/            |

#### Sentinel

```KQL
let Lookback = 180d;
let HighValueCredPaths = dynamic([
    "/proc/self/environ",
    "/proc/1/environ",
    "/var/run/secrets/kubernetes.io/serviceaccount",
    "/var/run/secrets/eks.amazonaws.com",
    "/var/run/secrets/azure/tokens",
    ".aws/credentials",
    ".azure/accessTokens.json",
    ".azure/msal_token_cache.json",
    ".config/gcloud/credentials.db",
    ".config/gcloud/application_default_credentials.json",
    ".config/gcloud/access_tokens.db",
    ".ssh/id_rsa",
    ".ssh/id_ed25519",
    ".ssh/id_ecdsa",
    ".kube/config",
    ".docker/config.json",
    ".netrc",
    ".git-credentials",
    ".config/gh/hosts.yml",
    ".huggingface/token",
    ".config/huggingface/token"
]);
let AppSecretPaths = dynamic([".env",".npmrc",".aws/config",".boto",".s3cfg"]);
let SystemCredentialPaths = dynamic(["/etc/shadow"]);
let WorkerProcesses = dynamic(["python","python3","node","gunicorn","uvicorn","celery","hypercorn","rq","dramatiq"]);
let GenAITools = dynamic(["ollama","cursor","claude","codex","windsurf","aider","continue","github-copilot","gemini","cline","copilot","gh-copilot","github-copilot-cli"]);
DeviceProcessEvents
| where Timestamp > ago(Lookback)
| where ProcessCommandLine has_any (HighValueCredPaths) or ProcessCommandLine has_any (AppSecretPaths) or ProcessCommandLine has_any (SystemCredentialPaths)
| where InitiatingProcessFileName in~ (WorkerProcesses) or InitiatingProcessFileName in~ (GenAITools) or FileName in~ (GenAITools)
| extend CredentialType = case(ProcessCommandLine has_any (SystemCredentialPaths),"Linux system credential",
         ProcessCommandLine has_any (HighValueCredPaths),"High-value credential/secret",
         ProcessCommandLine has_any (AppSecretPaths),"Application secret/config",
         "Other")
| extend ProcessCategory = case(FileName in~ (GenAITools) or InitiatingProcessFileName in~ (GenAITools),"GenAI tool",
         InitiatingProcessFileName in~ (WorkerProcesses), "AI/ML/Application worker",
         "Other")
| summarize
    AlertCount = count(),
    FirstSeen = min(Timestamp),
    LastSeen = max(Timestamp),
    SampleCommandLine = take_any(ProcessCommandLine),
    SampleParentCommandLine = take_any(InitiatingProcessCommandLine),
    SampleFolderPath = take_any(FolderPath)
    by DeviceName,AccountName,ProcessCategory,CredentialType,FileName,InitiatingProcessFileName
```

## Importance
| Impact Level | False Positive Rate    | Data Source    |
| ---  | --- | --- |
| 🔴 High | Low – Medium | Defender for Endpoint (DeviceProcessEvents) |

#### Investigation Steps
1. Analyze Command Context: Inspect SampleCommandLine and SampleParentCommandLine to verify whether the process was executed interactively or spawned autonomously by an AI agent or background job.
2. Review AI Agent Inputs: If triggered by a GenAI tool (Cursor, Claude, Aider), examine recent repository files, pull requests or untrusted prompt inputs processed by the tool for signs of Indirect Prompt Injection.
3. Audit Web & Worker Logs: If triggered by an application runtime (Gunicorn, Celery, Node), check web application access logs for Remote Code Execution (RCE) or Local File Inclusion (LFI) attempts.
4. Correlate Outbound Network Activity: Check DeviceNetworkEvents around LastSeen to determine if accessed tokens, credentials or SSH keys were transmitted to external IP addresses or unauthorized LLM endpoints.

#### Recommendations
1. Rotate Exposed Secrets: Immediately revoke and rotate any AWS, Azure, GCP, Kubernetes or SSH keys referenced in the execution parameters.
2. Restrict AI Sandbox Privileges: Configure developer AI assistants and local agent runtimes with read-only filesystem boundaries and path exclusions (~/.aws, ~/.ssh, .env).
3. Harden Application Workers: Ensure web workers run under least-privilege service accounts, isolate Kubernetes pods using network policies and disable unnecessary host mounts.

#### Author 
- **Name: Rohit Ashok**
- **Github: https://github.com/rohit8096-ag**
- **LinkedIn: https://linkedin.com/in/rohit-ashokgoud-5b77a0188**
