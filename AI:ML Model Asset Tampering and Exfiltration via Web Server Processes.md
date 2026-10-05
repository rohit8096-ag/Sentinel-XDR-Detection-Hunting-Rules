# *AI/ML Model Asset Tampering and Exfiltration via Web Server Processes*

#### Description
This detection looks for web application processes such as w3wp.exe, nginx, apache2, node, python, uvicorn, gunicorn, tomcat and caddy making changes to machine learning model files.

It monitors files such as .onnx, .pth, .safetensors, .pkl, config.json and tokenizer.json for actions like creating, modifying, renaming or deleting files.

An attacker who gains access to a public facing web application could use a file upload vulnerability, path traversal or RCE to modify files in a local ML model repository. This could affect platforms such as MLflow, Triton, TorchServe or Hugging Face.

The detection helps identify suspicious changes to model files from web server processes, which could be an early sign of model tampering, a backdoor being added or attempts to access or steal ML models.


#### MITRE ATT&CK
| Technique ID | Title | Link |
| --- | --- | --- |
|T1190       |Exploit Public-Facing Application             |https://attack.mitre.org/techniques/T1190/     |
|T1565.001   |Data Manipulation: Stored Data Manipulation   |https://attack.mitre.org/techniques/T1565/001/ |   
|T1005       |Data from Local System                        |https://attack.mitre.org/techniques/T1005/     |


#### MITRE ATLAS (AI Threat Framework)
| Technique ID | Title | Link |
| --- | --- | --- |
|AML.T0004	|Search Application Repositories	|https://atlas.mitre.org/techniques/AML.T0004/|
|AML.T0048	|Exfiltrate ML Model	            |https://atlas.mitre.org/techniques/AML.T0048/|
|AML.T0018	|Backdoor ML Model                  |https://atlas.mitre.org/techniques/AML.T0018/|
|AML.T0010  |ML Model Poisoning                 |https://atlas.mitre.org/techniques/AML.T0010/|



#### Sentinel

```KQL
let WebProcesses = dynamic([
    "w3wp.exe", "nginx.exe", "nginx", "httpd", "apache2",
    "node", "node.exe", "python", "python3", "uvicorn",
    "gunicorn", "java", "dotnet", "tomcat", "caddy"
]);
let HighConfidenceExtensions = dynamic([
    ".onnx", ".pth", ".h5", ".hdf5", ".tflite",
    ".mlmodel", ".safetensors", ".mar", ".savedmodel",
    ".ckpt", ".gguf", ".engine",
    ".pt", ".pkl", ".joblib"
]);
let MLConfigFiles = dynamic([
    "config.json", "tokenizer.json", "tokenizer_config.json",
    "model.json", "model_config.json", "special_tokens_map.json",
    "vocab.json", "vocab.txt", "merges.txt",
    "generation_config.json", "preprocessor_config.json",
    "model.safetensors.index.json"
]);
let ModelFolders = dynamic([
    "/models/", "\\models\\",
    "model_store", "model_repository",
    "mlflow", "triton", "torchserve",
    "savedmodel", "huggingface", ".cache/huggingface",
    "ollama", ".ollama/models"
]);
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated", "FileModified", "FileRenamed", "FileDeleted")
| where InitiatingProcessFileName in~ (WebProcesses)
| extend FileExtension = tolower(extract(@"(\.[a-zA-Z0-9]+)$", 1, FileName)),
         LowerFolderPath = tolower(FolderPath)
| where FileExtension in~ (HighConfidenceExtensions) or (FileName in~ (MLConfigFiles) and LowerFolderPath has_any (ModelFolders))
| extend MatchReason = case(
    FileExtension in~ (HighConfidenceExtensions), strcat("HighConf_MLExtension: ", FileExtension),
    FileName in~ (MLConfigFiles), strcat("MLConfigFile_in_ModelFolder: ", FileName),
    "Unknown" )
| project Timestamp,DeviceName,DeviceId,WebProcess = InitiatingProcessFileName,InitiatingProcessCommandLine,FileName,FileExtension,FolderPath,ActionType, MatchReason, AccountName = InitiatingProcessAccountName
```

## Importance
| Impact Level | False Positive Rate    | Data Source    |
| ---  | --- | --- |
| 🔴 High | Low  |Microsoft Defender for Endpoint (DeviceFileEvents) |

#### Investigation Steps
1. Check the web server process: Review InitiatingProcessCommandLine and the parent process tree to understand what caused the file change. Look for signs of file uploads, path traversal or a web shell.
2. Check the model file: Compare the modified .safetensors, .onnx, or .pth file with the known-good SHA256 hash. This helps confirm whether the model was changed or potentially tampered with.
3. Check web and WAF logs: Look at WAF, Nginx or Apache logs around the same time. Check for external IP addresses, unusual POST requests, file uploads or requests to model management endpoints.
4. Check model folders: Review locations such as .cache/huggingface, mlflow and triton for new or unexpected files. Pay particular attention to .pkl and .joblib files created by web service accounts, as these may be used to introduce malicious content.

#### Recommendations
1. Make model folders read-only: Mount production model folders such as /models/ as read-only so web applications and inference services cannot directly change or delete model files.
2. Limit web service permissions: Make sure service accounts such as www-data, nginx and nobody do not have write or delete access to ML model folders or cache directories.
3. Verify models before use: Use cryptographic signatures, such as Cosign or Sigstore, to verify .safetensors and .onnx models before they are loaded into production.

#### Author 
- **Name: Rohit Ashok**
- **Github: https://github.com/rohit8096-ag**
- **LinkedIn: https://linkedin.com/in/rohit-ashokgoud-5b77a0188**