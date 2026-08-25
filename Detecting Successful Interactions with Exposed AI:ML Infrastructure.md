# *# Detecting Successful Interactions with Exposed AI/ML Infrastructure*

#### Description
This detection identifies successful HTTP requests (HTTP 2xx response codes) routed through WAFs, API Gateways or Application Gateways targeting core Generative AI, Machine Learning model hosting and inference management endpoints (e.g., OpenAI-compatible endpoints /v1/chat/completions, MLflow /api/2.0/mlflow, TorchServe /invocations, Triton /v2/models). Continuous monitoring of successful interactions helps establish baseline usage, detect unauthorized API key usage, spot data exfiltration via model inference and identify automated model scraping across perimeter security controls.

#### MITRE ATT&CK
| Technique ID | Title | Link |
| --- | --- | --- |
| T1595    | Active Scanning                            | https://attack.mitre.org/techniques/T1595/    |
| T1071.001| Application Layer Protocol: Web Protocols  | https://attack.mitre.org/techniques/T1071/001/|


#### MITRE ATLAS (AI Threat Framework)
| Technique ID | Title | Link |
| --- | --- | --- |
| AML.T0006 | Active Scanning            | https://atlas.mitre.org/techniques/AML.T0006/ |
| AML.T0040 | ML Model Access            | https://atlas.mitre.org/techniques/AML.T0040/ |
| AML.T0013 | Discover ML Model Ontology | https://atlas.mitre.org/techniques/AML.T0013/ |



#### Sentinel

```KQL
//Imperva WAF — successful AI/ML API access
let AIPaths = dynamic([
    "/v1/models", "/v1/chat/completions", "/v1/completions",
    "/api/predict", "/invocations", "/score", "/api/score",
    "/api/jobs", "/api/cluster_status", "/api/nodes",
    "/api/messages", "/api/generate", "/api/tags",
    "/v2/models", "/v2/health", "/api/2.0/mlflow"
]);
ImpervaWAFCloud_CL
| where TimeGenerated > ago(24h)
| where Act == "REQ_PASSED"
| where Request has_any (AIPaths)
| extend HttpStatus = toint(Cn1)
| where HttpStatus between (200 .. 299)
| project TimeGenerated, ClientIP =Src, Request, HttpStatus = Cn1, UserAgent = RequestClientApplication, TargetSite = SourceServiceName,Action = Act

//Azure Application Gateway / APIM
let AIPaths = dynamic([
    "/v1/models", "/v1/chat/completions", "/v1/completions",
    "/api/predict", "/invocations", "/score", "/api/score",
    "/api/jobs", "/api/cluster_status", "/api/nodes",
    "/api/messages", "/api/generate", "/api/tags",
    "/v2/models", "/v2/health", "/api/2.0/mlflow"
]);
AzureDiagnostics
| where TimeGenerated > ago(24h)
| where ResourceType in ("APPLICATIONGATEWAYS")
| where isnotempty(requestUri_s)
| where requestUri_s  has_any (AIPaths)
| where httpStatus_d between (200 .. 299)
| project TimeGenerated,Resource,OperationName,RequestURI=requestUri_s,UserAgent=userAgent_s,HttpMethod=httpMethod_s,ClientIP=clientIP_s,RequestQuery=requestQuery_s,HTTPStaus=httpStatus_d,ORIGINALHOST=originalHost_s
```

## Importance
| Impact Level | False Positive Rate    | Data Source    |
| ---  | --- | --- |
| 🟡 Medium | Low  | Imperva WAF (ImpervaWAFCloud_CL), Azure Diagnostics (AzureDiagnostics) |

#### Investigation Steps
1. Examine Client IP & User Agent: Verify whether the requesting source IP originates from an authorized corporate developer network, CI/CD pipeline or known application integration.
2. Review Targeted Endpoints: Differentiate between standard operational queries (e.g., /v2/health, /v1/models) and high-impact data retrieval endpoints (e.g., /v1/chat/completions, /api/2.0/mlflow).
3. Analyze Request Volumes & Frequency: Check for rapid burst calls or off-hours spikes from a single client IP that might indicate model scraping or bulk inference data exfiltration.
4. Correlate Identity Context: Cross-reference the Client IP with APIM developer accounts, WAF authentication logs or Azure Active Directory sign-ins to map the request to an authenticated identity.

#### Recommendations
1. Enforce Strict Authentication: Ensure all AI/ML API endpoints routed through gateways require API keys, OAuth2 or Managed Identity tokens rather than remaining unauthenticated.
2. Implement Rate Limiting & Throttling: Apply APIM / WAF rate-limiting policies specifically on high-value paths (/v1/chat/completions, /score) to prevent automated model scraping and API abuse.
3. Establish Anomaly Baselines: Use this access query as a baseline dataset to alert on new client IPs, unusual user agents or abnormal spike patterns accessing ML model infrastructure.

#### Author 
- **Name: Rohit Ashok**
- **Github: https://github.com/rohit8096-ag**
- **LinkedIn: https://linkedin.com/in/rohit-ashokgoud-5b77a0188**
