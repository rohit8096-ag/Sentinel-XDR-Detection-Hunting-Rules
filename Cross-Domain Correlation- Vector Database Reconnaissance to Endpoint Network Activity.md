# *Cross-Domain Correlation: Vector Database Reconnaissance to Endpoint Network Activity*

#### Description
This cross-domain threat hunting detection bridges perimeter WAF/API Gateway logs with Endpoint Detection and Response (EDR) telemetry. It first aggregates external IP addresses probing perimeter vector database and RAG infrastructure endpoints (e.g.. /v1/schema, describe_index_stats, collections, vectors, _search). It then correlates these high-confidence reconnaissance IPs against DeviceNetworkEvents in Microsoft Defender for Endpoint (MDE) to determine if any internal servers, container hosts or workstations have established active inbound or outbound network sessions with the probing external infrastructure.

#### MITRE ATT&CK
| Technique ID | Title | Link |
| --- | --- | --- |
| T1595.002    | Active Scanning: Vulnerability Scanning    | https://attack.mitre.org/techniques/T1595/002/|
| T1071.001    | Application Layer Protocol: Web Protocols  | https://attack.mitre.org/techniques/T1071/001/|


#### MITRE ATLAS (AI Threat Framework)
| Technique ID | Title | Link |
| --- | --- | --- |
| AML.T0064     | Gather RAG-Indexed Targets                   | https://atlas.mitre.org/techniques/AML.T0064      |
| AML.T0085.001 | Discover ML Model Ontology                   | https://atlas.mitre.org/techniques/AML.T0013/     |
| AML.T0043     | Operational Environment Reconnaissance       | https://atlas.mitre.org/techniques/AML.T0043/     |
| AML.T0006     | Active Scanning                              | https://atlas.mitre.org/techniques/AML.T0006/     |



#### Sentinel

```KQL
let KnownScannerIPs   = dynamic(["10.0.0.0","10.0.0.1"]);
let VectorSurfaceRegex = @"(?i)/(v1/schema|v1/meta|describe_index_stats|_cat/indices|_mapping|collections|databases|indexes|points|vectors|query|_search)([/?\s]|$)";
let SuspectIPs = (union isfuzzy=true
    (ImpervaWAFCloud_V2_CL
    | where TimeGenerated > ago(1d)
    | extend UrlPath = extract(@"^[^/]+(/[^\s]*)$", 1, tostring(Request))
    | project TimeGenerated, SourceIp=tostring(Src), Surface=strcat(UrlPath," ",tostring(QStr)," ",tostring(PostBody))),
    (AGWAccessLogs
    | where TimeGenerated > ago(1d)
    | project TimeGenerated, SourceIp=tostring(ClientIp), Surface=tostring(RequestUri)))
| extend VectorSurface = extract(VectorSurfaceRegex, 1, Surface)
| where isnotempty(VectorSurface)
| where SourceIp !in (KnownScannerIPs)
| summarize DistinctEndpoints = dcount(VectorSurface) by SourceIp
| where DistinctEndpoints >= 4
| project SourceIp;
DeviceNetworkEvents
| where Timestamp > ago(1d)
| where RemoteIP in (SuspectIPs) or LocalIP in (SuspectIPs)
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, LocalIP, RemoteIP, RemotePort, RemoteUrl
```

## Importance
| Impact Level | False Positive Rate    | Data Source    |
| ---  | --- | --- |
| 🔴 High | Low  |Azure Application Gateway (AGWAccessLogs), Imperva WAF (ImpervaWAFCloud_V2_CL), Defender for Endpoint (DeviceNetworkEvents) |

#### Investigation Steps
1. Analyze Initiating Process: Examine InitiatingProcessFileName and InitiatingProcessCommandLine on the internal endpoint (DeviceName) to determine which binary or service established or accepted the connection to RemoteIP.
2. Determine Connection Directionality: Verify if the connection was an inbound probe allowed through network boundaries to an internal vector database host or an outbound connection (e.g.. reverse shell, data exfiltration or malicious callback) from an internal workload to the attacker's IP.
3. Inspect Endpoint Role: Check if DeviceName hosts LLM models, RAG microservices, vector stores (Milvus, Qdrant, ChromaDB, Elasticsearch) or developer environments with access to AI API keys.
4. Cross-Reference WAF Logs: Pivoting back to WAF logs for SuspectIPs to inspect the full HTTP request history and payload parameters sent during the initial vector surface enumeration.

#### Recommendations
1. Isolate Compromised Workloads: If InitiatingProcessFileName indicates abnormal process execution (e.g.. curl, python, powershell or an unauthorized reverse shell), immediately isolate DeviceName via Microsoft Defender for Endpoint.
2. Implement Dual-Layer IP Blocking: Immediately apply block rules for SuspectIPs at both the perimeter WAF/Gateway level and the host/firewall level.
3. Enforce Micro-segmentation for Vector DBs: Ensure internal vector stores and embedding endpoints are isolated from direct internet access and require explicit mTLS or OAuth 2.0 authentication.

#### Author 
- **Name: Rohit Ashok**
- **Github: https://github.com/rohit8096-ag**
- **LinkedIn: https://linkedin.com/in/rohit-ashokgoud-5b77a0188**