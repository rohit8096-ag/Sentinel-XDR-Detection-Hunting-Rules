# *Unsanctioned Probing and Surface Enumeration of Vector Databases and RAG Indexes*

#### Description
This detection identifies external IP addresses attempting to probe, map or enumerate exposed vector database endpoints and Retrieval-Augmented Generation (RAG) backend indexes across perimeter security controls. The query monitors traffic against WAF (Imperva) and API Gateway (Azure Application Gateway) logs, targeting API paths specific to vector store engines (e.g.. Pinecone, Qdrant, Weaviate, Milvus, ChromaDB, Elasticsearch/OpenSearch) such as /v1/schema, describe_index_stats, collections, points, vectors and _cat/indices. Attackers and automated AI scanners leverage these requests to discover vector embeddings, index schemas and proprietary knowledge bases for subsequent data exfiltration or RAG poisoning.

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
let ExcludeIPs = dynamic(["10.0.0.0","10.0.0.1"]); // Exclude known scanner IPs
let VectorSurface = @"(?i)/(v1/schema|v1/meta|describe_index_stats|_cat/indices|_mapping|collections|databases|indexes|points|vectors|query|_search)([/?\s]|$)";
let ToolRegex = @"(?i)(python-requests|httpx|aiohttp|curl|wget|go-http|okhttp|scrapy|postman|nuclei)";
let Imperva = ImpervaWAFCloud_CL
| where TimeGenerated > ago(1d)
| extend UrlPath = extract(@"^[^/]+(/[^\s]*)$", 1, tostring(Request))
| extend UrlPath = iff(isempty(UrlPath), tostring(Request), UrlPath)
| extend FullUri = strcat(UrlPath, iff(isempty(tostring(QStr)), "", strcat("?", tostring(QStr))))
| project TimeGenerated, Layer = "Imperva", SourceIp = tostring(Src), Host = tostring(SourceServiceName),
    HttpMethod = tostring(RequestMethod), FullUri, Body = tostring(PostBody),
    Action = tostring(Act), UserAgent = tostring(RequestClientApplication);
let AGW = AGWAccessLogs
| where TimeGenerated > ago(1d)
| project TimeGenerated, Layer = "AppGateway", SourceIp = tostring(ClientIp), Host = tostring(Host),
    HttpMethod = tostring(HttpMethod), FullUri = tostring(RequestUri), Body = "",
    Action = tostring(HttpStatus), UserAgent = tostring(UserAgent);
union isfuzzy=true Imperva, AGW
| where SourceIp !in (ExcludeIPs)
| extend Surface = strcat(FullUri, " ", Body)
| where Surface matches regex VectorSurface
| extend ScriptedClient = UserAgent matches regex ToolRegex
| summarize
    DistinctEndpoints = dcount(FullUri), Endpoints = make_set(FullUri, 30),
    Methods = make_set(HttpMethod, 10), Actions = make_set(Action, 10),
    Layers = make_set(Layer, 3), Hosts = make_set(Host, 10),
    UserAgents = make_set(UserAgent, 10), ScriptedClient = max(toint(ScriptedClient)),
    Events = count(), FirstSeen = min(TimeGenerated), LastSeen = max(TimeGenerated)
    by SourceIp, bin(TimeGenerated, 15m)
| where DistinctEndpoints >= 2
```

## Importance
| Impact Level | False Positive Rate    | Data Source    |
| ---  | --- | --- |
| 🔴 High | Low  |Azure Application Gateway (AGWAccessLogs), Imperva WAF (ImpervaWAFCloud_V2_CL) |

#### Investigation Steps
1. Analyze Vector API Surface: Inspect Endpoints and Methods to confirm if the requests targeted schema endpoints (/v1/schema, describe_index_stats), collection lists or raw query interfaces (/vectors, _search).
2. Review Client Automation & User-Agents: Check ScriptedClient and UserAgents to determine if the requests originated from automated security scanners (e.g., Nuclei), HTTP scripting libraries (e.g., python-requests, httpx) or web browsers.
3. Verify Connection Outcomes: Review Actions (HTTP Status codes or WAF actions) to evaluate whether any vector index requests bypassed perimeter security and returned 200 OK HTTP responses.
4. Determine Backend Exposure: Audit target hosts (Hosts) to confirm whether vector database instances or API gateways are improperly exposed directly to the public internet without proper API token/OAuth enforcement.

#### Recommendations
1. Restrict Perimeter Exposure: Immediately enforce zero-trust access controls, private endpoints or IP whitelist restrictions around vector DB interfaces (Pinecone, Qdrant, Milvus, Chroma, Elasticsearch).
2. Block Reconnaissance IP: Deploy explicit rate-limiting or drop rules on WAF and API Gateways for SourceIp addresses attempting unauthenticated index enumeration.
3. Enforce API Token & Schema Validation: Ensure all vector search and management APIs require authenticated bearer tokens and return standard generic response codes (401/404) for unauthorized path probes.subnets.

#### Author 
- **Name: Rohit Ashok**
- **Github: https://github.com/rohit8096-ag**
- **LinkedIn: https://linkedin.com/in/rohit-ashokgoud-5b77a0188**