# *Autonomous AI Agent Reconnaissance: IdP Metadata Discovery, JS Bundle Scraping and API Enumeration*

#### Description
This detection identifies multi-stage, automated web reconnaissance executed by autonomous AI agent frameworks (e.g.. Hermes, OpenClaw, SANDCLOCK) and AI-driven red team scanners. These multi-agent frameworks execute Phase 1 attack workflows by automatically downloading and parsing client-side JavaScript bundles (Angular, React, Vue), extracting embedded OAuth/Keycloak endpoints and unlinked API paths, probing Identity Provider (IdP) metadata (/.well-known/openid-configuration, /saml/metadata, JWKS keys) and executing systematic API path-busting across Web Application Firewalls (Imperva) and API Gateways (Azure Application Gateway). This rule detects the pre-foothold reconnaissance phase before agentic tools can exploit unauthenticated APIs or harvest credentials.

#### MITRE ATT&CK
| Technique ID | Title | Link |
| --- | --- | --- |
| T1190    | Exploit Public-Facing Application | https://attack.mitre.org/techniques/T1190/|
| T1018    | Remote System Discovery           | https://attack.mitre.org/techniques/T1018/|
| T1046    | Network Service Discovery         |https://attack.mitre.org/techniques/T1046/ |


#### MITRE ATLAS (AI Threat Framework)
| Technique ID | Title | Link |
| --- | --- | --- |
| AML.T0116     | Autonomous Reconnaissance                    | https://atlas.mitre.org/techniques/AML.T0116/     |
| AML.T0043     | Operational Environment Reconnaissance       | https://atlas.mitre.org/techniques/AML.T0043/     |
| AML.T0006     | Active Scanning                              | https://atlas.mitre.org/techniques/AML.T0006/     |
| AML.T0013     | Discover ML Model Ontology                   | https://atlas.mitre.org/techniques/AML.T0013/     |



#### Sentinel

```KQL
let idp_endpoints = dynamic([
    "/.well-known/openid-configuration",
    "/.well-known/oauth-authorization-server",
    "/.well-known/jwks.json",
    "/protocol/openid-connect/certs",
    "/saml/metadata",
    "/saml2/metadata",
    "/FederationMetadata/2007-06/FederationMetadata.xml",
    "/adfs/.well-known/openid-configuration",
    "/v2.0/.well-known/openid-configuration",
    "/oauth2/v1/keys",
    "/oauth2/v2.0/keys",
    "/discovery/keys"]);
let api_prefixes = dynamic(["/api/", "/v1/", "/v2/", "/v3/", "/rest/", "/graphql"]);
let LegitScannerIP=dynamic(["10.0.0.0","10.0.0.1"]); //Exclude known scanner IP's
let suspicious_ips =
union isfuzzy=true
    (
        AGWAccessLogs
        | where TimeGenerated > ago(2h)
        | where RequestUri has_any (idp_endpoints)
        | project SourceIP = ClientIp, IdpPath = RequestUri
    ),
    (
        ImpervaWAFCloud_CL
        | where TimeGenerated > ago(2h)
        | where Request has_any (idp_endpoints)
        | project SourceIP = Src, IdpPath = Request
    )
    | summarize IdpPathsFound = dcount(IdpPath) by SourceIP
    | where SourceIP !in (LegitScannerIP)
    | where IdpPathsFound >= 2
    | project SourceIP;
union isfuzzy=true
(
    AGWAccessLogs
    | where TimeGenerated > ago(2h)
    | where ClientIp !in (LegitScannerIP)
    | where ClientIp in (suspicious_ips)
    | where RequestUri has_any (idp_endpoints)
        or RequestUri has_any (api_prefixes)
        or RequestUri endswith ".js"
    | project
        TimeGenerated,
        SourceIP = ClientIp,
        RequestPath = RequestUri,
        TargetHost = Host,
        ResponseStatus = tostring(HttpStatus),
        LogSource = "agw",
        UserAgent
),
(
    ImpervaWAFCloud_CL
    | where TimeGenerated > ago(2h)
    | where Src !in (LegitScannerIP)
    | where Src in (suspicious_ips)
    | where Request has_any (idp_endpoints)
        or Request has_any (api_prefixes)
        or Request endswith ".js"
    | project
        TimeGenerated,
        SourceIP = Src,
        RequestPath = Request,
        TargetHost = SourceServiceName,
        ResponseStatus = tostring(Act),
        LogSource = "imperva",
        UserAgent = RequestClientApplication
)
| extend
    IsBundle = RequestPath matches regex @"(?i)(main|runtime|polyfills|vendor|chunk|bundle|app|index)[.\-][A-Za-z0-9_.\-]*\.js$",
    IsIdpDiscovery = RequestPath has_any (idp_endpoints),
    IsApiEnum = RequestPath has_any (api_prefixes) and not(RequestPath has_any (idp_endpoints)),
    RequestPassed = iff(LogSource == "agw", toint(ResponseStatus) between (200 .. 299), ResponseStatus has "PASSED")
| where IsBundle or IsIdpDiscovery or IsApiEnum
| summarize
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated),
    BundleFirstSeen = minif(TimeGenerated, IsBundle),
    Bundles = countif(IsBundle),
    IdpRequests = countif(IsIdpDiscovery),
    IdpPathsFound = dcountif(RequestPath, IsIdpDiscovery),
    ApiRequests = countif(IsApiEnum),
    ApiPathsFound = dcountif(RequestPath, IsApiEnum),
    ApiSucceeded = countif(IsApiEnum and RequestPassed),
    TargetHosts = dcount(TargetHost),
    IdpEndpoints = make_set_if(RequestPath, IsIdpDiscovery, 15),
    ApiEndpoints = make_set_if(RequestPath, IsApiEnum, 30),
    UserAgents = make_set(UserAgent, 5)
    by SourceIP, bin(TimeGenerated, 30m)
| where Bundles >= 1
| where IdpPathsFound >= 2
| where ApiPathsFound >= 10
| where BundleFirstSeen <= FirstSeen + 10m
| project FirstSeen, LastSeen, SourceIP, TargetHosts, Bundles, IdpRequests, IdpPathsFound, ApiRequests, ApiPathsFound, ApiSucceeded, IdpEndpoints, ApiEndpoints, UserAgents
```

## Importance
| Impact Level | False Positive Rate    | Data Source    |
| ---  | --- | --- |
| 🔴 High | Low  | Azure Application Gateway (AGWAccessLogs), Imperva WAF (ImpervaWAFCloud_CL) |

#### Investigation Steps
1. Analyze Agent Recon sequence: Confirm that client side JS bundle requests (Bundles) occurred within the first 10 minutes alongside IdP metadata queries (IdpEndpoints) and followed immediately by structured API enumeration (ApiEndpoints).
2. Review API Exposure & Unauthenticated Access: Check ApiSucceeded counts to identify if the AI agent discovered unauthenticated endpoints, sensitive administrative paths or exposed user data endpoints.
3. Audit Client-Side Bundles: Inspect requested JS bundles (main.js, vendor.js, chunk.js) on affected targets to determine if OAuth client IDs, Keycloak configuration objects, internal URLs or API keys were exposed in client-side code.
4. Identify Agentic Infrastructure: Examine UserAgents and cross reference SourceIP with proxy providers, hosting environments or known AI agent automation infrastructures.

#### Recommendations
1. Block Reconnaissance IP: Immediately deploy WAF and Application Gateway rate limiting or explicit drop rules for SourceIP to break the agent's automated recon loop.
2. Sanitize Production JS Bundles: Strip internal environment variables, unlinked API endpoints, OAuth client secrets and Keycloak realm configurations from production JavaScript builds.
3. Enforce Strict API Schema & Zero Trust Auth: Mandate token based authentication (OAuth 2.0 / OIDC) across all internal API endpoints discovered during path-busting, ensuring endpoints return 401 Unauthorized / 404 Not Found without revealing schema details.

#### Author 
- **Name: Rohit Ashok**
- **Github: https://github.com/rohit8096-ag**
- **LinkedIn: https://linkedin.com/in/rohit-ashokgoud-5b77a0188**