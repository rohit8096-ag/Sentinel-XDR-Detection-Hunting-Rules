# *Automated Entra ID User Enumeration via Scripted Frameworks*

#### Description
This detection looks for automated attempts to find valid user accounts in Microsoft Entra ID.Attackers may use scripts or tools such as python-requests, aiohttp, httpx, node-fetch, curl, go-http-client or okhttp to test a list of usernames against the login endpoints.When a username does not exist, Entra ID may return ResultType 50034, which indicates that the account was not found in the tenant.

The rule checks both interactive (SigninLogs) and non-interactive (AADNonInteractiveUserSignInLogs) sign-in failures and looks for activity coming from scripted UserAgent strings. It helps identify a single IP address or ASN repeatedly testing different usernames, which could be an early sign of user enumeration before password spraying or credential stuffing attempts.


#### MITRE ATT&CK
| Technique ID | Title | Link |
| --- | --- | --- |
|T1087.004	|Account Discovery: Cloud Account	            |https://attack.mitre.org/techniques/T1087/004/|


#### MITRE ATLAS (AI Threat Framework)
| Technique ID | Title | Link |
| --- | --- | --- |
|AML.T0087	|Gather Victim Identity Information	    |https://atlas.mitre.org/techniques/AML.T0087/|
|AML.T0043	|Operational Environment Reconnaissance	|https://atlas.mitre.org/techniques/AML.T0043/|



#### Sentinel

```KQL
let lookback = 1h; 
let ResultID = "50034"; // User account does not exist in tenant
union
(
    SigninLogs 
    | where TimeGenerated > ago(lookback) 
    | where ResultType == ResultID
    | extend LoginType = "Interactive"
    | project TimeGenerated, UserPrincipalName, IPAddress, AutonomousSystemNumber, UserAgent, AppDisplayName, LoginType
),
(
    AADNonInteractiveUserSignInLogs
    | where TimeGenerated > ago(lookback) 
    | where ResultType == ResultID
    | extend LoginType = "NonInteractive"
    | project TimeGenerated, UserPrincipalName, IPAddress, AutonomousSystemNumber, UserAgent, AppDisplayName, LoginType
)
| extend IsScriptedUA = UserAgent matches regex @"(?i)(python-requests|aiohttp|httpx|node-fetch|curl|go-http-client|okhttp)"
| where IsScriptedUA  
| summarize
    Attempts      = count(),
    DistinctUPNs  = dcount(UserPrincipalName),
    ScriptedHits  = countif(IsScriptedUA),
    UPNs          = make_set(UserPrincipalName, 25),
    UAs           = make_set(UserAgent, 10),
    MatchedUAs    = make_set_if(UserAgent, IsScriptedUA, 10),
    Apps          = make_set(AppDisplayName, 5),
    LoginType     = make_set(LoginType, 2),
    StartTime     = min(TimeGenerated),
    EndTime       = max(TimeGenerated)
    by IPAddress, AutonomousSystemNumber
| where DistinctUPNs >= 10 // Adjust threshold based on your requirement
```

## Importance
| Impact Level | False Positive Rate    | Data Source    |
| ---  | --- | --- |
| 🔴 High | Low  |Microsoft Entra ID (SigninLogs, AADNonInteractiveUserSignInLogs) |

#### Investigation Steps
1. Check the source IP and ASN: Check the IPAddress and AutonomousSystemNumber against threat intelligence and VPN/proxy information. Look for TOR nodes, suspicious hosting providers or residential proxies.
2. Check the usernames being tested: Review the UPNs to see which accounts were targeted. Look for patterns such as common username lists, employee names or usernames generated from a naming pattern.
3. Check for successful logins: Search SigninLogs and AADNonInteractiveUserSignInLogs for successful sign-ins (ResultType == 0) from the same IP or ASN. This will helps to identify whether any of the discovered accounts were later used successfully.
4. Check for password spraying: Look for follow-up activity from the same IP or ASN where the attacker moves from testing unknown users (50034) to trying passwords against valid accounts (50126 or 50053).

#### Recommendations
1. Use Conditional Access: Block or restrict sign-ins from known suspicious locations, proxy networks, TOR nodes or other untrusted sources where appropriate.
2. Enable Smart Lockout and Entra ID Protection: Make sure Smart Lockout and Identity Protection are enabled to detect unusual sign-in activity and apply controls such as MFA or password reset when needed.
3. Add rate limiting at the edge: Use a WAF or other edge protection to limit repeated authentication attempts and reduce large numbers of invalid username requests.

#### Author 
- **Name: Rohit Ashok**
- **Github: https://github.com/rohit8096-ag**
- **LinkedIn: https://linkedin.com/in/rohit-ashokgoud-5b77a0188**