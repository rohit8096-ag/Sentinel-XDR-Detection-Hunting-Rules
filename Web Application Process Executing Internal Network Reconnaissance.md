# *Web Application Process Executing Internal Network Reconnaissance*

#### Description
This detection identifies internet-facing web application processes (e.g.. w3wp, java, node, python, gunicorn, uvicorn, nginx) executing anomalous internal network scanning, host sweeps or port sweeps against private IP addresses. Following web server compromise (via Web Shells, RCE vulnerabilities or SSRF), attackers frequently leverage web application runtime environments to pivot and map the internal enterprise network. This rule builds a 14-day statistical baseline of normal inter-service communications for each internet-facing web process to isolate unauthorized internal reconnaissance from routine application traffic.

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



#### Sentinel

```KQL
let WebProcesses = dynamic([
    "w3wp", "java", "node",
    "python", "python3", "gunicorn", "uvicorn",
    "php-fpm", "php-cgi", "nginx", "httpd", "apache2",
    "dotnet", "ruby", "puma",
    "tomcat", "caddy", "lighttpd", "litespeed",
    "kestrel", "daphne", "hypercorn",
    "passenger", "unicorn", "thin",
    "iisexpress"
]);
let InternetFacingDevices = DeviceInfo
| where Timestamp > ago(7d)
| where IsInternetFacing == true
| distinct DeviceId;
let NormalBehavior =DeviceNetworkEvents
| where Timestamp between (ago(14d) .. ago(1h))
| extend ProcessName = replace_regex(tolower(InitiatingProcessFileName), @"\.exe$", "")
| where ProcessName in~ (WebProcesses)
| where ipv4_is_private(RemoteIP)
| where RemoteIP != LocalIP
| summarize
    HostsPer15m = dcount(RemoteIP),
    PortsPer15m = dcount(RemotePort)
    by DeviceId, ProcessName, bin(Timestamp, 15m)
| summarize
    BaselineHosts = avg(HostsPer15m),
    BaselinePorts = avg(PortsPer15m)
    by DeviceId, ProcessName;
DeviceNetworkEvents
| where Timestamp > ago(1h)
| where ActionType in ("ConnectionSuccess", "ConnectionFailed")
| extend ProcessName = replace_regex(tolower(InitiatingProcessFileName), @"\.exe$", "")
| where ProcessName in~ (WebProcesses)
| where ipv4_is_private(RemoteIP)
| where RemoteIP != LocalIP
| join kind=inner InternetFacingDevices on DeviceId
| summarize
    FirstSeen = min(Timestamp),
    LastSeen = max(Timestamp),
    DistinctHosts = dcount(RemoteIP),
    DistinctPorts = dcount(RemotePort),
    TotalConnections = count(),
    Failed = countif(ActionType == "ConnectionFailed"),
    Succeeded = countif(ActionType == "ConnectionSuccess"),
    Accounts = make_set(InitiatingProcessAccountName, 5),
    Targets = make_set(strcat(RemoteIP, ":", tostring(RemotePort)),30)
    by DeviceName, DeviceId, ProcessName
| join kind=leftouter NormalBehavior on DeviceId, ProcessName
| extend
    BaselineHosts = coalesce(BaselineHosts, 0.0),
    BaselinePorts = coalesce(BaselinePorts, 0.0)
| extend
    HostMultiplier = iff(BaselineHosts > 0, round(DistinctHosts / BaselineHosts, 1), real(null)),
    PortMultiplier = iff(BaselinePorts > 0, round(DistinctPorts / BaselinePorts, 1), real(null)),
    FailRate = iff(TotalConnections > 0, round(100.0 * Failed / TotalConnections, 1), 0.0)
| extend
    HostSweep = DistinctHosts >= 15 and (BaselineHosts == 0 or DistinctHosts > 3 * BaselineHosts),
    PortSweep = DistinctPorts >= 10 and (BaselinePorts == 0 or DistinctPorts > 3 * BaselinePorts),
    HighFailure = TotalConnections >= 15 and Failed >= 10 and FailRate >= 60
| extend ReconScore = toint(HostSweep) + toint(PortSweep) + toint(HighFailure)
| where ReconScore >= 2
| project
    FirstSeen,
    LastSeen,
    DeviceName,
    DeviceId,
    ProcessName,
    Accounts,
    DistinctHosts,
    BaselineHosts,
    HostMultiplier,
    DistinctPorts,
    BaselinePorts,
    PortMultiplier,
    TotalConnections,
    Failed,
    Succeeded,
    FailRate,
    ReconScore,
    Targets
```

## Importance
| Impact Level | False Positive Rate    | Data Source    |
| ---  | --- | --- |
| 🔴 High | Low  |Microsoft Defender for Endpoint (DeviceInfo, DeviceNetworkEvents) |

#### Investigation Steps
1. Examine Process Lineage & Child Processes: Check whether the web application process (ProcessName) spawned unexpected shells (cmd.exe, powershell.exe, sh, bash) or dropped web shells prior to the network scanning activity.
2. Review Ingress Web Traffic: Inspect WAF, IIS or application server ingress logs around FirstSeen to identify potential exploit payloads (e.g.. RCE, deserialization attacks, SSRF or unauthenticated file uploads).
3. Analyze Target Subnets & Ports: Inspect Targets to determine what internal assets are being probed (e.g.. Domain Controllers, database servers, internal API management endpoints).
4. Verify Account Context: Check Accounts to confirm if the web process ran under standard low-privilege service accounts (NT AUTHORITY\IUSR, www-data) or if context switching/privilege escalation occurred.

#### Recommendations
1. Isolate the Host: Immediately isolate the affected internet-facing device from the internal network to halt active pivoting.
2. Remediate Vulnerability & Persistence: Terminate rogue child processes, remove deployed web shells and patch the underlying public-facing web application vulnerability.
3. Enforce Network Segmentation: Restrict internet-facing application servers from initiating outbound connections to internal management subnets and non-essential private IP ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16).

#### Author 
- **Name: Rohit Ashok**
- **Github: https://github.com/rohit8096-ag**
- **LinkedIn: https://linkedin.com/in/rohit-ashokgoud-5b77a0188**