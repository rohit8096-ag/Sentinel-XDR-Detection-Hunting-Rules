# *Multi-Privilege Token Abuse Detection (Burst Activity)*

#### Description
This detection identifies instances where a non-standard process attempts to exercise high-impact privileges (like SeDebugPrivilege or SeImpersonatePrivilege). These privileges are frequently leveraged by adversaries for Token Manipulation or LSASS Dumping to escalate privileges or move laterally.

#### MITRE ATT&CK Technique(s)
| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1134 | Access Token Manipulation |https://attack.mitre.org/techniques/T1134/ |

#### Sentinel

```KQL
let TokenTheftPrivileges = dynamic([
    "SeDebugPrivilege",
    "SeImpersonatePrivilege",
    "SeAssignPrimaryTokenPrivilege",
    "SeTcbPrivilege",
    "SeCreateTokenPrivilege"
]);
//Add your legitimate process
let LegitimateProcesses = dynamic([
    @"c:\windows\system32\services.exe",
    @"c:\windows\system32\lsass.exe",
    @"c:\windows\system32\wininit.exe",
    @"c:\windows\system32\csrss.exe",
    @"c:\windows\system32\smss.exe",
    @"c:\program files\windows defender\msmpeng.exe"
]);
SecurityEvent
| where TimeGenerated > ago(1d)
| where EventID == 4673
| extend ProcNameLower = tolower(ProcessName)
| where ProcNameLower !in~ (LegitimateProcesses)
| extend Privileges = split(PrivilegeList, " ")
| mv-expand Privilege = Privileges
| extend Privilege = tostring(Privilege)
| where Privilege in (TokenTheftPrivileges)
| summarize
    DistinctPrivileges = dcount(Privilege),
    PrivilegeSet = make_set(Privilege, 10),
    InvocationCount = count(),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by Computer, Account, ProcessName, bin(TimeGenerated, 5m)
| where DistinctPrivileges >= 2 and InvocationCount >= 3
| project FirstSeen, LastSeen, Computer, Account, ProcessName, DistinctPrivileges, PrivilegeSet, InvocationCount
```

## Importance
| Impact Level | False Positive Rate    | Data Source    |
| ---  | --- | --- |
| 🔴 High | Medium | Windows Security Events (4673) |

#### Investigation Steps
1. Verify Process Legitimacy: Check if the ProcessName is a known internal tool or a third-party administrative agent not included in the exclusion list.
2. Analyze Account Context: Determine if the Account performing the action typically performs administrative tasks on that specific Computer.
3. Check for Correlation: Look for subsequent events like 4624 (Logon) or 4688 (Process Creation) occurring immediately after these privilege checks.
4. Frequency Analysis: High InvocationCount within a 5-minute window often suggests an automated tool or script rather than manual admin activity.

#### Recommendations
1. Isolate Host: If the process is unrecognized (e.g., located in Temp or Downloads), isolate the host immediately.
2. Credential Reset: Rotate credentials for the affected Account, as the token may have already been compromised.
3. Review GPO: Ensure the "Debug Programs" and "Impersonate a client after authentication" user rights are restricted to the smallest possible group.

#### Author 
- **Name: Rohit Ashok**
- **Github: https://github.com/rohit8096-ag**
- **LinkedIn: https://linkedin.com/in/rohit-ashokgoud-5b77a0188**