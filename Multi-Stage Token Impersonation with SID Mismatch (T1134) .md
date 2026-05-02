# *Multi-Stage Token Impersonation with SID Mismatch (T1134)*

#### Description
This detection tracks the chain of events where an attacker manipulates a security token to switch user contexts. It correlates three specific stages:

-The Invocation: A process calls sensitive APIs (like DuplicateToken or LsaLogonUser) or uses runas /netonly.

-The Logon: A successful logon event occurs shortly after the invocation on the same device.

-The Child Execution: A new process is spawned under the context of the newly acquired identity.

The query flags instances where the final executing identity differs from the original invoker, suggesting a successful identity shift.

#### MITRE ATT&CK Technique(s)
| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1134 | Access Token Manipulation |https://attack.mitre.org/techniques/T1134/ |

#### DefenderXDR

```KQL
let invokeWindow = 1h;
let childWindow  = 1h;
let lookback     = 7d;
let SystemSIDs   = dynamic(["S-1-5-18","S-1-5-19","S-1-5-20"]);
let stage1 =
DeviceProcessEvents
| where Timestamp > ago(lookback)
| where (FileName =~ "runas.exe" and ProcessCommandLine has "/netonly")
    or ProcessCommandLine has_any ("runas /netonly","LogonUser","LsaLogonUser", "DuplicateToken","ImpersonateLoggedOnUser","SetThreadToken")
| where InitiatingProcessAccountSid !in (SystemSIDs)
| project InvokeTime = Timestamp, DeviceId, DeviceName,InvokerProcess = FileName,InvokerCmd = ProcessCommandLine,InvokerAccount = AccountName, InvokerSid = AccountSid, InvokerParent = InitiatingProcessFileName, InvokerParentCmd = InitiatingProcessCommandLine;
let stage2 =
DeviceLogonEvents
| where Timestamp > ago(lookback)
| where ActionType == "LogonSuccess"
| where LogonType in ("Network","Interactive","NewCredentials")
| where InitiatingProcessFileName !in~ ("svchost.exe","lsass.exe")
| project LogonTime = Timestamp,DeviceId,LogonType,NewLogonId = LogonId,NewAccount = AccountName, NewSid = AccountSid, LogonProcess = InitiatingProcessFileName, RemoteIP, InitiatingProcessCommandLine;
let stage3 =
DeviceProcessEvents
| where Timestamp > ago(lookback)
| project ChildTime = Timestamp, DeviceId,ChildProcess = FileName,ChildCmd = ProcessCommandLine,ChildAccount = AccountName,ChildSid = AccountSid,
    ChildLogonId = LogonId,
    ChildParent = InitiatingProcessFileName,
    ChildParentCmd = InitiatingProcessCommandLine;
stage1
| join kind=inner stage2 on DeviceId
| where LogonTime between (InvokeTime .. (InvokeTime + invokeWindow))
| join kind=inner stage3 on DeviceId
| where ChildLogonId == NewLogonId
| where ChildTime between (LogonTime .. (LogonTime + childWindow))
| where ChildSid != InvokerSid
| where NewSid != InvokerSid
| extend IdentityShift = strcat(InvokerAccount, " → ", NewAccount, " → ", ChildAccount)
| project
    DeviceName, DeviceId,
    // Stage 1
    InvokeTime, InvokerAccount, InvokerSid,InvokerProcess, InvokerCmd,InvokerParent, InvokerParentCmd,
    // Stage 2
    LogonTime, LogonType, NewAccount, NewSid, NewLogonId, LogonProcess, InitiatingProcessCommandLine,
    RemoteIP,
    // Stage 3
    ChildTime, ChildAccount, ChildSid,ChildProcess, ChildCmd, ChildParent, ChildParentCmd,IdentityShift
```

## Importance
| Impact Level | False Positive Rate    | Data Source    |
| ---  | --- | --- |
| 🔴 High | Low | DeviceProcessEvents,DeviceLogonEvents |

#### Investigation Steps
1. Analyze the Identity Shift: Look at the IdentityShift field (Invoker → New → Child). Does this transition make sense for a standard admin workflow?  
2. Examine the Invoker: Check InvokerCmd. Is the process using high-level APIs like DuplicateToken? This is common in tools like Cobalt Strike or Mimikatz.  
3. Verify Stage 2 Process: Investigate the LogonProcess. If a non-standard process (not lsass.exe or svchost.exe) is initiating logons, it is highly suspicious.  
4. Check Remote IP: If LogonType is "Network", check the RemoteIP for signs of lateral movement from another compromised host.

#### Recommendations
1. Identify Impersonation Tools: Check the host for evidence of impersonation tools (e.g., incognito.exe, Rubeus).
2. Restrict Sensitive APIs: Use Attack Surface Reduction (ASR) rules to block the abuse of sensitive APIs by unauthorized applications.
3. Review Service Accounts: Ensure service accounts are not being used interactively to perform these shifts.

#### Author 
- **Name: Rohit Ashok**
- **Github: https://github.com/rohit8096-ag**
- **LinkedIn: https://linkedin.com/in/rohit-ashokgoud-5b77a0188**
