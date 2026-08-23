# *Active Scanning of AI-Assisted Service Mailboxes*

#### Description
This detection identifies instances where external threat actors send multiple patterned probe emails to corporate service mailboxes (support@, info@, help@, etc.) to measure automated response latency, validate active email targets, and fingerprint backend automated workflows or AI agents. Scripted attacks exhibiting extremely rapid, highly consistent auto-reply latency (AvgLatencySeconds < 60 and StdDevLatencySeconds < 15) indicate active scanning to discover backend ticketing parameters or test automated AI input handling pipelines prior to delivering phishing payloads or prompt injections.

#### MITRE ATT&CK
| Technique ID | Title | Link |
| --- | --- | --- |
| T1595    | Active Scanning            | https://attack.mitre.org/techniques/T1595/    |
| T1589.002| Gathering Victim Identity  | https://attack.mitre.org/techniques/T1589/002/|
| T1598    | Phishing for Information.  | https://attack.mitre.org/techniques/T1598/.   |

#### MITRE ATLAS (AI Threat Framework)
| Technique ID | Title | Link |
| --- | --- | --- |
| AML.T0006 | Active Scanning                    | https://atlas.mitre.org/techniques/AML.T0006/ |
| AML.T0087 | Gather Victim Identity Information | https://atlas.mitre.org/techniques/AML.T0087/ |
| AML.T0013 | Discover ML Model Ontology         | https://atlas.mitre.org/techniques/AML.T0013/ |



#### Sentinel

```KQL
let service_mailboxes = dynamic(["support@example.com","info@example.com","help@example.com","contact@example.com","sales@example.com"]);
let Inbound =EmailEvents
| where TimeGenerated > ago(24h)
| where EmailDirection == "Inbound"
| where SenderFromDomain !endswith "example.com"
| where RecipientEmailAddress in~ (service_mailboxes)
| project InboundTime = TimeGenerated, SenderFromAddress = tolower(SenderFromAddress),ServiceAddress = tolower(RecipientEmailAddress), InboundSubject = tostring(Subject);
let Outbound =EmailEvents
| where TimeGenerated > ago(24h)
| where EmailDirection == "Outbound"
| where SenderFromAddress in~ (service_mailboxes)
| where DeliveryAction == "Delivered"
| project ReplyTime = TimeGenerated, ReplyTo = tolower(RecipientEmailAddress), ServiceAddress = tolower(SenderFromAddress);
Inbound
| join kind=inner Outbound on $left.SenderFromAddress == $right.ReplyTo and $left.ServiceAddress == $right.ServiceAddress
| where ReplyTime >= InboundTime
| where ReplyTime <= InboundTime + 10m
| extend ReplyLatencySeconds = datetime_diff("second", ReplyTime, InboundTime)
| summarize arg_min(ReplyTime, ReplyLatencySeconds) by SenderFromAddress, ServiceAddress, InboundTime, InboundSubject
| summarize
    ProbeCount = count(),
    DistinctSubjects = dcount(InboundSubject),
    AvgLatencySeconds = round(avg(ReplyLatencySeconds), 1),
    StdDevLatencySeconds = round(stdev(ReplyLatencySeconds), 1),
    MinLatencySeconds = min(ReplyLatencySeconds),
    MaxLatencySeconds = max(ReplyLatencySeconds),
    FirstProbe = min(InboundTime),
    LastProbe = max(InboundTime),
    SubjectSamples = make_set(InboundSubject, 5)
    by SenderFromAddress, ServiceAddress
| extend ProbeDurationMinutes = datetime_diff("minute", LastProbe, FirstProbe)
| where ProbeCount >= 3 and DistinctSubjects >= 3 and AvgLatencySeconds < 60 and StdDevLatencySeconds < 15
| project SenderFromAddress,ServiceAddress,ProbeCount,DistinctSubjects,AvgLatencySeconds,StdDevLatencySeconds,MinLatencySeconds,MaxLatencySeconds,ProbeDurationMinutes,FirstProbe,LastProbe, SubjectSamples
```

## Importance
| Impact Level | False Positive Rate    | Data Source    |
| ---  | --- | --- |
| 🟡 Medium | Low  | Microsoft Defender for Office 365 (EmailEvents) |

#### Investigation Steps
1. Analyze Sender Infrastructure: Inspect SenderFromAddress and the originating IP address reputation for disposable email services, newly registered domains or known proxy networks.
2. Examine Subject Patterns: Review SubjectSamples to determine if subjects are synthetic, randomized or fuzzed prompts designed to trigger specific workflow logic.
3. Assess Target Architecture: Check whether ServiceAddress feeds directly into an automated ticketing platform, auto-responder bot or GenAI support workflow.
4. Monitor Follow-Up Activity: Query subsequent email logs for secondary inbound messages from the detected sender containing malicious attachments, links or prompt injections.

#### Recommendations
1. Enforce Rate Limiting: Apply rate-limiting controls on public service mailboxes to restrict automated responses to high-frequency external senders.
2. Harden AI Input Pipelines: Sanitize incoming email bodies and subjects processed by automated LLM support agents to prevent Indirect Prompt Injection.
3. Block Malicious Senders: Add verified probe domains and sender addresses to the email gateway tenant blocklist.

#### Author 
- **Name: Rohit Ashok**
- **Github: https://github.com/rohit8096-ag**
- **LinkedIn: https://linkedin.com/in/rohit-ashokgoud-5b77a0188**