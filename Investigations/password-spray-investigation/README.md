# Password Spray Investigation (Sentinel KQL + Splunk SPL)

## Overview
Investigation of a simulated password spray, performed in both Microsoft Sentinel (KQL) and Splunk (SPL) to show the same detection logic across two SIEMs.

## Objective
Determine whether multiple accounts were targeted from one source, whether any sign-in succeeded, and assess the likelihood of compromise.

## Environment
- Microsoft Sentinel, Entra ID SigninLogs, Log Analytics
- Splunk with Windows Security logs (EventCode 4624/4625)
- Simulated attacker IP: `<LAB_IP>`

## Scenario
Many failed authentications against several accounts from one IP, followed by a success on one account.

## Investigation Process

### Step 1: Review the incident
![Incident overview](screenshots/01-incident-overview.png)
*Severity, affected entities and alert time window.*

### Step 2: Failures vs successes per IP/user (KQL)
```kql
SigninLogs
| where TimeGenerated > ago(24h)
| summarize FailedAttempts = countif(ResultType != "0"),
            SuccessfulAttempts = countif(ResultType == "0")
            by IPAddress, UserPrincipalName
| order by FailedAttempts desc
```
![KQL results](screenshots/02-kql-failures-vs-success.png)

### Step 3: Identify broad targeting (KQL, then SPL)
```kql
SigninLogs
| where ResultType != "0"
| summarize TargetedUsers = dcount(UserPrincipalName), Attempts = count() by IPAddress
| where TargetedUsers > 5
```
```spl
index=wineventlog EventCode=4625 earliest=-24h
| stats dc(Account_Name) AS TargetedUsers count AS Attempts BY Source_Network_Address
| where TargetedUsers > 5
```
![SPL results](screenshots/03-spl-targeted-users.png)

### Step 4: Search for successful authentication
```kql
SigninLogs
| where IPAddress == "<LAB_IP>" and ResultType == "0"
| project TimeGenerated, UserPrincipalName, IPAddress, AppDisplayName, Location, DeviceDetail
```
![Successful sign-in](screenshots/04-successful-signin.png)

## Timeline
| Time | Event |
|---|---|
| 10:02 | Failed authentication begins |
| 10:03 | Multiple accounts targeted |
| 10:07 | Successful login observed |
| 10:15 | Incident investigated |
| 10:20 | Containment recommended |

## Findings
- Pattern consistent with password spraying.
- One IP targeted multiple accounts.
- At least one account succeeded after repeated failures, so compromise is likely.

## Incident Classification
| Field | Value |
|---|---|
| Classification | True Positive (simulated) |
| Severity | High |
| MITRE ATT&CK | T1110.003 Password Spraying |

## Recommended Response
1. Contain or disable the suspected account.
2. Reset credentials; check for password reuse.
3. Revoke sessions and refresh tokens.
4. Review MFA registrations and recent MFA events.
5. Investigate post-authentication activity.
6. Review all other targeted accounts.
7. Block the malicious IP where appropriate.
8. Review Conditional Access and sign-in risk policies.
9. Document and escalate per severity.

## Skills Demonstrated
KQL · SPL · Sentinel · Splunk · Entra ID · triage · MITRE mapping · incident response · documentation

## Lessons Learned
*Write 2-3 genuine points in your own words.*

## Lab Disclaimer
This investigation was performed in a controlled lab environment for cybersecurity training and professional development.
