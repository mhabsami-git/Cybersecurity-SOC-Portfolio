# KQL Security Queries (Microsoft Sentinel / Defender XDR)

> Lab-tested detection and hunting queries. Each states its purpose, tuning notes and limitations. A query result is a lead, not proof of compromise.

| # | Query | Table | MITRE |
|---|---|---|---|
| 1 | Repeated sign-in failures | SigninLogs | T1110 |
| 2 | Password spray: many users, one IP | SigninLogs | T1110.003 |
| 3 | Success after multiple failures | SigninLogs | T1110 / T1078 |
| 4 | Sign-ins from multiple countries | SigninLogs | T1078 |
| 5 | Windows failed logons (4625) | SecurityEvent | T1110 |
| 6 | Encoded PowerShell | DeviceProcessEvents | T1059.001 |
| 7 | User added to local Administrators | SecurityEvent | T1098 |

---
### 1. Repeated sign-in failures
**Purpose:** Find users/IPs with an unusual number of failures in a short window.
```kql
SigninLogs
| where TimeGenerated > ago(24h)
| where ResultType != "0"
| summarize Attempts = count() by UserPrincipalName, IPAddress, bin(TimeGenerated, 10m)
| where Attempts > 10
| order by Attempts desc
```
**Tuning:** Adjust the threshold to normal behaviour; exclude known service accounts.
**False positives:** Expired passwords, misconfigured apps, locked-out users.

![results](screenshots/kql-01-repeated-failures.png)

---
### 2. Password spray: many users, one IP
**Purpose:** Detect one source failing against many accounts.
```kql
SigninLogs
| where TimeGenerated > ago(24h)
| where ResultType in ("50126", "50053", "50057")   // bad password, locked, disabled
| summarize TargetedUsers = dcount(UserPrincipalName),
            Attempts = count(),
            FirstSeen = min(TimeGenerated),
            LastSeen = max(TimeGenerated)
            by IPAddress
| where TargetedUsers >= 5
| order by TargetedUsers desc
```
**Tuning:** Exclude corporate NAT/VPN egress IPs; adjust `TargetedUsers`.
**Limitations:** Attackers rotating IPs will evade a per-IP rule.

![results](screenshots/kql-02-password-spray.png)

---
### 3. Success after multiple failures
**Purpose:** Highlight likely compromise: failures followed by a success.
```kql
let failures = SigninLogs
    | where TimeGenerated > ago(24h) and ResultType != "0"
    | summarize FailCount = count(), LastFail = max(TimeGenerated) by IPAddress, UserPrincipalName;
SigninLogs
| where TimeGenerated > ago(24h) and ResultType == "0"
| join kind=inner failures on IPAddress, UserPrincipalName
| where TimeGenerated > LastFail and FailCount >= 5
| project TimeGenerated, UserPrincipalName, IPAddress, FailCount, AppDisplayName, Location
```
**Next step:** Review post-authentication activity (mailbox rules, MFA registration, app consent).

![results](screenshots/kql-03-success-after-failure.png)

---
### 4. Sign-ins from multiple countries
**Purpose:** Lead for impossible-travel investigation.
```kql
SigninLogs
| where TimeGenerated > ago(24h) and ResultType == "0"
| extend Country = tostring(LocationDetails.countryOrRegion)
| summarize Countries = make_set(Country), CountryCount = dcount(Country),
            First = min(TimeGenerated), Last = max(TimeGenerated) by UserPrincipalName
| where CountryCount > 1
| extend WindowMinutes = datetime_diff('minute', Last, First)
| where WindowMinutes < 120
```
**False positives:** VPN, proxies, mobile carriers, legitimate travel. Validate with device and user context.

---
### 5. Windows failed logons (4625)
```kql
SecurityEvent
| where TimeGenerated > ago(24h) and EventID == 4625
| summarize Failures = count(), Accounts = dcount(TargetAccount) by IpAddress, bin(TimeGenerated, 10m)
| where Failures > 20
| order by Failures desc
```

---
### 6. Encoded PowerShell
**Purpose:** Hunt for obfuscated PowerShell execution.
```kql
DeviceProcessEvents
| where TimeGenerated > ago(7d)
| where FileName in~ ("powershell.exe", "pwsh.exe")
| where ProcessCommandLine has_any ("-enc", "-EncodedCommand", "FromBase64String")
| project TimeGenerated, DeviceName, AccountName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by TimeGenerated desc
```
**False positives:** Some deployment tools use encoded commands. Check the parent process.

---
### 7. User added to local Administrators
```kql
SecurityEvent
| where TimeGenerated > ago(7d) and EventID == 4732
| where TargetUserName =~ "Administrators"
| project TimeGenerated, Computer, SubjectAccount, MemberSid, TargetUserName
```
