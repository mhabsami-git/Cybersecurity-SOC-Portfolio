# SPL Security Queries (Splunk)

> Lab-tested searches. Index, sourcetype and field names depend on your data source (Windows TA, Sysmon TA, Entra ID add-on). **Adjust them to match your lab** and note which you used.

| # | Search | Data Source | MITRE |
|---|---|---|---|
| 1 | Failed logons by user and source | WinEventLog:Security | T1110 |
| 2 | Password spray: many users, one IP | WinEventLog:Security | T1110.003 |
| 3 | Success after multiple failures | WinEventLog:Security | T1110 / T1078 |
| 4 | Encoded PowerShell | Sysmon (EID 1) | T1059.001 |
| 5 | User added to Administrators | WinEventLog:Security | T1098 |
| 6 | Rare parent-child processes | Sysmon (EID 1) | Hunting |

---
### 1. Failed logons by user and source
```spl
index=wineventlog sourcetype="WinEventLog:Security" EventCode=4625 earliest=-24h
| bin _time span=10m
| stats count AS Attempts BY _time, Account_Name, Source_Network_Address
| where Attempts > 10
| sort - Attempts
```
![results](screenshots/spl-01-failed-logons.png)

---
### 2. Password spray: many users, one IP
```spl
index=wineventlog sourcetype="WinEventLog:Security" EventCode=4625 earliest=-24h
| stats dc(Account_Name) AS TargetedUsers count AS Attempts
        min(_time) AS FirstSeen max(_time) AS LastSeen BY Source_Network_Address
| where TargetedUsers >= 5
| convert ctime(FirstSeen) ctime(LastSeen)
| sort - TargetedUsers
```
**Tuning:** Exclude VPN/NAT addresses. **Limitation:** Per-IP logic misses distributed sprays.

---
### 3. Success after multiple failures
```spl
index=wineventlog sourcetype="WinEventLog:Security" (EventCode=4625 OR EventCode=4624) earliest=-24h
| eval outcome=if(EventCode=4625,"fail","success")
| stats count(eval(outcome="fail")) AS Fails
        count(eval(outcome="success")) AS Successes
        latest(_time) AS LastEvent BY Source_Network_Address, Account_Name
| where Fails >= 5 AND Successes >= 1
| convert ctime(LastEvent)
```
**Next step:** Pivot into activity by that account after the first success.

---
### 4. Encoded PowerShell (Sysmon)
```spl
index=sysmon EventCode=1 earliest=-7d
    (Image="*\\powershell.exe" OR Image="*\\pwsh.exe")
    (CommandLine="*-enc*" OR CommandLine="*EncodedCommand*" OR CommandLine="*FromBase64String*")
| table _time host User ParentImage CommandLine
| sort - _time
```

---
### 5. User added to Administrators
```spl
index=wineventlog sourcetype="WinEventLog:Security" EventCode=4732 Group_Name="Administrators" earliest=-7d
| table _time host Subject_Account_Name Member_Security_ID Group_Name
```

---
### 6. Rare parent-child process pairs
**Purpose:** Hunting baseline; surface unusual process lineage.
```spl
index=sysmon EventCode=1 earliest=-30d
| stats count BY ParentImage, Image
| rare limit=20 count
```
