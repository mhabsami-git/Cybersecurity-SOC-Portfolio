# Cybersecurity SOC Portfolio

Hands-on SOC investigations, detection queries and playbooks built in controlled lab environments.
Focus: **Microsoft Sentinel (KQL)** and **Splunk (SPL)**.

> ⚠️ **Disclaimer:** All content was produced in controlled lab environments for training and professional development. It is not production or employer experience. Screenshots are sanitised.

## 📊 Portfolio Dashboard
| Project | Platform | Skills Demonstrated | MITRE |
|---|---|---|---|
| [Password Spray Investigation](Investigations/password-spray-investigation/) | Sentinel + Splunk | Identity analysis, KQL, SPL, response | T1110.003 |
| *Impossible Travel (coming soon)* | Sentinel | Context analysis, false-positive reasoning | T1078 |
| *Suspicious PowerShell (coming soon)* | Defender XDR / Splunk | Process analysis, hunting | T1059.001 |

## 📚 Query Libraries
- [KQL Security Queries](KQL-Queries/README.md): Sentinel / Defender XDR
- [SPL Security Queries](SPL-Queries/README.md): Splunk
- [KQL ↔ SPL cheat sheet](SPL-Queries/KQL-to-SPL-cheatsheet.md)

## 🗂 Repository Structure
```
Investigations/        Full case studies (one folder each, with screenshots/)
KQL-Queries/           Documented Sentinel queries
SPL-Queries/           Documented Splunk queries
Incident-Response-Playbooks/
diagrams/              Architecture and timeline diagrams
```

## 🧭 How Each Project Is Written
Overview → Objective → Environment → Scenario → Investigation (queries + screenshots) → Findings → Classification → MITRE mapping → Response → Lessons learned.

## 📸 Screenshot Policy
Every screenshot is sanitised: no tenant IDs, real usernames, public IPs of real people, tokens or keys.
See [SCREENSHOT-GUIDE.md](SCREENSHOT-GUIDE.md).
