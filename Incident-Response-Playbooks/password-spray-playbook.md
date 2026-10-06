# Playbook: Password Spray

| Phase | Actions |
|---|---|
| **Detection** | Alert: many failures across users from one IP |
| **Validation** | Check IP reputation, known VPN/NAT, error codes, user agents |
| **Investigation** | Run spray and success-after-failure queries (KQL/SPL); list targeted accounts |
| **Containment** | Block IP, contain compromised account, revoke sessions |
| **Eradication** | Reset credentials; remove attacker-created MFA methods, inbox rules, app consents |
| **Recovery** | Re-enable account with MFA verified; monitor for 7-14 days |
| **Lessons learned** | Tune thresholds, enforce MFA, add Conditional Access, block legacy auth |

**MITRE:** T1110.003
