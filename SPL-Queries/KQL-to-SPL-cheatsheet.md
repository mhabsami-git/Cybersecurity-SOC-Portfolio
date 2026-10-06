# KQL ↔ SPL Cheat Sheet

| Task | KQL | SPL |
|---|---|---|
| Time filter | `where TimeGenerated > ago(24h)` | `earliest=-24h` |
| Filter | `where ResultType != "0"` | `field!=value` or `\| where ...` |
| Count by field | `summarize count() by IPAddress` | `\| stats count BY src_ip` |
| Distinct count | `dcount(User)` | `dc(User)` |
| Time buckets | `bin(TimeGenerated, 10m)` | `\| bin _time span=10m` |
| Sort desc | `order by Attempts desc` | `\| sort - Attempts` |
| Select columns | `project A, B` | `\| table A B` |
| New field | `extend X = ...` | `\| eval X=...` |
| Conditional count | `countif(cond)` | `count(eval(cond))` |
| Contains | `has "text"` | `field="*text*"` |
| Join | `join kind=inner` | `\| join` (prefer `stats` to combine) |
| Rare values | `summarize count() \| order by count_ asc` | `\| rare` |
