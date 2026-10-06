# Screenshot Guide

## What to capture (per investigation)
| # | File name | What it shows |
|---|---|---|
| 1 | `01-incident-overview.png` | Sentinel incident / Splunk notable: severity, entities, time |
| 2 | `02-query-<purpose>.png` | The query **and** its results in one frame |
| 3 | `03-evidence-<detail>.png` | Key log rows (sign-in details, process tree, etc.) |
| 4 | `04-timeline.png` | Event timeline or investigation graph |
| 5 | `05-detection-rule.png` | Analytics rule / Splunk alert config |

## Naming and placement
- Keep images in the project's own `screenshots/` folder.
- Use lowercase, hyphens, numbered prefix, `.png` format.
- Keep each under ~1 MB (crop to what matters).

## Embedding in a README
```markdown
### Step 2: Identify broad targeting
![KQL results: users targeted per IP](screenshots/02-query-targeted-users.png)
*One source IP targeted 14 accounts in 10 minutes.*
```
Always add a one-line caption explaining **what the reader should notice**.

## Sanitise before you upload ✅
- [ ] Mask tenant ID, subscription ID, workspace ID
- [ ] Mask real names, emails, real public IPs (lab IPs are fine)
- [ ] No tokens, keys, passwords, webhook URLs
- [ ] No employer or client data
- [ ] Browser tabs, bookmarks and notifications cropped out

Tools: Windows Snipping Tool (Win+Shift+S), ShareX, Greenshot. Use a blur or solid black box, not light pixelation.
