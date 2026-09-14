# PSIRT hand-off records (G-12)

Written by the tooling, committed like any other operational record:

| File | Written by | Content |
|---|---|---|
| `handshake.json` | `scripts/psirt_ops.py handshake` | Last test POST to `psirt.webhook_url`: time, HTTP status, product. Governance G-12 needs a successful one younger than `psirt.handshake_max_age_days`. |
| `ledger.json` | `mara review --notify-psirt`, `scripts/psirt_ops.py record` / `close` | One item per finding key (product + target + file:line:cwe): every send attempt with its status, the 24 h / 72 h / 14 d deadlines from the review, the PSIRT's reference for the notification and final report stages, and the closing reason. |

Neither file exists in this repository yet: no PSIRT endpoint has been configured, so no handshake
has been made and nothing has been sent. The ledger names findings in shipped products; the Shanghai
and Chongqing pipelines keep their own copy on-site (report rule CN-3) and never merge it here.
