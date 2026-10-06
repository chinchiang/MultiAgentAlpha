# PSIRT hand-off records (G-12)

Written by the tooling, committed like any other operational record:

| File | Written by | Content |
|---|---|---|
| `handshake.json` | `scripts/psirt_ops.py handshake` | Last test POST to `psirt.webhook_url`: time, HTTP status, product. Governance G-12 needs a successful one younger than `psirt.handshake_max_age_days`. |
| `ledger.json` | `mara review --notify-psirt`, `scripts/psirt_ops.py confirm-event` / `record` / `close` | One item per finding key (product + target + file:line:cwe): every send attempt with its status (a failed one with `status_code: null` and an `error` code), the internal hand-off SLA the review sets (`internal_sla.handoff_by`), the legal deadlines once the PSIRT confirms an event (`confirm-event` or `mara review --psirt-event`: 24 h and 72 h from the confirmed awareness time, then the final report 14 days after a remediation for an actively exploited vulnerability, or one month after the notification for a severe incident; empty until then), the PSIRT's reference for each legal stage, and the closing reason. |

Neither file exists in this repository yet: no PSIRT endpoint has been configured, so no handshake
has been made and nothing has been sent. The ledger names findings in shipped products; the Shanghai
and Chongqing pipelines keep their own copy on-site (report rule CN-3) and never merge it here.
