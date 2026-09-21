# PSIRT 接入與 CRA 事件時鐘（G-12）

2026-09-18 修正：審查產出的是內部交接 `internal_handoff`，不能以審查完成時間代表製造商知悉事件的時間。法定通報是否適用，由 PSIRT 判定並提供事件資料。未確認的事件顯示「法定期限未知」。

依 [ENISA SRP 官方 FAQ](https://www.enisa.europa.eu/topics/product-security/single-reporting-platform-srp/frequently-asked-questions)，已遭主動利用的漏洞與嚴重資安事件都涉及知悉後 24 小時預警及 72 小時通報；漏洞最終報告的起點是修正或緩解措施可提供之日，嚴重事件最終報告則以事件通報提出之日計算一個月。實作分開這兩類起算點，不把它們簡化成「審查後 14 天」。

## 設定與交接

設定 `psirt.enabled`、`shipped`、`product`、HTTPS `webhook_url` 與 `token_env`。預設僅 accepted、A 級、Critical 的 finding 進入交接。`mara review` 產生 `out/psirt-notifications.json`；只有明確使用 `--notify-psirt` 才傳送。預設設定仍停用 PSIRT；mock CI 不傳送。

`mara-psirt/2` payload 保留 finding、引用、CVSS 與去重鍵，另包含：

| 欄位 | 語意 |
|---|---|
| `stage` | 固定為 `internal_handoff` |
| `internal_sla` | 從審查時間計算的內部服務目標；舊版 `early_warning_hours` 等設定只控制這些目標 |
| `clock_kind` | `unconfirmed` 或 `psirt_confirmed_event` |
| `incident_event` | PSIRT 明確提供的事件類型、確認人與時間 |
| `deadlines` | 只從已確認事件計算；缺最終報告起算點時不產生該期限 |

`dedupe_key` 仍以產品、target 與位置/CWE 去重；交接送達不代表已向主管機關完成預警。舊版 ledger 沒有可信的事件起算點時，必須重新確認，不能直接沿用舊期限。

## 事件確認與追蹤

PSIRT 提供 JSON；以下時間僅為格式示例，不能直接當成組織事件紀錄：

```json
{
  "event_type": "actively_exploited_vulnerability",
  "confirmed_by": "PSIRT operator identity",
  "awareness_at": "2026-09-18T09:00:00+08:00",
  "remediation_available_at": "2026-09-20T09:00:00+08:00"
}
```

另一類事件使用 `event_type: severe_incident` 與 `notification_at`。每個時間都必須有時區。`confirmed_by` 與 `awareness_at` 是必要欄位；修正可用時間或通報時間未知時可先不填。

```bash
python3 scripts/psirt_ops.py confirm-event --key <key> --event event.json --reference PSIRT-123
python3 scripts/psirt_ops.py record --key <key> --stage early_warning --reference SRP-early
python3 scripts/psirt_ops.py record --key <key> --stage notification --reference SRP-notification
python3 scripts/psirt_ops.py record --key <key> --stage final_report --reference SRP-final
python3 scripts/psirt_ops.py status
```

`confirm-event` 可在原交接送達後補登或更新事件，保留歷次事件參考與原送達紀錄。若最終報告起算點稍後才確定，再以完整事件 JSON 更新。`mara review --psirt-event event.json` 可在新交接附上同樣資料。`close --key … --reason …` 由 PSIRT 記錄結案理由。

## 握手與驗證界線

`python3 scripts/psirt_ops.py handshake --dry-run` 只顯示測試 payload。正式握手需要組織提供端點與環境變數中的 token；回應僅保存狀態碼及固定錯誤碼，不保存遠端回應本文。

G-12 要求設定完整、近期成功的握手及 ledger 無已知逾期階段。這些檢查不證明組織已辨識所有事件，也不證明法定通報已合規完成。`tests/test_psirt.py` 與 `tests/test_security_regressions.py` 使用合成事件和 MockTransport 驗證時鐘、去重、更新與傳送；本次修正未聯繫真實 PSIRT 或主管機關。
