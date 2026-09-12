# PSIRT 接入：A 級 Critical finding 與 EU CRA 第 14 條（G-12）

治理建議 G-12：「A 級 Critical finding 若涉及已出貨產品，直接接入 PSIRT 的 CRA 第 14 條通報流程。」本頁說明雛型如何落實、設定方式、payload 內容、時限計算，以及它刻意不做的事。日期：2026-09-12。

## 1. 為什麼是「接入」而不是「通報」

CRA（Regulation (EU) 2024/2847）第 14 條的義務對象是製造商，觸發條件是「主動遭利用的漏洞」（actively exploited vulnerability），時限是 24 小時內預警、72 小時內通報、修正措施後 14 天內最終報告；24 小時預警義務自 2026 年 9 月 11 日起適用（報告 C11.9）。審查管線能判定的是「這段程式碼有一個由確定性工具佐證、多家族一致、CVSS 4.0 為 Critical 的漏洞」（A 級 Critical），不能判定它是否已被利用。所以管線做的是把時鐘從「審查完成」那一刻起算並把證據交給 PSIRT，是否構成第 14 條事件由 PSIRT 判定。這也是 G-12 只限 A 級的理由：B 級與 C 級的誤報會消耗 PSIRT 的判斷時間。

## 2. 流程

```
mara review <target>
  L5 評分 → accepted 且 tier ∈ trigger_tiers 且 severity ∈ trigger_severities
          → 若 psirt.enabled 且 psirt.shipped：
              out/psirt-notifications.json（每個 finding 一個 payload，含三個時限）
              report.md 的「PSIRT hand-off」段、report.json 的 psirt 欄位、bias_audit.psirt_notifications
          → 若加 --notify-psirt：以 Bearer token（環境變數）POST 到 psirt.webhook_url，逐筆回報 HTTP 狀態
```

預設只寫檔不送出。CI 的 mock 模式不啟用 PSIRT（`config/mara.mock.yaml` 無 `psirt` 區塊）。

## 3. 設定（`config/mara.yaml` 的 `psirt:` 區塊）

| 欄位 | 意義 | 政策 P6 的限制 |
|---|---|---|
| `enabled` | 是否啟用接入 | 停用時 P6 一律通過 |
| `webhook_url` | PSIRT 接收端（工單系統或 SOAR 的 intake API） | 必須 `https://` |
| `token_env` | 存放 Bearer token 的環境變數名稱 | 不得為空；token 永不寫進設定檔 |
| `product` | 受審程式碼所屬的產品或元件識別 | 不得為空 |
| `shipped` | 受審目標是否為已出貨產品 | 為 false 時不產生 payload |
| `trigger_tiers` | 觸發的證據層級 | 非空且 ⊆ {A, B}，預設 [A] |
| `trigger_severities` | 觸發的 CVSS 嚴重度 | 非空且 ⊆ {Critical, High}，預設 [Critical] |
| `early_warning_hours` / `notification_hours` / `final_report_days` | 三個時限 | 上限 24 / 72 / 14，與第 14 條一致 |

`mara check-config` 會列出 P6 的結果；`config/examples/psirt-enabled.yaml` 是通過六條政策的完整範例。

## 4. Payload（`mara-psirt/1`）

每個 finding 一個 JSON 物件：

- `regulation`、`stage`（`early_warning`）、`product`、`target`、`detected_at`（審查完成時間，UTC）。
- `deadlines`：`early_warning_by`、`notification_by`、`final_report_by`，自 `detected_at` 起算。
- 證據：`finding_id`、`title`、`dimension`、`cwe`、`standard_refs`、`location`（檔案、行號、逐字引用）、`cvss4`（向量、分數、嚴重度）、`evidence_tier`、`ssvc`、`reachability`、紅隊的 `exploitable` 與 `preconditions`、`families_agreeing`、`tool_corroborated`、`consensus`。
- `note`：說明「是否主動遭利用」由 PSIRT 判定。

PSIRT 端拿到的是可重算的證據鏈（工具結果、逐字引用、家族裁決），不是一段自然語言摘要。

## 5. 驗證

- `tests/test_psirt.py`：只有 accepted 的 A 級 Critical 進入 payload（seeded fixture 有三筆：SQLi、pwn request、硬編碼 secret）；時限計算；`shipped: false` 或 `enabled: false` 時為空；未設 token 時拒絕送出；以 `httpx.MockTransport` 驗證 POST 的 URL、Bearer header 與 JSON；CLI 產出 `psirt-notifications.json`；P6 對五種錯誤設定各失敗一次。
- `scripts/governance_check.py` 的 G-12：`psirt` 區塊存在且 `enabled: true`、https、有產品識別、觸發範圍在 P6 允許內才通過；本 repo 的 `config/mara.yaml` 預設 `enabled: false`，因此 G-12 仍為失敗，證據欄寫明要填什麼。

## 6. 尚未做的事

- **接收端**：本 repo 不提供 PSIRT 系統；webhook 的格式是本專案自訂的 `mara-psirt/1`，接收端需做對應（例如轉成 Jira issue 或 CSAF/VEX 草稿）。
- **重送與去重**：`--notify-psirt` 每次都送全部 payload；同一 finding 在多次審查會重複送出，去重應在接收端以 `target + finding 的 file:line:cwe` 處理，或在後續版本加本地送出紀錄。
- **72 小時通報與 14 天報告**：管線只產出預警階段的 payload 與三個時限；後兩階段的內容（影響評估、修正措施）來自 PSIRT 的處理，不來自審查。
- **上海與重慶**：境內管線的 finding 明細不出境（CN-3），若境內產品同時受 CRA 約束，PSIRT 接入需在境內完成，webhook 指向境內端點。
