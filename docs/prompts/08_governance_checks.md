# Prompt 8：把治理建議 G-1 到 G-13 轉成可執行的合規檢查

類別：控制項即程式碼

```
請依報告第十部的 G-1 到 G-13，寫 scripts/governance_check.py，對本 repo 與其設定做可自動判定的檢查；無法自動判定的項目輸出「需人工確認」並說明需要什麼證據。至少涵蓋：

- G-2：config 中家族數 ≥ 3、judges 家族數 ≥ 3、reverse pass 未被關閉（檢查 pipeline 是否有停用旗標）、judge 視圖不含分數（對 bias/blinding.py 的輸出做結構檢查）。
- G-3：所有非 mock 模型的 data_residency 為 on_prem 或 vendor_api_zdr；無 fable/mythos 模型。
- G-5、G-7：tools/versions.lock 存在且每個工具有 SHA-256；若有 ML-BOM（CycloneDX）檔，檢查其中列出每個自架權重的雜湊。
- G-6：.github/workflows/*.yml 中所有 uses: 為 40 字元 SHA；無 pull_request_target；頂層 permissions 為空或只讀。
- G-8、G-9：docs/ 下是否存在 90 天內的 garak 或 CyberSecEval 報告與校準報告（依檔名日期）。
- G-12：是否存在 PSIRT 接入的設定（例如 config 中的 psirt_webhook 或等效欄位）。
- G-13：docs/ 下是否有 AI 素養訓練紀錄。

輸出格式：Markdown 表（建議編號、狀態 通過／失敗／需人工、證據、對應標準條文），並以非零結束碼表示任何失敗。加一個 GitHub Actions job 每週執行並把結果貼到 issue。

產出物：scripts/governance_check.py、.github/workflows/governance.yml、docs/governance-check-<日期>.md。
驗收：在本 repo 執行時，G-2、G-3、G-6 通過，G-5、G-7、G-8、G-9、G-12、G-13 依現況失敗或需人工，且每列都有證據欄。
```
