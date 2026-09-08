# Prompt 4：以真實三家族跑第一次校準並產出權重

類別：落地評估

```
請執行 MARA 的第一次校準。前置：config/mara.yaml 中三個家族的端點都可連線（用 mara check-config 確認）；ANTHROPIC_API_KEY 對應的組織已啟用 ZDR；DeepSeek 與 Nemotron 的 base_url 指向組織內網。

1. 準備校準集：clone OWASP Juice Shop 與 WebGoat 到 calib/，另用 fixtures/vuln-sample 的模式再產生 5 個 vibe-coded 樣本（每個含至少一個佔位式邏輯、一個未過濾輸入、一個機密外洩），把每個樣本的已知缺陷寫成 calib/<sample>/labels.json（dimension、cwe、file、line）。
2. 對每個樣本執行 mara review <sample> --config config/mara.yaml --out calib-out/<sample>。
3. 寫 scripts/calibrate.py：讀取 calib-out/*/report.json 與 labels.json，計算每個家族在每個 CWE 的精確度與召回率（以檔案與 ±3 行比對），計算 judge 家族兩兩一致率與 canary 回應率，並以 Dawid-Skene EM 估計家族權重（初始 1.0，限制在 0.2 到 2.0）。
4. 產出 docs/calibration-<日期>.md：每家族每 CWE 的表、兩兩一致率、拒答率、canary 回應率、建議權重，以及任何一致率高於 0.9 的家族對（標為相關錯誤風險）。
5. 不要自動改 config/mara.yaml；把建議權重寫在報告裡，由人決定是否採用。

產出物：scripts/calibrate.py、docs/calibration-<日期>.md、calib-out/。
驗收：報告中每個數字都能從 calib-out/ 重算；建議權重附信賴區間或至少樣本數。
```
