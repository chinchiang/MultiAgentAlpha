# Prompt 7：固定 L0 工具版本並加上簽章驗證

類別：控制項即程式碼

```
src/mara/tools/runner.py 目前對 semgrep、gitleaks、osv-scanner、zizmor、trivy 採「PATH 上有就執行」。請改成受控版本：

1. 新增 tools/versions.lock（YAML）：每個工具的版本、下載 URL、SHA-256、以及簽章驗證方式（cosign、GPG 或 GitHub attestation）。
2. 新增 scripts/install_tools.py：依 lock 下載、驗證雜湊與簽章、安裝到 .mara-tools/；任何驗證失敗即中止並說明。
3. runner.py 只從 .mara-tools/ 執行工具，不再用 shutil.which；找不到時記錄「未安裝，請執行 scripts/install_tools.py」。
4. 在 .github/workflows/mara-review.yml 的 deterministic-tools job 加入 install_tools 步驟；TruffleHog 若加入，必須在網路受限的 job 中執行（參考 Shai-Hulud 事件）。
5. 在 docs/ 加一頁 tools-provenance.md 說明每個工具的來源、授權與驗證方式。

產出物：tools/versions.lock、scripts/install_tools.py、修改後的 runner.py 與 workflow、docs/tools-provenance.md。
驗收：pytest 全綠；故意把 lock 中一個 SHA-256 改錯時 install_tools.py 會失敗。
```
