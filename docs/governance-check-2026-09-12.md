# 治理合規檢查（2026-09-12）

依附錄 E 的 prompt 8，對報告第十部治理建議 G-1 到 G-13 做可自動判定的檢查。本檔由 `scripts/governance_check.py` 產生；「需人工」表示無法從檔案判定，該列的證據欄寫明需要什麼證據。任一「失敗」使腳本以非零結束。

- 掃描根目錄：`MultiAgentAlpha/`；設定檔：`config/mara.yaml`；報告與紀錄的新鮮度門檻：90 天。
- 標準條文取自報告第 25.4 節對應總表；標 * 者的 ISO 控制項標題尚未對照正本（附錄 B）。

| 建議 | 內容 | 狀態 | 證據 | 對應標準條文 |
|---|---|---|---|---|
| G-1 | 自動審查定義為安全測試的一部分，而非取代 | **需人工** | docs/ 下沒有政策文件（檔名含 policy／政策）。需要：PSO 簽署的政策文件，明定 MARA 審查是 A.8.29 安全測試的一部分、通過不等於免除人工測試 | ISO/IEC 27001:2022 A.8.25, A.8.29；IEC 62443-4-1 SVV；NIST SSDF PW.7, PW.8 |
| G-2 | 家族數不低於三、反序 pass 不關閉、judge 不見分數 | **通過** | `config/mara.yaml`：reviewer 家族 ['anthropic', 'deepseek', 'nemotron']，judge 家族 ['anthropic', 'deepseek', 'nemotron']；`src/mara/pipeline.py` 對每個 judge 執行 forward 與 reverse 兩個 pass；pipeline.py 與 config.py 無任何可關閉反序 pass 的旗標；`bias/blinding.py::blind_finding` 輸出鍵 ['claim', 'cwe', 'dimension', 'evidence', 'exploit_sketch', 'finding_id', 'reachability', 'reachability_argument', 'skeptic', 'standard_refs']，不含身分、信心、CVSS；政策 P3 panel-size：PASS（reviewers span 3 families, judges 3）；政策 P4 gate-bounds：PASS（self_judge_discount=0.5, human_threshold_alpha=0.4） | NIST AI 600-1（Harmful Bias and Homogenization）；ISO/IEC 42001 |
| G-3 | 資料主權規則寫進設定檔驗證 | **通過** | `config/mara.yaml` 模型：claude-reviewer=anthropic/claude-opus-5/vendor_api_zdr, deepseek-reviewer=openai_compatible/deepseek-v3.2/on_prem, nemotron-reviewer=openai_compatible/nvidia/nemotron-3-super/on_prem；`src/mara/policy.py` P1/P2/P5 在載入時強制 | ISO/IEC 27001:2022 A.5.19–5.21*, A.8.10；Anthropic 資料保留條款 |
| G-4 | 模型可抽換性作為採購條件（冷備家族） | **需人工** | config/ 下沒有 Llama/Mistral/Qwen 冷備家族的設定。需要：冷備設定檔（可通過 `mara check-config`）、部署證明、換模演練（一週內完成）的紀錄 | ISO/IEC 27001:2022 A.5.20*；NIST CSF 2.0 GV.SC |
| G-5 | L0 工具固定版本並簽章驗證 | **通過** | cosign 3.1.3 sha256 4629c757b761… cosign-keyless；slsa-verifier 2.7.1 sha256 946dbec72909… slsa-provenance；gitleaks 8.30.1 sha256 551f6fc83ea4… checksums-file；osv-scanner 2.5.1 sha256 f9f25499a2c8… slsa-provenance；zizmor 1.30.1 sha256 e65324f4430c… github-attestation；trivy 0.74.0 sha256 2ae6fe3ee734… cosign-keyless；semgrep pip 鎖定 66 個 wheel hash；manifest：cosign=hash-only, slsa-verifier=hash-only, gitleaks=hash-only, osv-scanner=hash-only, zizmor=hash-only, trivy=hash-only, semgrep=hash-only；CI `deterministic-tools` job 以 `scripts/install_tools.py` 安裝並驗證 | ISO/IEC 27001:2022 A.8.8*；IEC 62443-4-1 SM-9；NIST SP 800-204D；SLSA v1.2 |
| G-6 | 審查 workflow 套用 SHA pinning 與 pull_request 限制 | **通過** | `.github/workflows/governance.yml`：2 個 uses 全為 SHA；`.github/workflows/governance.yml` job 層 write 權限（允許）：governance:issues；`.github/workflows/mara-review.yml`：7 個 uses 全為 SHA | ISO/IEC 27001:2022 A.8.32*；IEC 62443-4-1 SM；OpenSSF Scorecard；GitHub SHA-pinning 政策 |
| G-7 | 模型權重納入 SBOM（ML-BOM）並簽章 | **失敗** | 找不到 CycloneDX ML-BOM（`sbom/*.json`、`*.cdx.json`、`bom.json`）。設定中的自架家族 ['deepseek', 'nemotron'] 的權重需要 `type: machine-learning-model` 元件、來源、雜湊與簽章（cosign 或 NGC） | ISO/IEC 27001:2022 A.5.21*；IEC 62443-4-1 SM-9；EU CRA Annex I Part II (1)；CycloneDX 1.6+ |
| G-8 | 每季 garak 與 CyberSecEval 測試 | **失敗** | 無任何 garak／CyberSecEval 報告。需要：90 天內對三個家族執行 garak 與 CyberSecEval 4（Prompt Injection、False Refusal Rate）的報告，檔名含日期 | IEC 62443-4-1 SVV；NIST AI 600-1（Information Security）；OWASP Agentic Top 10 |
| G-9 | 校準迴圈每季重跑（真實家族） | **失敗** | `docs/calibration-2026-09-11.md`（2026-09-11，mock 模式）。需要：90 天內以真實三家族執行的校準報告（`python scripts/calibrate.py --mode live`），含每家族每 CWE 的精確度與召回率、更新後的權重 | ISO/IEC 27001:2022 A.8.29；IEC 62443-4-1 SVV；ISO/IEC 23894 |
| G-10 | 三階段導入：影子、建議、門檻阻擋 | **需人工** | 設定無 `rollout_phase`。需要：目前階段（shadow／advisory／blocking）、起訖日期、影子期結束時的基線報告與第一份校準報告 | ISO/IEC 27001:2022 A.8.25；IEC 62443-4-1 SM |
| G-11 | 人工佇列接工單、裁決回寫校準集 | **失敗** | 人工佇列未接工單、裁決未回寫。需要：workflow 把 needs_human finding 建成帶標籤的 issue、`calib/decisions/` 的裁決格式與 `calibrate.py` 讀取、佇列超量時收緊門檻的規則 | ISO/IEC 27001:2022 A.8.29；IEC 62443-4-1 DM；NIST SSDF RV.1 |
| G-12 | A 級 Critical 接入 PSIRT 的 CRA 第 14 條通報 | **失敗** | 設定無 `psirt_webhook`／`psirt:` 區塊。需要：PSIRT 接入端點與只對 A 級 Critical 觸發的規則，對應 CRA 第 14 條 24 小時預警（2026-09-11 起適用） | IEC 62443-4-1 DM, SUM；EU CRA Art. 14 |
| G-13 | AI 素養訓練 | **失敗** | docs/ 下沒有 AI 素養訓練紀錄（training-*、ai-literacy-*、含「素養」）。需要：開發者、安全團隊、人工裁決者的訓練紀錄（證據層級、偏誤稽核、「通過不等於安全」），對應 EU AI Act 第 4 條 | EU AI Act Art. 4 |

**摘要**：通過 4、失敗 6、需人工 3；結束碼 1。

