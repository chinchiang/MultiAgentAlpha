# Ground truth 季度更新　2026-09-21（附錄E prompt 2）

執行環境：Claude Code 遠端容器，出口代理。能開啟的一手網域：`github.com`（git clone／ls-remote）、`raw.githubusercontent.com`、`datadoghq.com`、`docs.datadoghq.com`、`cloud.google.com`。仍被封鎖（連線被拒或逾時）：`api.github.com`（403）、`cwe.mitre.org`、`cisa.gov`、`arxiv.org`、`owasp.org`、`genai.owasp.org`、`nist.gov`、`first.org`、`huggingface.co`、`api-docs.deepseek.com`、`developer.nvidia.com`、`anthropic.com`、`slsa.dev`、`artificialintelligenceact.eu`、`wikipedia.org`，以及附錄A 中「讀取＝摘要／否」的 162 個 URL 裡的 158 個。

規則（prompt 2 第 2 點）：**差異一律不直接覆寫 JSON**，只在 `_source` 追加查證日期；下表列出的每個變更都要由人核准後才進入 pinned 集。

## 1. 逐檔比對結果

| 檔案 | 上游來源（抓取 2026-09-21） | 結果 |
|---|---|---|
| `asvs_5_0.json` | `OWASP/ASVS` tag `v5.0.0_release`（commit 5cf9b03，2025-05-30）與 master 2b30071（2026-09-03）的 `5.0/docs_en/OWASP_Application_Security_Verification_Standard_5.0.0_en.csv`（345 條需求） | **有差異**（見 §2） |
| `owasp_top10_2025.json` | `OWASP/Top10` master 66ebc47，`2025/docs/en/` 檔案清單與 `A10_2025-Mishandling_of_Exceptional_Conditions.md` | 十個類別與 24 個 A10 CWE 完全一致 |
| `owasp_api_top10_2023.json` | `OWASP/API-Security` master e85ddfa（2026-01-01），`editions/2023/en/0x11-t10.md` | 十個類別完全一致 |
| `owasp_llm_top10_2025.json` | `OWASP/www-project-top-10-for-large-language-model-applications` master 99f4395（2026-08-05），`2_0_vulns/` | 十個類別完全一致；倉庫沒有 2026 版目錄（`2_0_vulns` 仍是 v2025，`Archive/` 只到 `2_0_voting`），故未新增 `owasp_llm_top10_2026.json`（prompt 2 第 4 點不觸發）。`genai.owasp.org` 封鎖，無法排除官網另行發布 2026 版 |
| `cwe_known.json` | OWASP A10:2025 的 24 個 CWE：與上游一致。2025 CWE Top 25（CISA 2025-12-11）：`cwe.mitre.org` 與 `cisa.gov` 皆封鎖 | **A10 子集已驗；Top 25 子集本次無法重驗** |

## 2. ASVS 5.0：新增、移除與改名

比對對象是 **5.0.0 正式版 tag**（不是後續修訂），所以下列差異是本 repo 2026-09-08 轉錄時的遺漏，不是上游改版：

| 類型 | ID | 本 repo | 上游 5.0.0（v5.0.0_release） | 來源 |
|---|---|---|---|---|
| 新增（章） | ASVS 5.0 V17 | 不存在 | **WebRTC** | CSV 第 `V17` 列群 |
| 新增（節） | ASVS 5.0 V17.1 | 不存在 | TURN Server | 同上 |
| 新增（節） | ASVS 5.0 V17.2 | 不存在 | Media | 同上 |
| 新增（節） | ASVS 5.0 V17.3 | 不存在 | Signaling | 同上 |
| 改名（節） | ASVS 5.0 V4.2 | HTTP Message Structure, Semantics, and Validation | HTTP Message Structure Validation | CSV `section_name` |
| 改名（節） | ASVS 5.0 V10.1 | Generic OAuth and OIDC security | Generic OAuth and OIDC Security | CSV `section_name`（大小寫） |
| 移除 | — | — | — | 無 |

master（2b30071）與 5.0.0 tag 在章節層級沒有差異；tag 之後唯一觸及 CSV 的 commit 是 2026-09-03 的印尼文翻譯說明。

**採用 V17 的影響**（人核准前先知道）：`validate_ref` 目前把 `ASVS 5.0 V17` 判為不存在，`tests/test_bias_and_scoring.py:58` 與 `tests/test_pipeline_mock.py:78` 明確斷言 V17 會被剔除，`fixtures/mock-responses` 也刻意用 V17.1 當「捏造的標準編號」。核准後需要：在 `chapters` 加入 `"17"`、改這兩個測試的假編號（例如 V18）、重新產生 mock fixtures（`scripts/gen_mock_fixtures.py`），並把 `owasp_top10`／報告第 12.4 節提到「V1 到 V16」之處一併更新。附錄B 第 52 項已依本次證據關閉。

## 3. 附錄B 缺口的關閉與部分核對

依 prompt 2 第 3 點，只對能開啟的 URL 寫入「已於 2026-09-21 關閉」，寫在 `docs/parts/B_gaps.md` 該項末尾；本次關閉 6 項（19、23、24、52、53、60），部分核對但未關閉 2 項（20、65），其餘 66 項因網域封鎖保持原狀。逐項證據：

| 項 | 證據（一手） |
|---|---|
| 19 DeepSeek-V3.2 日期 | `git clone https://github.com/deepseek-ai/DeepSeek-V3.2`：首個 commit 81dcc85「Initial commit」2025-09-29；最後 commit 87e509a「Update README」2025-11-18。兩個日期都真實：前者是發布，後者是 GitHub 頁面顯示的最後更新（報告所見 11-17 為時區差） |
| 20 DeepSeek V4 | `git ls-remote https://github.com/deepseek-ai/DeepSeek-V4{,-Pro,-Flash}` 皆要求登入（GitHub 對不存在的倉庫的回應；對照組 `DeepSeek-V3.2` 正常回傳 HEAD）。截至 2026-09-21 GitHub 組織下沒有 V4 倉庫；規格與授權仍無一手來源，**不關閉** |
| 23 NeMo Agent Toolkit 前身 | `NVIDIA/NeMo-Agent-Toolkit` 013255a：`CHANGELOG.md` v1.1.0（2025-05-16）「Rename packages agentiq -> aiqtoolkit」（PR #152）；`docs/source/resources/migration-guide.md` v1.1.0「The `agentiq` package has been renamed to `aiqtoolkit`」，之後「The `aiqtoolkit` package has been renamed to `nvidia-nat`」 |
| 24 CyberSecEval 各版日期 | `meta-llama/PurpleLlama` 4be64c3 的 git 歷史：`CybersecurityBenchmarks/` 首個 commit 2023-12-06（v1）；「CyberSecEval V2: first update」2024-04-18；「New Release of … CyberSecEval 4 …」2025-04-29。v3 在 git 歷史中沒有標示發布的 commit，日期仍未證實 |
| 52 ASVS V17 | 見 §2：5.0.0 正式版 CSV 含 V17 WebRTC 三節 |
| 53 Top 10:2025 定稿日期 | `OWASP/Top10` git 歷史：`2025/docs/en` 骨架 2025-10-28，「Removed RC」「Remove RC notice」2025-12-24，之後只有錯字修正（最近 2026-04-06）。定稿日應為 2025-12-24，而非第三方所稱 2026-01 |
| 60 版本與年份 | tag 的 commit 日期：`gitleaks/gitleaks` v8.30.1 → 2026-03-12；`dependency-check/DependencyCheck` v13.0.0 → 2026-08-03。`git ls-remote --tags` 最新版：detect-secrets v1.5.0、poutine v1.1.6、TruffleHog v3.97.5 |
| 65 LLM Top 10 2026 版 | 官方 GitHub 倉庫 99f4395（2026-08-05）沒有 2026 版；`genai.owasp.org` 封鎖，**不關閉** |

另有三筆附錄A 來源本次可直接讀取（原標「摘要」），內容與正文引用一致，附錄A 的「讀取」欄依 prompt 1 第 4 點不動：A62（Datadog 部落格，頁面標示 Published Oct 28, 2025；原文「prompts tuned for filtering false positives risked missing real issues」支持正文「坦承過濾過度會漏真問題」，無精確率／召回率數字）、A63（Datadog 文件頁存在，標題 AI-Enhanced Static Code Analysis）、C11.13（Mandiant 2023-04-20，標題即「Initiated by a Prior Software Supply Chain Compromise」，Trading Technologies 為前一起供應鏈事件）。

## 4. pytest

`pytest -q`：見本次 PR 的 CI。JSON 內容未變（只有 `_source` 字串），所以沒有測試因資料而改變；§2 說明了若採用 V17 會失敗的兩個測試與原因（程式與 fixture 依舊資料寫死，不是程式錯誤）。

## 5. 下次季更（2026-12）待辦

- 在能連 `cwe.mitre.org` 與 `cisa.gov` 的環境重驗 2025 CWE Top 25 子集；若 2026 版 Top 25 已發布，列出增減。
- 人核准 §2 後套用 V17 與兩處改名，並同步測試與 mock fixtures。
- 在能連 `genai.owasp.org` 的環境確認 LLM Top 10 是否有 2026 版。
