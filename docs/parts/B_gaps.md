# 附錄B　查證缺口清單

每項列出：無法查證什麼、為什麼、要查證需要什麼、暫時採用了哪一級證據。前置說明：本次研究環境的出口代理伺服器封鎖了以下一手網域：arxiv.org、anthropic.com、openai.com、deepmind.google、github.blog、docs.github.com、nist.gov 全系（含 csrc、nvlpubs）、owasp.org、genai.owasp.org、cwe.mitre.org、capec.mitre.org、atlas.mitre.org、cisa.gov、w3.org、first.org、slsa.dev、oasis-open.org、developer.mozilla.org、iso.org、artificialintelligenceact.eu、huggingface.co、nvidianews.nvidia.com、developer.nvidia.com、crowdstrike.com、blogs.cisco.com、garanteprivacy.it、moda.gov.tw、ey.gov.tw、veracode.com、semgrep.dev、api-docs.deepseek.com、thehackernews.com、dl.acm.org、wikipedia。三個研究 agent 的搜尋配額（各 200 次）亦已用盡。以下缺口中標「代理封鎖」者，其題名、日期與數字來自搜尋引擎摘要，未直接讀取原頁；關閉方式一律是在不受封鎖的環境開啟該 URL 核對。2026-10-06 的複核已能讀取上列大部分網域（iso.org、EUR-Lex、usenix.org 的 PDF 與 NVD 仍讀不到），逐項結果記在附錄A 的狀態欄與 `docs/source-verification.json`；複核由 Claude Code 代理以 WebFetch、官方 API 與 `gh api` 執行，未經人工複核。以下各項的「2026-10-06」附記即該次結果。

## B-1 方法與環境層缺口

1. **arXiv 全部條目未直接讀取。** 原因：代理封鎖。需要：開啟每個 arXiv 頁核對題名、作者、日期與數字。暫採：第三方評論（preprint）。2026-10-06 部分核對：被引用的 arXiv 條目已以 arXiv API 讀取題名、作者、日期與摘要，並另查發表場次；確認已刊於同儕審查場次的改為已證實（如 A85、A115、A122、B1、B8、B17），仍是 preprint 的維持第三方評論。摘要以外的數字（表格內的值）多數未逐一比對全文，不關閉。
2. **NIST 全部文件未直接讀取**（AI RMF 1.0、AI 600-1、SP 800-218/218A、SP 800-63-4、SP 800-160、SP 800-204D、CAISI 兩份評估、NVD 政策）。原因：代理封鎖。暫採：已證實（政府出版物，依出版者強度），數字標「摘要」。2026-10-06 部分核對：SP 800-63-4、SP 800-160 Vol.1 Rev.1、SP 800-204D、SP 800-218 與其 Rev.1 草案、CSF 2.0、NVD 政策公告、CAISI 兩份評估已直接讀取（C 組與 B95、B96）；AI RMF 1.0 與 AI 600-1 本次未讀，不關閉。
3. **OWASP 官網未直接讀取**，但 OWASP 的 GitHub 官方 repo（ASVS、Top10、API-Security、CheatSheetSeries）可讀，本報告以 repo 為一手。原因：代理封鎖。暫採：已證實（repo）。2026-10-06 附記：owasp.org 與 genai.owasp.org 已可讀；Top 10:2025 的正式網址已改為 top10.owasp.org/2025，Risk Rating Methodology 轉址到 community.owasp.org。Input Validation Cheat Sheet 於 2026-10-03 大幅改寫，第 10.9 節已依新版改寫。
4. **Anthropic 官方公告頁全部未讀取**（安全審查公告、Claude Code Security、Glasswing、Opus 5 系統卡）；platform.claude.com 的文件可讀。暫採：公告為廠商主張（依二手）；文件為已證實。2026-10-06 部分核對：Claude Code Security 公告（A7）、Claude Security public beta（B134）、Opus 5.5 公告（B125）已直接讀取；Opus 5 系統卡只找到 PDF 位址（B85），內容仍未讀，不關閉。

## B-2 工具與產品（A 組）

5. **LLMSmith** 找不到任何相符結果；可能名稱有誤。暫採：未引用。
6. **PentestGPT 原始論文**未取得 arXiv 編號與發表場次。暫採：未引用。
7. **Socket AI 與 Amplify Security 的發布日期**未找到。暫採：日期不可驗證。
8. **ARVO 的 arXiv 編號與日期**只有二手描述。暫採：未引用。
9. **gitleaks 與 Trivy 的官方 SARIF 文件頁**未取得，只有二手部落格。暫採：尚未證實（功能普遍認知為真）。2026-10-06 部分核對：本 repo 以 `tools/versions.lock` 鎖定的 gitleaks 8.30.1 與 trivy 0.74.0 實際輸出 SARIF，並經 `scripts/code_scanning_prep.py` 上傳 GitHub Code Scanning（`docs/tools-provenance.md`）；功能已實測，官方文件頁仍未讀取，不關閉。
10. **Copilot Autofix 的獨立第三方評測**未取得內容（arXiv:2509.13650 僅連結）。暫採：未引用。
11. **DARPA AIxCC 2025 決賽結果**未查（配額用盡）。暫採：未引用；建議補查。
12. **claude-code-security-review Action 的正式 release 日期**：倉庫無 tag，2025-08-06 依三家媒體交叉。暫採：第三方評論。
13. **「Project Glasswing／Mythos Preview 找出逾一萬個 high/critical 漏洞」**單一二手來源。暫採：尚未證實，正文未引用數字。
14. **Claude Code 權限請求 97% 核准率與 2026-08-14 auto mode 預設**：單一二手來源。暫採：尚未證實，第 15.2 節明示。2026-10-06 附記：重讀該二手報導，生效日（2026-08-14）、適用方案與 13.6%／89% 兩個數字已補入正文，但仍無一手來源，不關閉。
15. **OpenAI Aardvark 92% 召回與 10 個 CVE**：openai.com 封鎖，依搜尋摘要與媒體。暫採：廠商主張。
16. **Codex Security 定價 $0.018／千行**：單一二手來源。暫採：尚未證實，未引用。
17. **CodeMender 公告確切日期**（推測 2025-10-06）。暫採：2025-10。已於 2026-10-06 關閉：Google DeepMind 公告頁直接讀取，日期為 2025-10-06（A18）。
18. **Big Sleep 首次公開日期 2024-11-01**：Project Zero 原文未取得。暫採：第三方評論。
19. **DeepSeek-V3.2 發布日期矛盾**：GitHub 頁面渲染 2025-11-17，業界記載 2025-09-29。暫採：尚未證實，兩者並列。已於 2026-09-21 關閉：直接 clone `deepseek-ai/DeepSeek-V3.2`，首個 commit 81dcc85 為 2025-09-29，最後 commit 87e509a 為 2025-11-18；前者是發布日，後者是 GitHub 頁面顯示的最後更新，兩者不矛盾。
20. **DeepSeek V4 全部規格與授權**（1.6T/49B、284B/13B、1M、MIT）：官方 news 頁與 HF 模型卡封鎖，GitHub 組織頁未列 V4 倉庫。暫採：尚未證實。2026-09-21 部分核對：`git ls-remote` 確認 GitHub `deepseek-ai` 組織下沒有 DeepSeek-V4、V4-Pro、V4-Flash 倉庫；官方 news 頁與 HF 模型卡仍封鎖，規格與授權未關閉。已於 2026-10-06 關閉：Hugging Face `deepseek-ai/DeepSeek-V4-Pro` 模型卡讀取，MIT 授權、safetensors 格式，發布 2026-04-22（A78）；規格依官方 news 頁（A77，廠商主張）。
21. **NVIDIA Nemotron 3 各型號發布日期、參數量（Ultra 500B vs 550B）與授權對應**：全為二手。暫採：尚未證實。已於 2026-10-06 關閉：Hugging Face 官方模型卡（B131）載明 Nano 30B（2025-12-15）與 Super 120B（2026-03-11）採 NVIDIA Nemotron Open Model License、Ultra 550B（2026-06-04）採 OpenMDW-1.1。
22. **NVIDIA 容器安全 Blueprint 由 Nemotron 3 Ultra／3.5 Lightning 驅動**：build.nvidia.com 摘要。暫採：尚未證實；這是「Nemotron 用於資安多代理」的唯一具體證據，優先覆核。已於 2026-10-06 關閉：`NVIDIA-AI-Blueprints/vulnerability-analysis` v3.0.0（2026-08-19）的原始碼載明主代理用 Nemotron 3 Ultra、CVE 研究子代理用 Nemotron 3.5 Lightning（B132）。
23. **NeMo Agent Toolkit 前身為 AgentIQ**：倉庫未載明。暫採：尚未證實。已於 2026-09-21 關閉：`NVIDIA/NeMo-Agent-Toolkit`（013255a）的 CHANGELOG v1.1.0（2025-05-16）載明「Rename packages agentiq -> aiqtoolkit」，migration guide 載明 `agentiq` → `aiqtoolkit` → `nvidia-nat` 兩次改名。
24. **CyberSecEval v1 到 v4 各版發表日期**：README 未載明。暫採：未引用日期。已於 2026-09-21 關閉（v3 除外）：`meta-llama/PurpleLlama` git 歷史顯示 `CybersecurityBenchmarks/` 首個 commit 2023-12-06（v1）、「CyberSecEval V2: first update」2024-04-18、CyberSecEval 4 發布 2025-04-29；v3 沒有標示發布的 commit，日期仍未證實。
25. **美國各州 DeepSeek 禁令清單**（Texas 等）：無一手政府文件，彙整彼此不一致。暫採：尚未證實，正文只寫「多州」。
26. **義大利 Garante 與南韓 PIPC 原始公告**：主管機關網站封鎖，依律師事務所與媒體。暫採：Garante 已證實（多重獨立記載）；PIPC 第三方評論。
27. **GitClear 2026「Maintainability Gap」具體數字**：只有標題。暫採：未引用。
28. **DryRun 2025 SAST Accuracy Report 全文與方法論**。暫採：廠商主張，標利益相關。
29. **ZeroPath 在 curl 上「找到 98% bug」**：二手轉述。暫採：尚未證實，未引用。
30. **九篇 2026 年 arXiv 論文**（RealVuln、SastBench、AgenticSCR、Refute-or-Promote、QASecClaw、Revelio、Multi-LLMSecCodeEval、Diverse LLMs vs. Vulnerabilities、(In)Security of Vibe-Coded Applications）：無法存取 arXiv 做獨立覆核。暫採：第三方評論（preprint），並在正文標「需覆核」。其中 A136 為核心引用，優先覆核。2026-10-06 部分核對：九篇都已以 arXiv API 讀取摘要；AgenticSCR 已獲 ASE 2026 Industry Track 接受（A94），A136 已更新到 v4（2026-09-14），其餘仍是 preprint，不關閉。
31. **DVDR-LLM（ETASR 期刊）發表日期**未取得。暫採：未引用。
32. **Anthropic security-review 的精確率或召回率**：公告無測量數據。暫採：無數字可引。

## B-3 偏誤與模型（B 組）

33. **「Large Language Models Share Representations…」**作為集成多樣性論文不存在；同名者為多語言可解釋性論文（arXiv:2501.06346）。暫採：改引 B17、B18、B19。
34. **OWASP Agentic Top 10 2026 的 ASI04 到 ASI10**未確認。暫採：只引 ASI01 到 03。
35. **MITRE ATLAS v5.1.0 的計數**（16 tactics／84 techniques 等）只有第三方追蹤者。暫採：第三方評論。已於 2026-10-06 關閉：改引官方 `mitre-atlas/atlas-data` 的 CHANGELOG（B46），逐版新增數已寫入第 16.2 節。
36. **NASA 與美國海軍的 DeepSeek 備忘錄**只有二手。暫採：未引用為一手。
37. **CAISI 對 DeepSeek V4 Pro 的評估（2026-05）**只有題名與 URL。暫採：尚未證實；這是對部署決策最重要的缺口。已於 2026-10-06 關閉：nist.gov 原頁已讀（B96，2026-05-01），內容只含能力評估，沒有安全面測試，第 20 章已照實寫。
38. **DeepSeek 隱私政策「資料存於 PRC」條款原文與最後更新日 2026-02-10**：未直接讀取。暫採：廠商主張。已於 2026-10-06 關閉：隱私政策原文已讀（B88），最後更新日 2026-02-10。
39. **Nemotron Open Model License 全文**未讀。暫採：尚未證實。2026-10-06 附記：哪個型號採哪個授權已由模型卡確認（B131），授權條文全文仍未讀，不關閉。
40. **Mistral 官方模型卡**未找到。暫採：未引用。
41. **跨 Claude／DeepSeek／Nemotron 的 CyberSecEval 比較分數表**未取得。暫採：無數字可引。關閉途徑：治理檢查 G-8 的工具鏈已備（`scripts/model_eval.py`，garak 與 PurpleLlama 皆固定版本），對三個家族實際執行後產出的 `docs/cyberseceval-<日期>.md` 即可提供本項所缺的比較表；截至 2026-10-06 尚未執行。
42. **異質 LLM 資安審查者的跨模型一致性研究**似乎不存在；最接近者為人類資安審稿 κ 0.27 到 0.77（arXiv:2512.09549）、四個 LLM 對架構違規的 Fleiss' κ 0.724（arXiv:2602.07609）。暫採：列為本專案可貢獻的空白。
43. **生產環境 AI code reviewer 遭程式碼註解 prompt injection 的實例**（CodeRabbit、Copilot、Cursor、Greptile）：配額用盡前未取得。暫採：尚未證實，正文只引學術證據。
44. **Mixture-of-Agents 的發表場次**（常引為 ICLR 2025）未確認。暫採：preprint。
45. **Dawid & Skene 1979 的 DOI 與頁碼**依記憶未驗。暫採：已證實但註明。已於 2026-10-06 關閉：DOI 10.2307/2346806 經 Crossref metadata 確認（B62）。
46. **多篇 2026 年 arXiv 偏誤論文**（B4、B5、B6、B29、B32、B33、B36）僅題名。暫採：未引用。
47. **Anthropic Opus 5 系統卡的 cyber 評估內容**未讀。暫採：尚未證實。2026-10-06 附記：已找到 PDF 位址並寫入附錄A（B85），內容仍未讀，不關閉；Opus 5.5 另有自己的系統卡，也未讀。
48. **Krippendorff's α 在本雛型的「單一 finding」層級是簡化的代理指標**（見 `pipeline._agreement_proxy`：每個 judge 家族取一個裁決，計算眾數占比並對三類裁決做機遇校正；評審家族少於兩個時為未定義；2026-09-18 起報告欄位改名為 `agreement_proxy`，2026-10-03 起不再輸出恆為空的 `krippendorff_alpha` 欄位），不是嚴格的 α；嚴格的 α 只在語料層級計算（2026-10-06 起每個 finding 每個家族只計一個標籤，全部標籤相同時為未定義；此前正反序被當成兩個評分者，數值有偏差）。暫採：正文第 11.2 節與程式碼註解已標示。

## B-4 標準與事件（C 組）

49. **CWE 與 CAPEC 目錄的當前版本號與日期**未驗。暫採：未引用版本。
50. **SARIF 2.1.0 的 OASIS 批准日**（2020-03-27）與 2.2 時程：A 組來源給出批准與公告日，C 組未能驗，兩組不矛盾。暫採：已證實（A142）。
51. **GitHub code scanning 的 SARIF 上傳數值上限**未驗。暫採：正文只寫「子集」。附記：雛型的 `scripts/code_scanning_prep.py` 採用每次 25,000 筆、10 MB 的上限並拒絕超量上傳，但數值來源未記錄，不能據此關閉。已於 2026-10-06 關閉：GitHub 的 SARIF support 文件（A144）已直接讀取，載明每個 run 最多 25,000 筆結果（超過只保留依嚴重度排序的前 5,000 筆）、每個 gzip 壓縮後的 SARIF 檔最大 10 MB。雛型以「每個檔案」計筆數、以未壓縮大小計位元組，兩項檢查都比文件嚴；2026-10-07 已在程式內補上出處註記（v0.4.1）。
52. **ASVS 5.0 是否有 V17 WebRTC**：官方 CSV 渲染止於 V16。暫採：V1 到 V16 已證實，V17 尚未證實；雛型 ground truth 只收錄 V1 到 V16。已於 2026-09-21 關閉：`OWASP/ASVS` tag v5.0.0_release（5cf9b03，2025-05-30）的官方 CSV 有 17 章，V17 WebRTC 含 V17.1 TURN Server、V17.2 Media、V17.3 Signaling；雛型 ground truth 已於同日核准後收錄 V17，見 `docs/groundtruth-diff-2026-09-21.md`。
53. **OWASP Top 10:2025 的定稿日期**：官方 Introduction 無日期。暫採：第三方（2025-11 公布、2026-01 定稿）。已於 2026-09-21 關閉：`OWASP/Top10` git 歷史顯示 2025 版骨架建於 2025-10-28，「Removed RC」與「Remove RC notice」於 2025-12-24，其後只有錯字修正；定稿日為 2025-12-24，第三方所稱 2026-01 不確。
54. **OWASP SAMM 是否有 2.1**：未找到。暫採：引 2.0。
55. **Microsoft 棄用 DREAD 的一手聲明**未找到。暫採：尚未證實，第 11.3 節明示。
56. **STRIDE 的原始 Microsoft 文件**未驗。暫採：未引用出處。
57. **CSP Level 3 最新 WD 日期**：2025-06-06 與 2026-05-05 矛盾。暫採：尚未證實。已於 2026-10-06 關閉：w3.org 原頁顯示最新為 2026-09-16 的 WD（C4.1），兩個舊日期都已過時。
58. **CVE-2025-48700 Zimbra XSS 的 KEV 收錄日期與官方 advisory**未直接驗。暫採：第三方評論；若無法確認應換一個可查的 KEV XSS 案例。已於 2026-10-06 關閉：CISA KEV 的 JSON feed 顯示收錄日 2026-04-20，GitHub Advisory 的 CVSS 為 6.1（C3.7）。
59. **EPSS v4 的 FIRST 官方公告頁**未取得。暫採：日期為第三方。已於 2026-10-06 關閉：FIRST 的 How it works 頁載明 v4 自 2025-03-17、v5 自 2026-06-15 起發布（C6.7）；初版研究時 v5 已上線，正文已改為 v5。
60. **detect-secrets、poutine、TruffleHog 的當前版本；gitleaks v8.30.1 與 Dependency-Check v13.0.0 的發布年份**：GitHub 頁未渲染年份。暫採：版本已證實，年份不可驗證。已於 2026-09-21 關閉：tag 的 commit 日期 gitleaks v8.30.1 為 2026-03-12、Dependency-Check v13.0.0 為 2026-08-03；`git ls-remote --tags` 最新版 detect-secrets v1.5.0、poutine v1.1.6、TruffleHog v3.97.5。
61. **CISA KEV 總條目數（2026-09）**未驗。暫採：未引用。
62. **ua-parser-js（2021）與 event-stream（2018）事件**未研究。暫採：未引用。
63. **Uber 2022 與 Toyota 憑證外洩事件**未研究。暫採：未引用。
64. **「Kong」GitHub Actions 事件**未找到。暫採：未引用。
65. **OWASP LLM Top 10 2026 版**（疑似 2026-08-04 發布）未驗；若存在，LLM01:2025 的引用需更新。暫採：引 2025 版。2026-09-21 部分核對：官方 GitHub 倉庫（99f4395，2026-08-05）沒有 2026 版目錄；`genai.owasp.org` 封鎖，不能排除官網另行發布，仍引 2025 版。2026-10-06 附記：genai.owasp.org 已可讀，LLM01 現行頁面仍是 2025 版（B43、C9.6），不關閉。
66. **ISO/IEC 27001:2022 條文**付費牆；5.19 到 5.21、8.8、8.32 的標題依實務通用引用。暫採：尚未證實，第十部標 *。
67. **SEMI E187 的發布日期與修訂版**未驗。暫採：未引用日期。
68. **IEC 62443-4-1 各實務的活動計數**（SM-1 到 SM-13 等）來自 arXiv:2105.13413 而非標準本身。暫採：第三方評論。
69. **Bybit 2025 事件細節**：只在 OWASP A03:2025 內引用。暫採：OWASP 主張已證實，事件本身未獨立驗。
70. **NVD「僅 15 到 20% CVE 受 enrichment」的業界估計**。暫採：第三方評論，正文未引數字。

## B-5 雛型自身的缺口

71. **真實模型的精確率與召回率**：雛型只在 mock 家族上驗證行為。關閉方式：以真實三家族在 seeded benchmark 上跑第一次校準（附錄E prompt 4）。進度（2026-10-06，未關閉）：`scripts/calibration_run.py --mode live` 與 Alternative Annotator Test 已實作，mock 校準已於 2026-09-11 與 2026-10-03 各跑一次，live 校準前會使結果失真的問題（含答案檔外洩給模型）已修正；尚無真實家族的數字。
72. **bias sensitivity 測試**（第 13 章第 16 項）未實作。
73. **三家族設定的獨立 judge 不足**是固有性質而非缺口，但四家族的效果未驗證。
74. **L0 工具版本未固定**：雛型「有就跑」。關閉方式：附錄E prompt 7。已於 2026-09-26 關閉：自 2026-09-12（a9867dc）起 `tools/versions.lock` 以版本、下載 URL 與 SHA-256 固定全部 L0 工具並指定發行者驗證方式，`scripts/install_tools.py` 驗證後裝入 `.mara-tools/bin`，`mara/tools/runner.py` 只從該目錄執行、不查 PATH；CI 每次重新安裝並驗證，治理檢查 G-5 通過（`docs/governance-check-2026-09-26.md`）。2026-10-06 補記：鎖定工具於 2026-10-01 增為九個（加入 csp-evaluator，以 npm registry 的 `dist.integrity` 驗證）；工具目錄改為相對 MARA workspace（`MARA_HOME`）解析，位於被審查目標之內時拒絕執行，被審查的 repo 不能以自帶的工具頂替。
75. **正式面板的 Gemini 與 GLM 未經本報告評估**：v0.4.2 起雛型的正式設定改為 Amazon Bedrock 上的 Claude、付費層的 Gemini API 與 IEC 內網自架的 GLM，但本報告的模型比較（第七部、第 20 章）只涵蓋 Claude、DeepSeek 與 Nemotron。Gemini 的資料保留條款、GLM 的權重來源與授權、兩者的拒答率與資安評估都未查證；Gemini 與 GLM 的模型 ID 在設定檔中也仍是暫定值。另外，經 Bedrock 的 Claude 標為 `vendor_api_zdr`，依據的是 AWS 的承諾而非 Anthropic 的 ZDR 協議，需法務確認。暫採：尚未證實。 2026-10-07 部分核對（未關閉）：第 7.1 節與第 20 章已改以正式面板比較；Gemini API 付費層的保留條款（B139、B140）、Bedrock 的預設不儲存與 `global.` 路由（B137、B138）、GLM-5.3-Flash 的授權與發布日期（B143）、智譜的實體清單紀錄（B144）與 CAISI 對 GLM-5.2／5.3 的評估（B146、B147）已直接讀取。仍未關閉：Bedrock 的不保留承諾與 Anthropic ZDR 是否等同（法務）、IEC 實際部署的 GLM 權重來源與版本、兩個新家族的拒答率與真實校準。
76. **設定檔的模型 ID 與廠商現行清單不符**：`config/mara.yaml` 的 `gemini-3-pro` 不在 Gemini API 的現行模型清單上（現行 Pro 級為 `gemini-3.1-pro-preview`，`gemini-3-pro-preview` 已於 2026-03-09 關閉並改指向 3.1 Pro【B141】）；GLM 的 `GLM-5.3-Flash-FP8` 在 Hugging Face 上沒有同名倉庫（官方倉庫為 `zai-org/GLM-5.3-Flash`，標示 fp8【B143】），可能只是部署端的服務名稱。需要：以正式金鑰列出 Gemini 的可用模型、向 IEC 平台團隊確認 GLM 端點的 `/v1/models` 與下載來源。暫採：尚未證實；第一次 live 執行前必須關閉。2026-10-07 Gemini 部分關閉：以正式金鑰呼叫 Gemini API 的 models 端點，清單含 `gemini-3.8-flash`、不含 `gemini-3-pro`，正式設定與兩份冷備設定改為 `gemini-3.8-flash`（2026-09-02 正式發布【B141】）。GLM 部分已於 2026-10-07 關閉：地端閘道以同一端點、同一把 key 提供 `glm` 與 `deepseek` 兩個模型名稱，正式設定改為 `glm`（v0.4.4）；閘道未標明 `deepseek` 背後的版本，仍待平台團隊確認。
77. **Bedrock 的 `global.` 跨區路由與資料保留模式**：`global.` 設定檔可在任一 AWS 商用區域處理，被保留的資料存於目的區域【B138】；Bedrock 新增的資料保留模式設定對 Opus 5.5 是否提供「不保留」，文件沒有載明【B137】。需要：以 AWS 帳戶查詢 Opus 5.5 允許的保留模式，並由各廠區（尤其 Brno 的 EU 合約）確認跨區路由是否可接受。暫採：尚未證實。
78. **Gemini API 付費層的保留天數**：條款只寫「有限期間」【B139】，沒有天數；常被引用的 55 天是 AI Studio 中開發者自有紀錄的預設上限，不是濫用偵測紀錄。需要：Google 的書面確認或企業資料處理協議。暫採：尚未證實；核准單號 20261006-GISMD-Approve-01 依據的保留條件應附在核准紀錄中。
79. **GLM 的安全面獨立評估**：CAISI 對 GLM-5.2 的評估只給定性結論【B147】，對 GLM-5.3 的評估只含能力、未涵蓋 Flash 版本【B146】；本次未找到 CrowdStrike、Cisco 等對 GLM 的 jailbreak 或敏感詞研究，也未找到台灣對智譜或 GLM 的公務機關限制。需要：上述研究或政府文件，以及治理檢查 G-8 對 IEC 端點實際執行的 garak 與 CyberSecEval 結果。暫採：尚未證實。
