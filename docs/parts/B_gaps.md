# 附錄B　查證缺口清單

每項列出：無法查證什麼、為什麼、要查證需要什麼、暫時採用了哪一級證據。前置說明：本次研究環境的出口代理伺服器封鎖了以下一手網域：arxiv.org、anthropic.com、openai.com、deepmind.google、github.blog、docs.github.com、nist.gov 全系（含 csrc、nvlpubs）、owasp.org、genai.owasp.org、cwe.mitre.org、capec.mitre.org、atlas.mitre.org、cisa.gov、w3.org、first.org、slsa.dev、oasis-open.org、developer.mozilla.org、iso.org、artificialintelligenceact.eu、huggingface.co、nvidianews.nvidia.com、developer.nvidia.com、crowdstrike.com、blogs.cisco.com、garanteprivacy.it、moda.gov.tw、ey.gov.tw、veracode.com、semgrep.dev、api-docs.deepseek.com、thehackernews.com、dl.acm.org、wikipedia。三個研究 agent 的搜尋配額（各 200 次）亦已用盡。以下缺口中標「代理封鎖」者，其題名、日期與數字來自搜尋引擎摘要，未直接讀取原頁；關閉方式一律是在不受封鎖的環境開啟該 URL 核對。

## B-1 方法與環境層缺口

1. **arXiv 全部條目未直接讀取。** 原因：代理封鎖。需要：開啟每個 arXiv 頁核對題名、作者、日期與數字。暫採：第三方評論（preprint）。
2. **NIST 全部文件未直接讀取**（AI RMF 1.0、AI 600-1、SP 800-218/218A、SP 800-63-4、SP 800-160、SP 800-204D、CAISI 兩份評估、NVD 政策）。原因：代理封鎖。暫採：已證實（政府出版物，依出版者強度），數字標「摘要」。
3. **OWASP 官網未直接讀取**，但 OWASP 的 GitHub 官方 repo（ASVS、Top10、API-Security、CheatSheetSeries）可讀，本報告以 repo 為一手。原因：代理封鎖。暫採：已證實（repo）。
4. **Anthropic 官方公告頁全部未讀取**（安全審查公告、Claude Code Security、Glasswing、Opus 5 系統卡）；platform.claude.com 的文件可讀。暫採：公告為廠商主張（依二手）；文件為已證實。

## B-2 工具與產品（A 組）

5. **LLMSmith** 找不到任何相符結果；可能名稱有誤。暫採：未引用。
6. **PentestGPT 原始論文**未取得 arXiv 編號與發表場次。暫採：未引用。
7. **Socket AI 與 Amplify Security 的發布日期**未找到。暫採：日期不可驗證。
8. **ARVO 的 arXiv 編號與日期**只有二手描述。暫採：未引用。
9. **gitleaks 與 Trivy 的官方 SARIF 文件頁**未取得，只有二手部落格。暫採：尚未證實（功能普遍認知為真）。
10. **Copilot Autofix 的獨立第三方評測**未取得內容（arXiv:2509.13650 僅連結）。暫採：未引用。
11. **DARPA AIxCC 2025 決賽結果**未查（配額用盡）。暫採：未引用；建議補查。
12. **claude-code-security-review Action 的正式 release 日期**：倉庫無 tag，2025-08-06 依三家媒體交叉。暫採：第三方評論。
13. **「Project Glasswing／Mythos Preview 找出逾一萬個 high/critical 漏洞」**單一二手來源。暫採：尚未證實，正文未引用數字。
14. **Claude Code 權限請求 97% 核准率與 2026-08-14 auto mode 預設**：單一二手來源。暫採：尚未證實，第 15.2 節明示。
15. **OpenAI Aardvark 92% 召回與 10 個 CVE**：openai.com 封鎖，依搜尋摘要與媒體。暫採：廠商主張。
16. **Codex Security 定價 $0.018／千行**：單一二手來源。暫採：尚未證實，未引用。
17. **CodeMender 公告確切日期**（推測 2025-10-06）。暫採：2025-10。
18. **Big Sleep 首次公開日期 2024-11-01**：Project Zero 原文未取得。暫採：第三方評論。
19. **DeepSeek-V3.2 發布日期矛盾**：GitHub 頁面渲染 2025-11-17，業界記載 2025-09-29。暫採：尚未證實，兩者並列。
20. **DeepSeek V4 全部規格與授權**（1.6T/49B、284B/13B、1M、MIT）：官方 news 頁與 HF 模型卡封鎖，GitHub 組織頁未列 V4 倉庫。暫採：尚未證實。
21. **NVIDIA Nemotron 3 各型號發布日期、參數量（Ultra 500B vs 550B）與授權對應**：全為二手。暫採：尚未證實。
22. **NVIDIA 容器安全 Blueprint 由 Nemotron 3 Ultra／3.5 Lightning 驅動**：build.nvidia.com 摘要。暫採：尚未證實；這是「Nemotron 用於資安多代理」的唯一具體證據，優先覆核。
23. **NeMo Agent Toolkit 前身為 AgentIQ**：倉庫未載明。暫採：尚未證實。
24. **CyberSecEval v1 到 v4 各版發表日期**：README 未載明。暫採：未引用日期。
25. **美國各州 DeepSeek 禁令清單**（Texas 等）：無一手政府文件，彙整彼此不一致。暫採：尚未證實，正文只寫「多州」。
26. **義大利 Garante 與南韓 PIPC 原始公告**：主管機關網站封鎖，依律師事務所與媒體。暫採：Garante 已證實（多重獨立記載）；PIPC 第三方評論。
27. **GitClear 2026「Maintainability Gap」具體數字**：只有標題。暫採：未引用。
28. **DryRun 2025 SAST Accuracy Report 全文與方法論**。暫採：廠商主張，標利益相關。
29. **ZeroPath 在 curl 上「找到 98% bug」**：二手轉述。暫採：尚未證實，未引用。
30. **九篇 2026 年 arXiv 論文**（RealVuln、SastBench、AgenticSCR、Refute-or-Promote、QASecClaw、Revelio、Multi-LLMSecCodeEval、Diverse LLMs vs. Vulnerabilities、(In)Security of Vibe-Coded Applications）：無法存取 arXiv 做獨立覆核。暫採：第三方評論（preprint），並在正文標「需覆核」。其中 A136 為核心引用，優先覆核。
31. **DVDR-LLM（ETASR 期刊）發表日期**未取得。暫採：未引用。
32. **Anthropic security-review 的精確率或召回率**：公告無測量數據。暫採：無數字可引。

## B-3 偏誤與模型（B 組）

33. **「Large Language Models Share Representations…」**作為集成多樣性論文不存在；同名者為多語言可解釋性論文（arXiv:2501.06346）。暫採：改引 B17、B18、B19。
34. **OWASP Agentic Top 10 2026 的 ASI04 到 ASI10**未確認。暫採：只引 ASI01 到 03。
35. **MITRE ATLAS v5.1.0 的計數**（16 tactics／84 techniques 等）只有第三方追蹤者。暫採：第三方評論。
36. **NASA 與美國海軍的 DeepSeek 備忘錄**只有二手。暫採：未引用為一手。
37. **CAISI 對 DeepSeek V4 Pro 的評估（2026-05）**只有題名與 URL。暫採：尚未證實；這是對部署決策最重要的缺口。
38. **DeepSeek 隱私政策「資料存於 PRC」條款原文與最後更新日 2026-02-10**：未直接讀取。暫採：廠商主張。
39. **Nemotron Open Model License 全文**未讀。暫採：尚未證實。
40. **Mistral 官方模型卡**未找到。暫採：未引用。
41. **跨 Claude／DeepSeek／Nemotron 的 CyberSecEval 比較分數表**未取得。暫採：無數字可引。
42. **異質 LLM 資安審查者的跨模型一致性研究**似乎不存在；最接近者為人類資安審稿 κ 0.27 到 0.77（arXiv:2512.09549）、四個 LLM 對架構違規的 Fleiss' κ 0.724（arXiv:2602.07609）。暫採：列為本專案可貢獻的空白。
43. **生產環境 AI code reviewer 遭程式碼註解 prompt injection 的實例**（CodeRabbit、Copilot、Cursor、Greptile）：配額用盡前未取得。暫採：尚未證實，正文只引學術證據。
44. **Mixture-of-Agents 的發表場次**（常引為 ICLR 2025）未確認。暫採：preprint。
45. **Dawid & Skene 1979 的 DOI 與頁碼**依記憶未驗。暫採：已證實但註明。
46. **多篇 2026 年 arXiv 偏誤論文**（B4、B5、B6、B29、B32、B33、B36）僅題名。暫採：未引用。
47. **Anthropic Opus 5 系統卡的 cyber 評估內容**未讀。暫採：尚未證實。
48. **Krippendorff's α 在本雛型的「單一 finding」層級是簡化的 modal-share 代理指標**（見 `pipeline._per_finding_alpha`），不是嚴格的 α；全域 α 才是嚴格計算。暫採：正文第 11.2 節與程式碼註解已標示。

## B-4 標準與事件（C 組）

49. **CWE 與 CAPEC 目錄的當前版本號與日期**未驗。暫採：未引用版本。
50. **SARIF 2.1.0 的 OASIS 批准日**（2020-03-27）與 2.2 時程：A 組來源給出批准與公告日，C 組未能驗，兩組不矛盾。暫採：已證實（A142）。
51. **GitHub code scanning 的 SARIF 上傳數值上限**未驗。暫採：正文只寫「子集」。
52. **ASVS 5.0 是否有 V17 WebRTC**：官方 CSV 渲染止於 V16。暫採：V1 到 V16 已證實，V17 尚未證實；雛型 ground truth 只收錄 V1 到 V16。
53. **OWASP Top 10:2025 的定稿日期**：官方 Introduction 無日期。暫採：第三方（2025-11 公布、2026-01 定稿）。
54. **OWASP SAMM 是否有 2.1**：未找到。暫採：引 2.0。
55. **Microsoft 棄用 DREAD 的一手聲明**未找到。暫採：尚未證實，第 11.3 節明示。
56. **STRIDE 的原始 Microsoft 文件**未驗。暫採：未引用出處。
57. **CSP Level 3 最新 WD 日期**：2025-06-06 與 2026-05-05 矛盾。暫採：尚未證實。
58. **CVE-2025-48700 Zimbra XSS 的 KEV 收錄日期與官方 advisory**未直接驗。暫採：第三方評論；若無法確認應換一個可查的 KEV XSS 案例。
59. **EPSS v4 的 FIRST 官方公告頁**未取得。暫採：日期為第三方。
60. **detect-secrets、poutine、TruffleHog 的當前版本；gitleaks v8.30.1 與 Dependency-Check v13.0.0 的發布年份**：GitHub 頁未渲染年份。暫採：版本已證實，年份不可驗證。
61. **CISA KEV 總條目數（2026-09）**未驗。暫採：未引用。
62. **ua-parser-js（2021）與 event-stream（2018）事件**未研究。暫採：未引用。
63. **Uber 2022 與 Toyota 憑證外洩事件**未研究。暫採：未引用。
64. **「Kong」GitHub Actions 事件**未找到。暫採：未引用。
65. **OWASP LLM Top 10 2026 版**（疑似 2026-08-04 發布）未驗；若存在，LLM01:2025 的引用需更新。暫採：引 2025 版。
66. **ISO/IEC 27001:2022 條文**付費牆；5.19 到 5.21、8.8、8.32 的標題依實務通用引用。暫採：尚未證實，第十部標 *。
67. **SEMI E187 的發布日期與修訂版**未驗。暫採：未引用日期。
68. **IEC 62443-4-1 各實務的活動計數**（SM-1 到 SM-13 等）來自 arXiv:2105.13413 而非標準本身。暫採：第三方評論。
69. **Bybit 2025 事件細節**：只在 OWASP A03:2025 內引用。暫採：OWASP 主張已證實，事件本身未獨立驗。
70. **NVD「僅 15 到 20% CVE 受 enrichment」的業界估計**。暫採：第三方評論，正文未引數字。

## B-5 雛型自身的缺口

71. **真實模型的精確率與召回率**：雛型只在 mock 家族上驗證行為。關閉方式：以真實三家族在 seeded benchmark 上跑第一次校準（附錄E prompt 4）。
72. **bias sensitivity 測試**（第 13 章第 16 項）未實作。
73. **三家族設定的獨立 judge 不足**是固有性質而非缺口，但四家族的效果未驗證。
74. **L0 工具版本未固定**：雛型「有就跑」。關閉方式：附錄E prompt 7。
