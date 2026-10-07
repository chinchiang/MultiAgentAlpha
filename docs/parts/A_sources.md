# 附錄A　引用來源清單

**核對規則（2026-09-18 修正）：來源類型與聲明真偽分開記錄。僅見摘要者一律待核實；既有「已證實」不代表本次已讀原文。缺少逐項核對摘錄、日期及審查人者，不升級為已核對。機器可讀登錄簿見 `docs/source-verification.json`。**

編號規則：A 開頭為工具與文獻調查（第二、四、七部主要引用），B 開頭為 LLM 評審偏誤、模型現況與治理框架，C 開頭為十一面向的標準與事件（C 後的第一個數字是面向編號）。「讀取」欄標示本次研究是否直接讀到原頁：是＝直接讀取；摘要＝原頁被出口代理伺服器封鎖，題名、日期與數字來自搜尋引擎摘要。日期無法驗證者列於附錄B。2026-10-06 複核後：「是（arXiv API）」表示經 arXiv 官方 API 讀取題名、作者、日期與摘要；核對狀態「原文核對（2026-10-06）」表示該次已逐條留下摘錄（見登錄簿的 `claim_excerpt`），核對者為 Claude Code 代理，未經人工複核。

## A 組：工具、產品與文獻

| 編號 | 出版者 | 題名 | URL | 日期 | 級別 | 讀取 | 核對狀態 |
|---|---|---|---|---|---|---|---|
| A1 | Anthropic | anthropics/claude-code-security-review（GitHub Action） | https://github.com/anthropics/claude-code-security-review | 無 release 標籤；公告 2025-08-06 | 廠商主張（原始碼可查） | 是 | 原文核對（2026-10-06） |
| A2 | Anthropic | `/security-review` 命令定義檔 | https://github.com/anthropics/claude-code-security-review/blob/main/.claude/commands/security-review.md | 同上 | 已證實（檔案存在） | 是 | 原文核對（2026-10-06） |
| A3 | VentureBeat | Anthropic ships automated security reviews for Claude Code | https://venturebeat.com/ai/anthropic-ships-automated-security-reviews-for-claude-code-as-ai-generated-vulnerabilities-surge | 2025-08-06 | 第三方評論 | 是 | 原文核對（2026-10-06） |
| A6 | VentureBeat | Claude Code Security 找到 500+ 漏洞 | https://venturebeat.com/security/anthropic-claude-code-security-reasoning-vulnerability-hunting | 2026-02-23 | 第三方評論（產品已改名 Claude Security，見 B134） | 是 | 原文核對（2026-10-06） |
| A7 | Anthropic | Making frontier cybersecurity capabilities available to defenders（Claude Code Security 公告；原引 Axios 報導讀不到，改引一手） | https://www.anthropic.com/news/claude-code-security | 2026-02-20 | 廠商主張 | 是 | 原文核對（2026-10-06） |
| A11 | CybersecurityNews | Claude Code 改用 auto mode 分類器 | https://cybersecuritynews.com/claude-code-shifts-agent-security/ | 2026-08-10（生效 2026-08-14） | 尚未證實（單一二手） | 是 | 原文核對（2026-10-06） |
| A12 | OpenAI | Introducing Aardvark | https://openai.com/index/introducing-aardvark/ | 2025-10-30 | 廠商主張 | 摘要 | 待核實（僅摘要） |
| A15 | OpenAI | Codex Security（文件；原公告頁讀不到） | https://learn.chatgpt.com/docs/security | 公告 2026-03-06；文件為活文件 | 廠商主張 | 是 | 原文核對（2026-10-06） |
| A17 | The Hacker News | Codex Security 掃描 120 萬 commits | https://thehackernews.com/2026/03/openai-codex-security-scanned-12.html | 2026-03-07 | 第三方評論 | 是 | 原文核對（2026-10-06） |
| A18 | Google DeepMind | Introducing CodeMender | https://deepmind.google/blog/introducing-codemender-an-ai-agent-for-code-security/ | 2025-10-06 | 廠商主張 | 是 | 原文核對（2026-10-06） |
| A22 | Wiz / The Hacker News | Big Sleep 與 CVE-2025-6965 | https://www.wiz.io/vulnerability-database/cve/cve-2025-6965 | 2025-07-15 | 第三方評論（頁面為 AI 生成，CVSS 與 NVD 連結有誤；CVE 宜改引 NVD） | 是 | 原文核對（2026-10-06） |
| A25 | GitHub | Responsible use of Copilot Autofix for code scanning | https://docs.github.com/en/code-security/responsible-use/responsible-use-autofix-code-scanning | 日期不可驗證（活文件） | 已證實（文件存在） | 是 | 原文核對（2026-10-06） |
| A26 | GitHub | Copilot Autofix for CodeQL code scanning alerts is now generally available | https://github.blog/changelog/2024-08-14-copilot-autofix-for-codeql-code-scanning-alerts-is-now-generally-available/ | 2024-08-14 | 廠商主張 | 是 | 原文核對（2026-10-06） |
| A31 | GitHub | Security reviews now available in the GitHub Copilot app | https://github.blog/changelog/2026-07-14-security-reviews-now-available-in-the-github-copilot-app/ | 2026-07-14 | 廠商主張（public preview） | 是 | 原文核對（2026-10-06） |
| A37 | Semgrep | Building an AppSec AI that security researchers agree with 96% of the time | https://semgrep.dev/blog/2025/building-an-appsec-ai-that-security-researchers-agree-with-96-of-the-time/ | 2025-01-22 | 廠商主張 | 是 | 原文核對（2026-10-06） |
| A38 | Semgrep | Semgrep is confidently handling 60% of all triage | https://semgrep.dev/blog/2025/semgrep-is-confidently-handling-60-of-all-triage-for-users-without-reducing-coverage/ | 2025-09-10 | 廠商主張 | 是 | 原文核對（2026-10-06） |
| A40 | Semgrep | Semgrep Assistant overview（docs） | https://docs.semgrep.dev/semgrep-assistant/overview | 活文件 | 已證實（文件存在；現行文件寫 OpenAI 為主、Bedrock 備援） | 是 | 原文核對（2026-10-06） |
| A41 | Semgrep | semgrep/mcp | https://github.com/semgrep/mcp | 2025-10-28 封存，已併入 semgrep 主 repo | 已證實 | 是 | 原文核對（2026-10-06） |
| A43 | Snyk | DeepCode AI 平台頁 | https://snyk.io/platform/deepcode-ai/ | 日期不可驗證 | 廠商主張 | 是 | 原文核對（2026-10-06） |
| A44 | Snyk | DCAIF under the hood | https://snyk.io/articles/snyk-dcaif-under-the-hood/ | 2026-04-27 | 廠商主張 | 是 | 原文核對（2026-10-06） |
| A45 | Snyk | Secure adoption in the GenAI era | https://snyk.io/reports/secure-adoption-in-the-genai-era/ | 約 2024-06 | 廠商主張 | 是 | 原文核對（2026-10-06） |
| A54 | Joshua Rogers | Hacking with AI SASTs | https://joshua.hu/llm-engineer-review-sast-security-ai-tools-pentesters | 2025-09-18 | 第三方評論 | 是 | 原文核對（2026-10-06） |
| A56 | Endor Labs / PR Newswire | Endor Labs Debuts AI-Native Multi-Modal SAST | https://www.prnewswire.com/news-releases/endor-labs-debuts-ai-native-multi-modal-sast-marking-a-new-era-in-code-flaw-detection-302619629.html | 2025-11-19 | 廠商主張 | 是 | 原文核對（2026-10-06） |
| A57 | Endor Labs | Introducing AI Security Code Review（blog；原引 docs 頁沒有相關內容） | https://www.endorlabs.com/learn/introducing-ai-security-code-review | 2025-04-23（更新 2025-08-25） | 廠商主張 | 是 | 原文核對（2026-10-06） |
| A61 | Infosecurity Magazine | 惡意 npm 套件操弄 AI 偵測 | https://www.infosecurity-magazine.com/news/malware-ai-detection-npm-package/ | 2025-12-01 | 第三方評論 | 是 | 原文核對（2026-10-06） |
| A62 | Datadog | Using LLMs to filter out false positives from static code analysis | https://www.datadoghq.com/blog/using-llms-to-filter-out-false-positives/ | 2025-10-28 | 廠商主張 | 是 | 原文核對（2026-10-06） |
| A63 | Datadog | AI-Enhanced Static Code Analysis（docs） | https://docs.datadoghq.com/security/code_security/static_analysis/ai_enhanced_sast/ | 活文件 | 已證實（文件存在） | 是 | 原文核對（2026-10-06） |
| A67 | 二手部落格彙整 | Nemotron 3 家族規格與授權 | https://www.digitalapplied.com/blog/nvidia-nemotron-3-ultra-550b-open-reasoning-model-2026 | 2026-06-05 | 第三方評論（二手；主要來源改為 B131） | 是 | 原文核對（2026-10-06） |
| A68 | NVIDIA | NVIDIA/NeMo-Agent-Toolkit | https://github.com/NVIDIA/NeMo-Agent-Toolkit | v1.9.0 2026-09-10 | 已證實 | 是 | 原文核對（2026-10-06） |
| A70 | NVIDIA | Applying Generative AI for CVE Analysis at an Enterprise Scale | https://developer.nvidia.com/blog/applying-generative-ai-for-cve-analysis-at-an-enterprise-scale/ | 2024-05-23 | 廠商主張 | 是 | 原文核對（2026-10-06） |
| A72 | NVIDIA | Vulnerability Analysis for Container Security Blueprint | https://build.nvidia.com/nvidia/vulnerability-analysis-for-container-security | 日期不可驗證 | 已證實（Nemotron 3 Ultra 驅動） | 是 | 原文核對（2026-10-06） |
| A75 | DeepSeek | deepseek-ai/DeepSeek-V3.2 | https://github.com/deepseek-ai/DeepSeek-V3.2 | V3.2-Exp 2025-09-29；V3.2 正式版 2025-12-01（URL 轉址到 V3.2-Exp 倉庫） | 已證實；China-affiliated | 是 | 原文核對（2026-10-06） |
| A77 | DeepSeek | DeepSeek V4 Preview Release | https://api-docs.deepseek.com/news/news260424/ | 2026-04-24 | 廠商主張；China-affiliated | 是 | 原文核對（2026-10-06） |
| A78 | DeepSeek | deepseek-ai/DeepSeek-V4-Pro（Hugging Face） | https://huggingface.co/deepseek-ai/DeepSeek-V4-Pro | 2026-04-22 | 已證實（MIT、safetensors）；China-affiliated | 是 | 原文核對（2026-10-06） |
| A80 | Australian Government Department of Home Affairs | PSPF Direction — DeepSeek products, applications and web services | https://www.protectivesecurity.gov.au/news/pspf-direction-update-deepseek-products-applications-and-web-services | 2025-02-04 | 待原文核實 | 摘要 | 待核實（僅摘要） |
| A82 | U.S. Congress | S.765 / H.R.1121 No DeepSeek on Government Devices Act | https://www.congress.gov/bill/119th-congress/senate-bill/765 | 119th Congress，2025 | 已證實（Congress.gov 官方 API；停在委員會） | 是（官方 API） | 原文核對（2026-10-06） |
| A83 | U.S. Congress | S.2177 / H.R.4142 No Adversarial AI Act | https://www.congress.gov/bill/119th-congress/senate-bill/2177/text | 2025 | 已證實（Congress.gov 官方 API；停在委員會） | 是（官方 API） | 原文核對（2026-10-06） |
| A85 | Li et al. | IRIS: LLM-Assisted Static Analysis for Detecting Security Vulnerabilities（ICLR 2025） | https://arxiv.org/abs/2405.17238 | 2024-05-27；ICLR 2025 | 已證實（ICLR 2025） | 是（arXiv API） | 原文核對（2026-10-06） |
| A86 | Guo et al. | RepoAudit: An Autonomous LLM-Agent for Repository-Level Code Auditing | https://arxiv.org/abs/2501.18160 | 2025-01-30 | 已證實（ICML 2025） | 是（arXiv API） | 原文核對（2026-10-06） |
| A87 | Wang, Li et al. | VulAgent: Hypothesis-Validation based Multi-Agent Vulnerability Detection | https://arxiv.org/abs/2509.11523 | 2025-09-15 | 第三方評論（preprint） | 是（arXiv API） | 原文核對（2026-10-06） |
| A89 | — | Multi-role Consensus through LLMs Discussions for Vulnerability Detection | https://arxiv.org/abs/2403.14274 | 2024-03 | 已證實（IEEE QRS-C 2024，兩頁短文） | 是（arXiv API） | 原文核對（2026-10-06） |
| A93 | Sun, Wu et al. | GPTScan（ICSE 2024） | https://dl.acm.org/doi/10.1145/3597503.3639117 | 2024 | 已證實（ICSE 2024；限 Solidity） | 是（arXiv） | 原文核對（2026-10-06） |
| A94 | — | AgenticSCR | https://arxiv.org/html/2601.19138v1 | 2026-01 | 已證實（ASE 2026 Industry Track 已接受） | 是 | 原文核對（2026-10-06） |
| A102 | — | Vul-RAG（ACM TOSEM） | https://arxiv.org/abs/2406.11147 ; https://dl.acm.org/doi/10.1145/3797277 | 2024-06；TOSEM | 已證實（TOSEM） | 是（arXiv API） | 原文核對（2026-10-06） |
| A105 | — | QLCoder: A Query Synthesizer For Static Analysis of Security Vulnerabilities | https://arxiv.org/abs/2511.08462 | 2025-11 | 第三方評論（preprint） | 是（arXiv API） | 原文核對（2026-10-06） |
| A115 | Ding et al. | Vulnerability Detection with Code Language Models: How Far Are We?（PrimeVul，ICSE 2025） | https://arxiv.org/abs/2403.18624 | 2024-03；ICSE 2025 | 已證實（ICSE 2025） | 是（arXiv API） | 原文核對（2026-10-06） |
| A116 | Ullah et al. | LLMs Cannot Reliably Identify and Reason About Security Vulnerabilities (Yet?)（SecLLMHolmes，IEEE S&P 2024） | https://arxiv.org/abs/2312.12575 | 2023-12；S&P 2024 | 已證實（IEEE S&P 2024） | 是（arXiv API） | 原文核對（2026-10-06） |
| A122 | Zhu et al. (UIUC) | CVE-Bench（ICML 2025 spotlight） | https://arxiv.org/abs/2503.17332 | 2025-03；ICML 2025 | 已證實（ICML 2025） | 是（arXiv API） | 原文核對（2026-10-06） |
| A123 | Wang et al. (UC Berkeley) | CyberGym | https://arxiv.org/abs/2506.02548 | 2025-06 | 第三方評論（preprint） | 是（arXiv API） | 原文核對（2026-10-06） |
| A124 | — | SEC-bench（NeurIPS 2025） | https://arxiv.org/abs/2506.11791 | 2025-06；NeurIPS 2025 | 已證實（NeurIPS 2025） | 是（arXiv API） | 原文核對（2026-10-06） |
| A128 | — | RealVuln | https://arxiv.org/abs/2604.13764 | 2026-04 | 第三方評論（preprint；作者自家產品居榜首） | 是（arXiv API） | 原文核對（2026-10-06） |
| A132 | Perry, Srivastava, Kumar, Boneh | Do Users Write More Insecure Code with AI Assistants?（ACM CCS 2023） | https://dl.acm.org/doi/10.1145/3576915.3623157 | 2023-11 | 已證實（CCS 2023） | 是（arXiv） | 原文核對（2026-10-06） |
| A133 | CSET Georgetown | Cybersecurity Risks of AI-Generated Code | https://cset.georgetown.edu/publication/cybersecurity-risks-of-ai-generated-code/ | 2024-11 | 已證實 | 是 | 原文核對（2026-10-06） |
| A134 | Veracode | 2025 GenAI Code Security Report | https://www.veracode.com/resources/analyst-reports/2025-genai-code-security-report/ | 2025-07；頁面已更新為 2025-10 版 | 廠商主張 | 是（landing page；細項數字只在 PDF） | 原文核對（2026-10-06） |
| A135 | Veracode / BusinessWire | 2026 GenAI Code Security Report | https://www.veracode.com/resources/analyst-reports/2026-genai-code-security-report/ | 2026-07-28 | 廠商主張 | 是 | 原文核對（2026-10-06） |
| A136 | Deng et al. | Understanding the (In)Security of Vibe-Coded Applications | https://arxiv.org/abs/2606.23130 | v1 2026-06；v4 2026-09-14 | 第三方評論（preprint） | 是 | 原文核對（2026-10-06） |
| A137 | GitClear | AI Copilot Code Quality: 2025 Data Suggests 4x Growth in Code Clones | https://www.gitclear.com/ai_assistant_code_quality_2025_research | 2025-02 | 廠商主張 | 摘要 | 待核實（僅摘要） |
| A140 | Apiiro | 4x Velocity, 10x Vulnerabilities | https://apiiro.com/blog/4x-velocity-10x-vulnerabilities-ai-coding-assistants-are-shipping-more-risks/ | 2025-09-04 | 廠商主張 | 摘要 | 待核實（僅摘要） |
| A142 | OASIS | SARIF Version 2.1.0 OASIS Standard | https://www.oasis-open.org/standard/sarif-v2-1-0/ | CS01 2019-07-23；OASIS Standard 2020-03-27 | 已證實 | 是 | 原文核對（2026-10-06） |
| A144 | GitHub | SARIF support for code scanning | https://docs.github.com/en/code-security/code-scanning/integrating-with-code-scanning/sarif-support-for-code-scanning | 活文件 | 已證實 | 是 | 原文核對（2026-10-06） |
| A145 | Veracode | Spring 2026 GenAI Code Security Update | https://www.veracode.com/blog/spring-2026-genai-code-security/ | 2026-03-24 | 廠商主張 | 是 | 原文核對（2026-10-06） |

## B 組：LLM 評審偏誤、共識方法、模型現況、治理框架

| 編號 | 出版者 | 題名 | URL | 日期 | 級別 | 讀取 | 核對狀態 |
|---|---|---|---|---|---|---|---|
| B1 | Panickssery, Bowman, Feng | LLM Evaluators Recognize and Favor Their Own Generations（NeurIPS 2024） | https://arxiv.org/abs/2404.13076 | 2024-04-15 | 已證實（NeurIPS 2024） | 是（arXiv API） | 原文核對（2026-10-06） |
| B2 | Wataoka, Takahashi, Ri | Self-Preference Bias in LLM-as-a-Judge | https://arxiv.org/abs/2410.21819 | 2024-10-29 | 第三方評論（NeurIPS 2024 workshop） | 是（arXiv API） | 原文核對（2026-10-06） |
| B7 | Zheng et al. | Judging LLM-as-a-Judge with MT-Bench and Chatbot Arena（NeurIPS 2023 D&B） | https://arxiv.org/abs/2306.05685 | 2023-06-09 | 已證實（NeurIPS 2023 D&B） | 是（PDF） | 原文核對（2026-10-06） |
| B8 | Ye et al. | Justice or Prejudice? Quantifying Biases in LLM-as-a-Judge（CALM，ICLR 2025） | https://arxiv.org/abs/2410.02736 | 2024-10-03 | 已證實（ICLR 2025） | 是（arXiv API） | 原文核對（2026-10-06） |
| B9 | Shi et al. | Judging the Judges: A Systematic Study of Position Bias | https://arxiv.org/abs/2406.07791 | 2024-06-12 | 已證實（AACL-IJCNLP 2025） | 是（arXiv API） | 原文核對（2026-10-06） |
| B12 | — | LLMs-as-Judges: A Comprehensive Survey | https://arxiv.org/abs/2412.05579 | 2024-12-07 | 第三方評論（preprint） | 是（arXiv API） | 原文核對（2026-10-06） |
| B13 | — | Anchoring Bias in LLM-as-a-Judge: Prior Scores Compromise Evaluation Independence | https://arxiv.org/abs/2608.25869 | 2026-08-26 | 已證實（CIKM 2026 已接受） | 是（arXiv API） | 原文核對（2026-10-06） |
| B14 | Zhao, Esmaeili, Fard (UBC) | Bias in the Loop: Auditing LLM-as-a-Judge for Software Engineering | https://arxiv.org/abs/2604.16790 | 2026-04-18 | 第三方評論（preprint） | 是（arXiv API） | 原文核對（2026-10-06） |
| B15 | — | Evaluating Scoring Bias in LLM-as-a-Judge | https://arxiv.org/abs/2506.22316 | 2025-06 | 已證實（DASFAA 2026） | 是（arXiv API） | 原文核對（2026-10-06） |
| B16 | — | Evaluating and Mitigating LLM-as-a-judge Bias in Communication Systems | https://arxiv.org/abs/2510.12462 | 2025-10 | 第三方評論（IEEE Network，DOI 待確認） | 是（arXiv API） | 原文核對（2026-10-06） |
| B17 | Goel et al. | Great Models Think Alike and this Undermines AI Oversight（ICML 2025） | https://arxiv.org/abs/2502.04313 | 2025-02-06 | 已證實（ICML 2025） | 是（arXiv API） | 原文核對（2026-10-06） |
| B18 | Kim, Garg, Peng, Garg | Correlated Errors in Large Language Models（ICML 2025，PMLR v267） | https://arxiv.org/abs/2506.07962 | 2025-06-09 | 已證實（ICML 2025） | 是（arXiv API） | 原文核對（2026-10-06） |
| B22 | Verga et al. (Cohere) | Replacing Judges with Juries（PoLL） | https://arxiv.org/abs/2404.18796 | 2024-04-29 | 第三方評論（preprint） | 是（arXiv API） | 原文核對（2026-10-06） |
| B26 | — | Stop Overvaluing Multi-Agent Debate | https://arxiv.org/abs/2502.08788 | 2025-02-12 | 第三方評論（preprint） | 是（arXiv API） | 原文核對（2026-10-06） |
| B27 | — | When and Why Does Multi-Agent Debate Fail | https://arxiv.org/abs/2510.20963 | 2025-10 | 第三方評論（preprint） | 是（arXiv API） | 原文核對（2026-10-06） |
| B30 | Wang et al. | MARS: toward more efficient multi-agent collaboration for LLM reasoning（初版誤引 2608.18167〈Adversarial Review〉） | https://arxiv.org/abs/2509.20502 | 2025-09-24 | 第三方評論（preprint） | 是（arXiv API） | 原文核對（2026-10-06） |
| B31 | — | Refute-or-Promote | https://arxiv.org/abs/2604.19049 | 2026-04 | 第三方評論（preprint） | 是（arXiv API） | 原文核對（2026-10-06） |
| B34 | Tian et al. | Overconfidence in LLM-as-a-Judge | https://arxiv.org/abs/2508.06225 | 2025-08-08 | 第三方評論（preprint） | 是（arXiv API） | 原文核對（2026-10-06） |
| B37 | — | Sifting the Noise: LLM Agents in Vulnerability False Positive Filtering | https://arxiv.org/abs/2601.22952 | 2026-01 | 已證實（ISSTA 2026） | 是（arXiv API） | 原文核對（2026-10-06） |
| B39 | — | Are Frontier LLMs Ready for Cybersecurity? | https://arxiv.org/abs/2605.23243 | 2026-05 | 第三方評論（preprint） | 是（arXiv API） | 原文核對（2026-10-06） |
| B42 | Daniel Stenberg（curl 維護者） | The end of the curl bug-bounty（原引 BleepingComputer 讀不到，改引一手） | https://daniel.haxx.se/blog/2026/01/26/the-end-of-the-curl-bug-bounty/ | 2026-01-26（終止日 2026-01-31） | 已證實（維護者公告） | 是 | 原文核對（2026-10-06） |
| B43 | OWASP GenAI Security Project | OWASP Top 10 for LLM Applications 2025 | https://genai.owasp.org/llmrisk/llm01-prompt-injection/ | 2024-11 | 已證實 | 是 | 原文核對（2026-10-06） |
| B45 | OWASP GenAI Security Project | OWASP Top 10 for Agentic Applications 2026 | https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/ | 2025-12-09 | 待原文核實（僅 ASI01–03 確認） | 摘要 | 待核實（僅摘要） |
| B46 | MITRE | ATLAS | https://github.com/mitre-atlas/atlas-data/blob/main/CHANGELOG.md | v5.0.0 2025-09-30；v5.1.0 2025-11-06；最新 v2026.09 | 已證實（官方 changelog） | 是 | 原文核對（2026-10-06） |
| B48 | — | Prompt Injection Attacks on Agentic Coding Assistants | https://arxiv.org/abs/2601.17548 | 2026-01 | 第三方評論（preprint） | 是 | 原文核對（2026-10-06） |
| B49 | — | Prompt Injection Attacks on LLM Generated Reviews of Scientific Publications | https://arxiv.org/abs/2509.10248 | 2025-09 | 第三方評論（preprint） | 是（arXiv API） | 原文核對（2026-10-06） |
| B55 | Sharma et al. (Anthropic) | Towards Understanding Sycophancy in Language Models（ICLR 2024） | https://arxiv.org/abs/2310.13548 | 2023-10-20 | 已證實（ICLR 2024） | 是（arXiv API） | 原文核對（2026-10-06） |
| B58 | Laban et al. | LLMs Get Lost In Multi-Turn Conversation | https://arxiv.org/abs/2505.06120 | 2025-05-09 | 第三方評論（preprint；ICLR 2026 刊登未能確認） | 是（arXiv API） | 原文核對（2026-10-06） |
| B60 | Wang et al. | Self-Consistency Improves Chain of Thought Reasoning（ICLR 2023） | https://arxiv.org/abs/2203.11171 | 2022-03-21 | 已證實（ICLR 2023） | 是（arXiv API） | 原文核對（2026-10-06） |
| B62 | Dawid & Skene | Maximum Likelihood Estimation of Observer Error-Rates Using the EM Algorithm，JRSS-C 28(1) | DOI 10.2307/2346806 | 1979 | 已證實（DOI 經 Crossref 確認） | 是（Crossref metadata） | 原文核對（2026-10-06） |
| B63 | — | Variance-Aware LLM Annotation for Strategy Research | https://arxiv.org/abs/2601.02370 | 2025-12-02（v3 2026-01-19） | 第三方評論（preprint） | 是 | 原文核對（2026-10-06） |
| B64 | — | Empirical Study on the Characteristics and Evolution of AI-usage in GitHub Repositories | https://arxiv.org/abs/2606.06843 | 2026-06 | 第三方評論（preprint） | 是（arXiv API） | 原文核對（2026-10-06） |
| B68 | — | Automated Malware Family Classification using Weighted Hierarchical Ensembles of LLMs | https://arxiv.org/abs/2604.02490 | 2026-04 | 第三方評論（preprint） | 是 | 原文核對（2026-10-06） |
| B70 | — | The Alternative Annotator Test for LLM-as-a-Judge | https://arxiv.org/abs/2501.10970 | 2025-01 | 已證實（ACL 2025） | 是（arXiv API） | 原文核對（2026-10-06） |
| B72 | MethodsX（PMC） | K-Alpha Calculator — Krippendorff's Alpha | https://pmc.ncbi.nlm.nih.gov/articles/PMC11636850/ | 2024 | 已證實（處理缺值的部分） | 是 | 原文核對（2026-10-06） |
| B79 | Anthropic | Claude models overview | https://platform.claude.com/docs/en/about-claude/models/overview | 2026-10-06 讀取 | 已證實 | 是 | 原文核對（2026-10-06） |
| B80 | Anthropic | Claude Opus 5 model page | https://platform.claude.com/docs/en/models/opus-5/overview | 發布 2026-07-24 | 已證實（已列舊版，退役不早於 2027-07-24） | 是 | 原文核對（2026-10-06） |
| B81 | Anthropic | API and data retention | https://platform.claude.com/docs/en/manage-claude/api-and-data-retention | 2026-10-06 讀取 | 已證實 | 是 | 原文核對（2026-10-06） |
| B82 | Anthropic Privacy Center | ZDR 適用產品 | https://privacy.claude.com/en/articles/8956058 | 活文件（2026-10-06 讀取） | 已證實 | 是 | 原文核對（2026-10-06） |
| B84 | Anthropic | claude-code-security-review（同 A1） | https://github.com/anthropics/claude-code-security-review | — | 廠商主張 | 是 | 原文核對（2026-10-06） |
| B85 | Anthropic | Claude Opus 5 system card | https://www-cdn.anthropic.com/ceaf5c7ff2783855203fde8208ec311252dced5b/Claude%20Opus%205%20System%20Card.pdf | — | 尚未證實（未讀取） | 否 | 待核實（缺逐項核對紀錄） |
| B86 | DeepSeek | V4 preview release notes（同 A77） | https://api-docs.deepseek.com/news/news260424/ | 2026-04-24 | 廠商主張；China-affiliated | 是 | 原文核對（2026-10-06） |
| B88 | DeepSeek | Privacy Policy | https://cdn.deepseek.com/policies/en-US/deepseek-privacy-policy.html | 2026-02-10 | 廠商主張；China-affiliated | 是 | 原文核對（2026-10-06） |
| B89 | Garante per la protezione dei dati personali | DeepSeek 限制處理令 docweb 10097450 / 10098477 | https://www.garanteprivacy.it/home/docweb/-/docweb-display/docweb/10097450 | 2025-01-30 | 已證實 | 是 | 原文核對（2026-10-06） |
| B90 | ThaiCERT / Digital Policy Alert | 韓國 PIPC 暫停 DeepSeek 下載 | https://www.thaicert.or.th/en/2025/02/19/7304/ | 2025-02-15 | 第三方評論 | 是 | 原文核對（2026-10-06） |
| B91 | 行政院 | 公務機關全面禁用 DeepSeek | https://www.ey.gov.tw/Page/9277F759E41CCD91/3ce9fe8f-2f5f-4d1d-8176-6fa4cf622b82 | 2025-02-03 | 已證實 | 是 | 原文核對（2026-10-06） |
| B92 | 數位發展部 | 新聞稿 15104 | https://moda.gov.tw/press/press-releases/15104 | 2025-01-31 | 已證實 | 是 | 原文核對（2026-10-06） |
| B93 | Australian Government / CNN | PSPF Direction 001-2025 | https://www.cnn.com/2025/02/04/business/australia-deepseek-ban-security-concerns-intl/index.html | 2025-02-04 | 待原文核實（指令）；細節第三方 | 摘要 | 待核實（僅摘要） |
| B95 | NIST CAISI | CAISI Evaluation of DeepSeek AI Models Finds Shortcomings and Risks | https://www.nist.gov/news-events/news/2025/09/caisi-evaluation-deepseek-ai-models-finds-shortcomings-and-risks | 2025-09-30 | 已證實 | 是 | 原文核對（2026-10-06） |
| B96 | NIST CAISI | CAISI Evaluation of DeepSeek V4 Pro | https://www.nist.gov/news-events/news/2026/05/caisi-evaluation-deepseek-v4-pro | 2026-05-01 | 已證實（只含能力評估） | 是 | 原文核對（2026-10-06） |
| B97 | CrowdStrike | 政治觸發詞降低 DeepSeek-R1 程式碼安全性 | https://www.crowdstrike.com/en-us/blog/crowdstrike-researchers-identify-hidden-vulnerabilities-ai-coded-software/ | 2025-11-20 | 第三方評論（廠商研究） | 是 | 原文核對（2026-10-06） |
| B98 | Cisco | Evaluating Security Risk in DeepSeek and Other Frontier Reasoning Models | https://blogs.cisco.com/security/evaluating-security-risk-in-deepseek-and-other-frontier-reasoning-models | 2025-01-31 | 第三方評論 | 是 | 原文核對（2026-10-06） |
| B100 | NVIDIA | NVIDIA Debuts Nemotron 3 Family of Open Models | https://nvidianews.nvidia.com/news/nvidia-debuts-nemotron-3-family-of-open-models | 2025-12-15 | 廠商主張 | 是 | 原文核對（2026-10-06） |
| B102 | NVIDIA | NIM microservices | https://www.nvidia.com/en-us/ai-data-science/products/nim-microservices/ | 活頁面 | 廠商主張 | 是 | 原文核對（2026-10-06） |
| B104 | NVIDIA | garak | https://github.com/NVIDIA/garak | v0.15.0 2026-05-01；最新 v0.17.0 2026-09-09 | 已證實 | 是 | 原文核對（2026-10-06） |
| B106 | Meta | Llama 4 model card | https://github.com/meta-llama/llama-models/blob/main/models/llama4/MODEL_CARD.md | 2025-04-05 | 已證實 | 是 | 原文核對（2026-10-06） |
| B107 | Qwen team | Qwen3 | https://qwenlm.github.io/blog/qwen3/ | 2025-04-29 | 廠商主張；China-affiliated | 是 | 原文核對（2026-10-06） |
| B111 | Vero et al. (ETH Zurich) | BaxBench | https://arxiv.org/abs/2502.11844 ; https://baxbench.com/ | 2025-02-17（v3 2025-05-30） | 第三方評論（preprint） | 是 | 原文核對（2026-10-06） |
| B113 | Meta | PurpleLlama CybersecurityBenchmarks（CyberSecEval 4） | https://github.com/meta-llama/PurpleLlama/tree/main/CybersecurityBenchmarks | 無日期 | 已證實 | 是 | 原文核對（2026-10-06） |
| B118 | NIST | AI 600-1 Generative AI Profile | https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.600-1.pdf | 2024-07-26 | 已證實 | 是 | 原文核對（2026-10-06） |
| B119 | NIST | SP 800-218A | https://csrc.nist.gov/pubs/sp/800/218/a/final | 2024-07-26 | 已證實 | 是 | 原文核對（2026-10-06） |
| B121 | ISO/IEC | ISO/IEC 42001:2023 | https://www.iso.org/standard/42001 | 2023 | 待原文核實 | 摘要 | 待核實（僅摘要） |
| B122 | ISO/IEC | ISO/IEC 23894:2023 | https://www.iso.org/standard/77304.html | 2023 | 待原文核實 | 摘要 | 待核實（僅摘要） |
| B123 | European Union | AI Act Article 4 | https://artificialintelligenceact.eu/article/4/ | 適用 2025-02-02 | 第三方評論（修正後條文經彙整網站讀取） | 是 | 原文核對（2026-10-06） |
| B124 | Anthropic | Claude Opus 5.5（模型頁） | https://platform.claude.com/docs/en/models/opus-5-5/overview | 2026-09-22 | 已證實 | 是 | 原文核對（2026-10-06） |
| B125 | Anthropic | Introducing Claude Opus 5.5（公告） | https://www.anthropic.com/claude-opus-5-5 | 2026-09-22 | 廠商主張 | 是 | 原文核對（2026-10-06） |
| B126 | Anthropic | Model deprecations | https://platform.claude.com/docs/en/about-claude/model-deprecations | 活文件（2026-10-06 讀取） | 已證實 | 是 | 原文核對（2026-10-06） |
| B127 | Anthropic Help Center | Real-time cyber safeguards on Claude Opus and Sonnet | https://support.claude.com/en/articles/14604842-real-time-cyber-safeguards-on-claude-opus-and-sonnet | 活文件（2026-10-06 讀取） | 廠商主張（政策文件） | 是 | 原文核對（2026-10-06） |
| B128 | Anthropic | Pricing | https://platform.claude.com/docs/en/about-claude/pricing | 活文件（2026-10-06 讀取） | 已證實 | 是 | 原文核對（2026-10-06） |
| B129 | Anthropic | Claude Sonnet 5.5（模型頁） | https://platform.claude.com/docs/en/models/sonnet-5-5/overview | 2026-09-28 | 已證實 | 是 | 原文核對（2026-10-06） |
| B130 | DeepSeek | DeepSeek-V4.1-Flash Release（news 與 HF 模型卡） | https://api-docs.deepseek.com/news/news260910 | 2026-09-10 | 廠商主張；China-affiliated | 是 | 原文核對（2026-10-06） |
| B131 | NVIDIA | Nemotron 3 Nano／Super／Ultra 模型卡（Hugging Face） | https://huggingface.co/nvidia/NVIDIA-Nemotron-3-Ultra-550B-A55B-BF16（另見 Nano-30B-A3B-BF16、Super-120B-A12B-BF16） | 2025-12-15／2026-03-11／2026-06-04 | 已證實（授權與日期） | 是 | 原文核對（2026-10-06） |
| B132 | NVIDIA | NVIDIA-AI-Blueprints/vulnerability-analysis | https://github.com/NVIDIA-AI-Blueprints/vulnerability-analysis | v3.0.0 2026-08-19 | 已證實（原始碼）；效能廠商主張 | 是 | 原文核對（2026-10-06） |
| B133 | European Commission | AI Act（Regulatory framework 頁，AI Omnibus） | https://digital-strategy.ec.europa.eu/en/policies/regulatory-framework-ai | 活文件（2026-10-06 讀取） | 已證實（政府頁） | 是 | 原文核對（2026-10-06） |
| B134 | Anthropic | Claude Security is now in public beta（含產品頁） | https://claude.com/blog/claude-security-public-beta | 2026-04-30 | 廠商主張 | 是 | 原文核對（2026-10-06） |
| B135 | GitHub | AI-powered security detections in pull requests（public preview） | https://github.com/orgs/community/discussions/201543 | 2026-07-10 | 廠商主張 | 是 | 原文核對（2026-10-06） |
| B136 | GitHub | Agentic autofix now uses Copilot Memory | https://github.blog/changelog/2026-09-25-agentic-autofix-now-uses-copilot-memory | 2026-09-25 | 廠商主張 | 是 | 原文核對（2026-10-06） |
| B137 | AWS | Amazon Bedrock：Abuse detection（另見 Data protection、Model invocation logging） | https://docs.aws.amazon.com/bedrock/latest/userguide/abuse-detection.html | 活文件（2026-10-07 讀取） | 已證實（雲端供應商文件） | 是 | 原文核對（2026-10-07） |
| B138 | AWS | Amazon Bedrock：Cross-Region inference 與 Global cross-Region inference（另見 Claude Opus 5.5 model card） | https://docs.aws.amazon.com/bedrock/latest/userguide/cross-region-inference.html | 活文件（2026-10-07 讀取） | 已證實（雲端供應商文件） | 是 | 原文核對（2026-10-07） |
| B139 | Google | Gemini API Additional Terms of Service | https://ai.google.dev/gemini-api/terms | 最後修改 2026-04-28 | 已證實（服務條款） | 是 | 原文核對（2026-10-07） |
| B140 | Google | Gemini API：Zero data retention | https://ai.google.dev/gemini-api/docs/zdr | 活文件（2026-10-07 讀取） | 已證實 | 是 | 原文核對（2026-10-07） |
| B141 | Google | Gemini API：Models 與 Release notes（changelog） | https://ai.google.dev/gemini-api/docs/models | 活文件（2026-10-07 讀取） | 已證實 | 是 | 原文核對（2026-10-07） |
| B142 | Google DeepMind | Gemini 3 Pro Frontier Safety Framework Report（另見 Gemini 3.1 Pro model card） | https://storage.googleapis.com/deepmind-media/gemini/gemini_3_pro_fsf_report.pdf | 2025-11／2026-02-19 | 廠商主張 | 是 | 原文核對（2026-10-07） |
| B143 | Z.ai（智譜） | zai-org/GLM-5.3-Flash 模型卡（另見 Hugging Face API 的 zai-org 模型清單） | https://huggingface.co/zai-org/GLM-5.3-Flash | 2026-08-25 | 已證實（授權與日期）；China-affiliated | 是 | 原文核對（2026-10-07） |
| B144 | U.S. Department of Commerce, BIS | Additions to the Entity List（Federal Register 2025-00704） | https://www.federalregister.gov/documents/full_text/text/2025/01/16/2025-00704.txt | 2025-01-16 | 已證實（政府出版物） | 是 | 原文核對（2026-10-07） |
| B145 | Z.ai（智譜） | Privacy Policy | https://docs.z.ai/legal-agreement/privacy-policy | 2025-09-29 | 廠商主張；China-affiliated | 是 | 原文核對（2026-10-07） |
| B146 | NIST CAISI | CAISI's Assessment of Z.ai's GLM-5.3 Cyber Capabilities | https://www.nist.gov/news-events/news/2026/09/caisis-assessment-zais-glm-53-cyber-capabilities | 2026-09-17 | 已證實（只含能力評估） | 是 | 原文核對（2026-10-07） |
| B147 | NIST CAISI | CAISI Assessment of Z.ai's GLM-5.2 | https://www.nist.gov/news-events/news/2026/07/caisi-assessment-zais-glm-52 | 2026-07-17 | 已證實 | 是 | 原文核對（2026-10-07） |
| B148 | Google | Gemini API：Pricing | https://ai.google.dev/gemini-api/docs/pricing | 活文件（2026-10-07 讀取） | 已證實 | 是 | 原文核對（2026-10-07） |
| B149 | AWS | Amazon Bedrock Security and Privacy（產品頁） | https://aws.amazon.com/bedrock/security-compliance/ | 活頁面（2026-10-07 讀取） | 廠商主張 | 是 | 原文核對（2026-10-07） |
| B150 | Google DeepMind | Gemini 3.8 Flash Model Card | https://storage.googleapis.com/deepmind-media/Model-Cards/Gemini-3-8-Flash-Model-Card.pdf | 2026-09 | 廠商主張 | 是 | 原文核對（2026-10-07） |

## C 組：十一面向的標準、工具與事件

| 編號 | 出版者 | 題名 | URL | 日期／版本 | 級別 | 讀取 | 核對狀態 |
|---|---|---|---|---|---|---|---|
| C1.1 | OWASP | ASVS 5.0.0（官方 CSV） | https://github.com/OWASP/ASVS | 2025-05-30（v5.0.0_release） | 已證實 | 是 | 原文核對（2026-10-06） |
| C1.2 | OWASP | ASVS 5.0 V15.2 requirements | 同上 | 2025-05-30 | 已證實 | 是 | 原文核對（2026-10-06） |
| C1.3 | OWASP | SAMM 2.0 | https://owaspsamm.org/model/ | 2020-02-11（本頁無日期，待核實） | 已證實（內容） | 是 | 原文核對（2026-10-06） |
| C1.4 | NIST | SP 800-160 Vol.1 Rev.1 | https://csrc.nist.gov/pubs/sp/800/160/v1/r1/final | 2022-11 | 已證實 | 是 | 原文核對（2026-10-06） |
| C1.5 | Threat Modeling Manifesto | 同名（五個價值） | https://www.threatmodelingmanifesto.org/ | 2020（頁面無日期，待核實） | 已證實 | 是 | 原文核對（2026-10-06） |
| C1.6 | OWASP | Threat Dragon v2.6.2 | https://github.com/OWASP/threat-dragon | 2026-05-10 | 已證實 | 是 | 原文核對（2026-10-06） |
| C1.10 | Simon Brown | C4 model | https://c4model.com/ | 活頁面 | 已證實（活頁面，無日期） | 是 | 原文核對（2026-10-06） |
| C2.1 | OWASP | OWASP Top 10:2025（官方 repo） | https://top10.owasp.org/2025/（官方 repo：github.com/OWASP/Top10） | 2025-11（正式版） | 已證實 | 是 | 原文核對（2026-10-06） |
| C2.3 | OWASP | A03:2025 Software Supply Chain Failures（對應 6 個 CWE） | 同上 | — | 已證實 | 是 | 原文核對（2026-10-06） |
| C2.4 | OWASP | A10:2025 Mishandling of Exceptional Conditions | 同上 | — | 已證實 | 是 | 原文核對（2026-10-06） |
| C2.5 | CISA | 2025 CWE Top 25 alert（資料窗與排名見 C2.9） | https://www.cisa.gov/news-events/alerts/2025/12/11/2025-cwe-top-25-most-dangerous-software-weaknesses | 2025-12-11 | 已證實（發布日期） | 是 | 原文核對（2026-10-06） |
| C2.7 | NIST | NIST Updates NVD Operations to Address Record CVE Growth | https://www.nist.gov/news-events/news/2026/04/nist-updates-nvd-operations-address-record-cve-growth | 2026-04-15（2026-04-17 更新） | 已證實（措辭為「優先」，其餘列最低優先） | 是 | 原文核對（2026-10-06） |
| C2.8 | CISA | BOD 26-04 Prioritizing Security Updates Based on Risk | https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk | 2026-06-10 | 已證實（同時撤銷 BOD 19-02） | 是 | 原文核對（2026-10-06） |
| C2.9 | MITRE | 2025 CWE Top 25 Methodology | https://cwe.mitre.org/top25/archive/2025/2025_methodology.html | 2025-12 | 已證實 | 是 | 原文核對（2026-10-06） |
| C3.1 | OWASP | XSS Prevention Cheat Sheet | https://github.com/OWASP/CheatSheetSeries | 活文件（最後 commit 2026-10-04） | 已證實 | 是 | 原文核對（2026-10-06） |
| C3.2 | OWASP | DOM based XSS Prevention Cheat Sheet | 同上 | 活文件 | 已證實 | 是 | 原文核對（2026-10-06） |
| C3.3 | W3C | Trusted Types WD | https://www.w3.org/TR/2026/WD-trusted-types-20260623/ | 2026-06-23 | 已證實 | 是 | 原文核對（2026-10-06） |
| C3.7 | CISA KEV（JSON）／GitHub Advisory | CVE-2025-48700 Zimbra XSS | https://www.cisa.gov/known-exploited-vulnerabilities-catalog | KEV 收錄 2026-04-20 | 已證實 | 是 | 原文核對（2026-10-06） |
| C4.1 | W3C | CSP Level 3（WD） | https://www.w3.org/TR/CSP3/ | WD 2026-09-16 | 已證實（仍為 WD） | 是 | 原文核對（2026-10-06） |
| C4.2 | W3C | CSP Level 2（REC） | https://www.w3.org/TR/CSP2/ | REC 2016-12-15 | 已證實 | 是 | 原文核對（2026-10-06） |
| C4.4 | OWASP | CSP Cheat Sheet | https://github.com/OWASP/CheatSheetSeries | 活文件 | 已證實（unsafe-inline／unsafe-eval 的警告句現行版找不到，已刪） | 是 | 原文核對（2026-10-06） |
| C4.5 | Weichselbaum, Spagnuolo, Lekies, Janc | CSP Is Dead, Long Live CSP!（ACM CCS 2016） | https://research.google/pubs/csp-is-dead-long-live-csp-on-the-insecurity-of-whitelists-and-the-future-of-content-security-policy/ | 2016-10-24 | 第三方評論（同儕審查） | 是（摘要頁） | 原文核對（2026-10-06） |
| C4.6 | Google | csp-evaluator | https://github.com/google/csp-evaluator | 活專案 | 已證實 | 是 | 原文核對（2026-10-06） |
| C5.1 | OWASP | ASVS 5.0 V6–V10 | https://github.com/OWASP/ASVS | 2025-05 | 已證實 | 是 | 原文核對（2026-10-06） |
| C5.2 | NIST | SP 800-63-4 | https://csrc.nist.gov/pubs/sp/800/63/4/final | 2025-07 | 已證實（日期與取代關係；passkeys 細節在 63B，未讀） | 是 | 原文核對（2026-10-06） |
| C5.3 | IETF | draft-ietf-oauth-v2-1-16 | https://datatracker.ietf.org/doc/draft-ietf-oauth-v2-1/ | 2026-09-03（到期 2027-03-07） | 已證實（仍為 Internet-Draft） | 是 | 原文核對（2026-10-06） |
| C5.4 | W3C | WebAuthn Level 3（REC） | https://www.w3.org/TR/webauthn-3/ | 2026-08-25 | 已證實 | 是 | 原文核對（2026-10-06） |
| C5.5 | OWASP | Authorization Cheat Sheet | https://github.com/OWASP/CheatSheetSeries | 活文件 | 已證實 | 是 | 原文核對（2026-10-06） |
| C5.7 | OWASP | API Security Top 10 2023 | https://github.com/OWASP/API-Security | 2023 | 已證實 | 是 | 原文核對（2026-10-06） |
| C6.1 | OWASP | Dependency-Check v13.0.0 | https://github.com/dependency-check/DependencyCheck | 2026-08-03 | 已證實 | 是 | 原文核對（2026-10-06） |
| C6.2 | Google / OpenSSF | OSV.dev、OSV Schema | https://ossf.github.io/osv-schema/ | Schema 1.9.1（活文件） | 已證實 | 是 | 原文核對（2026-10-06） |
| C6.3 | Google | OSV-Scanner v2.0.0 | https://github.com/google/osv-scanner | 2025-03-17；最新 v2.6.0 2026-09-14 | 已證實 | 是 | 原文核對（2026-10-06） |
| C6.6 | Anchore | Grype（引用時為 v0.118.0，最新 v0.120.0） | https://github.com/anchore/grype | v0.118.0 2026-08-27；v0.120.0 2026-10-02 | 已證實 | 是 | 原文核對（2026-10-06） |
| C6.7 | FIRST | EPSS（How it works；現行 v5） | https://www.first.org/epss/how-it-works | v4 2025-03-17；v5 2026-06-15 | 已證實 | 是 | 原文核對（2026-10-06） |
| C6.8 | FIRST | CVSS v4.0 Specification | https://www.first.org/cvss/v4.0/specification-document | 2023-11-01（文件 v1.2，2024-06-18 勘誤） | 已證實 | 是 | 原文核對（2026-10-06） |
| C6.9 | CISA | SSVC | https://www.cisa.gov/stakeholder-specific-vulnerability-categorization-ssvc | — | 已證實 | 是 | 原文核對（2026-10-06） |
| C6.10 | Spracklen et al. | We Have a Package for You!（USENIX Security 2025） | https://www.usenix.org/publications/loginonline/we-have-package-you-comprehensive-analysis-package-hallucinations-code | 2025 | 第三方評論（同儕審查） | 是（arXiv HTML 與 USENIX 摘要頁） | 原文核對（2026-10-06） |
| C6.11 | NVD／GitHub Advisory | CVE-2024-3094 | https://github.com/advisories/GHSA-rxwq-x6h5-x525（NVD 頁未能讀取） | 2024-03-29 | 已證實（經 GHSA） | 是 | 原文核對（2026-10-06） |
| C6.12 | Sansec | polyfill.io supply chain attack | https://sansec.io/research/polyfill-supply-chain-attack | 2024-06-25 | 廠商主張 | 是 | 原文核對（2026-10-06） |
| C6.13 | CISA | Widespread Supply Chain Compromise Impacting npm Ecosystem | https://www.cisa.gov/news-events/alerts/2025/09/23/widespread-supply-chain-compromise-impacting-npm-ecosystem | 2025-09-23 | 已證實（未提到 TruffleHog 與 metadata 端點） | 是 | 原文核對（2026-10-06） |
| C6.14 | Semgrep 等 | chalk / debug npm compromise | https://semgrep.dev/blog/2025/chalk-debug-and-color-on-npm-compromised-in-new-supply-chain-attack/ | 2025-09-08 | 廠商主張 | 是 | 原文核對（2026-10-06） |
| C6.15 | Palo Alto Networks Unit 42 | "Shai-Hulud" Worm Compromises npm Ecosystem | https://unit42.paloaltonetworks.com/npm-supply-chain-attack/ | 2025-09-17 | 第三方評論 | 是 | 原文核對（2026-10-06） |
| C7.1 | GitHub | Security hardening for GitHub Actions | https://docs.github.com/en/actions/reference/security/secure-use | 活文件 | 已證實（URL 已轉址） | 是 | 原文核對（2026-10-06） |
| C7.4 | GitHub Security Lab | Preventing pwn requests | https://securitylab.github.com/resources/github-actions-preventing-pwn-requests/ | 2021-08-03 | 已證實 | 是 | 原文核對（2026-10-06） |
| C7.5 | GitHub Security Lab | Untrusted input | https://securitylab.github.com/resources/github-actions-untrusted-input/ | 2021-08-04 | 已證實 | 是 | 原文核對（2026-10-06） |
| C7.8 | GitHub | Actions policy now supports blocking and SHA pinning actions | https://github.blog/changelog/2025-08-15-github-actions-policy-now-supports-blocking-and-sha-pinning-actions/ | 2025-08-15 | 已證實 | 是 | 原文核對（2026-10-06） |
| C7.9 | zizmorcore | zizmor | https://github.com/zizmorcore/zizmor | v1.30.1 2026-09-09 | 已證實 | 是 | 原文核對（2026-10-06） |
| C7.10 | rhysd | actionlint v1.7.12 | https://github.com/rhysd/actionlint | 2026-03-30 | 已證實 | 是 | 原文核對（2026-10-06） |
| C7.11 | BoostSecurity | poutine | https://github.com/boostsecurityio/poutine | v1.1.6 2026-05-22 | 已證實 | 是 | 原文核對（2026-10-06） |
| C7.12 | StepSecurity | Harden-Runner（引用時 v2.21.0，最新 v2.22.0） | https://github.com/step-security/harden-runner | v2.22.0 2026-10-06 | 廠商主張 | 是 | 原文核對（2026-10-06） |
| C7.13 | OpenSSF | Scorecard v5.5.0 | https://github.com/ossf/scorecard | 2026-04-23 | 已證實 | 是 | 原文核對（2026-10-06） |
| C7.14 | GitHub Advisory Database | GHSA-mrrh-fwg8-r2c3 / CVE-2025-30066 tj-actions/changed-files | https://github.com/advisories/GHSA-mrrh-fwg8-r2c3 | 2025-03-15 | 已證實 | 是 | 原文核對（2026-10-06） |
| C7.15 | CISA | Supply Chain Compromise of tj-actions/changed-files and reviewdog/action-setup | https://www.cisa.gov/news-events/alerts/2025/03/18/supply-chain-compromise-third-party-tj-actionschanged-files-cve-2025-30066-and-reviewdogaction | 2025-03-18 | 已證實（CISA 措辭為「可能」） | 是 | 原文核對（2026-10-06） |
| C7.16 | Nx maintainers | s1ngularity postmortem | https://nx.dev/blog/s1ngularity-postmortem | 2025-08-26 事件 | 已證實（一手 post-mortem） | 是 | 原文核對（2026-10-06） |
| C7.17 | Socket / HiddenLayer | Ultralytics PyPI compromise via Actions cache poisoning | https://socket.dev/blog/ultralytics-pypi-package-compromised-through-github-actions-cache-poisoning | 事件 2024-12-04；文章 2024-12-10 | 廠商主張 | 是 | 原文核對（2026-10-06） |
| C7.18 | Nx maintainers | GHSA-cxm3-wv7p-598c（s1ngularity advisory） | https://github.com/nrwl/nx/security/advisories/GHSA-cxm3-wv7p-598c | 2025-08-27 | 已證實 | 是 | 原文核對（2026-10-06） |
| C8.1 | GitHub | About push protection | https://docs.github.com/en/code-security/secret-scanning/introduction/about-push-protection | 活文件 | 已證實 | 是 | 原文核對（2026-10-06） |
| C8.2 | gitleaks | gitleaks v8.30.1 | https://github.com/gitleaks/gitleaks | 2026-03-21 | 已證實 | 是 | 原文核對（2026-10-06） |
| C8.3 | Truffle Security | TruffleHog | https://github.com/trufflesecurity/trufflehog | 活專案（v3.98.0 2026-10-05） | 已證實 | 是 | 原文核對（2026-10-06） |
| C8.4 | Yelp | detect-secrets | https://github.com/Yelp/detect-secrets | v1.5.0 2024-05-06 | 已證實 | 是 | 原文核對（2026-10-06） |
| C8.5 | OWASP | Secrets Management Cheat Sheet | https://github.com/OWASP/CheatSheetSeries | 活文件 | 已證實 | 是 | 原文核對（2026-10-06） |
| C8.7 | GitGuardian | State of Secrets Sprawl 2026 | https://www.gitguardian.com/state-of-secrets-sprawl-report-2026 | 2026-03 | 廠商主張 | 是 | 原文核對（2026-10-06） |
| C8.8 | Microsoft MSRC | Microsoft mitigated exposure of internal information in a storage account due to overly permissive SAS token | https://www.microsoft.com/en-us/msrc/blog/2023/09/microsoft-mitigated-exposure-of-internal-information-in-a-storage-account-due-to-overly-permissive-sas-token | 2023-09 | 已證實（只支持「權限過大的 SAS token」；細節見 C8.9） | 是 | 原文核對（2026-10-06） |
| C8.9 | Wiz Research | 38TB of data accidentally exposed by Microsoft AI researchers | https://www.wiz.io/blog/38-terabytes-of-private-data-accidentally-exposed-by-microsoft-ai-researchers | 2023-09-18 | 第三方評論 | 是 | 原文核對（2026-10-06） |
| C9.1 | OWASP | Input Validation Cheat Sheet | https://github.com/OWASP/CheatSheetSeries | 活文件（2026-10-03 大幅改寫） | 已證實 | 是 | 原文核對（2026-10-06） |
| C9.3 | OWASP | ASVS 5.0 V1.2 / V2.2 | https://github.com/OWASP/ASVS | 2025-05 | 已證實 | 是 | 原文核對（2026-10-06） |
| C9.6 | OWASP GenAI | LLM01:2025 Prompt Injection | https://genai.owasp.org/llmrisk/llm01-prompt-injection/ | 2024-11-14（PDF 檔名） | 已證實 | 是 | 原文核對（2026-10-06） |
| C10.1 | OWASP | Error Handling Cheat Sheet | https://github.com/OWASP/CheatSheetSeries | 活文件 | 已證實 | 是 | 原文核對（2026-10-06） |
| C10.2 | OWASP | Logging Cheat Sheet / Logging Vocabulary | 同上 | 活文件 | 已證實 | 是 | 原文核對（2026-10-06） |
| C10.3 | OWASP | ASVS 5.0 V16 | https://github.com/OWASP/ASVS | 2025-05 | 已證實 | 是 | 原文核對（2026-10-06） |
| C10.5 | OWASP | A09:2025 / A10:2025 | https://github.com/OWASP/Top10 | — | 已證實 | 是 | 原文核對（2026-10-06） |
| C11.1 | OpenSSF | SLSA v1.1（2025-04-21）、v1.2（2025-11-24） | https://slsa.dev/blog/2025/11/announce-slsa-v1.2 | 2025-11-24 | 已證實 | 是 | 原文核對（2026-10-06） |
| C11.2 | OWASP / Ecma | CycloneDX 1.6 = ECMA-424 1st ed.；1.7 = 2nd ed. | https://ecma-international.org/publications-and-standards/standards/ecma-424/ | 2024-06；2025-12（1.7.2 2026-09-17） | 已證實 | 是 | 原文核對（2026-10-06） |
| C11.3 | Linux Foundation / ISO | SPDX 3.0；ISO/IEC 5962:2021；DIS 5962 | https://www.iso.org/standard/93810.html | 2024-04-16 | 待原文核實 | 摘要 | 待核實（僅摘要） |
| C11.4 | Sigstore | cosign 3.0 available | https://blog.sigstore.dev/cosign-3-0-available/ | 2025-10-08（最新 v3.1.3） | 已證實（未提到 NGC） | 是 | 原文核對（2026-10-06） |
| C11.5 | in-toto | Attestation Framework v1 | https://github.com/in-toto/attestation | v1.2.0 2026-03-18 | 已證實 | 是 | 原文核對（2026-10-06） |
| C11.6 | NIST | SP 800-204D | https://csrc.nist.gov/pubs/sp/800/204/d/final | 2024-02 | 已證實 | 是 | 原文核對（2026-10-06） |
| C11.7 | NIST | SP 800-218 SSDF v1.1 | https://csrc.nist.gov/projects/ssdf | 2022-02 | 已證實（v1.1 仍為最新定稿；v1.2 草案見 C11.16） | 是 | 原文核對（2026-10-06） |
| C11.8 | CISA | Secure by Design；Pledge | https://www.cisa.gov/resources-tools/resources/secure-by-design | 2023-04（修訂 2023-10-25）；Pledge 日期待核實 | 已證實（三原則） | 是 | 原文核對（2026-10-06） |
| C11.9 | European Union | Regulation (EU) 2024/2847（CRA） | https://eur-lex.europa.eu/eli/reg/2024/2847/oj | 2024 | 已證實（適用日期，經 Commission 頁）；Annex I 待原文核實 | 部分（Commission 與 ENISA 頁；EUR-Lex 未讀） | 交叉核對（2026-10-06；EUR-Lex 原文未讀，改讀 Commission 與 ENISA 頁） |
| C11.10 | OpenSSF | S2C2F v1.1 | https://github.com/ossf/s2c2f/blob/main/specification/framework.md | 2022-10-19 | 已證實 | 是 | 原文核對（2026-10-06） |
| C11.11 | CISA | ED 21-01（closed）；AA20-352A | https://www.cisa.gov/news-events/directives/ed-21-01-mitigate-solarwinds-orion-code-compromise-closed | 2020-12-13；2026-01-08 結案 | 已證實（ED 頁沒有 18,000，見 C11.14） | 是 | 原文核對（2026-10-06） |
| C11.12 | Codecov | April 2021 post-mortem | https://about.codecov.io/apr-2021-post-mortem/ | 2021-04（2021-04-01 偵測） | 已證實 | 是 | 原文核對（2026-10-06） |
| C11.13 | Mandiant (Google Cloud) | 3CX Software Supply Chain Compromise | https://cloud.google.com/blog/topics/threat-intelligence/3cx-software-supply-chain-compromise | 2023-04-20 | 廠商主張 | 是 | 原文核對（2026-10-06） |
| C11.14 | SolarWinds（SEC） | Form 8-K（2020-12-14） | https://www.sec.gov/Archives/edgar/data/1739942/000162828020017451/swi-20201214.htm | 2020-12-14 | 已證實 | 是 | 原文核對（2026-10-06） |
| C11.15 | ENISA | The CRA Single Reporting Platform is launched | https://www.enisa.europa.eu/news/the-cra-single-reporting-platform-is-launched | 2026-09-11 | 已證實 | 是 | 原文核對（2026-10-06） |
| C11.16 | NIST | SP 800-218 Rev. 1 ipd（SSDF v1.2 初始公開草案） | https://csrc.nist.gov/pubs/sp/800/218/r1/ipd | 2025-12-17（徵詢至 2026-01-30） | 已證實 | 是 | 原文核對（2026-10-06） |
| C12.1 | FIRST | CVSS v4.0 calculator & spec | https://www.first.org/cvss/calculator/4.0 | 2023-11-01 | 已證實（規格） | 是（規格文件；計算器原始碼另見 FIRSTdotorg/cvss-v4-calculator） | 原文核對（2026-10-06） |
| C12.2 | OWASP | Risk Rating Methodology | https://community.owasp.org/OWASP_Risk_Rating_Methodology | 活文件 | 已證實（URL 已轉址） | 是 | 原文核對（2026-10-06） |
| C12.6 | 實務來源 | DREAD 棄用說法 | — | — | 尚未證實 | — | 待核實（缺逐項核對紀錄） |
| C13.1 | ISO/IEC | ISO/IEC 27001:2022 | https://www.iso.org/standard/27001 | 2022 | 已證實（條文付費牆） | 否 | 待核實（缺逐項核對紀錄） |
| C13.2 | 本報告 | 面向 → Annex A 映射提案 | — | — | 設計提案 | — | 待核實（缺逐項核對紀錄） |
| C13.3 | IEC | IEC 62443-4-1:2018 | https://webstore.ansi.org/preview-pages/iec/preview_iec62443-4-1%7Bed1.0%7Db.pdf | 2018 | 待原文核實（預覽） | 摘要 | 待核實（僅摘要） |
| C13.4 | NIST | CSF 2.0（CSWP 29） | https://doi.org/10.6028/NIST.CSWP.29 | 2024-02-26 | 已證實 | 是 | 原文核對（2026-10-06） |
| C13.5 | SEMI | E187 | https://store-us.semi.org/products/e18700-semi-e187-specification-for-cybersecurity-of-fab-equipment | 日期未驗 | 待原文核實（出版者） | 摘要 | 待核實（僅摘要） |

另：FIRST CVSS v4.0 參考計算器原始碼（BSD-2-Clause）https://github.com/FIRSTdotorg/cvss-v4-calculator 於本次直接讀取並移植，見雛型 `src/mara/scoring/cvss4.py`。
