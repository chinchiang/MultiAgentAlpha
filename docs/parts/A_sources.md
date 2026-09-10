# 附錄A　引用來源清單

編號規則：A 開頭為工具與文獻調查（第二、四、七部主要引用），B 開頭為 LLM 評審偏誤、模型現況與治理框架，C 開頭為十一面向的標準與事件（C 後的第一個數字是面向編號）。「讀取」欄標示本次研究是否直接讀到原頁：是＝直接讀取；摘要＝原頁被出口代理伺服器封鎖，題名、日期與數字來自搜尋引擎摘要。日期無法驗證者列於附錄B。

## A 組：工具、產品與文獻

| 編號 | 出版者 | 題名 | URL | 日期 | 級別 | 讀取 |
|---|---|---|---|---|---|---|
| A1 | Anthropic | anthropics/claude-code-security-review（GitHub Action） | https://github.com/anthropics/claude-code-security-review | 無 release 標籤；公告 2025-08-06 | 廠商主張（原始碼可查） | 是 |
| A2 | Anthropic | `/security-review` 命令定義檔 | https://github.com/anthropics/claude-code-security-review/blob/main/.claude/commands/security-review.md | 同上 | 已證實（檔案存在） | 是 |
| A3 | VentureBeat | Anthropic ships automated security reviews for Claude Code | https://venturebeat.com/ai/anthropic-ships-automated-security-reviews-for-claude-code-as-ai-generated-vulnerabilities-surge | 2025-08-06 | 第三方評論 | 摘要 |
| A6 | VentureBeat | Claude Code Security 找到 500+ 漏洞 | https://venturebeat.com/security/anthropic-claude-code-security-reasoning-vulnerability-hunting | 2026-02 | 第三方評論 | 摘要 |
| A7 | Axios | Anthropic 新模型擅長找安全缺陷 | https://axios.com/2026/02/05/anthropic-claude-opus-46-software-hunting | 2026-02-05 | 第三方評論 | 摘要 |
| A11 | CybersecurityNews | Claude Code 改用 auto mode 分類器 | https://cybersecuritynews.com/claude-code-shifts-agent-security/ | 日期不可驗證 | 尚未證實（單一二手） | 摘要 |
| A12 | OpenAI | Introducing Aardvark | https://openai.com/index/introducing-aardvark/ | 2025-10-30 | 廠商主張 | 摘要 |
| A15 | OpenAI | Codex Security now in research preview | https://openai.com/index/codex-security-now-in-research-preview/ | 2026-03-06 | 廠商主張 | 摘要 |
| A17 | The Hacker News | Codex Security 掃描 120 萬 commits | https://thehackernews.com/2026/03/openai-codex-security-scanned-12.html | 2026-03 | 第三方評論 | 摘要 |
| A18 | Google DeepMind | Introducing CodeMender | https://deepmind.google/blog/introducing-codemender-an-ai-agent-for-code-security/ | 2025-10（確切日不可驗證） | 廠商主張 | 摘要 |
| A22 | Wiz / The Hacker News | Big Sleep 與 CVE-2025-6965 | https://www.wiz.io/vulnerability-database/cve/cve-2025-6965 | 2025-07-15 | CVE 已證實；報導第三方評論 | 摘要 |
| A25 | GitHub | Responsible use of Copilot Autofix for code scanning | https://docs.github.com/en/code-security/responsible-use/responsible-use-autofix-code-scanning | 日期不可驗證（活文件） | 已證實 | 摘要 |
| A26 | GitHub | Copilot Autofix for CodeQL code scanning alerts is now generally available | https://github.blog/changelog/2024-08-14-copilot-autofix-for-codeql-code-scanning-alerts-is-now-generally-available/ | 2024-08-14 | 廠商主張 | 摘要 |
| A31 | GitHub | Security reviews now available in the GitHub Copilot app | https://github.blog/changelog/2026-07-14-security-reviews-now-available-in-the-github-copilot-app/ | 2026-07-14 | 廠商主張 | 摘要 |
| A37 | Semgrep | Building an AppSec AI that security researchers agree with 96% of the time | https://semgrep.dev/blog/2025/building-an-appsec-ai-that-security-researchers-agree-with-96-of-the-time/ | 2025 | 廠商主張 | 摘要 |
| A38 | Semgrep | Semgrep is confidently handling 60% of all triage | https://semgrep.dev/blog/2025/semgrep-is-confidently-handling-60-of-all-triage-for-users-without-reducing-coverage/ | 2025 | 廠商主張 | 摘要 |
| A40 | Semgrep | Semgrep Assistant overview（docs） | https://semgrep.dev/docs/semgrep-assistant/overview | 活文件 | 已證實 | 摘要 |
| A41 | Semgrep | semgrep/mcp | https://github.com/semgrep/mcp | 約 2025-03 | 已證實 | 是 |
| A43 | Snyk | DeepCode AI 平台頁 | https://snyk.io/platform/deepcode-ai/ | 日期不可驗證 | 廠商主張 | 摘要 |
| A44 | Snyk | DCAIF under the hood | https://snyk.io/articles/snyk-dcaif-under-the-hood/ | 日期不可驗證 | 廠商主張 | 摘要 |
| A45 | Snyk | Secure adoption in the GenAI era | https://snyk.io/reports/secure-adoption-in-the-genai-era/ | 日期不可驗證 | 廠商主張 | 摘要 |
| A54 | Joshua Rogers | Hacking with AI SASTs | https://joshua.hu/llm-engineer-review-sast-security-ai-tools-pentesters | 2025-09-18 | 第三方評論 | 摘要 |
| A56 | Endor Labs / PR Newswire | Endor Labs Debuts AI-Native Multi-Modal SAST | https://www.prnewswire.com/news-releases/endor-labs-debuts-ai-native-multi-modal-sast-marking-a-new-era-in-code-flaw-detection-302619629.html | 2025-11-19 | 廠商主張 | 摘要 |
| A57 | Endor Labs | AI Code Security Review（docs） | https://docs.endorlabs.com/secure-ai-coding/ai-security-review | 活文件 | 已證實（文件）/ 廠商主張（效能） | 摘要 |
| A61 | Infosecurity Magazine | 惡意 npm 套件操弄 AI 偵測 | https://www.infosecurity-magazine.com/news/malware-ai-detection-npm-package/ | 日期不可驗證 | 第三方評論 | 摘要 |
| A62 | Datadog | Using LLMs to filter out false positives from static code analysis | https://www.datadoghq.com/blog/using-llms-to-filter-out-false-positives/ | 2025-10-28 | 廠商主張 | 摘要 |
| A63 | Datadog | AI-Enhanced Static Code Analysis（docs） | https://docs.datadoghq.com/security/code_security/static_analysis/ai_enhanced_sast/ | 活文件 | 已證實 | 摘要 |
| A67 | 二手部落格彙整 | Nemotron 3 家族規格與授權 | https://www.digitalapplied.com/blog/nvidia-nemotron-3-ultra-550b-open-reasoning-model-2026 | 2026 | 尚未證實 | 摘要 |
| A68 | NVIDIA | NVIDIA/NeMo-Agent-Toolkit | https://github.com/NVIDIA/NeMo-Agent-Toolkit | v1.5.0 | 已證實 | 是 |
| A70 | NVIDIA | Applying Generative AI for CVE Analysis at an Enterprise Scale | https://developer.nvidia.com/blog/applying-generative-ai-for-cve-analysis-at-an-enterprise-scale/ | 日期不可驗證 | 廠商主張 | 摘要 |
| A72 | NVIDIA | Vulnerability Analysis for Container Security Blueprint | https://build.nvidia.com/nvidia/vulnerability-analysis-for-container-security | 日期不可驗證 | 尚未證實 | 摘要 |
| A75 | DeepSeek | deepseek-ai/DeepSeek-V3.2 | https://github.com/deepseek-ai/DeepSeek-V3.2 | 頁面 2025-11-17 與業界 2025-09-29 矛盾 | 授權已證實；日期尚未證實；China-affiliated | 是 |
| A77 | DeepSeek | DeepSeek V4 Preview Release | https://api-docs.deepseek.com/news/news260424/ | 2026-04-24 | 廠商主張；China-affiliated | 摘要 |
| A78 | DeepSeek | deepseek-ai/DeepSeek-V4-Pro（Hugging Face） | https://huggingface.co/deepseek-ai/DeepSeek-V4-Pro | 2026 | 尚未證實；China-affiliated | 摘要 |
| A80 | Australian Government Department of Home Affairs | PSPF Direction — DeepSeek products, applications and web services | https://www.protectivesecurity.gov.au/news/pspf-direction-update-deepseek-products-applications-and-web-services | 2025-02-04 | 已證實 | 摘要 |
| A82 | U.S. Congress | S.765 / H.R.1121 No DeepSeek on Government Devices Act | https://www.congress.gov/bill/119th-congress/senate-bill/765 | 119th Congress，2025 | 已證實（已提出未通過） | 摘要 |
| A83 | U.S. Congress | S.2177 / H.R.4142 No Adversarial AI Act | https://www.congress.gov/bill/119th-congress/senate-bill/2177/text | 2025 | 已證實（已提出未通過） | 摘要 |
| A85 | Li et al. | IRIS: LLM-Assisted Static Analysis for Detecting Security Vulnerabilities（ICLR 2025） | https://arxiv.org/abs/2405.17238 | 2024-05-27；ICLR 2025 | 已證實 | 摘要 |
| A86 | Guo et al. | RepoAudit: An Autonomous LLM-Agent for Repository-Level Code Auditing | https://arxiv.org/abs/2501.18160 | 2025-01-30 | 第三方評論（preprint） | 摘要 |
| A87 | Wang, Li et al. | VulAgent: Hypothesis-Validation based Multi-Agent Vulnerability Detection | https://arxiv.org/abs/2509.11523 | 2025-09-15 | 第三方評論（preprint） | 摘要 |
| A89 | — | Multi-role Consensus through LLMs Discussions for Vulnerability Detection | https://arxiv.org/abs/2403.14274 | 2024-03 | 第三方評論（preprint） | 摘要 |
| A93 | Sun, Wu et al. | GPTScan（ICSE 2024） | https://dl.acm.org/doi/10.1145/3597503.3639117 | 2024 | 已證實 | 摘要 |
| A94 | — | AgenticSCR | https://arxiv.org/html/2601.19138v1 | 2026-01 | 第三方評論（preprint，需覆核） | 摘要 |
| A102 | — | Vul-RAG（ACM TOSEM） | https://arxiv.org/abs/2406.11147 ; https://dl.acm.org/doi/10.1145/3797277 | 2024-06；TOSEM | 已證實 | 摘要 |
| A105 | — | QLCoder: A Query Synthesizer For Static Analysis of Security Vulnerabilities | https://arxiv.org/abs/2511.08462 | 2025-11 | 第三方評論（preprint） | 摘要 |
| A115 | Ding et al. | Vulnerability Detection with Code Language Models: How Far Are We?（PrimeVul，ICSE 2025） | https://arxiv.org/abs/2403.18624 | 2024-03；ICSE 2025 | 已證實 | 摘要 |
| A116 | Ullah et al. | LLMs Cannot Reliably Identify and Reason About Security Vulnerabilities (Yet?)（SecLLMHolmes，IEEE S&P 2024） | https://arxiv.org/abs/2312.12575 | 2023-12；S&P 2024 | 已證實 | 摘要 |
| A122 | Zhu et al. (UIUC) | CVE-Bench（ICML 2025 spotlight） | https://arxiv.org/abs/2503.17332 | 2025-03；ICML 2025 | 已證實 | 摘要 |
| A123 | Wang et al. (UC Berkeley) | CyberGym | https://arxiv.org/abs/2506.02548 | 2025-06 | 第三方評論（preprint） | 摘要 |
| A124 | — | SEC-bench（NeurIPS 2025） | https://arxiv.org/abs/2506.11791 | 2025-06；NeurIPS 2025 | 已證實 | 摘要 |
| A128 | — | RealVuln | https://arxiv.org/abs/2604.13764 | 2026-04 | 第三方評論（preprint，需覆核） | 摘要 |
| A132 | Perry, Srivastava, Kumar, Boneh | Do Users Write More Insecure Code with AI Assistants?（ACM CCS 2023） | https://dl.acm.org/doi/10.1145/3576915.3623157 | 2023-11 | 已證實 | 摘要 |
| A133 | CSET Georgetown | Cybersecurity Risks of AI-Generated Code | https://cset.georgetown.edu/publication/cybersecurity-risks-of-ai-generated-code/ | 2024-11 | 已證實 | 摘要 |
| A134 | Veracode | 2025 GenAI Code Security Report | https://www.veracode.com/resources/analyst-reports/2025-genai-code-security-report/ | 2025-07/08 | 廠商主張 | 摘要 |
| A135 | Veracode / BusinessWire | 2026 GenAI Code Security Report | https://www.veracode.com/resources/analyst-reports/2026-genai-code-security-report/ | 2026-07-28 | 廠商主張 | 摘要 |
| A136 | Deng et al. | Understanding the (In)Security of Vibe-Coded Applications | https://arxiv.org/abs/2606.23130 | 2026-06 | 第三方評論（preprint，需覆核） | 摘要 |
| A137 | GitClear | AI Copilot Code Quality: 2025 Data Suggests 4x Growth in Code Clones | https://www.gitclear.com/ai_assistant_code_quality_2025_research | 2025-02 | 廠商主張 | 摘要 |
| A140 | Apiiro | 4x Velocity, 10x Vulnerabilities | https://apiiro.com/blog/4x-velocity-10x-vulnerabilities-ai-coding-assistants-are-shipping-more-risks/ | 2025-09-04 | 廠商主張 | 摘要 |
| A142 | OASIS | SARIF Version 2.1.0 OASIS Standard | https://www.oasis-open.org/standard/sarif-v2-1-0/ | 2020-03-27 通過；2020-04-08 公告 | 已證實 | 摘要 |
| A144 | GitHub | SARIF support for code scanning | https://docs.github.com/en/code-security/code-scanning/integrating-with-code-scanning/sarif-support-for-code-scanning | 活文件 | 已證實 | 摘要 |
| A145 | Veracode | Spring 2026 GenAI Code Security Update | https://www.veracode.com/blog/spring-2026-genai-code-security/ | 2026 | 廠商主張 | 摘要 |

## B 組：LLM 評審偏誤、共識方法、模型現況、治理框架

| 編號 | 出版者 | 題名 | URL | 日期 | 級別 | 讀取 |
|---|---|---|---|---|---|---|
| B1 | Panickssery, Bowman, Feng | LLM Evaluators Recognize and Favor Their Own Generations（NeurIPS 2024） | https://arxiv.org/abs/2404.13076 | 2024-04-15 | 已證實 | 摘要 |
| B2 | Wataoka, Takahashi, Ri | Self-Preference Bias in LLM-as-a-Judge | https://arxiv.org/abs/2410.21819 | 2024-10-29 | 第三方評論（preprint） | 摘要 |
| B7 | Zheng et al. | Judging LLM-as-a-Judge with MT-Bench and Chatbot Arena（NeurIPS 2023 D&B） | https://arxiv.org/abs/2306.05685 | 2023-06-09 | 已證實 | 摘要 |
| B8 | Ye et al. | Justice or Prejudice? Quantifying Biases in LLM-as-a-Judge（CALM，ICLR 2025） | https://arxiv.org/abs/2410.02736 | 2024-10-03 | 已證實 | 摘要 |
| B9 | Shi et al. | Judging the Judges: A Systematic Study of Position Bias | https://arxiv.org/abs/2406.07791 | 2024-06-12 | 第三方評論（preprint） | 摘要 |
| B12 | — | LLMs-as-Judges: A Comprehensive Survey | https://arxiv.org/abs/2412.05579 | 2024-12-07 | 第三方評論（preprint） | 摘要 |
| B13 | — | Anchoring Bias in LLM-as-a-Judge Systems | https://arxiv.org/abs/2608.25869 | 2026-08 | 第三方評論（preprint） | 摘要 |
| B14 | Zhao, Esmaeili, Fard (UBC) | Bias in the Loop: Auditing LLM-as-a-Judge for Software Engineering | https://arxiv.org/abs/2604.16790 | 2026-04-18 | 第三方評論（preprint） | 摘要 |
| B15 | — | Evaluating Scoring Bias in LLM-as-a-Judge | https://arxiv.org/abs/2506.22316 | 2025-06 | 第三方評論（preprint） | 摘要 |
| B16 | — | Evaluating and Mitigating LLM-as-a-judge Bias in Communication Systems | https://arxiv.org/abs/2510.12462 | 2025-10 | 第三方評論（preprint） | 摘要 |
| B17 | Goel et al. | Great Models Think Alike and this Undermines AI Oversight（ICML 2025） | https://arxiv.org/abs/2502.04313 | 2025-02-06 | 已證實 | 摘要 |
| B18 | Kim, Garg, Peng, Garg | Correlated Errors in Large Language Models（ICML 2025，PMLR v267） | https://arxiv.org/abs/2506.07962 | 2025-06-09 | 已證實 | 摘要 |
| B22 | Verga et al. (Cohere) | Replacing Judges with Juries（PoLL） | https://arxiv.org/abs/2404.18796 | 2024-04-29 | 第三方評論（preprint） | 摘要 |
| B26 | — | Stop Overvaluing Multi-Agent Debate | https://arxiv.org/abs/2502.08788 | 2025-02-12 | 第三方評論（preprint） | 摘要 |
| B27 | — | When and Why Does Multi-Agent Debate Fail | https://arxiv.org/abs/2510.20963 | 2025-10 | 第三方評論（preprint） | 摘要 |
| B30 | — | Adversarial Review: Structured Disagreement for Grounded Agentic Code Review（MARS） | https://arxiv.org/abs/2608.18167 | 2026-08 | 第三方評論（preprint） | 摘要 |
| B31 | — | Refute-or-Promote | https://arxiv.org/abs/2604.19049 | 2026-04 | 第三方評論（preprint） | 摘要 |
| B34 | Tian et al. | Overconfidence in LLM-as-a-Judge | https://arxiv.org/abs/2508.06225 | 2025-08-08 | 第三方評論（preprint） | 摘要 |
| B37 | — | Sifting the Noise: LLM Agents in Vulnerability False Positive Filtering | https://arxiv.org/abs/2601.22952 | 2026-01 | 第三方評論（preprint） | 摘要 |
| B39 | — | Are Frontier LLMs Ready for Cybersecurity? | https://arxiv.org/abs/2605.23243 | 2026-05 | 第三方評論（preprint） | 摘要 |
| B42 | BleepingComputer | curl ending bug bounty program after flood of AI slop reports | https://www.bleepingcomputer.com/news/security/curl-ending-bug-bounty-program-after-flood-of-ai-slop-reports/ | 2026-02 | 第三方評論 | 摘要 |
| B43 | OWASP GenAI Security Project | OWASP Top 10 for LLM Applications 2025 | https://owasp.org/www-project-top-10-for-large-language-model-applications/assets/PDF/OWASP-Top-10-for-LLMs-v2025.pdf | 2024-11 | 已證實 | 摘要 |
| B45 | OWASP GenAI Security Project | OWASP Top 10 for Agentic Applications 2026 | https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/ | 2025-12-09 | 已證實（僅 ASI01–03 確認） | 摘要 |
| B46 | MITRE | ATLAS | https://atlas.mitre.org/ | v5.1.0，2025-11 | 已證實（框架）；計數第三方評論 | 摘要 |
| B48 | — | Prompt Injection Attacks on Agentic Coding Assistants | https://arxiv.org/abs/2601.17548 | 2026-01 | 第三方評論（preprint） | 摘要 |
| B49 | — | Prompt Injection Attacks on LLM Generated Reviews of Scientific Publications | https://arxiv.org/abs/2509.10248 | 2025-09 | 第三方評論（preprint） | 摘要 |
| B55 | Sharma et al. (Anthropic) | Towards Understanding Sycophancy in Language Models（ICLR 2024） | https://arxiv.org/abs/2310.13548 | 2023-10-20 | 已證實 | 摘要 |
| B58 | Laban et al. | LLMs Get Lost In Multi-Turn Conversation（ICLR 2026） | https://arxiv.org/abs/2505.06120 | 2025-05-09 | 已證實 | 摘要 |
| B60 | Wang et al. | Self-Consistency Improves Chain of Thought Reasoning（ICLR 2023） | https://arxiv.org/abs/2203.11171 | 2022-03-21 | 已證實 | 摘要 |
| B62 | Dawid & Skene | Maximum Likelihood Estimation of Observer Error-Rates Using the EM Algorithm，JRSS-C 28(1) | DOI 10.2307/2346806 | 1979 | 已證實（DOI 本次未驗） | 否 |
| B63 | — | Variance-Aware LLM Annotation for Strategy Research | https://arxiv.org/abs/2601.02370 | 2026-01 | 第三方評論（preprint） | 摘要 |
| B64 | — | Empirical Study on the Characteristics and Evolution of AI-usage in GitHub Repositories | https://arxiv.org/abs/2606.06843 | 2026-06 | 第三方評論（preprint） | 摘要 |
| B68 | — | Automated Malware Family Classification using Weighted Hierarchical Ensembles of LLMs | https://arxiv.org/abs/2604.02490 | 2026-04 | 第三方評論（preprint） | 摘要 |
| B70 | — | The Alternative Annotator Test for LLM-as-a-Judge | https://arxiv.org/abs/2501.10970 | 2025-01 | 第三方評論（preprint） | 摘要 |
| B72 | PMC | K-Alpha Calculator — Krippendorff's Alpha | https://www.ncbi.nlm.nih.gov/pmc/articles/PMC11636850/ | 2024 | 已證實 | 摘要 |
| B79 | Anthropic | Claude models overview | https://platform.claude.com/docs/en/about-claude/models/overview | 2026-09-08 讀取 | 已證實 | 是 |
| B80 | Anthropic | Claude Opus 5 model page | https://platform.claude.com/docs/en/models/opus-5/overview | 發布 2026-07-24 | 已證實 | 是 |
| B81 | Anthropic | API and data retention | https://platform.claude.com/docs/en/manage-claude/api-and-data-retention | 2026-09-08 讀取 | 已證實 | 是 |
| B82 | Anthropic Privacy Center | ZDR 適用產品 | https://privacy.claude.com/en/articles/8956058 | 活文件 | 已證實 | 摘要 |
| B84 | Anthropic | claude-code-security-review（同 A1） | https://github.com/anthropics/claude-code-security-review | — | 廠商主張 | 是 |
| B85 | Anthropic | Claude Opus 5 system card | https://www.anthropic.com/claude-opus-5-system-card | — | 尚未證實（未讀取） | 否 |
| B86 | DeepSeek | V4 preview release notes（同 A77） | https://api-docs.deepseek.com/news/news260424/ | 2026-04-24 | 廠商主張；China-affiliated | 摘要 |
| B88 | DeepSeek | Privacy Policy | https://cdn.deepseek.com/policies/en-US/deepseek-privacy-policy.html | 2026-02-10（二手） | 廠商主張；China-affiliated | 摘要 |
| B89 | Garante per la protezione dei dati personali | DeepSeek 限制處理令 docweb 10097450 / 10098477 | https://www.garanteprivacy.it/home/docweb/-/docweb-display/docweb/10097450 | 2025-01-30 | 已證實 | 摘要 |
| B90 | ThaiCERT / Digital Policy Alert | 韓國 PIPC 暫停 DeepSeek 下載 | https://www.thaicert.or.th/en/2025/02/19/7304/ | 2025-02-15 | 第三方評論 | 摘要 |
| B91 | 行政院 | 公務機關全面禁用 DeepSeek | https://www.ey.gov.tw/Page/9277F759E41CCD91/3ce9fe8f-2f5f-4d1d-8176-6fa4cf622b82 | 2025-02-03 | 已證實 | 摘要 |
| B92 | 數位發展部 | 新聞稿 15104 / 15296 | https://moda.gov.tw/press/press-releases/15104 | 2025-02 | 已證實 | 摘要 |
| B93 | Australian Government / CNN | PSPF Direction 001-2025 | https://www.cnn.com/2025/02/04/business/australia-deepseek-ban-security-concerns-intl/index.html | 2025-02-04 | 已證實（指令）；細節第三方 | 摘要 |
| B95 | NIST CAISI | CAISI Evaluation of DeepSeek AI Models Finds Shortcomings and Risks | https://www.nist.gov/news-events/news/2025/09/caisi-evaluation-deepseek-ai-models-finds-shortcomings-and-risks | 2025-09-30 | 已證實 | 摘要 |
| B96 | NIST CAISI | CAISI Evaluation of DeepSeek V4 Pro | https://www.nist.gov/news-events/news/2026/05/caisi-evaluation-deepseek-v4-pro | 2026-05 | 尚未證實（僅題名） | 否 |
| B97 | CrowdStrike | 政治觸發詞降低 DeepSeek-R1 程式碼安全性 | https://www.crowdstrike.com/en-us/blog/crowdstrike-researchers-identify-hidden-vulnerabilities-ai-coded-software/ | 2025-11 | 第三方評論（廠商研究） | 摘要 |
| B98 | Cisco | Evaluating Security Risk in DeepSeek and Other Frontier Reasoning Models | https://blogs.cisco.com/security/evaluating-security-risk-in-deepseek-and-other-frontier-reasoning-models | 2025-01/02 | 第三方評論 | 摘要 |
| B100 | NVIDIA | NVIDIA Debuts Nemotron 3 Family of Open Models | https://nvidianews.nvidia.com/news/nvidia-debuts-nemotron-3-family-of-open-models | 2025-12-15 | 廠商主張 | 摘要 |
| B102 | NVIDIA | NIM microservices | https://www.nvidia.com/en-us/ai-data-science/products/nim-microservices/ | 活頁面 | 廠商主張 | 摘要 |
| B104 | NVIDIA | garak | https://github.com/NVIDIA/garak | v0.15.0 2026-05-01（二手） | 已證實 | 是 |
| B106 | Meta | Llama 4 model card | https://github.com/meta-llama/llama-models/blob/main/models/llama4/MODEL_CARD.md | 2025-04-05 | 已證實 | 是 |
| B107 | Qwen team | Qwen3 | https://qwenlm.github.io/blog/qwen3/ | 2025-04-29 | 廠商主張；China-affiliated | 摘要 |
| B111 | Vero et al. (ETH Zurich) | BaxBench | https://arxiv.org/abs/2502.11844 ; https://baxbench.com/ | 2025-02-17 | 第三方評論（preprint） | 摘要 |
| B113 | Meta | PurpleLlama CybersecurityBenchmarks（CyberSecEval 4） | https://github.com/meta-llama/PurpleLlama/tree/main/CybersecurityBenchmarks | 無日期 | 已證實 | 是 |
| B118 | NIST | AI 600-1 Generative AI Profile | https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.600-1.pdf | 2024-07-26 | 已證實 | 摘要 |
| B119 | NIST | SP 800-218A | https://csrc.nist.gov/pubs/sp/800/218/a/final | 2024-07-26 | 已證實 | 摘要 |
| B121 | ISO/IEC | ISO/IEC 42001:2023 | https://www.iso.org/standard/42001 | 2023 | 已證實 | 摘要 |
| B122 | ISO/IEC | ISO/IEC 23894:2023 | https://www.iso.org/standard/77304.html | 2023 | 已證實 | 摘要 |
| B123 | European Union | AI Act Article 4 | https://artificialintelligenceact.eu/article/4/ | 適用 2025-02-02 | 已證實 | 摘要 |

## C 組：十一面向的標準、工具與事件

| 編號 | 出版者 | 題名 | URL | 日期／版本 | 級別 | 讀取 |
|---|---|---|---|---|---|---|
| C1.1 | OWASP | ASVS 5.0.0（官方 CSV） | https://github.com/OWASP/ASVS | 2025-05 | 已證實 | 是 |
| C1.2 | OWASP | ASVS 5.0 V15.2 requirements | 同上 | 2025-05 | 已證實 | 是 |
| C1.3 | OWASP | SAMM 2.0 | https://owaspsamm.org/model/ | 2020-02-11 | 已證實 | 摘要 |
| C1.4 | NIST | SP 800-160 Vol.1 Rev.1 | https://csrc.nist.gov/pubs/sp/800/160/v1/r1/final | 2022-11 | 已證實 | 摘要 |
| C1.5 | Threat Modeling Manifesto | 同名 | https://www.threatmodelingmanifesto.org/ | 2020 | 已證實 | 摘要 |
| C1.6 | OWASP | Threat Dragon v2.6.2 | https://github.com/OWASP/threat-dragon | 年份未渲染 | 已證實 | 是 |
| C1.10 | Simon Brown | C4 model | https://c4model.com/ | 活頁面 | 已證實（日期不可驗證） | 摘要 |
| C2.1 | OWASP | OWASP Top 10:2025（官方 repo） | https://github.com/OWASP/Top10/tree/master/2025/docs/en | 2025-11 公布（第三方） | 已證實 | 是 |
| C2.3 | OWASP | A03:2025 Software Supply Chain Failures | 同上 | — | 已證實 | 是 |
| C2.4 | OWASP | A10:2025 Mishandling of Exceptional Conditions | 同上 | — | 已證實 | 是 |
| C2.5 | CISA / MITRE | 2025 CWE Top 25 | https://www.cisa.gov/news-events/alerts/2025/12/11/2025-cwe-top-25-most-dangerous-software-weaknesses | 2025-12-11 | 已證實 | 摘要 |
| C2.7 | NIST | NIST Updates NVD Operations to Address Record CVE Growth | https://www.nist.gov/news-events/news/2026/04/nist-updates-nvd-operations-address-record-cve-growth | 2026-04 | 已證實 | 摘要 |
| C2.8 | CISA | BOD 26-04 Prioritizing Security Updates Based on Risk | https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk | 2026-06-10 | 已證實 | 摘要 |
| C3.1 | OWASP | XSS Prevention Cheat Sheet | https://github.com/OWASP/CheatSheetSeries | 活文件 | 已證實 | 是 |
| C3.2 | OWASP | DOM based XSS Prevention Cheat Sheet | 同上 | 活文件 | 已證實 | 是 |
| C3.3 | W3C | Trusted Types WD | https://www.w3.org/TR/2026/WD-trusted-types-20260623/ | 2026-06-23 | 已證實 | 摘要 |
| C3.7 | CISA KEV（經二手） | CVE-2025-48700 Zimbra XSS | — | 2026 | 第三方評論 | 摘要 |
| C4.1 | W3C | CSP Level 3（WD） | https://www.w3.org/TR/CSP3/ | WD 日期矛盾 | 已證實（狀態） | 摘要 |
| C4.2 | W3C | CSP Level 2（REC） | https://www.w3.org/TR/CSP2/ | REC | 已證實 | 摘要 |
| C4.4 | OWASP | CSP Cheat Sheet | https://github.com/OWASP/CheatSheetSeries | 活文件 | 已證實 | 是 |
| C4.5 | Weichselbaum, Spagnuolo, Lekies, Janc | CSP Is Dead, Long Live CSP!（ACM CCS 2016） | https://research.google/pubs/csp-is-dead-long-live-csp-on-the-insecurity-of-whitelists-and-the-future-of-content-security-policy/ | 2016-10-24 | 第三方評論（同儕審查） | 摘要 |
| C4.6 | Google | csp-evaluator | https://github.com/google/csp-evaluator | 活專案 | 已證實 | 是 |
| C5.1 | OWASP | ASVS 5.0 V6–V10 | https://github.com/OWASP/ASVS | 2025-05 | 已證實 | 是 |
| C5.2 | NIST | SP 800-63-4 | https://csrc.nist.gov/pubs/sp/800/63/4/final | 2025-07 | 已證實 | 摘要 |
| C5.3 | IETF | draft-ietf-oauth-v2-1-15 | https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-15 | 到期 2026-09-03 | 已證實（Internet-Draft） | 摘要 |
| C5.4 | W3C | WebAuthn Level 3（REC） | https://www.w3.org/TR/webauthn-3/ | 2026-08-25 | 已證實 | 摘要 |
| C5.5 | OWASP | Authorization Cheat Sheet | https://github.com/OWASP/CheatSheetSeries | 活文件 | 已證實 | 是 |
| C5.7 | OWASP | API Security Top 10 2023 | https://github.com/OWASP/API-Security | 2023 | 已證實 | 是 |
| C6.1 | OWASP | Dependency-Check v13.0.0 | https://github.com/dependency-check/DependencyCheck | 年份未渲染 | 已證實 | 是 |
| C6.2 | Google / OpenSSF | OSV.dev、OSV Schema | https://osv.dev/ | 活專案 | 已證實 | 摘要 |
| C6.3 | Google | OSV-Scanner v2.0.0 | https://github.com/google/osv-scanner | 2025-03 | 已證實 | 是 |
| C6.6 | Anchore | Grype v0.118.0 | https://github.com/anchore/grype | 年份未渲染 | 已證實 | 是 |
| C6.7 | FIRST | EPSS v4 | https://www.first.org/epss/ | 2025-03-17（二手） | 已證實（專案）；日期第三方 | 摘要 |
| C6.8 | FIRST | CVSS v4.0 Specification | https://www.first.org/cvss/v4.0/specification-document | 2023-11-01 | 已證實 | 摘要 |
| C6.9 | CISA | SSVC | https://www.cisa.gov/resources-tools/resources/stakeholder-specific-vulnerability-categorization-ssvc | — | 已證實 | 摘要 |
| C6.10 | Spracklen et al. | We Have a Package for You!（USENIX Security 2025） | https://www.usenix.org/publications/loginonline/we-have-package-you-comprehensive-analysis-package-hallucinations-code | 2025 | 第三方評論（同儕審查） | 摘要 |
| C6.11 | NVD | CVE-2024-3094 | https://nvd.nist.gov/vuln/detail/CVE-2024-3094 | 2024-03-29 | 已證實 | 摘要 |
| C6.12 | Sansec | polyfill.io supply chain attack | https://sansec.io/research/polyfill-supply-chain-attack | 2024-06-24 | 廠商主張 | 摘要 |
| C6.13 | CISA | Widespread Supply Chain Compromise Impacting npm Ecosystem | https://www.cisa.gov/news-events/alerts/2025/09/23/widespread-supply-chain-compromise-impacting-npm-ecosystem | 2025-09-23 | 已證實 | 摘要 |
| C6.14 | Semgrep 等 | chalk / debug npm compromise | https://semgrep.dev/blog/2025/chalk-debug-and-color-on-npm-compromised-in-new-supply-chain-attack/ | 2025-09-08 | 廠商主張 | 摘要 |
| C7.1 | GitHub | Security hardening for GitHub Actions | https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions | 活文件 | 已證實 | 摘要 |
| C7.4 | GitHub Security Lab | Preventing pwn requests | https://securitylab.github.com/resources/github-actions-preventing-pwn-requests/ | — | 已證實 | 摘要 |
| C7.5 | GitHub Security Lab | Untrusted input | https://securitylab.github.com/resources/github-actions-untrusted-input/ | — | 已證實 | 摘要 |
| C7.8 | GitHub | Actions policy now supports blocking and SHA pinning actions | https://github.blog/changelog/2025-08-15-github-actions-policy-now-supports-blocking-and-sha-pinning-actions/ | 2025-08-15 | 已證實 | 摘要 |
| C7.9 | zizmorcore | zizmor | https://github.com/zizmorcore/zizmor | 活專案 | 已證實 | 是 |
| C7.10 | rhysd | actionlint v1.7.12 | https://github.com/rhysd/actionlint | 日期不可驗證 | 已證實 | 是 |
| C7.11 | BoostSecurity | poutine | https://github.com/boostsecurityio/poutine | 版本未驗 | 已證實 | 是 |
| C7.12 | StepSecurity | Harden-Runner v2.21.0 | https://github.com/step-security/harden-runner | — | 廠商主張 | 是 |
| C7.13 | OpenSSF | Scorecard v5.5.0 | https://github.com/ossf/scorecard | 2026-04-23（第三方） | 已證實 | 是 |
| C7.14 | GitHub Advisory Database | GHSA-mrrh-fwg8-r2c3 / CVE-2025-30066 tj-actions/changed-files | https://github.com/advisories/GHSA-mrrh-fwg8-r2c3 | 2025-03-15 | 已證實 | 是 |
| C7.15 | CISA | Supply Chain Compromise of tj-actions/changed-files and reviewdog/action-setup | https://www.cisa.gov/news-events/alerts/2025/03/18/supply-chain-compromise-third-party-tj-actionschanged-files-cve-2025-30066-and-reviewdogaction | 2025-03-18 | 已證實 | 摘要 |
| C7.16 | Nx maintainers | s1ngularity postmortem | https://nx.dev/blog/s1ngularity-postmortem | 2025-08 | 已證實（一手 post-mortem） | 摘要 |
| C7.17 | Socket / HiddenLayer | Ultralytics PyPI compromise via Actions cache poisoning | https://socket.dev/blog/ultralytics-pypi-package-compromised-through-github-actions-cache-poisoning | 2024-12-04/05 | 廠商主張 | 摘要 |
| C8.1 | GitHub | About secret scanning / push protection | https://docs.github.com/en/code-security/secret-scanning/introduction/about-secret-scanning | 活文件 | 已證實 | 摘要 |
| C8.2 | gitleaks | gitleaks v8.30.1 | https://github.com/gitleaks/gitleaks | 年份未渲染 | 已證實 | 是 |
| C8.3 | Truffle Security | TruffleHog | https://github.com/trufflesecurity/trufflehog | 活專案 | 已證實 | 是 |
| C8.4 | Yelp | detect-secrets | https://github.com/Yelp/detect-secrets | 版本未驗 | 已證實 | 是 |
| C8.5 | OWASP | Secrets Management Cheat Sheet | https://github.com/OWASP/CheatSheetSeries | 活文件 | 已證實 | 是 |
| C8.7 | GitGuardian | State of Secrets Sprawl 2026 | https://www.gitguardian.com/state-of-secrets-sprawl-report-2026 | 2026-03 | 廠商主張 | 摘要 |
| C8.8 | Microsoft MSRC | Microsoft mitigated exposure of internal information in a storage account due to overly permissive SAS token | https://www.microsoft.com/en-us/msrc/blog/2023/09/microsoft-mitigated-exposure-of-internal-information-in-a-storage-account-due-to-overly-permissive-sas-token | 2023-09 | 已證實 | 摘要 |
| C9.1 | OWASP | Input Validation Cheat Sheet | https://github.com/OWASP/CheatSheetSeries | 活文件 | 已證實 | 是 |
| C9.3 | OWASP | ASVS 5.0 V1.2 / V2.2 | https://github.com/OWASP/ASVS | 2025-05 | 已證實 | 是 |
| C9.6 | OWASP GenAI | LLM01:2025 Prompt Injection | https://genai.owasp.org/resource/owasp-top-10-for-llm-applications-2025/ | 2024-11-14（PDF 檔名） | 已證實 | 摘要 |
| C10.1 | OWASP | Error Handling Cheat Sheet | https://github.com/OWASP/CheatSheetSeries | 活文件 | 已證實 | 是 |
| C10.2 | OWASP | Logging Cheat Sheet / Logging Vocabulary | 同上 | 活文件 | 已證實 | 是 |
| C10.3 | OWASP | ASVS 5.0 V16 | https://github.com/OWASP/ASVS | 2025-05 | 已證實 | 是 |
| C10.5 | OWASP | A09:2025 / A10:2025 | https://github.com/OWASP/Top10 | — | 已證實 | 是 |
| C11.1 | OpenSSF | SLSA v1.1（2025-04-21）、v1.2（2025-11-24） | https://slsa.dev/blog/2025/11/announce-slsa-v1.2 | 2025-11-24 | 已證實 | 摘要 |
| C11.2 | OWASP / Ecma | CycloneDX 1.6 = ECMA-424 1st ed.；1.7 = 2nd ed. | https://ecma-international.org/publications-and-standards/standards/ecma-424/ | 2024-06；2025-12 | 已證實 | 摘要 |
| C11.3 | Linux Foundation / ISO | SPDX 3.0；ISO/IEC 5962:2021；DIS 5962 | https://www.iso.org/standard/93810.html | 2024-04-16 | 已證實 | 摘要 |
| C11.4 | Sigstore | cosign 3.0 available | https://blog.sigstore.dev/cosign-3-0-available/ | 2025-10-08 | 已證實 | 摘要 |
| C11.5 | in-toto | Attestation Framework v1 | https://github.com/in-toto/attestation | 活專案 | 已證實 | 是 |
| C11.6 | NIST | SP 800-204D | https://csrc.nist.gov/pubs/sp/800/204/d/final | 2024-02 | 已證實 | 摘要 |
| C11.7 | NIST | SP 800-218 SSDF v1.1 | https://csrc.nist.gov/projects/ssdf | 2022-02 | 已證實（日期本次未驗） | 摘要 |
| C11.8 | CISA | Secure by Design；Pledge | https://www.cisa.gov/resources-tools/resources/secure-by-design | 2023-04；2024-05 | 已證實 | 摘要 |
| C11.9 | European Union | Regulation (EU) 2024/2847（CRA） | https://eur-lex.europa.eu/eli/reg/2024/2847/oj | 2024 | 已證實 | 摘要 |
| C11.10 | OpenSSF | S2C2F v1.1 | https://github.com/ossf/s2c2f/blob/main/specification/framework.md | 2022-10-19 | 已證實 | 是 |
| C11.11 | CISA | ED 21-01（closed）；AA20-352A | https://www.cisa.gov/news-events/directives/ed-21-01-mitigate-solarwinds-orion-code-compromise-closed | 2020-12-13；2026-01-08 結案 | 已證實 | 摘要 |
| C11.12 | Codecov | April 2021 post-mortem | https://about.codecov.io/apr-2021-post-mortem/ | 2021-04 | 已證實 | 摘要 |
| C11.13 | Mandiant (Google Cloud) | 3CX Software Supply Chain Compromise | https://cloud.google.com/blog/topics/threat-intelligence/3cx-software-supply-chain-compromise | 2023 | 廠商主張 | 摘要 |
| C12.1 | FIRST | CVSS v4.0 calculator & spec | https://www.first.org/cvss/calculator/4.0 | 2023-11-01 | 已證實 | 摘要（計算器原始碼直接讀取） |
| C12.2 | OWASP | Risk Rating Methodology | https://owasp.org/www-community/OWASP_Risk_Rating_Methodology | 活文件 | 已證實 | 摘要 |
| C12.6 | 實務來源 | DREAD 棄用說法 | — | — | 尚未證實 | — |
| C13.1 | ISO/IEC | ISO/IEC 27001:2022 | https://www.iso.org/standard/27001 | 2022 | 已證實（條文付費牆） | 否 |
| C13.2 | 本報告 | 面向 → Annex A 映射提案 | — | — | 設計提案 | — |
| C13.3 | IEC | IEC 62443-4-1:2018 | https://webstore.ansi.org/preview-pages/iec/preview_iec62443-4-1%7Bed1.0%7Db.pdf | 2018 | 已證實（預覽） | 摘要 |
| C13.4 | NIST | CSF 2.0（CSWP 29） | https://doi.org/10.6028/NIST.CSWP.29 | 2024-02-26 | 已證實 | 摘要 |
| C13.5 | SEMI | E187 | https://store-us.semi.org/products/e18700-semi-e187-specification-for-cybersecurity-of-fab-equipment | 日期未驗 | 已證實（出版者） | 摘要 |

另：FIRST CVSS v4.0 參考計算器原始碼（BSD-2-Clause）https://github.com/FIRSTdotorg/cvss-v4-calculator 於本次直接讀取並移植，見雛型 `src/mara/scoring/cvss4.py`。
