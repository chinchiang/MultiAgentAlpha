# 第六部　資安風險

審查系統本身是一個處理組織最敏感資產（原始碼、憑證、架構）的系統。本部依 OWASP 的 Agentic AI 威脅分類與 LLM Top 10 檢視它自己的風險。

## 第 16 章　審查系統的六類風險

### 16.1 原始碼外洩

這是最直接的風險。原始碼會經過三條路徑：送往 Anthropic API、送往組織內的 vLLM 或 NIM、存放在 Actions 的 artifact 與日誌中。第一條路徑的控制是 ZDR 協議與模型選擇（第 7.1 節）；Anthropic 的文件明載 Fable 系列不在 ZDR 範圍內【已證實｜B81】，而且 code execution 工具與 programmatic tool calling 不符合 ZDR【已證實｜B81】，本架構不使用這兩者。第二條路徑的控制是網路隔離：vLLM 與 NIM 的端點只能從 runner 的網段存取，且 DeepSeek 權重的部署主機不得有出口網路。第三條路徑最常被忽略：GitHub Actions 的日誌是公開倉庫的公開內容，私有倉庫的 artifact 也有保留期；tj-actions 事件的 payload 正是把 secret 以 base64 寫進公開的 workflow 日誌【已證實｜C7.14】。雛型的 Markdown 報告只輸出引用的前 160 字元，prompt 要求 secret 遮蔽，但這不能取代 artifact 的存取控制。

### 16.2 Prompt Injection 操縱審查結果

第 9 章的五道防線對應這個風險。這裡補充一個治理面的觀察：OWASP 2026 年 Agentic Applications Top 10 的第一項是 Agent Goal Hijack，第二項是 Tool Misuse，第三項是 Identity and Privilege Abuse【已證實（僅前三項確認）｜B45】。本架構的 agent 沒有工具、沒有身分、沒有權限，所以第二與第三項在設計上不存在；第一項則靠 canary 量測而非靠 prompt 祈禱。MITRE ATLAS 於 2025 年 10 月新增了 14 項 AI agent 技術【第三方評論（計數未直接驗證）｜B46】，治理建議要求每半年對照一次。

### 16.3 模型供應鏈

自架權重本身是供應鏈風險。Hugging Face 上的模型檔可能含惡意的 pickle；權重的來源必須可驗證（NVIDIA NGC 自 2025 年 7 月起對模型簽章【第三方評論｜C11.4】）；DeepSeek 的 GitHub 組織頁未列出 V4 倉庫，V4 權重的正式來源在本次研究中無法確認【尚未證實｜A78】。治理建議要求：只從官方來源下載權重、以 cosign 或 NGC 簽章驗證、以 safetensors 而非 pickle 格式載入、記錄權重的雜湊值進入 SBOM（CycloneDX 1.6 以上支援 ML-BOM【已證實｜C11.2】）。

### 16.4 審查系統自己的 GitHub Actions

一個審查 workflow 安全性的 workflow，若自己不安全，會是諷刺也會是災難。雛型的 workflow 做到：`pull_request` 而非 `pull_request_target`、頂層 `permissions: {}` 且每個 job 明示只讀、所有 action 固定到 40 字元 SHA 並附版本註解、`persist-credentials: false`、工具 job 與模型 job 分離、模型 job 不 checkout 可執行內容。GitHub 於 2025 年 8 月提供的組織層級 SHA pinning 政策【已證實｜C7.8】應在組織層級開啟，讓這些選擇成為強制而非慣例。

### 16.5 過度信任與責任稀釋

當閘門是綠的，開發者會假設程式碼是安全的。這是第 2.2 節「能力錯覺」的系統版本。控制有三：閘門只在 A 級與 B 級 High 以上阻擋，其他一律是「建議」，報告明示「本審查不涵蓋什麼」（第九部）；每份報告的偏誤稽核區塊讓讀者看到本次審查有幾次拒答、幾個 canary 回應、幾張折半票；治理建議把「審查通過」定義為「進入人工複審的資格」而非「可以部署」，對照 ISO/IEC 27001:2022 的 8.29 安全測試控制項，自動審查是測試的一部分而非全部。

### 16.6 成本失控與可用性

三個家族、十一個面向、正反序兩次裁決，一次全庫審查的模型呼叫數是 11 × 3（reviewer）+ 3（skeptic）+ 3（red team）+ 3 × 2（judge）≈ 45 次以上，每次的輸入是整個 bundle。第 22 章估算成本；這裡指出的風險是：成本壓力會誘使組織減少家族數或關掉反序 pass，而這兩者正是去偏誤的核心。治理建議把「家族數不低於三、反序 pass 不關閉」列為政策而非設定。

## 第 17 章　與 OWASP LLM Top 10 2025 的對應

| LLM Top 10 2025 | 對本架構的適用性 | 控制 |
|---|---|---|
| LLM01 Prompt Injection | 高。被審查內容全是攻擊者可控 | 第 9 章五道防線；canary 指標 |
| LLM02 Sensitive Information Disclosure | 高。原始碼與 secret 經過模型 | ZDR、地端部署、secret 遮蔽、artifact 存取控制 |
| LLM03 Supply Chain | 中。自架權重的來源 | 第 16.3 節 |
| LLM04 Data and Model Poisoning | 低。本架構不微調 | 校準資料的人工裁決來源需有存取控制 |
| LLM05 Improper Output Handling | 中。模型輸出進入 SARIF 與 PR 評論 | schema 驗證；Markdown 輸出經跳脫；SARIF 只放結構化欄位 |
| LLM06 Excessive Agency | 低。agent 無工具、無權限 | 架構層級 |
| LLM07 System Prompt Leakage | 低。prompt 是公開的（附錄E） | 不依賴 prompt 保密 |
| LLM08 Vector and Embedding Weaknesses | 不適用。無 RAG | — |
| LLM09 Misinformation | 高。幻覺 finding | 來源證據驗證；pinned 標準 ID；證據層級 |
| LLM10 Unbounded Consumption | 中。bundle 大小與呼叫次數 | bundle 上限；每 PR token 預算 |

這個對應表的用途是稽核：ISO/IEC 42001 的稽核者會問「你們用了什麼框架評估這個 AI 系統的風險」，這張表與第十部的 NIST AI RMF 對應是答案。
