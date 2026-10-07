# 附錄C　術語對照表

| 英文 | 中文說明 | 本報告用法 |
|---|---|---|
| Vibe Coding | 以自然語言描述意圖、由 AI 產生大部分程式碼並以「跑起來像不像對的」驗收的開發方式 | 第 2.1 節 |
| Multi-agent | 多個獨立的模型呼叫各司其職、以結構化資料交換 | 第三部；本報告不含代理間自由對話 |
| Model family | 同一供應商或同一訓練譜系的模型集合（正式面板：Anthropic、Gemini、GLM；冷備援 DeepSeek；初版另有 Nemotron） | 異質性的單位 |
| Evidence tier | finding 的可信度層級 A 到 D | 第 11.2 節；勿與 source grade 混淆 |
| Source grade | 本報告引用來源的四級（已證實、廠商主張、第三方評論、尚未證實） | 第 12.6 節 |
| Provenance | finding 的來源證據：檔案、行號、逐字引用 | 第 12.3 節 |
| Canary | 植入資料中的隨機標記，用以偵測模型把資料當指令執行；回應 canary 的呼叫整批作廢 | 第 9 章；雛型用於 L1 到 L3 |
| Skeptic | L3 中負責否證 finding 的 agent | 第 6.4 節 |
| Red team | L3 中負責判斷可利用性的 agent | 第 6.4 節 |
| Judge / Jury | L4 中盲審 finding 的 agent 集合 | 第 6.5 節 |
| Blinding | 移除模型身分、分數與長度訊號的視圖轉換 | 第 6.5 節 |
| Forward / reverse pass | 同一批 finding 以正序與精確倒序各裁決一次 | 位置偏誤對策 |
| Self-preference bias | 模型偏好自己（或同家族）產出的內容 | 第 13 章第 1 項 |
| Position bias | 裁決受呈現順序影響 | 第 13 章第 2 項 |
| Verbosity bias | 裁決受篇幅影響 | 第 13 章第 3 項 |
| Anchoring bias | 裁決受先前分數影響 | 第 13 章第 4 項 |
| Sycophancy | 模型迎合使用者或上下文中的觀點 | 第 13 章第 6 項 |
| Correlated errors | 不同模型在同一項目上以相同方式出錯 | 第 13 章第 7 項 |
| CAPA | Chance Adjusted Probabilistic Agreement，量測模型錯誤相似度的指標 | 第 4.4 節 |
| Krippendorff's α | 可處理缺值與多評分者的一致性係數 | 第 11.2 節；雛型只在整批 finding（語料層級）計算，單一 finding 改用 agreement proxy |
| Agreement proxy | 單一 finding 的評審一致度代理指標：每個 judge 家族取一個裁決，計算眾數占比並做機遇校正；不是 Krippendorff's α | 第 13 章第 13 項、附錄B 第 48 項 |
| Alternative Annotator Test (AAT) | 以人工裁決為對照，檢定管線的判斷能否在統計上替代人類標註者；通過前不允許無監督地不採納 finding | 第 15.3 節、G-9 |
| Human queue | 人工佇列：不得自動採納、須由安全團隊裁決的 finding；未清空前審查標記為不完整 | 第 15.1 節 |
| Shadow mode | 影子模式：只產出報告、不評論也不阻擋的導入階段 | 第 15.4 節、G-10 |
| Cold standby | 冷備家族：事先備妥設定、可在一週內替換既有家族的模型 | 第 7.3 節、G-4 |
| Seeded benchmark | 刻意植入已知漏洞並附標籤的樣本集，用於校準 | 第 11.5 節、`calib/` |
| Fail-closed | 任何必要步驟失敗時判為不完整、閘門不通過，而不是當成「沒有發現」 | 第 6.1 節 |
| MARA_HOME | MARA 工作區（鎖定工具、校準證據）的位置；位於被審 repo 內時拒絕審查 | 第 9 章 |
| P1–P8 | 雛型在載入設定時強制的政策規則（資料主權、家族多樣性、無監督不採納等） | 第 10 章、`src/mara/policy.py` |
| Dawid-Skene | 無金標準下同時估計真實標籤與標註者混淆矩陣的 EM 演算法 | 第 11.5 節 |
| PoLL | Panel of LLM evaluators，不同供應商的小模型評審團 | 第 4.4 節 |
| SARIF | Static Analysis Results Interchange Format，OASIS 標準 | 第 6.1 節 |
| CVSS 4.0 | Common Vulnerability Scoring System 第 4 版 | 第 11.2 節 |
| CVSS-B / BT / BE / BTE | 依套用 Base、Threat、Environmental 指標組的命名 | 第 11.2 節 |
| MacroVector | CVSS 4.0 計算中的六位數等價類索引 | `cvss4.py` |
| EPSS | Exploit Prediction Scoring System，30 天內遭利用機率 | 第 10.6 節 |
| KEV | CISA Known Exploited Vulnerabilities 目錄 | 第 10.2 節 |
| SSVC | Stakeholder-Specific Vulnerability Categorization；Track / Track* / Attend / Act | 第 11.2 節 |
| BOLA / IDOR | Broken Object Level Authorization / Insecure Direct Object Reference | 第 10.5 節 |
| Pwn request | `pull_request_target` 加 checkout PR head 的危險組合 | 第 10.7 節 |
| SHA pinning | 以完整 40 字元 commit SHA 引用 action | 第 10.7 節 |
| Slopsquatting | 攻擊者預先註冊 LLM 常幻覺的套件名稱 | 第 2.3 節 |
| SBOM / ML-BOM | 軟體物料清單／模型物料清單 | 第 10.11 節、G-7 |
| SLSA | Supply-chain Levels for Software Artifacts | 第 10.11 節 |
| S2C2F | Secure Supply Chain Consumption Framework | 第 10.11 節 |
| ZDR | Zero Data Retention，零資料保留 | 第 7.1 節 |
| Covered Models | Anthropic 對需 30 天保留、不得 ZDR 的模型的稱呼 | 第 7.1 節 |
| NIM | NVIDIA Inference Microservices | 第 7.1 節 |
| vLLM | 開源推論伺服器，提供 OpenAI 相容端點 | 第 7.2 節 |
| On-prem | 組織內部署，資料不離境 | 設定檔 `data_residency: on_prem`（須為私有位址或宣告的私有 DNS 區上的 OpenAI 相容端點）；另一個允許值 `vendor_api_zdr` 表示在零資料保留協議或雲端平台的不保留承諾下送往廠商 API |
| vendor_api_retained | 廠商會保留資料一段期間、但不用於訓練的 API（正式面板的 Gemini） | 第 7.1 節；policy P5 只在該模型附 `retention_approval_ref` 時放行 |
| Cross-region inference profile | Amazon Bedrock 的跨區推論設定檔；`global.` 前綴可路由到任一 AWS 商用區域 | 第 7.1 節、第 21.1 節 |
| Entity List | 美國商務部 BIS 的出口管制實體清單（智譜列於其上） | 第 7.1 節、第 7.3 節 |
| CSL / DSL / PIPL | 中國網路安全法、資料安全法、個人資訊保護法 | 第 21.2 節、第 26 章 |
| CRA | EU Cyber Resilience Act，Regulation (EU) 2024/2847 | 第 10.11 節 |
| PSIRT | Product Security Incident Response Team | G-12 |
| Placeholder logic | AI 生成程式碼中的佔位式邏輯 | 第 2.2 節 |
| Trusted Types | 瀏覽器層以型別強制 DOM sink 安全的機制 | 第 10.3 節 |
| strict-dynamic | CSP 指令，信任由 nonce 腳本動態載入的腳本 | 第 10.4 節 |
| GSMD | 本系列文件的編號前綴 | 封面 |
