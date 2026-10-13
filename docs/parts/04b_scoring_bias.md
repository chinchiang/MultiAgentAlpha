## 第 11 章　評分方法

### 11.1 設計原則：分數由程式算，模型只提供判斷的輸入

LLM 給出的數字分數不可信。《Overconfidence in LLM-as-a-Judge》系統性地記錄了評審模型的自報信心顯著高估其實際正確率【第三方評論（preprint）｜B34】；《Evaluating Scoring Bias in LLM-as-a-Judge》與同類研究指出評分受提示措辭與順序影響【已證實（DASFAA 2026）｜B15】。因此本架構中模型從不輸出「分數」，只輸出分數的「輸入」：CVSS 4.0 的各項基礎指標、可利用性的類別、裁決的類別、嚴重度的區間。所有數值都由 L5 的程式計算，可重算、可稽核。

### 11.2 單一 finding 的四個維度

**嚴重度（Severity）。** 由 L2 reviewer 提供 CVSS 4.0 基礎向量（AV、AC、AT、PR、UI、VC、VI、VA、SC、SI、SA 十一個指標），L5 以移植自 FIRST 參考實作的計算器算分。CVSS 4.0 規範於 2023 年 11 月 1 日發布，分為 Base、Threat、Environmental、Supplemental 四組指標，並以 CVSS-B、BT、BE、BTE 命名法標示套用了哪幾組【已證實｜C12.1】。雛型的計算器逐字重現 FIRST 的 MacroVector 查表（270 個 MacroVector）、EQ 最高向量表與嚴重度深度表，並以 FIRST 官方 JavaScript 產生的 28 組參考向量（含 12 組進位邊界）做迴歸測試，全數一致。2026 年 10 月另以 FIRST 參考實作對全部 419,904 個 base×E 向量做了一次性的窮舉比對，找出並修正一個捨入差異：原本的計算器在 14,166 個向量上少算 0.1，改為與參考實作的 `Math.round` 相同的四捨五入後完全一致。窮舉比對的成本太高，未納入日常測試，只留下邊界向量作迴歸。L4 judge 的嚴重度意見另存為 `operational_severity`，不覆寫 CVSS 計算出的嚴重度。無效向量會被拒收；防禦性回退為 `Unknown` 與空分數，轉人工處理，不能以 0 分解除阻擋。

**可利用性（Exploitability）。** 依 finding 的類型分流。依賴類 finding 以 EPSS 分數與 KEV 是否收錄為準，兩者都由工具查詢而非模型回憶；EPSS（現行 v5，2026 年 6 月 15 日起）只能作為「可能性」軸【已證實｜C6.7】。程式碼類 finding 以 L3 Red Team 的類別（yes、conditional、no、unknown）與 L2 的可達性判斷（reachable、conditional、unreachable、unknown）為準。

**共識（Consensus）。** 共識分數範圍 0 到 1，是裁決的彙整指標，尚未校準為正確率或安全機率。計算方式：每個 judge 家族對該 finding 的正序與反序投票取平均（true_positive 記 1、needs_human 記 0.5、false_positive 記 0），再以家族權重加權平均。每一家族必須有且僅有一張正序及反序有效回票；重複、缺漏與未知 finding 的回覆不計入有效票。發現者同家族的票即使折減，也不補足獨立家族數。至少達到 `min_independent_judges` 個實際獨立家族、正反序一致且無其他待判原因，才可採納。工具佐證不進入共識分數，而是進入證據層級；未解決的工具結果也單獨保留並阻擋 gate。

**證據層級（Evidence tier）。** 這是本架構最重要的輸出，也是「資料可信度」問題的直接答案。四級定義如下，判定順序由上而下：

| 層級 | 條件 | 意義 |
|---|---|---|
| D | 來源證據未通過驗證；或 Skeptic 否證且共識分數低於門檻；或不符合 A、B 且共識分數未達門檻 | 不採納。捏造引用或已被否證 |
| A | 來源證據通過驗證，且負責該面向的 L0 確定性工具在同一路徑 ±3 行、CWE 相同（或工具未給 CWE）處有 error 或 warning 等級的結果，且至少一個模型家族同意 | 工具與模型指向同一處。最高可信度 |
| B | 來源證據通過驗證，≥2 個模型家族同意（發現或裁決），可達性為 reachable 或 conditional，Skeptic 已回應且未否證（棄權視為未經挑戰） | 跨家族共識且有可達論證 |
| C | 來源證據通過驗證，共識分數達門檻，但不符合 A 或 B（例如只有單一家族、可達性不明，或 Skeptic 棄權） | 證據不足以升級的判斷，需人工確認 |

證據層級與第 12 章的「報告本身的證據四級」是兩套不同的東西：前者是 finding 的可信度，後者是本報告引用來源的可信度。混淆兩者是常見的溝通錯誤，第九部會再提醒。

**SSVC 決策。** CISA 的 Stakeholder-Specific Vulnerability Categorization 以決策樹輸出 Track、Track*、Attend、Act 四種行動【已證實｜C6.9】。雛型實作的是簡化版：D 級一律 Track；Critical 且可利用為 yes 或 conditional 且對外曝露是 Act（雛型目前一律假設對外曝露，尚未接上資產清冊）；High 或 Critical 且非不可利用是 Attend，不可利用則為 Track*；Medium 且可利用是 Track*；其餘 Track。這裡的「可利用」是 Red Team 在審查中的判斷，不是 KEV 意義下的「野外遭利用」，報告中必須如此標示。

### 11.3 為什麼不用 DREAD，也不只用 OWASP Risk Rating

DREAD（Damage、Reproducibility、Exploitability、Affected users、Discoverability）常被引用為 Microsoft 在 2008 年前後因評分主觀且不一致而棄用；但本次研究找不到 Microsoft 的一手棄用聲明，這個說法只能以實務共識的層級陳述【尚未證實｜C12.6】。無論出處，DREAD 的問題在本架構中會被放大：五個主觀維度交給 LLM 打分，正是第 11.1 節要避免的事。OWASP Risk Rating Methodology 的 16 個子因子（威脅代理四項、弱點四項、技術影響四項、業務影響四項，各 0 到 9）【已證實｜C12.2】比 DREAD 結構化得多，是強迫 LLM 輸出固定 schema 的理想格式；但它的業務影響四項（財務、聲譽、合規、隱私）需要組織脈絡，不適合由審查 agent 判斷。本架構的取捨是：技術面用 CVSS 4.0（可重算、業界可比），行動面用 SSVC（決策導向），業務影響留給人工佇列。

### 11.4 面向分數與閘門

每個面向從 100 分起算，每個被採納的 finding 依嚴重度扣分（Critical 40、High 25、Medium 10、Low 3），再乘以證據層級係數（A 1.0、B 0.8、C 0.4、D 0），最低 0 分。整體分數是十一個面向的平均。閘門在下列情況不通過：任何被採納的 A 級或 B 級 finding 嚴重度為 High 或 Critical；任何面向分數低於 60；或審查不完整（必要工具未執行、任何拒答、截斷或 canary 回應、仍有待人工裁決的 finding、有未處理的工具 error／warning 結果），此時整體分數為 null，不給出一個看似可信的平均。C 級 High 以上的 finding 平時進入人工佇列；佇列積壓超過上限時改為直接阻擋，並把一致度門檻提高 0.1。這些數字都在設定檔中，是起始值而非定論；第五部的校準迴圈會修正它們。

雛型 v0.3.22 在 fixture 上的實際輸出如下（三個 mock 家族、預錄的 semgrep、gitleaks、zizmor 與 csp-evaluator SARIF；與 CI 相同的指令，2026 年 10 月 6 日重跑；`--provider mock` 的 mock 面板沿用初版的 Anthropic、DeepSeek、Nemotron 三個家族標籤，不隨正式面板改變，2026 年 10 月 7 日以 v0.4.2 重跑，下列計數與面向分數相同）：審查狀態為 incomplete，整體分數為 null，閘門阻擋。不完整的原因有四：osv-scanner 與 trivy 沒有預錄結果、Nemotron 刻意拒答一次、人工佇列未清空、工具結果未處理。61 個原始 finding 去重為 30 個，其中 6 個被採納（2 個 A 級、4 個 B 級；營運嚴重度為 High 的 2 個，CVSS 4.0 嚴重度為 High 的 3 個），其餘 24 個全部進入人工佇列，沒有任何 finding 被靜默拒絕；24 個中有 22 個的原因是獨立 judge 不足（第 13 章第 7 項）。面向分數最低的是 GitHub Actions 75 分、認證授權與 XSS 各 80 分。機密外洩面向得 100 分，原因不是沒有缺陷：fixture 的預錄回覆引用了原始的機密值，而 bundle 在送出前已把機密值遮蔽為 `[REDACTED]`，兩個機密 finding 因此無法通過引用驗證而落為 D 級。真實模型只會看到遮蔽後的文字，不會遇到這個落差；它是 fixture 需要隨遮蔽功能更新的地方，而不是真實審查的盲點。這個結果與初版報告（2026 年 9 月）記載的「67.0 分、27 個採納」相去甚遠，差異來自之後補上的 fail-closed 規則：管線寧可把 finding 交給人，也不在證據不足時自動採納。

### 11.5 校準：從 seeded benchmark 到家族權重

家族權重的初始值都是 1.0，這是無知的表現而不是判斷。校準迴圈的做法是：以帶標籤的漏洞語料跑完整管線，計算每個家族在每個 CWE 類別上的精確度與召回率，再以 Dawid-Skene 型的 EM 估計家族可靠度，產出建議權重。雛型目前只有 5 個依第 2.2 節研究特徵自製的 vibe-coded 樣本（51 個標籤）；OWASP Juice Shop 與 WebGoat 只提供下載腳本，尚未標註。建議權重的公式是 0.6 ×（0.5 + F1）+ 0.4 ×（2 × DS 可靠度），夾在 0.2 到 2.0 之間，再依被 Skeptic 否證的比率、無效輸出率（超過 10% 時乘 0.8）與紅隊測試結果折抵；它只是建議值，須經人工核定才寫入設定檔。截至 2026 年 10 月 6 日，校準只以 mock 家族執行過。Dawid 與 Skene 於 1979 年提出的演算法能在沒有金標準的情況下同時估計每個項目的真實標籤與每個標註者的混淆矩陣【已證實｜B62】；近期研究已建議在 LLM 標註者一致度低時改用 Dawid-Skene【第三方評論（preprint）｜B63】，也有研究實際以它彙整多個 LLM 的預測【第三方評論（preprint）｜B64】。惡意軟體分類的實證則顯示，平權多數決已勝過最強的單一模型，不分層的加權投票反而略遜於平權投票；階層加權的最終版本只多約 1 個百分點的 accuracy、Macro-F1 相同，也沒有做顯著性檢定【第三方評論（preprint）｜B68】。所以增益主要來自集成本身，本架構「先分層再加權」的順序是設計選擇，目前沒有實證支持它比平權投票更好。

校準必須每季重跑。模型會被供應商更新，自架權重會升版，任何一次升版都會讓舊權重失效。這不是假設：本報告初版（2026 年 9 月）建議的 Claude Opus 5，在 9 月 22 日 Opus 5.5 發布後列為舊版模型【已證實｜B79、B124】（Opus 5 系統卡的內容至今未讀取【尚未證實｜B85】）。這是第九部列出的限制之一。

## 第 12 章　資料可信度模型

### 12.1 問題的兩個層次

「資料可信度」在本報告中有兩個層次。第一層是審查系統輸出的 finding 可不可信，第 11.2 節的 A 到 D 級回答了它。第二層是審查系統輸入的資料可不可信，本章處理。

### 12.2 輸入資料的三種來源與各自的信任規則

**被審查的程式碼**是不可信的，而且是主動敵對的。它可能包含針對審查者的指令（第 9 章）、可能刻意讓工具與模型看到不同的東西（xz-utils 的 tarball 與 git tree 不一致【C6.11】）、可能把惡意行為藏在 build 腳本、Actions cache 或 postinstall 中（Ultralytics【C7.17】、Shai-Hulud【C6.13】）。因此 L1 收集的是「文字」而非「行為」，L2 到 L4 從不執行它。

**外部事實**（CVE、EPSS、KEV、advisory、套件是否存在）只能來自工具查詢，不能來自模型記憶。理由有三：模型有知識截止日；NVD 自 2026 年 4 月起只優先處理少數類別，多數新 CVE 不會很快有官方 enrichment【C2.7】；模型會幻覺出不存在的套件名稱，且幻覺是持續的【C6.10】。雛型的依賴 reviewer prompt 明文禁止模型宣稱具體 CVE。

**Pinned 的標準條文**是本架構唯一預設可信的輸入，但它們必須以機器可讀的形式存放並標明來源與查證日期。雛型的 `groundtruth/` 目錄存放 ASVS 5.0 的章節表（來自官方 CSV）、OWASP Top 10:2025 的類別表與 A10 的 24 個 CWE（來自官方 repo）、API Security Top 10 2023、LLM Top 10 2025 與一個 CWE 子集。任何 finding 引用的 ID 都由確定性程式對照這些檔案，不存在的 ID 被剝除並計入稽核。這個設計直接回應第 10 章開頭的三個常見錯誤：ASVS 5.0 沒有 V1 架構章、Top 10:2025 的順序、BOD 22-01 已廢止。一個流暢的模型會自信地引用「ASVS V1.1.1」，而 pinned 清單讓這個引用在進入報告前就消失。

### 12.3 來源證據的三要件

每個 finding 必須有：檔案路徑、行號、3 到 400 字元的逐字引用。L5 的驗證是確定性的：引用的文字（正規化空白後）必須出現在該檔案該行的 ±3 行內。這個檢查便宜、無法被說服、而且直接打擊最常見的幻覺型態。SecLLMHolmes 顯示模型對變數名稱極為敏感【A116】；來源證據驗證讓「引用一段看起來很像但不存在的程式碼」變成 D 級。在 fixture 上，mock 的 Anthropic 家族刻意產出一個引用不存在程式碼的 SQL injection finding。它在管線中被來源驗證拒絕（D 級），也被 Skeptic 否證（指出該行使用參數化查詢）；但兩個獨立的 judge 家族（judge 不審自家產出）在盲化視圖下正反序都判為 true_positive。這說明 judge 只看主張與摘錄時無法識破捏造，真正有效的防線是確定性的來源驗證；把 judge 當成最後一道防線是錯的。

### 12.4 模型輸出的三重驗證

模型的每個輸出經過 schema 驗證（pydantic，欄位長度、列舉值、正規表示式）、來源證據驗證（第 12.3 節）與標準 ID 驗證（第 12.2 節）。任何一項失敗都不會讓整批輸出作廢，而是讓該個別項目被丟棄並記錄；雛型的偏誤稽核輸出 `invalid_findings_dropped`、`findings_with_unverified_quotes`（含依家族分列）、`standard_refs_stripped`、`unknown_cwe`，以及 Skeptic、Red Team、context 各自的無效項目與截斷計數，它們是各家族「說話可不可信」的直接量測。

### 12.5 拒答與棄權的處理

模型會拒答，尤其在攻擊性的內容上【B39】。本架構把拒答視為棄權而非零 finding：reviewer 拒答時該面向由其他家族覆蓋，稽核記錄 `reviewer_refusals`；judge 拒答時該家族在該批 finding 上沒有票；若因此獨立家族不足，該 finding 轉人工佇列。任何角色的拒答都使整份審查標為不完整。單一 finding 的分歧以家族一致度（agreement proxy，眾數占比的機遇校正）判斷；整批層級則以能處理缺值的 Krippendorff's α 量測（這是選 α 而不選 Cohen's κ 的原因【已證實（處理缺值的部分）｜B72】），並把每個 finding 的每個 judge 家族視為一個評分者，正反序兩次先取平均，不重複計為兩個評分者。Fixture 中 mock 的 Nemotron 家族刻意拒答，用來驗證 `review_status=incomplete`、`overall_score=null` 與 gate 阻擋；其餘家族的輸出仍保留，但不冒稱完整審查。

### 12.6 本報告自身的證據分級

本報告引用的每一項事實都標示四級之一：已證實（法規原文、標準條文、同儕審查論文、官方公告、CVE 條目，且發布日期可驗證）、廠商主張（廠商自述，未經獨立驗證）、第三方評論（分析機構、媒體、研究者評述，預印本歸此類並標明）、尚未證實（有流通但缺乏可驗證來源或來源矛盾）。初版研究環境的一個重要限制是：出口代理伺服器封鎖了 arxiv.org、nist.gov、owasp.org、first.org、w3.org、cisa.gov、github.blog、anthropic.com、openai.com 等大量一手網域，只有 github.com 與 platform.claude.com 可直接讀取。凡未能直接讀取原頁的引用，都在附錄A 標註「依搜尋摘要」，並依技能規範以較嚴的級別標示；arXiv 條目一律標為第三方評論（preprint）。2026 年 10 月 6 日的複核在可連外的環境重新讀取了附錄A 233 條中的 218 條，讀到原文的條目已在附錄A 與 `docs/source-verification.json` 更新狀態並留下核對紀錄；arXiv 條目確認已刊於同儕審查場次者改標已證實；仍未讀到的維持原標示。第九部說明剩餘缺口對結論的影響。

## 第 13 章　去偏誤機制目錄

本章把第 3.2 節的偏誤文獻對應到具體機制與雛型模組。ICLR 2025 的 CALM 框架整理的 12 種偏誤是骨架【B8】，本報告依資安審查的情境增補了四種（相關錯誤、拒答、政治敏感 token、語言）。

| # | 偏誤 | 文獻 | 機制 | 雛型模組 | 稽核指標 |
|---|---|---|---|---|---|
| 1 | 自我偏好（judge 偏好自家輸出） | Panickssery et al. NeurIPS 2024【B1】；Wataoka et al.【B2】 | Skeptic、Red Team 與 judge 的家族應 ≠ 發現者家族（無可用家族時退回同家族並計數）；獨立 judge 不足時同家族票折半、不計入獨立家族數，該 finding 轉人工佇列 | `bias/diversity.py`、`pipeline.run_jury` | `self_preference_exclusions`、`self_family_fallback_votes`、`skeptic_same_family`、`redteam_same_family` |
| 2 | 位置偏誤 | Zheng et al. NeurIPS 2023【B7】；Shi et al.【B9】 | 順序由內容雜湊與 judge 家族決定；每個 judge 正反序各看一次；正反序裁決不同者標記為位置不一致並送人工佇列 | `bias/blinding.py` | `position_flips` |
| 3 | 篇幅偏誤 | Zheng et al.【B7】 | 盲化視圖固定寬度：主張 120、可達性論證 300、攻擊路徑 300、證據引用每段 200（最多三段）、Skeptic 理由 300、控制項 150 字元 | `bias/blinding.py` | 無需指標（結構性消除） |
| 4 | 錨定偏誤 | 2026 年錨定研究【B13】 | judge 看不到任何分數、信心、CVSS 向量與其他 judge 的意見 | `bias/blinding.py` | 無需指標（結構性消除） |
| 5 | 權威與從眾偏誤 | LLMs-as-Judges survey【B12】；通訊系統研究【B16】 | 不顯示引用數量、語氣或「多數同意」；judge 之間無通訊（MARS 的獨立審查者拓樸【B30】） | `agents/judge.py` | 無需指標 |
| 6 | 諂媚（sycophancy） | Sharma et al. ICLR 2024【B55】 | L1 不讀取作者、commit message、PR 描述；prompt 禁止推測作者意圖 | `context/repo_map.py` | 無需指標 |
| 7 | 相關錯誤（家族間錯誤重疊） | Goel et al. ICML 2025【B17】；Kim et al. ICML 2025【B18】 | 家族多樣性是設定檔的硬約束；持續量測 judge 家族兩兩一致率；一致率過高的家族應在校準時折減權重（雛型僅量測，尚未折減） | `bias/diversity.py`、`config.py` | `judge_agreement[家族~家族]`、全域 α |
| 8 | 過度自信 | Tian et al.【B34】 | 自報信心不進入任何計算，只作為校準的觀察值 | `schemas.Finding.model_confidence` | 校準時比對自報信心與實際精確度（雛型未實作） |
| 9 | 訓練資料過時與套件幻覺 | Spracklen et al. USENIX Sec 2025【C6.10】；NVD 政策【C2.7】 | CVE、EPSS、KEV、套件存在性一律工具查詢 | `tools/`、reviewer_dependencies prompt | `standard_refs_stripped` |
| 10 | Prompt injection | OWASP LLM01:2025【B43】；審稿注入研究【B49】 | untrusted 包裹、canary、不執行、來源驗證 | `agents/base.py` | `canary_echoes`、`skeptic_canary_echoes`、`redteam_canary_echoes` |
| 11 | 拒答導致的安靜少報 | 雙模式基準研究【B39】 | 拒答記為棄權；其他家族覆蓋；審查標為不完整；整批 α 處理缺值 | `providers/*`、`scoring/consensus.py` | `reviewer_refusals`、`judge_refusals`、`skeptic_refusals`、`redteam_refusals`、`context_refusals`、`reviewer_errors` |
| 12 | 多輪對話漂移 | Laban et al. 2025【B58】 | 所有呼叫都是單輪、自足的 | 架構層級 | 無需指標 |
| 13 | 共識過早收斂壓掉異議 | debate hacking 研究【B27】 | 無辯論；少數異議進入人工佇列而非被投票淹沒（finding 的 `agreement_proxy` 低於有效門檻即 needs_human） | `pipeline.score` | `human_queue` |
| 14 | 政治敏感 token 影響輸出品質 | CrowdStrike 2025 年 11 月【B97】 | 自架、中性提示模板；校準集納入含敏感詞的樣本比對各家族輸出差異 | 校準迴圈（雛型未實作） | 附錄B 缺口 |
| 15 | 語言偏誤 | 本報告的假設，無直接文獻 | 校準集以中英雙語提示各跑一次 | 校準迴圈（雛型未實作） | 附錄B 缺口 |
| 16 | 評估者自身的 bias sensitivity | Zhao et al. 2026【B14】 | 對同一 finding 做語意保持的擾動（改變數名、重排欄位）再跑 judge，回報裁決變化率 | 校準迴圈（雛型未實作） | 附錄B 缺口 |

第 14 項需要說明。CrowdStrike 於 2025 年 11 月報告，DeepSeek-R1 在中性提示下產出弱點程式碼的比率約 19%，與同儕相當；但當提示中含有與程式任務無關的政治敏感修飾語（西藏、法輪功、維吾爾）時，程式碼明顯較不安全：告知模型是為「設在西藏的工業控制系統」寫程式時，含嚴重弱點的比率升到 27.2%，相對基線增加約 43%（絕對 8.2 個百分點；原文標題稱「近 50%」，而 27.2% 是工業控制系統與西藏的組合條件，不是單獨的西藏），例如為「一家設在西藏的金融機構」寫支付處理程式時出現硬編碼 secret 與較不安全的資料抽取方式；報告並記錄了模型規劃完完整技術回應後拒絕輸出程式碼的「內建開關」（intrinsic kill switch）【第三方評論（廠商研究）｜B97】。這項發現若成立，意味著 DeepSeek 作為審查者的輸出品質取決於被審查程式碼中是否恰好出現某些與安全無關的字串，而這在真實程式庫中是不可控的變數。本報告不因此排除 DeepSeek，但要求：它只能是三個家族之一而非唯一；校準集必須包含含敏感詞與不含敏感詞的配對樣本，量測其輸出差異；差異顯著時降低其權重。這項研究量測的是程式碼生成而非審查，配對樣本如何移植到審查情境、需要多少樣本，見研究筆記 `docs/research-cn2-2026-10-14.md`。正式面板的 GLM 同為中國開發的模型，本次沒有找到針對它的同類研究【尚未證實】，但同一套配對樣本應同樣適用於它。NIST CAISI 於 2025 年 9 月 30 日的評估（對象為 R1、R1-0528 與 V3.1）另指出 DeepSeek 模型被誘導偏離使用者任務的機率是美國前沿模型的約 12 倍、在常見 jailbreak 手法下回應 94% 的明顯惡意請求（美國參考模型為 8%）【已證實｜B95】；2026 年 5 月 1 日對 V4 Pro 的評估只量測能力，結論是落後前沿約 8 個月、cyber CTF 基準 32%，沒有 jailbreak 或 agent hijacking 等安全面的結果，所以上述安全結論還沒有 V4 的版本【已證實｜B96】。

第 7 項是整個目錄中最不能省略的一項。三個家族的設定在數學上很脆弱：一個 finding 若被兩個家族同時發現，只剩一個獨立的 judge；fixture 的稽核顯示有 53 個「judge 家族 × finding」組合只能由發現者的同家族審理（正反序共 106 張折半票），這些票不補足獨立家族數，使 30 個 finding 中有 22 個因獨立 judge 不足而轉人工佇列。ICML 2025 的證據說明即使真正獨立的家族，其錯誤仍高度相關【B17、B18】。因此第十部的建議之一是把家族數擴到四個以上（例如加入自架的 Llama 4 或 Mistral），而不是把三家族視為足夠。
