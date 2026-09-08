## 第 11 章　評分方法

### 11.1 設計原則：分數由程式算，模型只提供判斷的輸入

LLM 給出的數字分數不可信。《Overconfidence in LLM-as-a-Judge》系統性地記錄了評審模型的自報信心顯著高估其實際正確率【第三方評論（preprint）｜B34】；《Evaluating Scoring Bias in LLM-as-a-Judge》與同類研究指出評分受提示措辭與順序影響【第三方評論｜B15】。因此本架構中模型從不輸出「分數」，只輸出分數的「輸入」：CVSS 4.0 的各項基礎指標、可利用性的類別、裁決的類別、嚴重度的區間。所有數值都由 L5 的程式計算，可重算、可稽核。

### 11.2 單一 finding 的四個維度

**嚴重度（Severity）。** 由 L2 reviewer 提供 CVSS 4.0 基礎向量（AV、AC、AT、PR、UI、VC、VI、VA、SC、SI、SA 十一個指標），L5 以移植自 FIRST 參考實作的計算器算分。CVSS 4.0 規範於 2023 年 11 月 1 日發布，分為 Base、Threat、Environmental、Supplemental 四組指標，並以 CVSS-B、BT、BE、BTE 命名法標示套用了哪幾組【已證實｜C12.1】。雛型的計算器逐字重現 FIRST 的 MacroVector 查表（270 個 MacroVector）、EQ 最高向量表與嚴重度深度表，並以 FIRST 官方 JavaScript 產生的 16 組參考向量做迴歸測試，全數一致。L4 judge 給出的嚴重度區間中位數作為健全性檢查：若 judge 的中位數低於向量算出的區間，取較低者並記錄「嚴重度被評審團下修」。這個單向下修的設計是刻意的：模型傾向高報嚴重度以顯得重要，評審團只能減不能加。

**可利用性（Exploitability）。** 依 finding 的類型分流。依賴類 finding 以 EPSS 分數與 KEV 是否收錄為準，兩者都由工具查詢而非模型回憶；EPSS v4（2025 年 3 月）只能作為「可能性」軸【已證實｜C6.7】。程式碼類 finding 以 L3 Red Team 的類別（yes、conditional、no、unknown）與 L2 的可達性判斷（reachable、conditional、unreachable、unknown）為準。

**信心（Confidence）。** 由共識分數表示，範圍 0 到 1。計算方式：每個 judge 家族對該 finding 的正序與反序投票取平均（true_positive 記 1、needs_human 記 0.5、false_positive 記 0），再以家族權重加權平均。一個家族在正反序給出不同裁決，其貢獻自然被平均稀釋；同家族在獨立 judge 不足時的投票乘以 0.5 的折減。工具佐證不進入共識分數，而是進入證據層級。

**證據層級（Evidence tier）。** 這是本架構最重要的輸出，也是「資料可信度」問題的直接答案。四級定義如下，判定順序由上而下：

| 層級 | 條件 | 意義 |
|---|---|---|
| D | 來源證據未通過驗證；或 Skeptic 否證且共識分數低於門檻 | 不採納。捏造引用或已被否證 |
| A | 來源證據通過驗證，且 L0 確定性工具在同檔案 ±3 行、CWE 相容處有結果，且至少一個模型家族同意 | 工具與模型指向同一處。最高可信度 |
| B | 來源證據通過驗證，≥2 個模型家族同意（發現或裁決），可達性為 reachable 或 conditional，Skeptic 未否證 | 跨家族共識且有可達論證 |
| C | 來源證據通過驗證，共識分數達門檻，但只有單一家族 | 單一家族的判斷，需人工確認 |

證據層級與第 12 章的「報告本身的證據四級」是兩套不同的東西：前者是 finding 的可信度，後者是本報告引用來源的可信度。混淆兩者是常見的溝通錯誤，第九部會再提醒。

**SSVC 決策。** CISA 的 Stakeholder-Specific Vulnerability Categorization 以決策樹輸出 Track、Track*、Attend、Act 四種行動【已證實｜C6.9】。雛型實作的是簡化版：D 級一律 Track；Critical 且可利用為 yes 或 conditional 且對外曝露是 Act；High 或 Critical 且非不可利用是 Attend；Medium 且可利用是 Track*；其餘 Track。這裡的「可利用」是 Red Team 在審查中的判斷，不是 KEV 意義下的「野外遭利用」，報告中必須如此標示。

### 11.3 為什麼不用 DREAD，也不只用 OWASP Risk Rating

DREAD（Damage、Reproducibility、Exploitability、Affected users、Discoverability）常被引用為 Microsoft 在 2008 年前後因評分主觀且不一致而棄用；但本次研究找不到 Microsoft 的一手棄用聲明，這個說法只能以實務共識的層級陳述【尚未證實｜C12.6】。無論出處，DREAD 的問題在本架構中會被放大：五個主觀維度交給 LLM 打分，正是第 11.1 節要避免的事。OWASP Risk Rating Methodology 的 16 個子因子（威脅代理四項、弱點四項、技術影響四項、業務影響四項，各 0 到 9）【已證實｜C12.2】比 DREAD 結構化得多，是強迫 LLM 輸出固定 schema 的理想格式；但它的業務影響四項（財務、聲譽、合規、隱私）需要組織脈絡，不適合由審查 agent 判斷。本架構的取捨是：技術面用 CVSS 4.0（可重算、業界可比），行動面用 SSVC（決策導向），業務影響留給人工佇列。

### 11.4 面向分數與閘門

每個面向從 100 分起算，每個被採納的 finding 依嚴重度扣分（Critical 40、High 25、Medium 10、Low 3），再乘以證據層級係數（A 1.0、B 0.8、C 0.4、D 0），最低 0 分。整體分數是十一個面向的平均。閘門在兩種情況下阻擋：任何被採納的 A 級或 B 級 finding 嚴重度為 High 或 Critical；或任何面向分數低於 60。C 級 finding 不阻擋，只進入人工佇列。這些數字都在設定檔中，是起始值而非定論；第五部的校準迴圈會修正它們。

雛型在 fixture 上的實際輸出如下（三個 mock 家族、三個預錄的 SARIF）：整體 67.0 分，閘門阻擋；十一個面向中機密外洩 20 分（三個 A 級 Critical）、認證授權 40 分、GitHub Actions 45 分為最低；30 個去重後的 finding 中 27 個被採納、3 個不採納（一個捏造引用、一個位置不一致的 open redirect、一個單家族的 hygiene 問題）。這個分布與 fixture 的設計意圖一致，也與第 2.2 節引用的 Apiiro 觀察（缺陷集中在權限與架構）一致。

### 11.5 校準：從 seeded benchmark 到家族權重

家族權重的初始值都是 1.0，這是無知的表現而不是判斷。校準迴圈的做法是：以帶標籤的漏洞語料（OWASP Juice Shop、WebGoat、以及依第 2.2 節研究特徵自製的 vibe-coded 樣本）跑完整管線，計算每個家族在每個 CWE 類別上的精確度與召回率，再依 Dawid-Skene 型的 EM 估計更新家族權重。Dawid 與 Skene 於 1979 年提出的演算法能在沒有金標準的情況下同時估計每個項目的真實標籤與每個標註者的混淆矩陣【已證實（DOI 本次未驗）｜B62】；2026 年的研究已將其用於 LLM 標註者【第三方評論（preprint）｜B63、B64】。有趣的是，惡意軟體分類的實證顯示平權多數決已勝過個別模型，而加權投票的額外增益有限，真正帶來改善的是階層結構【第三方評論（preprint）｜B68】；這與本架構「先分層再加權」的順序一致。

校準必須每季重跑。模型會被供應商更新（Claude Opus 5 的系統卡與行為說明本次無法讀取【尚未證實｜B85】），自架權重會升版，任何一次升版都會讓舊權重失效。這是第九部列出的限制之一。

## 第 12 章　資料可信度模型

### 12.1 問題的兩個層次

「資料可信度」在本報告中有兩個層次。第一層是審查系統輸出的 finding 可不可信，第 11.2 節的 A 到 D 級回答了它。第二層是審查系統輸入的資料可不可信，本章處理。

### 12.2 輸入資料的三種來源與各自的信任規則

**被審查的程式碼**是不可信的，而且是主動敵對的。它可能包含針對審查者的指令（第 9 章）、可能刻意讓工具與模型看到不同的東西（xz-utils 的 tarball 與 git tree 不一致【C6.11】）、可能把惡意行為藏在 build 腳本、Actions cache 或 postinstall 中（Ultralytics【C7.17】、Shai-Hulud【C6.13】）。因此 L1 收集的是「文字」而非「行為」，L2 到 L4 從不執行它。

**外部事實**（CVE、EPSS、KEV、advisory、套件是否存在）只能來自工具查詢，不能來自模型記憶。理由有三：模型有知識截止日；NVD 自 2026 年 4 月起的縮編使多數新 CVE 缺乏官方 enrichment【C2.7】；模型會幻覺出不存在的套件名稱，且幻覺是持續的【C6.10】。雛型的依賴 reviewer prompt 明文禁止模型宣稱具體 CVE。

**Pinned 的標準條文**是本架構唯一預設可信的輸入，但它們必須以機器可讀的形式存放並標明來源與查證日期。雛型的 `groundtruth/` 目錄存放 ASVS 5.0 的章節表（來自官方 CSV）、OWASP Top 10:2025 的類別表與 A10 的 24 個 CWE（來自官方 repo）、API Security Top 10 2023、LLM Top 10 2025 與一個 CWE 子集。任何 finding 引用的 ID 都由確定性程式對照這些檔案，不存在的 ID 被剝除並計入稽核。這個設計直接回應第 10 章開頭的三個常見錯誤：ASVS 5.0 沒有 V1 架構章、Top 10:2025 的順序、BOD 22-01 已廢止。一個流暢的模型會自信地引用「ASVS V1.1.1」，而 pinned 清單讓這個引用在進入報告前就消失。

### 12.3 來源證據的三要件

每個 finding 必須有：檔案路徑、行號、3 到 400 字元的逐字引用。L5 的驗證是確定性的：引用的文字（正規化空白後）必須出現在該檔案該行的 ±3 行內。這個檢查便宜、無法被說服、而且直接打擊最常見的幻覺型態。SecLLMHolmes 顯示模型對變數名稱極為敏感【A116】；來源證據驗證讓「引用一段看起來很像但不存在的程式碼」變成 D 級。在 fixture 上，mock 的 Anthropic 家族刻意產出一個引用不存在程式碼的 SQL injection finding，它在管線中同時被來源驗證拒絕、被 Skeptic 否證（指出該行使用參數化查詢）、被三個 judge 家族一致判為 false_positive；三道防線各自獨立地抓到它。

### 12.4 模型輸出的三重驗證

模型的每個輸出經過 schema 驗證（pydantic，欄位長度、列舉值、正規表示式）、來源證據驗證（第 12.3 節）與標準 ID 驗證（第 12.2 節）。任何一項失敗都不會讓整批輸出作廢，而是讓該個別項目被丟棄並記錄；雛型的偏誤稽核輸出 `invalid_findings_dropped`、`findings_with_unverified_quotes`、`standard_refs_stripped` 三個計數，它們是各家族「說話可不可信」的直接量測。

### 12.5 拒答與棄權的處理

模型會拒答，尤其在攻擊性的內容上【B39】。本架構把拒答視為棄權而非零 finding：reviewer 拒答時該面向由其他家族覆蓋，稽核記錄 `reviewer_refusals`；judge 拒答時該家族在該批 finding 上沒有票，共識分數只以有票的家族計算，Krippendorff's α 天生能處理缺值（這是選 α 而不選 Cohen's κ 的原因【已證實｜B72】）。Fixture 中 mock 的 Nemotron 家族刻意在錯誤處理面向拒答，管線正確地以另外兩個家族完成該面向。

### 12.6 本報告自身的證據分級

本報告引用的每一項事實都標示四級之一：已證實（法規原文、標準條文、同儕審查論文、官方公告、CVE 條目，且發布日期可驗證）、廠商主張（廠商自述，未經獨立驗證）、第三方評論（分析機構、媒體、研究者評述，預印本歸此類並標明）、尚未證實（有流通但缺乏可驗證來源或來源矛盾）。本次研究環境的一個重要限制是：出口代理伺服器封鎖了 arxiv.org、nist.gov、owasp.org、first.org、w3.org、cisa.gov、github.blog、anthropic.com、openai.com 等大量一手網域，只有 github.com 與 platform.claude.com 可直接讀取。凡未能直接讀取原頁的引用，都在附錄A 標註「依搜尋摘要」，並依技能規範以較嚴的級別標示；arXiv 條目一律標為第三方評論（preprint）。這使附錄B 的查證缺口比往常更多，第九部會說明其對結論的影響。

## 第 13 章　去偏誤機制目錄

本章把第 3.2 節的偏誤文獻對應到具體機制與雛型模組。ICLR 2025 的 CALM 框架整理的 12 種偏誤是骨架【B8】，本報告依資安審查的情境增補了四種（相關錯誤、拒答、政治敏感 token、語言）。

| # | 偏誤 | 文獻 | 機制 | 雛型模組 | 稽核指標 |
|---|---|---|---|---|---|
| 1 | 自我偏好（judge 偏好自家輸出） | Panickssery et al. NeurIPS 2024【B1】；Wataoka et al.【B2】 | Skeptic 與 judge 的家族必須 ≠ 發現者家族；獨立 judge 不足時同家族票折半 | `bias/diversity.py`、`pipeline.run_jury` | `self_preference_exclusions`、`self_family_fallback_votes` |
| 2 | 位置偏誤 | Zheng et al. NeurIPS 2023【B7】；Shi et al.【B9】 | 順序由內容雜湊決定；每個 judge 正反序各看一次；正反序裁決不同者標記並折半 | `bias/blinding.py` | `position_flips` |
| 3 | 篇幅偏誤 | Zheng et al.【B7】 | 盲化視圖固定寬度：主張 120、論證 300、路徑 300 字元 | `bias/blinding.py` | 無需指標（結構性消除） |
| 4 | 錨定偏誤 | 2026 年錨定研究【B13】 | judge 看不到任何分數、信心、CVSS 向量與其他 judge 的意見 | `bias/blinding.py` | 無需指標（結構性消除） |
| 5 | 權威與從眾偏誤 | LLMs-as-Judges survey【B12】；通訊系統研究【B16】 | 不顯示引用數量、語氣或「多數同意」；judge 之間無通訊（MARS 拓樸【B30】） | `agents/judge.py` | 無需指標 |
| 6 | 諂媚（sycophancy） | Sharma et al. ICLR 2024【B55】 | L1 剝除作者、commit message、PR 描述；prompt 禁止推測作者意圖 | `context/repo_map.py` | 無需指標 |
| 7 | 相關錯誤（家族間錯誤重疊） | Goel et al. ICML 2025【B17】；Kim et al. ICML 2025【B18】 | 家族多樣性是設定檔的硬約束；持續量測 judge 家族兩兩一致率；一致率過高的家族在校準時折減權重 | `bias/diversity.py`、`config.py` | `judge_agreement[家族~家族]`、全域 α |
| 8 | 過度自信 | Tian et al.【B34】 | 自報信心不進入任何計算，只作為校準的觀察值 | `schemas.Finding.model_confidence` | 校準時比對自報信心與實際精確度 |
| 9 | 訓練資料過時與套件幻覺 | Spracklen et al. USENIX Sec 2025【C6.10】；NVD 政策【C2.7】 | CVE、EPSS、KEV、套件存在性一律工具查詢 | `tools/`、reviewer_dependencies prompt | `standard_refs_stripped` |
| 10 | Prompt injection | OWASP LLM01:2025【B43】；審稿注入研究【B49】 | untrusted 包裹、canary、不執行、來源驗證 | `agents/base.py` | `canary_echoes` |
| 11 | 拒答導致的安靜少報 | 雙模式基準研究【B39】 | 拒答記為棄權；其他家族覆蓋；α 處理缺值 | `providers/*`、`scoring/consensus.py` | `reviewer_refusals`、`judge_refusals` |
| 12 | 多輪對話漂移 | Laban et al. ICLR 2026【B58】 | 所有呼叫都是單輪、自足的 | 架構層級 | 無需指標 |
| 13 | 共識過早收斂壓掉異議 | debate hacking 研究【B27】 | 無辯論；少數異議進入人工佇列而非被投票淹沒（α 低於門檻即 needs_human） | `pipeline.score` | `human_queue` |
| 14 | 政治敏感 token 影響輸出品質 | CrowdStrike 2025 年 11 月【B97】 | 自架、中性提示模板；校準集納入含敏感詞的樣本比對各家族輸出差異 | 校準迴圈 | 校準報告 |
| 15 | 語言偏誤 | 本報告的假設，無直接文獻 | 校準集以中英雙語提示各跑一次 | 校準迴圈 | 校準報告 |
| 16 | 評估者自身的 bias sensitivity | Zhao et al. 2026【B14】 | 對同一 finding 做語意保持的擾動（改變數名、重排欄位）再跑 judge，回報裁決變化率 | 校準迴圈（雛型未實作） | 附錄B 缺口 |

第 14 項需要說明。CrowdStrike 於 2025 年 11 月報告，DeepSeek-R1 在中性提示下產出弱點程式碼的比率約 19%，與同儕相當；但當提示中含有與程式任務無關的政治敏感詞（西藏、法輪功、維吾爾）時，嚴重弱點的機率最多上升 50%，例如「為一家西藏的金融機構」寫 PayPal webhook 處理器時出現硬編碼 secret 與較不安全的資料抽取方式；報告並記錄了模型規劃完完整技術回應後拒絕輸出程式碼的「內建開關」【第三方評論（廠商研究，原頁被擋）｜B97】。這項發現若成立，意味著 DeepSeek 作為審查者的輸出品質取決於被審查程式碼中是否恰好出現某些與安全無關的字串，而這在真實程式庫中是不可控的變數。本報告不因此排除 DeepSeek，但要求：它只能是三個家族之一而非唯一；校準集必須包含含敏感詞與不含敏感詞的配對樣本，量測其輸出差異；差異顯著時降低其權重。NIST CAISI 於 2025 年 9 月 30 日的評估另指出 DeepSeek R1-0528 遵從惡意指令的機率是美國前沿模型的約 12 倍、在公開 jailbreak 提示下 95% 到 100% 產出釣魚與惡意程式內容【已證實（頁面被擋，依搜尋摘要）｜B95】，2026 年 5 月對 V4 Pro 的評估則只取得標題【尚未證實｜B96】。

第 7 項是整個目錄中最不能省略的一項。三個家族的設定在數學上很脆弱：一個 finding 若被兩個家族同時發現，只剩一個獨立的 judge；fixture 的稽核顯示 53 張票是同家族折半票。ICML 2025 的證據說明即使真正獨立的家族，其錯誤仍高度相關【B17、B18】。因此第十部的建議之一是把家族數擴到四個以上（例如加入自架的 Llama 4 或 Mistral），而不是把三家族視為足夠。
