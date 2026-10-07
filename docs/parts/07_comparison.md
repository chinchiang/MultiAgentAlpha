# 第七部　方案比較

本部的三張比較表在填表前先固定準則，避免準則被偏好的答案反推。

## 第 18 章　架構層級的比較

準則：（1）召回率的證據基礎；（2）精確率的證據基礎；（3）對單一模型偏誤的抗性；（4）對 prompt injection 的抗性；（5）可稽核性（能否從中間產物重算結果）；（6）資料主權（原始碼是否離境）；（7）每次審查的成本量級；（8）導入複雜度。

| 準則 | 純確定性工具（SAST + SCA + secret scanner） | 單一 LLM 審查（如 `/security-review`） | 同質多 agent（同一家族的多個角色） | 異質多 agent 錨定確定性工具（本報告） |
|---|---|---|---|---|
| 召回率證據 | 高於 LLM 於已知 pattern；對架構與授權缺陷幾乎為零（RealVuln 中 Semgrep F3 17.7【A128】） | 對語意缺陷有召回，但不可重現（SecLLMHolmes【A116】） | 無獨立證據高於單一 LLM | 工具召回 + 模型語意召回；IRIS 顯示 27→55【A85】 |
| 精確率證據 | 高誤報（OWASP Benchmark 初始 FP 92%【B37】） | 依模型而異；curl 事件顯示規模化後崩潰【B42】 | 多角色共識提升 P 13.48%（兩頁短文的初步結果）【A89】 | 工具佐證 + 否證 + 盲審；VulAgent FP −36%【A87】 |
| 偏誤抗性 | 無偏誤（無模型） | 無抗性 | 低：同家族錯誤高度相關【B17、B18】 | 中到高：家族互斥、盲審、正反序、持續量測 |
| Injection 抗性 | 免疫 | 低 | 低 | 中：五道防線 + canary 量測 |
| 可稽核性 | 完全 | 低（自由文字） | 中 | 高：每層結構化、分數可重算 |
| 資料主權 | 完全（本地） | 依供應商；Fable 不可 ZDR【B81】 | 依供應商 | 可設計：正式面板為一家族地端、一家族經雲端平台預設不儲存、一家族經核准的有限期保留【B137、B139】；初版設計為兩家族地端 |
| 成本量級 | 低 | 中 | 中高 | 高（約 45 次以上呼叫／全庫） |
| 導入複雜度 | 低 | 低 | 中 | 高 |

結論不是「本報告的架構在每個準則都最好」，它在成本與導入複雜度上明顯最差。它的正當性來自第一、二、三、五列：在 vibe-coded 程式碼的缺陷集中於架構與授權（工具幾乎無召回）且單一 LLM 不可重現的前提下，它是唯一同時提供語意召回與可稽核精確率的選項。若組織的程式碼不是 vibe-coded、缺陷型態以已知 pattern 為主，純確定性工具加單一 LLM 分流是更合理的選擇。

## 第 19 章　商用與開源方案的比較

準則：（1）核心方法；（2）是否公開精確率或召回率的可驗證數據；（3）多模型或多代理的程度；（4）資料主權選項；（5）與確定性工具的整合；（6）證據級別。

| 方案 | 核心方法 | 公開的效能數據 | 多模型／多代理 | 資料主權 | 工具整合 | 證據級別 |
|---|---|---|---|---|---|---|
| Anthropic claude-code-security-review Action（2025-08-06） | Claude Code 分析 + 另一次 LLM 誤報過濾呼叫 + 可讀可改的 prompt 與誤報排除清單 | 無精確率數據；README 自承未防 prompt injection、只應審查可信任的 PR【A1】；預設模型 Opus 4.1 已於 2026-08-05 退役，須自行指定【已證實｜B126】 | 單模型 | Anthropic API；Enterprise 可 ZDR | 無內建 | 原始碼已證實【B84】 |
| Anthropic Claude Security（原 Claude Code Security；2026-02-20 研究預覽，2026-04-30 public beta） | 代理式掃描，每筆 finding 再經一次對抗式驗證 | 宣稱以 Opus 4.6 在開源專案中找到 500+ 個高嚴重度漏洞；Enterprise 掃描現在跑在 Mythos 5.1 上 | 單模型多代理 | Anthropic 雲端 | 無內建 | 廠商主張【A6、A7、B134】 |
| OpenAI Aardvark → Codex Security（2025-10-30 / 2026-03-06） | GPT-5 代理式推理，沙箱驗證每筆 finding | 宣稱 golden repo 92% 召回（OpenAI 原頁未讀到）、10 個 CVE；30 天掃 120 萬 commit、792 critical、10,561 high | 單模型多代理 | OpenAI 雲端（研究預覽），另有 CLI、SDK 與桌面 plugin | 據報不用 fuzzing 或 SCA（未讀到原文） | 廠商主張【A12、A15、A17】 |
| Google CodeMender（2025-10-06）/ Big Sleep | Gemini Deep Think 代理，修補前人工複審 | 72 個上游修補；Big Sleep 攔截 CVE-2025-6965 | 單模型多代理 | Google 雲端 | 使用 debugger、fuzzer、靜態與動態分析、SMT solver | 廠商主張【A18】；CVE 的轉述來源品質偏弱【A22】 |
| GitHub Copilot Autofix / code review / `/security-review`（2026-07-14，public preview） | CodeQL 結果 + LLM 修補；Copilot app 內建安全審查；PR 內另有 CodeQL 之外的 AI 偵測（2026-07-10，public preview，不阻擋合併）；agentic autofix 會把修補模式存進 Copilot Memory 跨次沿用（2026-09-25，public preview） | 修復快 3×、XSS 7×、SQLi 12×（beta 資料） | 單模型 | GitHub 雲端 | Autofix 整合 CodeQL；`/security-review` 只是與 code scanning 互補 | 廠商主張【A26、A31、B135、B136】；Responsible-use 文件已證實【A25】 |
| Semgrep Assistant + MCP（GA 2024-03-20） | LLM + RAG 對每筆 finding 判 TP/FP | TP 與研究員一致 96%、FP 僅 41%；承接約 60% 分流 | 現行文件寫 OpenAI 為主、Amazon Bedrock 備援 | Semgrep 雲端 | 原生（它就是 SAST） | 廠商主張【A37、A38】；文件已證實【A40】 |
| Snyk DeepCode AI / Agent Fix | 符號式 + 生成式混合；2026 年起改以 Anthropic 前沿模型加 Snyk 情資產生修補 | autofix 準確率 85%（約 150 個測試的 85.4%） | Anthropic 模型為主，宣稱不綁模型 | Snyk 雲端 | 原生 | 廠商主張【A43、A44】 |
| Endor Labs AI Security Code Review（2025-04-23） | Developer / Architect / Security 三代理審 PR，標出需要人深入審查的安全變更 | 未公開數字 | 多代理（同家族） | Endor 雲端 | 原生 SCA | 廠商主張【A57】 |
| Endor Labs AI SAST（2025-11-19） | Detection / Triage / Remediation 代理 + 程式分析 | 宣稱 FP −95% | 多代理 | Endor 雲端 | 原生 | 廠商主張【A56】 |
| DryRun / Corgea / ZeroPath / Amplify | AI-native SAST，以推理模型為主偵測引擎 | 自家基準 88%、FP −75% 等 | 依廠商 | 雲端為主 | 部分 | 廠商主張；Joshua Rogers 2025-09 的獨立橫評實測 ZeroPath、Corgea、Amplify 等，未測 DryRun，為第三方評論【A54】 |
| Datadog AI-Enhanced SAST（2025-10-28） | LLM 過濾 SAST 誤報；現行文件另有 AI-native SAST（LLM 偵測 + 第二個 LLM 以 taint 分析獨立複驗） | 未公開數字，blog 坦承過濾過度會漏真問題 | 兩階段 LLM | 只限 Datadog 託管的掃描 | 原生 | 廠商主張【A62】；文件已證實【A63】 |
| NVIDIA Vulnerability Analysis Blueprint | RAG + 代理判斷 CVE 可利用性，輸出 VEX | 2024 年的 Llama3 版本宣稱平行處理比序列快 9.3× | 多代理；3.0 版（2026-08-19）以 Nemotron 3 Ultra 為主代理 | 模型推論可地端（NIM），CVE 研究階段會對外查詢 | 掃描器輸出為輸入 | 廠商主張【A70】；Nemotron 驅動已證實【B132】 |
| 學術：IRIS（ICLR 2025）、RepoAudit（ICML 2025）、VulAgent、GPTScan（ICSE 2024） | LLM + CodeQL／靜態確認／假設驗證 | 同儕審查或預印本的量化結果 | 單模型多代理 | 依部署 | 深度整合 | 已證實或第三方評論【A85、A86、A87、A93】 |
| 本報告 MARA 雛型 | 六層：工具錨定、異質家族、否證、盲審、程式評分 | 僅 fixture 與五個植入漏洞樣本上的 mock 行為驗證，無真實模型的效能數據 | 三家族多代理（正式面板：Claude、Gemini、GLM；冷備援 DeepSeek） | 一家族地端；其餘兩家族經 Bedrock 或附核准單號的 Gemini API；境內可全地端 | 原生（以固定版本執行六個掃描工具，產出 SARIF） | 雛型；效能尚未證實 |

三個觀察。第一，沒有任何商用方案公開可獨立驗證的精確率與召回率；「96% 一致」「FP −95%」全是廠商自述，且各自的基準不同。第二，多模型混編在商用產品中已有先例（Semgrep 的現行文件寫明以 OpenAI 為主、Amazon Bedrock 備援【A40】），但沒有任何產品公開說明它如何處理家族間的偏誤與相關錯誤。第三，最接近本報告架構的商用先例是 Endor Labs 的三代理審查【A57】，最接近的學術先例是 MARS 的獨立審查者【B30】與 Refute-or-Promote 的對抗式階段閘門【B31】（後者也記錄了十個審查者一致背書一個不存在的漏洞，正是相關錯誤的實例）；本報告的差異在於把「異質家族」與「盲審」做成硬約束，並把分數計算完全移出模型。

## 第 20 章　正式面板的三個家族與冷備援在此用途上的適配性

準則：（1）部署方式與資料主權；（2）授權條款；（3）公開的資安相關評估；（4）採購與稽核風險；（5）在本架構中的建議角色。比較對象是雛型自 v0.4.2 起的正式面板（Claude、Gemini、GLM）與冷備援 DeepSeek；初版面板的 Nemotron 不再列入，它的事實見第 7.1 節。

| 準則 | Anthropic Claude（Opus 5.5，經 Amazon Bedrock） | Google Gemini（3.8 Flash，Gemini API 付費層） | 智譜 GLM（GLM-5.3-Flash，IEC 網路內自架） | DeepSeek（V4，冷備援，自架） |
|---|---|---|---|---|
| 部署與資料主權 | 跨境；Bedrock 預設不儲存輸入與輸出，濫用標記的流量最多保留 30 天、不分享給 Anthropic【已證實｜B137】；`global.` 設定檔可在任一 AWS 商用區域處理【已證實｜B138】；與 Anthropic ZDR 是否等同待法務確認【尚未證實】；Fable 系列不可 ZDR【已證實｜B81】 | 跨境；付費層不用於改進產品，但有限期間記錄提示與回應以偵測濫用，天數未載明【已證實｜B139】；不是 ZDR，保證零保留須改用 Vertex AI【已證實｜B140】；雛型以 `vendor_api_retained` 加核准單號放行 | 自架，無資料離境；廠商 API 一律拒絕（P2）；Z.ai 稱 API 內容不儲存、個資在新加坡處理，與本架構無關【廠商主張｜B145】 | 只能自架權重；隱私政策載明資料存於中國【廠商主張｜B88】；API 不得用於原始碼 |
| 授權 | 商業 API 條款（經 AWS） | 商業 API 條款（Gemini API 附加條款）【B139】 | GLM-5.3-Flash 為 MIT；同代的 GLM-5.3 為自訂授權【已證實｜B143】；IEC 實際部署的權重來源與版本未記錄 | V3.2 與 V4 皆為 MIT【已證實｜A75、A78】 |
| 公開資安評估 | 2026 年宣稱 Opus 4.6 找到 500+ 漏洞【廠商主張｜A7】；RealVuln 中 Sonnet 4.6 為最佳通用模型 51.7（26 個 Python repo；榜首是作者自家產品）【第三方評論｜A128】；Opus 5.5 會把多數資安任務轉給 Opus 4.8【廠商主張｜B125】 | 3.8 Flash 沿用 3.7 Flash 的評估，未達任何追蹤或關鍵能力水準【廠商主張｜B150】；Pro 級在 Cyber Uplift Level 1 達警示門檻【廠商主張｜B142】；未找到獨立評估【尚未證實】 | NIST CAISI 2026-07 對 GLM-5.2：防護允許協助代理式漏洞利用開發，對 agent hijacking 與 jailbreak 可能比其他受評中國開放權重模型穩健，自架時防護可被繞過【已證實｜B147】；CAISI 2026-09 對 GLM-5.3：最具 cyber 能力的開放權重模型、落後前沿約 4 個月，只含能力評估、未涵蓋 Flash【已證實｜B146】 | NIST CAISI 2025-09：被誘導偏離任務（agent hijacking）的機率 12 倍、常見 jailbreak 下回應 94% 的明顯惡意請求、軟體工程與 cyber 任務上最佳美國模型多解 20% 以上【已證實｜B95】；CAISI 2026-05 對 V4 Pro：能力落後前沿約 8 個月、cyber CTF 基準 32%，未含安全面測試【已證實｜B96】；CrowdStrike：敏感詞使弱點率最多 +50%【第三方評論｜B97】；Cisco：HarmBench 50 個隨機提示的攻擊成功率 100%【第三方評論｜B98】 |
| 採購與稽核風險 | 低；需確認 Bedrock 的不保留承諾與 ZDR 等同、invocation logging 保持關閉、`global.` 跨區路由是否符合各廠區要求 | 中；資料保留須逐模型核准並記錄單號，換模型時重新核准；Flash 級約每一兩個月出一個正式版【已證實｜B141】，升版即須重新校準 | 高；開發商在美國實體清單上【已證實｜B144】，客戶稽核可能拒絕；ML-BOM 仍為 PENDING | 高；多國政府禁令與立法提案【尚未證實｜B89、B93、A82、A83】，客戶稽核可能拒絕；冷備援所用的 V4-Flash 已被淘汰且無 ML-BOM 項目 |
| 建議角色 | reviewer、judge 與 L1 情境建構；不作為唯一的 skeptic | reviewer、judge 與紅隊（正式設定的 red team） | reviewer、skeptic 與 judge；地端部署使它適合處理最敏感的 repo；校準集應納入敏感詞配對（雛型尚未實作） | 冷備援：任一家族退出時接手；用它替代 GLM 不解決中國關聯的稽核問題 |

這張表的結論是：三個正式家族沒有一個可以單獨承擔審查，也沒有一個應該被排除。Claude 有最強的公開能力證據，但它與 Gemini 都是跨境者；Gemini 是唯一不在零保留條件下接觸原始碼的家族，也是版本漂移最快的一個；GLM 有最強的資料主權保證（自架），卻有最高的採購風險，而且它的安全面只有一份定性評估。與初版面板相比，新面板用 GLM 換掉了 DeepSeek 與 Nemotron 兩個自架家族，跨境家族由一個變成兩個：資料主權的保證變弱，換來的是兩個前沿供應商的雲端模型與較少的自架 GPU 需求。冷備援全部指向 DeepSeek，意味著一旦客戶要求排除中國關聯模型，GLM 被替換後面板仍含中國關聯家族，治理建議 G-4 因此指出這種要求需要另備一個非中國關聯的自架家族。這仍是異質面板的論證：每個家族的弱點都由另一個家族的強項覆蓋，而每個家族的偏誤都被另一個家族的裁決制衡。
