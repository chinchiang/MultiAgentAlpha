# 第七部　方案比較

本部的三張比較表在填表前先固定準則，避免準則被偏好的答案反推。

## 第 18 章　架構層級的比較

準則：（1）召回率的證據基礎；（2）精確率的證據基礎；（3）對單一模型偏誤的抗性；（4）對 prompt injection 的抗性；（5）可稽核性（能否從中間產物重算結果）；（6）資料主權（原始碼是否離境）；（7）每次審查的成本量級；（8）導入複雜度。

| 準則 | 純確定性工具（SAST + SCA + secret scanner） | 單一 LLM 審查（如 `/security-review`） | 同質多 agent（同一家族的多個角色） | 異質多 agent 錨定確定性工具（本報告） |
|---|---|---|---|---|
| 召回率證據 | 高於 LLM 於已知 pattern；對架構與授權缺陷幾乎為零（RealVuln 中 Semgrep F3 17.7【A128】） | 對語意缺陷有召回，但不可重現（SecLLMHolmes【A116】） | 無獨立證據高於單一 LLM | 工具召回 + 模型語意召回；IRIS 顯示 27→55【A85】 |
| 精確率證據 | 高誤報（OWASP Benchmark 初始 FP 92%【B37】） | 依模型而異；curl 事件顯示規模化後崩潰【B42】 | 多角色共識提升 P 13.48%【A89】 | 工具佐證 + 否證 + 盲審；VulAgent FP −36%【A87】 |
| 偏誤抗性 | 無偏誤（無模型） | 無抗性 | 低：同家族錯誤高度相關【B17、B18】 | 中到高：家族互斥、盲審、正反序、持續量測 |
| Injection 抗性 | 免疫 | 低 | 低 | 中：五道防線 + canary 量測 |
| 可稽核性 | 完全 | 低（自由文字） | 中 | 高：每層結構化、分數可重算 |
| 資料主權 | 完全（本地） | 依供應商；Fable 不可 ZDR【B81】 | 依供應商 | 可設計：兩家族地端、一家族 ZDR |
| 成本量級 | 低 | 中 | 中高 | 高（約 45 次以上呼叫／全庫） |
| 導入複雜度 | 低 | 低 | 中 | 高 |

結論不是「本報告的架構在每個準則都最好」，它在成本與導入複雜度上明顯最差。它的正當性來自第一、二、三、五列：在 vibe-coded 程式碼的缺陷集中於架構與授權（工具幾乎無召回）且單一 LLM 不可重現的前提下，它是唯一同時提供語意召回與可稽核精確率的選項。若組織的程式碼不是 vibe-coded、缺陷型態以已知 pattern 為主，純確定性工具加單一 LLM 分流是更合理的選擇。

## 第 19 章　商用與開源方案的比較

準則：（1）核心方法；（2）是否公開精確率或召回率的可驗證數據；（3）多模型或多代理的程度；（4）資料主權選項；（5）與確定性工具的整合；（6）證據級別。

| 方案 | 核心方法 | 公開的效能數據 | 多模型／多代理 | 資料主權 | 工具整合 | 證據級別 |
|---|---|---|---|---|---|---|
| Anthropic claude-code-security-review Action（2025-08-06） | 單一 Claude 呼叫 + 可讀可改的 prompt + 誤報排除清單 | 無精確率數據；2026 年宣稱 Opus 4.6 找到 500+ 漏洞 | 單模型 | Anthropic API；Enterprise 可 ZDR | 無內建 | 原始碼已證實【B84】；效能廠商主張【A6、A7】 |
| OpenAI Aardvark → Codex Security（2025-10-30 / 2026-03-06） | GPT-5 代理式推理，沙箱驗證每筆 finding | 宣稱 golden repo 92% 召回、10 個 CVE；30 天掃 120 萬 commit、792 critical | 單模型多代理 | OpenAI 雲端 | 明言不用 fuzzing 或 SCA | 廠商主張【A12、A15、A17】 |
| Google CodeMender / Big Sleep | Gemini Deep Think 代理，修補前人工複審 | 72 個上游修補；Big Sleep 攔截 CVE-2025-6965 | 單模型多代理 | Google 雲端 | 使用 debugger、fuzzer | 廠商主張【A18】；CVE 已證實【A22】 |
| GitHub Copilot Autofix / code review / `/security-review`（2026-07-14） | CodeQL 結果 + LLM 修補；Copilot app 內建安全審查 | 修復快 3×、XSS 7×、SQLi 12×；逾三分之二建議可直接套用 | 單模型 | GitHub 雲端 | 深度整合 CodeQL | 廠商主張【A26】；Responsible-use 文件已證實【A25】 |
| Semgrep Assistant + MCP（GA 2024-03-20） | LLM + RAG 對每筆 finding 判 TP/FP | 與研究員一致 96%；承接 60% 分流 | 文件曾混用 OpenAI 與 Claude on Bedrock | Semgrep 雲端；可自帶 key | 原生（它就是 SAST） | 廠商主張【A37、A38】；文件已證實【A40】 |
| Snyk DeepCode AI | 符號式 + 生成式混合，修補後以符號規則複驗 | autofix 準確率 85% | 多模型（廠商自述） | Snyk 雲端 | 原生 | 廠商主張【A43、A44】 |
| Endor Labs AI Code Security Review（2025-11-19） | Developer / Architect / AppSec 三專家代理審 PR | 宣稱 FP −95% | 多代理（同家族） | Endor 雲端 | 原生 SCA | 廠商主張【A56、A57】 |
| DryRun / Corgea / ZeroPath / Amplify | AI-native SAST，以推理模型為主偵測引擎 | 自家基準 88%、FP −75% 等 | 依廠商 | 雲端為主 | 部分 | 廠商主張；Joshua Rogers 2025-09 獨立橫評為第三方評論【A54】 |
| Datadog AI-Enhanced SAST（2025-10-28） | LLM 過濾 SAST 誤報 | 未公開數字，坦承過濾過度會漏真問題 | 單模型 | Datadog 雲端 | 原生 | 廠商主張【A62】；文件已證實【A63】 |
| NVIDIA Vulnerability Analysis Blueprint | RAG + 代理判斷 CVE 可利用性，輸出 VEX | 宣稱 9.3× 加速 | 多代理；據稱以 Nemotron 3 Ultra 驅動 | 完全地端（NIM） | 掃描器輸出為輸入 | 廠商主張【A70】；Nemotron 驅動一事尚未證實【A72】 |
| 學術：IRIS（ICLR 2025）、RepoAudit、VulAgent、GPTScan（ICSE 2024） | LLM + CodeQL／靜態確認／假設驗證 | 同儕審查或預印本的量化結果 | 單模型多代理 | 依部署 | 深度整合 | 已證實或第三方評論【A85、A86、A87、A93】 |
| 本報告 MARA 雛型 | 六層：工具錨定、異質家族、否證、盲審、程式評分 | 僅 fixture 上的行為驗證，無真實模型的效能數據 | 三家族多代理 | 可設計為兩家族地端 | 原生（SARIF 匯入） | 雛型；效能尚未證實 |

三個觀察。第一，沒有任何商用方案公開可獨立驗證的精確率與召回率；「96% 一致」「FP −95%」全是廠商自述，且各自的基準不同。第二，多模型混編在商用產品中已有先例（Semgrep 的文件曾同時列出 OpenAI 與 Claude on Bedrock【A40】），但沒有任何產品公開說明它如何處理家族間的偏誤與相關錯誤。第三，最接近本報告架構的商用先例是 Endor Labs 的三專家代理【A57】，最接近的學術先例是 MARS 的無通訊三審查者【B30】與 Refute-or-Promote 的對抗式階段閘門【B31】；本報告的差異在於把「異質家族」與「盲審」做成硬約束，並把分數計算完全移出模型。

## 第 20 章　三個模型家族在此用途上的適配性

準則：（1）部署方式與資料主權；（2）授權條款；（3）公開的資安相關評估；（4）採購與稽核風險；（5）在本架構中的建議角色。

| 準則 | Anthropic Claude（Opus 5） | DeepSeek（V3.2 / V4） | NVIDIA Nemotron 3 |
|---|---|---|---|
| 部署與資料主權 | API 或 Bedrock / Vertex / Foundry；ZDR 需申請；Fable 系列不可 ZDR【尚未證實｜B79–B82】 | 只能自架權重；隱私政策載明資料存於中國【廠商主張｜B88】；API 不得用於原始碼 | NIM 地端，無資料離境【廠商主張｜B102】 |
| 授權 | 商業 API 條款 | V3.2 為 MIT【已證實｜A75】；V4 授權尚未證實 | NVIDIA Open Model License 或 OpenMDW【尚未證實｜B100】 |
| 公開資安評估 | 2026 年宣稱 Opus 4.6 找到 500+ 漏洞【第三方評論｜A7】；RealVuln 中 Sonnet 4.6 為最佳通用模型 51.7【第三方評論｜A128】 | NIST CAISI 2025-09：遵從惡意指令 12 倍、jailbreak 95–100%、cyber 任務完成率較低【尚未證實（摘要）｜B95】；CrowdStrike：敏感詞使弱點率最多 +50%【第三方評論｜B97】；Cisco：HarmBench 攻擊成功率 100%【第三方評論｜B98】 | 本次未找到針對 Nemotron 3 的獨立資安評估【尚未證實】 |
| 採購與稽核風險 | 低；需確認 ZDR 涵蓋範圍 | 高；多國政府禁令與立法提案【尚未證實｜B89、B93、A82、A83】，客戶稽核可能拒絕 | 低；NVIDIA 為美系供應商 |
| 建議角色 | 三個家族中唯一跨境者；作為 reviewer 與 judge，不作為唯一的 skeptic | reviewer 與 judge 之一；必須是可抽換的家族；校準集納入敏感詞配對 | reviewer、skeptic 與 judge；地端部署使它適合處理最敏感的 repo |

這張表的結論是：三個家族沒有一個可以單獨承擔審查，也沒有一個應該被排除。Claude 有最強的公開能力證據但是唯一的跨境者；DeepSeek 有最強的自架彈性但有最多的採購與行為風險；Nemotron 有最強的資料主權保證但最少的獨立評估。這正是異質面板的論證：每個家族的弱點都由另一個家族的強項覆蓋，而每個家族的偏誤都被另一個家族的裁決制衡。
