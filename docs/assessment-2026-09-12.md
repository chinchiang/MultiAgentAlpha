# 六層差距評估（2026-09-12）

依附錄 D 的 60 題問卷（`docs/appendix-d-maturity.md`），對本組織目前的程式碼審查流程做差距評估。本檔由附錄 E 的 prompt 3 產出。

## 0. 評估範圍、證據與規則

**評估對象。** 本 repo（`chinchiang/MultiAgentAlpha`）所代表的程式碼審查流程：MARA 雛型本身、它的 GitHub Actions workflow、設定檔與校準工具。

**可用證據。** 只有本 repo 的檔案：`.github/workflows/mara-review.yml`、`config/`、`src/mara/`、`tests/`、`scripts/`、`calib/`、`docs/`。對話中沒有提供任何關於組織其他 repo、工單系統、人力或流程的說明，因此凡是問「每個 repo」「定期」「接工單」「每季」的題目，若本 repo 內沒有對應證據，一律給 0 分並標「無證據」，不推測。

**評分規則（附錄 D 的五級如何套到本 repo）。**

| 分數 | 附錄 D 定義 | 本次判定方式 |
|---|---|---|
| 0 | 沒有做 | repo 內找不到任何實作或執行紀錄 |
| 1 | 臨時或個案 | 只有設計文字（報告、prompt 檔、註解）或只有未接進管線的程式片段 |
| 2 | 有文件但未全面 | 程式已實作並有測試，但只在 mock 模式、或只涵蓋部分角色／工具、或未進 CI 阻擋 |
| 3 | 全面執行且有紀錄 | 程式強制執行、CI 每次 PR 都跑、輸出留在 `out/` 或 `bias_audit` 中可查（PR #1 到 #3 的 check run 為紀錄） |
| 4 | 全面執行、有量測、有持續改善 | 需要跨期量測與改善紀錄；本 repo 只有一次 mock 校準，無任何題目達此級 |

**兩個必須先講的限制。** 第一，CI 只跑 mock 模式，三個真實家族（Claude、DeepSeek、Nemotron）從未在本 repo 執行過（`docs/calibration-2026-09-11.md` 開頭已註明），所以所有 L2 到 L5 的 3 分都是「機制由程式強制且在 mock 下驗證」，不是「真實模型上已驗證」。第二，本 repo 是唯一的 repo，「每個 repo」類題目的滿分上限實際上受限於樣本數為一。

## 1. 逐題評分

### L0 確定性錨定層

| # | 題目 | 分數 | 證據 |
|---|---|---:|---|
| 1 | 每個 repo 的 CI 都執行 SAST（semgrep 或 CodeQL）並輸出 SARIF | 1 | `src/mara/tools/runner.py` 有 semgrep 包裝（`--sarif`），但 `.github/workflows/mara-review.yml` 沒有 semgrep 步驟；CI 的 mock review 讀的是預錄的 `fixtures/vuln-sample-sarif/`。有包裝、無執行 |
| 2 | 每個 repo 的 CI 都執行 secret scanner（gitleaks、TruffleHog 或 detect-secrets） | 2 | workflow `deterministic-tools` job 以 `gitleaks/gitleaks-action` 執行並輸出 SARIF，但 `continue-on-error: true`、`GITLEAKS_ENABLE_UPLOAD_GITHUB: "false"`，結果不阻擋也不上傳 |
| 3 | 每個 repo 的 CI 都執行 SCA（OSV-Scanner、Trivy 或 Grype）且以 OSV 而非只以 CPE 比對 | 1 | `runner.py` 有 osv-scanner 與 trivy 包裝，均以 OSV 比對；workflow 沒有任何 SCA 步驟 |
| 4 | 所有 GitHub Actions workflow 都經 zizmor 或 actionlint 檢查 | 2 | workflow 以 `zizmorcore/zizmor-action` 檢查（本 repo 唯一的 workflow），但 `continue-on-error: true`（註解：fixture 的 workflow 刻意觸發 zizmor），所以不阻擋 |
| 5 | OpenSSF Scorecard 定期對所有 repo 執行並追蹤分數 | 0 | 無證據。`src/mara/prompts/reviewer_github_actions.md` 只在文字中提到 Scorecard 的檢查項，沒有任何執行 |
| 6 | CSP 政策以 csp-evaluator 自動檢查 | 0 | 無證據。`runner.py` 的 `TOOL_DIMENSIONS` 沒有 csp-evaluator；`csp` 面向只有 LLM prompt（`reviewer_csp.md`） |
| 7 | 工具版本固定並有簽章或雜湊驗證 | 2 | workflow 中四個 action 全部固定到完整 commit SHA（checkout、setup-python、zizmor-action、gitleaks-action、upload-artifact）；但 `runner.py` 直接呼叫 PATH 上的 semgrep/gitleaks/osv-scanner/zizmor/trivy，無版本固定也無雜湊；`pyproject.toml` 只有下限版本 |
| 8 | 工具在隔離 runner 執行，與模型呼叫分屬不同 job | 3 | workflow 分為 `deterministic-tools` 與 `tests-and-mock-review` 兩個 job，後者 `needs` 前者，各自 `permissions: contents: read`、`persist-credentials: false`；每次 PR 都跑（PR #1 到 #3 check runs）。備註：job 之間沒有以 artifact 傳遞 SARIF，job B 讀的是 repo 內預錄的 SARIF |
| 9 | 工具結果上傳至集中式 code scanning 或等效系統 | 1 | 只有 `actions/upload-artifact` 把 `out/` 存為 artifact；沒有 `codeql-action/upload-sarif`，gitleaks 上傳明示關閉 |
| 10 | 工具結果作為模型審查的校準集使用 | 1 | `pipeline.py` 的 `_tool_corroborates` 只把工具結果當作證據層級 A 的佐證；`scripts/calibrate.py` 的校準集是 `calib/samples/*/labels.json`（人工標籤），不使用工具結果。報告第 15 章有此設計，程式未做 |

### L1 情境建構層

| # | 題目 | 分數 | 證據 |
|---|---|---:|---|
| 11 | 審查前自動建立 repo 的入口點與信任邊界清單 | 2 | `src/mara/context/repo_map.py` 的 `_ENTRY_PATTERNS` 自動抓 Flask/FastAPI/Express 入口點並寫進 `RepoContext.entry_points`；信任邊界沒有任何產出 |
| 12 | 審查輸入剝除 commit message、作者與 PR 描述 | 3 | `repo_map.py` 只讀工作樹檔案、`SKIP_DIRS` 排除 `.git`，從不讀 git 中繼資料或 PR 事件；`_common_system.md` 規則 7 禁止提及作者；`tests/test_agent_harness.py::test_context_strips_nothing_but_records_entry_points` |
| 13 | 依賴清單與 workflow 清單自動納入審查範圍 | 3 | `repo_map.py` 的 `MANIFESTS` 與 `.github/workflows` 偵測，寫入 `RepoContext.manifests` / `workflows` 並進入 `bundle()`；`ctx.summary()` 列出兩者 |
| 14 | 增量審查會納入與變更相關的檔案而非只有 diff | 0 | 無證據。`build_context` 只有全 repo 模式，沒有 diff 或增量模式，因此「相關檔案」的規則不存在 |
| 15 | bundle 有大小上限且超限時有明確的優先規則 | 2 | `repo_map.py` 有 `MAX_FILE_BYTES = 200_000`、`MAX_TOTAL_CHARS = 400_000`；超限的檔案依路徑排序被靜默略過，沒有優先規則，也不記錄略過了什麼 |
| 16 | 被審查內容以明確標籤包裹為不可信資料 | 3 | `src/mara/agents/base.py::untrusted_block` 以 `<untrusted_repository_data>` 與每檔 `<file path=...>` 包裹；`_common_system.md` 規則 1 宣告為資料；reviewer、skeptic、redteam 三種呼叫都經此函式 |
| 17 | 每次審查植入 canary 並記錄回應率 | 3 | `base.py::Canary` 每次 review 產生隨機 token 並植入 bundle；`pipeline.py` 記錄 `canary_echoes` 與 `canary_echoes[family]` 進 `bias_audit`；`tests/test_agent_harness.py::test_canary_is_planted_and_detected` |
| 18 | 審查內容的雜湊作為可重現性的種子 | 3 | `repo_map.py` 計算 `content_hash`（SHA-256）；`bias/blinding.py::blinded_batches` 以 `content_hash + family` 作亂數種子；`tests/test_bias_and_scoring.py::test_reverse_pass_is_exact_mirror_and_seeded_order_is_deterministic` |
| 19 | C4 或等效的架構視圖由審查自動產生 | 1 | `src/mara/prompts/context.md` 存在，但 `pipeline.py` 從未呼叫它；沒有任何架構視圖輸出 |
| 20 | 情境建構的產出可被人工查閱 | 2 | `cli.py::review` 把 `pipeline.log` 寫到 `out/`，其中 `L1:` 一行是 `ctx.summary()`（檔案數、語言、manifest、workflow、入口點）；送給模型的完整 bundle 本身沒有存檔 |

### L2 專家審查層

| # | 題目 | 分數 | 證據 |
|---|---|---:|---|
| 21 | 十一個面向都有專屬的審查 prompt | 3 | `src/mara/prompts/reviewer_*.md` 共 11 個，`agents/reviewer.py::review_dimension` 依面向載入；`config/mara.yaml` 的 `dimensions` 列 11 項 |
| 22 | 每個面向至少由兩個不同模型家族獨立審查 | 3 | `pipeline.py::run_reviewers` 對每個面向逐一呼叫 `roles.reviewers` 全部；`policy.py` P3 要求 reviewer 家族數 ≥ 3（恰為 2 需書面理由）；`tests/test_policy.py` |
| 23 | 審查者之間沒有任何通訊 | 3 | `run_reviewers` 每次呼叫只帶 `ctx` 與 prompt，不帶其他家族的輸出；`pipeline.py` 檔頭註解明示 |
| 24 | 模型輸出限制為嚴格的 JSON schema 並經驗證 | 3 | `reviewer.py::FINDING_SCHEMA`（`additionalProperties: false`）、`judge.py::JUDGE_SCHEMA`、`skeptic.py`、`redteam.py` 皆同；`base.py::parse_items` 以 pydantic 驗證，無效項計入 `invalid_findings_dropped` |
| 25 | 每個 finding 都有檔案、行號與逐字引用 | 3 | `FINDING_SCHEMA.provenance` 為 `minItems: 1`，每項必填 `file`、`line`、`quote`（3 到 400 字元）；`schemas.py::Provenance` |
| 26 | 引用不存在於檔案的 finding 自動作廢 | 3 | `base.py::verify_quote`（±3 行逐字比對）；`scoring/tiers.py::assign_tier` 對 `provenance_verified=False` 直接給 D 級、不得接受；`tests/test_pipeline_mock.py::test_fabricated_quote_is_rejected_as_tier_d`；`dedupe` 不把未驗證 finding 併入已驗證者 |
| 27 | 標準條文 ID 對照 pinned 的機器可讀清單驗證 | 3 | `scoring/idcheck.py::check_finding_refs` 對照 `src/mara/groundtruth/*.json`（ASVS 5.0、OWASP Top 10:2025、API 2023、LLM 2025、CWE 子集）；`tests/test_bias_and_scoring.py::test_idcheck_strips_nonexistent_refs` |
| 28 | 模型的自報信心不直接進入任何計算 | 3 | `schemas.py::Finding.model_confidence` 註解「never used directly」；`grep` 顯示 `pipeline.py` 與 `scoring/` 皆未讀取此欄位；`blinding.py` 對 judge 隱藏 |
| 29 | 審查者拒答被記錄為棄權而非零 finding | 2 | reviewer 與 judge 的拒答分別計入 `reviewer_refusals[family]` 與 `judge_refusals`（`tests/test_pipeline_mock.py::test_bias_audit_captures_refusal_and_position_flip`）；但 skeptic 與 redteam 的拒答只在 `parse_items` 回傳 `refused_or_empty` 並計入 `*_invalid_items`，未區分棄權與無效輸出，且被拒答的 finding 在後續被視為「無 skeptic 裁決」而非「棄權」 |
| 30 | 每個模型家族的無效輸出率被追蹤 | 2 | reviewer 層有 `invalid_findings_dropped[family]`、`findings_with_unverified_quotes[family]`；judge、skeptic、redteam 的 `*_invalid_items` 只有總數，沒有按家族；`scripts/calibrate.py::audit_rates` 只彙整 reviewer 層 |

### L3 對抗驗證層

| # | 題目 | 分數 | 證據 |
|---|---|---:|---|
| 31 | 每個 finding 都有一個否證者（Skeptic）嘗試推翻 | 3 | `pipeline.py::run_skeptics` 對去重後的全部 finding 分組送 skeptic；`run()` 在 redteam 與 jury 之前執行 |
| 32 | 否證者的家族必須不同於發現者的家族且由程式強制 | 3 | `run_skeptics` 對每個 finding 挑選家族不在 `finders[f.id]` 的模型；`bias/diversity.py::pick_skeptic` 找不到時 `raise RuntimeError`；`tests/test_bias_and_scoring.py::test_config_rejects_single_family_panel` |
| 33 | 否證必須引用程式碼中的具體控制（檔案與行號） | 2 | `prompts/skeptic.md` 要求 `sanitizer_or_control` 附 `file:line`；但 `SKEPTIC_SCHEMA` 只是 300 字元自由文字，程式不驗證引用的檔案與行號存在（reviewer 層有 `verify_quote`，skeptic 層沒有） |
| 34 | 紅隊對存活的 finding 給出可利用性類別與前置條件 | 3 | `agents/redteam.py::REDTEAM_SCHEMA` 必填 `exploitable`（yes/conditional/no/unknown）與 `preconditions`；`pipeline.py::run()` 只把 `survivors`（未被否證者）送紅隊；結果進 `ssvc_decision` |
| 35 | 紅隊禁止產出可執行的 exploit | 2 | `prompts/redteam.md`「Do not write exploit code」、`_common_system.md` 規則 4；只靠 prompt 與 `preconditions` 500 字元上限，沒有程式偵測輸出中的程式碼 |
| 36 | 否證與紅隊的產出進入人工佇列的脈絡 | 1 | `ReviewReport` 保留 `skeptic` 與 `redteam` 全文（`out/report.json`），但 `report/markdown_out.py` 只印 `skeptic refuted: True/False`，不印理由、控制與前置條件；沒有人工佇列的輸出物（見第 58 題） |
| 37 | 被否證的 finding 不再進入阻擋邏輯 | 2 | `run()` 把被否證者排除在紅隊之外；`assign_tier` 在「被否證且共識低於門檻」時給 D；但被否證而陪審團共識仍高的 finding 可取得 A 或 C 級並進入閘門（設計上讓陪審團可推翻 skeptic），與題目字面不符 |
| 38 | 否證率按家族追蹤 | 1 | `pipeline.log` 的 `L3:` 行印出每個 skeptic 家族的 refuted 數；`bias_audit` 與 `calibrate.py` 都沒有按 skeptic 家族或按 finder 家族的否證率 |
| 39 | 否證者看不到發現者的身分 | 3 | `agents/skeptic.py::_view` 只給 `finding_id`、`claim`、`cwe`、`evidence`、`reachability_argument`，無 `source_family`／`source_model`；`skeptic.md` 明示「you cannot see it」 |
| 40 | 對抗層的呼叫是單輪且自足的 | 3 | `run_skeptic` 與 `run_redteam` 各為一次 `base.call`，帶完整 bundle 與 finding 批次，沒有多輪對話；`providers/base.py::complete` 介面無對話歷史 |

### L4 陪審裁決層

| # | 題目 | 分數 | 證據 |
|---|---|---:|---|
| 41 | judge 看不到模型身分、信心與 CVSS 向量 | 3 | `bias/blinding.py::blind_finding` 註解「deliberately absent: source_family, source_model, model_confidence, cvss vector」；`tests/test_bias_and_scoring.py::test_blinding_strips_identity_and_scores_and_clips_length` |
| 42 | judge 看到的文字有固定寬度上限 | 3 | `blinding.py::_clip`，`MAX_FIELD = 300`，claim 120、quote 200；`JUDGE_SCHEMA.reason` 上限 400 |
| 43 | 每個 judge 以正序與倒序各裁決一次 | 3 | `blinding.py::blinded_batches` 回傳 forward 與 reverse；`pipeline.py::run_jury` 對每個 judge 各跑 `"forward"` 與 `"reverse"` |
| 44 | 正反序不一致的裁決被標記並折減 | 2 | `consensus.py::weighted_consensus` 回傳 `position_consistent` 並寫入 `ConsensusResult`，`bias_audit["position_flips"]` 計數；折減只是「取正反序平均」的隱含效果，沒有明確的折減係數或設定項；`tests/test_bias_and_scoring.py::test_weighted_consensus_penalises_position_flip_and_self_votes` |
| 45 | 一個家族不裁決自己產出的 finding，或折半計票 | 3 | `run_jury` 排除自家 finding（`self_preference_exclusions`），獨立家族不足時以 `self_family=True` 投票並套 `gate.self_judge_discount`；`policy.py` P4 限制該係數 ≤ 0.5 |
| 46 | judge 之間沒有通訊 | 3 | `run_jury` 每個 judge 各自收到盲化批次，投票獨立收集；`judge.md` 說明另一 juror 只看到反序批次 |
| 47 | judge 家族至少三個且來自不同供應商 | 3 | `config/mara.yaml` 的 `judges` 為 anthropic、deepseek、nemotron 三家族；`policy.py` P3 強制 ≥ 3（`config/examples/prc-site.yaml` 示範例外需 `reduced_panel_reason`）。備註：真實三家族未在本 repo 執行過 |
| 48 | judge 家族的兩兩一致率被追蹤 | 3 | `bias/diversity.py::pairwise_family_agreement`，結果寫入 `bias_audit["judge_agreement[a~b]"]`；`calibrate.py::judge_agreement` 彙整 |
| 49 | Krippendorff's α 或等效指標對每次審查計算 | 3 | `consensus.py::krippendorff_alpha_nominal`（全域）與 `pipeline.py::_per_finding_alpha`（單 finding 的機率修正代理值）；`bias_audit["global_krippendorff_alpha"]`；`tests/test_bias_and_scoring.py::test_krippendorff_alpha_known_values` |
| 50 | α 低於門檻的 finding 進入人工佇列而非投票決定 | 2 | `pipeline.py::score` 在 `alpha < gate.human_threshold_alpha` 時設 `needs_human`，該 finding 不被接受並計入 `DimensionScore.human_queue`；但「人工佇列」只是計數與 `accepted=False` 旗標，沒有佇列物件、輸出檔或工單 |

### L5 評分與輸出層

| # | 題目 | 分數 | 證據 |
|---|---|---:|---|
| 51 | CVSS 4.0 分數由程式計算且計算器對照 FIRST 參考實作驗證 | 3 | `scoring/cvss4.py` 移植 FIRST `cvss-v4-calculator`（查表 `cvss4_lookup.json` 逐字複製）；`tests/test_cvss4.py` 以 `cvss4_reference.json`（用 FIRST 的 `cvss_score.js` 產生）逐向量比對 |
| 52 | 每個 finding 都有證據層級 A 到 D 且規則公開 | 3 | `scoring/tiers.py::assign_tier` 為純函式，規則寫在程式與 README「The six layers」；`tests/test_bias_and_scoring.py::test_tier_rules` |
| 53 | SSVC 或等效的行動決策自動產生 | 3 | `tiers.py::ssvc_decision`（Track / Track* / Attend / Act），輸入為嚴重度、紅隊可利用性、層級；`tests/...::test_ssvc_decisions` |
| 54 | 面向分數與整體分數的公式公開且可重算 | 3 | `scoring/dimension_score.py` 的 `PENALTY` 與 `TIER_FACTOR` 為模組常數；整體分數為面向平均（`pipeline.py::run`）；`out/report.json` 含全部中間值可重算 |
| 55 | 閘門只在 A 級與 B 級的 High 以上阻擋 | 2 | `config/mara.yaml` 的 `block_on_tiers: [A, B]`、`block_on_severity: [High, Critical]` 符合；但 `min_dimension_score: 60` 是第二條阻擋路徑，而面向分數會被 C 級 finding 以 0.4 係數扣分，因此 C 級可間接觸發阻擋 |
| 56 | 輸出為 SARIF 2.1 並上傳 code scanning | 2 | `report/sarif_out.py` 產出 SARIF 2.1（`level`、`rank`、`properties` 含層級與共識）；workflow 只以 artifact 保存，沒有上傳 code scanning |
| 57 | 每份報告含偏誤稽核區塊（拒答、canary、翻轉、折半票） | 3 | `markdown_out.py` 的「Bias and integrity audit」列出 `reviewer_refusals`、`canary_echoes`、`position_flips`、`self_family_fallback_votes`、`self_preference_exclusions`、`judge_agreement[*]` 等；`tests/test_pipeline_mock.py::test_reports_render` |
| 58 | 人工佇列接工單系統且裁決回寫校準集 | 0 | 無證據。repo 內沒有任何 issue／工單整合，`calib/` 沒有人工裁決回寫的格式或路徑；報告第 15 章描述了此設計 |
| 59 | 家族權重每季依校準更新 | 1 | `scripts/calibrate.py` 產出建議權重（0.2 到 2.0）且明示「never edits config/mara.yaml」；只有一次 mock 校準（`docs/calibration-2026-09-11.md`），`config/mara.yaml` 三家族權重仍為 1.0，無季度流程 |
| 60 | 校準通過統計檢定後才允許無監督的「不採納」 | 0 | 無證據。`calibrate.py` 有 Dawid-Skene 但沒有 Alternative Annotator Test 或任何檢定；管線目前已直接以 `accepted=False` 無監督不採納 |

## 2. 六層彙總

| 層 | 得分 | 滿分 | 百分比 | 低於 20？ |
|---|---:|---:|---:|---|
| L0 確定性錨定層 | 13 | 40 | 32.5% | **是** |
| L1 情境建構層 | 22 | 40 | 55.0% | 否 |
| L2 專家審查層 | 28 | 40 | 70.0% | 否 |
| L3 對抗驗證層 | 23 | 40 | 57.5% | 否 |
| L4 陪審裁決層 | 28 | 40 | 70.0% | 否 |
| L5 評分與輸出層 | 20 | 40 | 50.0% | 否（剛好在門檻） |
| 合計 | 134 | 240 | 55.8% | |

**附錄 D 的解讀。** 合計 134 落在 120 到 180 的「單模型階段」區間。但附錄 D 的四個區間假設「工具階段通常 L0 高、其餘低」，本 repo 的剖面正好相反：L2 與 L4 最高，L0 最低。這是雛型先做模型層、後做工具層的結果。附錄 D 的另一條規則更重要：**任何一層低於 20 都應優先處理，因為六層是串聯的，最弱的一層決定整體可信度。** L0 得 13，意味著目前 A 級（工具佐證）證據只在 CI 讀取預錄 SARIF 時存在，真正對受審 repo 執行的確定性工具只有 gitleaks 與 zizmor，且兩者都不阻擋。L5 得 20 是因為評分計算本身完整，但「輸出接到人與工單」的後半段完全沒有。

一句話結論：**模型層的去偏誤機制已由程式強制並在 mock 下驗證，但錨定它的確定性工具層與承接它的人工裁決層都還沒有接上。** 進入影子模式（G-10 第一階段）之前，L0 必須先補到 20 以上。

## 3. 每層最低兩題的最小可行下一步

每段引用報告第十部的治理建議編號（G-1 到 G-13，見 `docs/parts/10_governance.md`）。

### L0

**第 5 題（0 分）OpenSSF Scorecard。** 在 `mara-review.yml` 的 `deterministic-tools` job 加一步 `ossf/scorecard-action`，固定到完整 SHA、`results_format: sarif`、`publish_results: false`，並加 `schedule: cron` 每週對 `main` 跑一次；把 `results.sarif` 放進 `out/tools/` 讓 `load_prerecorded` 讀入。這一步同時給第 8 題補上 job 間的 artifact 傳遞。對應 **G-6**（Scorecard 的 Dangerous-Workflow 與 Pinned-Dependencies 就是這個 action 的檢查項）與 **G-5**（版本固定）。

**第 6 題（0 分）csp-evaluator。** 在 `src/mara/tools/runner.py` 的 `TOOL_DIMENSIONS` 加 `csp-evaluator: ["csp"]`，包裝方式：從原始碼中以 regex 抓 `Content-Security-Policy` 標頭字串（Flask/Express 的 `set_header`、meta tag、nginx/`_headers` 檔），逐條餵給 `csp-evaluator` CLI（npm 套件，版本固定），把每個 finding 轉為 SARIF 並標 `csp` 面向。`fixtures/vuln-sample/` 目前沒有 CSP，需加一個含 `unsafe-inline` 的樣本讓 CI 有東西可抓。對應 **G-5**（新增的 L0 工具同樣要固定版本並簽章）與 **G-1**（CSP 檢查是安全測試的一部分，不由 LLM 單獨判定）。

同分備註：第 1、3、9、10 題都是 1 分。其中第 1 題（semgrep）與第 3 題（osv-scanner）只需在 workflow 加兩步就能升到 2 分，成本最低，建議與第 5 題同一個 PR 做。

### L1

**第 14 題（0 分）增量審查。** 在 `cli.py::review` 加 `--base <ref>` 選項：以 `git diff --name-only <base>...HEAD` 取得變更檔案，再從 `RepoContext.content` 中找出「import／require 了變更檔案」與「被變更檔案 import」的一階鄰居（Python 的 `from x import` / `import x`，JS 的 `require('./x')` / `from './x'`），bundle 只包含變更檔案加鄰居加全部 manifest 與 workflow。`bias_audit` 記錄 `bundle_files_changed`、`bundle_files_related`。對應 **G-10**（影子模式對每個 PR 執行，全 repo bundle 的 token 成本在真實 repo 上不可行，第 22 章的成本模型以增量為前提）。

**第 19 題（1 分）架構視圖。** 把已存在但未用的 `prompts/context.md` 接進管線：在 `run_reviewers` 之前由單一家族（設定檔新增 `roles.context`）呼叫一次，輸出 JSON schema 固定的 C4-lite（containers、external_systems、trust_boundaries、data_stores，每項附 file:line 證據並經 `verify_quote`），存為 `out/context.json`，並把 `trust_boundaries` 附在 `architecture` 與 `authn_authz` 兩個面向的 reviewer 輸入中。這同時把第 11 題的「信任邊界」補上。對應 **G-1**（架構面向是審查的一部分，不是取代威脅建模）。

### L2

**第 29 題（2 分）拒答記為棄權。** 在 `agents/base.py::parse_items` 把 `refused_or_empty` 拆成 `refused` 與 `empty` 兩種回傳，`run_skeptics` 與 `run_redteam` 各自計 `skeptic_refusals[family]`、`redteam_refusals[family]`；被拒答的 finding 在 `score()` 中以 `skeptic_verdict = "abstained"` 處理，`assign_tier` 對 abstained 不視為 stands（不能拿 B 級）。對應 **G-8**（每季的 False Refusal Rate 測試需要管線先有按家族的拒答計數）與 **G-2**（偏誤稽核區塊要能看到誰在拒答）。

**第 30 題（2 分）無效輸出率按家族。** 把 `judge_invalid_items`、`skeptic_invalid_items`、`redteam_invalid_items` 改為 `*_invalid_items[family]`，並在 `scripts/calibrate.py::audit_rates` 納入三個角色的無效率；`suggest_weights` 對無效率超過 10% 的家族把建議權重乘 0.8 並在報告註明。對應 **G-9**（校準迴圈的輸出之一是「每個家族的 canary 回應率與拒答率」，無效輸出率是同一類指標）。

### L3

**第 36 題（1 分）人工佇列脈絡。** 新增 `report/human_queue_out.py`，對每個 `needs_human` 或 C 級 High 以上的 finding 輸出一段 Markdown（`out/human_queue.md`）：L2 原始 finding 全文與家族、skeptic 的 `verdict`／`reason`／`sanitizer_or_control`、redteam 的 `exploitable`／`preconditions`、每個 judge 家族正序與反序的 `verdict`／`reason`。這是報告第 15.1 節描述的「人看得到誰說了什麼」的不對稱設計，目前只存在於 `report.json` 的原始資料中。對應 **G-11**（人工佇列接工單的前提是每項都附完整脈絡）。

**第 38 題（1 分）否證率按家族。** 在 `run_skeptics` 對 `bias_audit` 寫入 `skeptic_items[skeptic_family]`、`skeptic_refuted[skeptic_family]`，以及 `finder_refuted[finder_family]`（該家族的 finding 被否證的比例）；`calibrate.py` 的家族表加「被否證率」欄，`suggest_weights` 把它納入精確度的修正。對應 **G-9**（家族權重應反映該家族 finding 的存活率，不只反映與標籤的比對）。

同分備註：第 33 題（skeptic 引用不驗證）與第 36、38 題同為低分。最小修法是在 `run_skeptic` 對 `sanitizer_or_control` 中的 `path:line` 樣式套用 `verify_quote` 的檔案存在檢查，不通過者把 `refuted` 降為 `weakened`。

### L4

**第 44 題（2 分）翻轉折減。** 在 `GateConfig` 加 `position_flip_discount: float = 0.5`（`policy.py` P4 限制 ≤ 0.5 以外再加 ≥ 0.25 的下限，避免設為 0 等於關閉反序 pass），`weighted_consensus` 對 `per_family_verdicts` 有兩種以上裁決的家族乘以該係數，而不是只取平均。對應 **G-2**（「反序 pass 不關閉」列為政策，折減係數要成為可稽核的設定項而不是隱含行為）。

**第 50 題（2 分）人工佇列成為物件。** 在 `schemas.py::ReviewReport` 加 `human_queue: list[HumanQueueItem]`（finding_id、原因：`alpha_below_threshold` / `majority_needs_human` / `tier_c_high`、α 值、判定時間），`sarif_out.py` 對這些 result 加 `properties.humanQueue = true` 並把 `level` 設為 `note` 以免在 code scanning 中被當作已確認。第 36 題的 `human_queue.md` 從這個物件產生。對應 **G-11**（佇列超量時收緊門檻的前提是佇列長度可量測）。

### L5

**第 58 題（0 分）接工單並回寫。** 在 `mara-review.yml` 加第三個 job `human-queue`，`needs: tests-and-mock-review`、只給 `issues: write`，用 `actions/github-script`（固定 SHA）為 `out/human_queue.md` 中每一項建立或更新一個帶 `mara-human-queue` 標籤的 issue（以 finding 的 file:line:cwe 雜湊去重）。裁決回寫：新增 `calib/decisions/README.md` 規範格式（issue 編號、finding 雜湊、`true_positive` / `false_positive`、裁決者、日期），`scripts/calibrate.py` 讀取此目錄把人工裁決併入標籤集。對應 **G-11**（人工佇列接工單、裁決回寫校準集）與 **G-12**（A 級 Critical 若涉及已出貨產品，issue 需帶 PSIRT 標籤）。

**第 60 題（0 分）無監督不採納的統計驗收。** 在 `scripts/calibrate.py` 實作 Alternative Annotator Test（報告 B70）：以 `calib/decisions/` 的人工裁決為對照，檢定「以模型面板取代人工裁決」的優勢機率是否顯著高於 0.5；在 `GateConfig` 加 `unsupervised_reject_allowed: bool = False`，`policy.py` 新增 P6：只有 `calib/latest.json` 記錄檢定通過（含日期與樣本數，90 天內有效）時才允許設為 `true`；為 `false` 時所有 `accepted=False` 且非 D 級的 finding 一律進人工佇列而非直接丟棄。對應 **G-9**（Alternative Annotator Test 作為無監督「不採納」的驗收門檻，每季重跑）。

同分備註：第 59 題（權重每季更新）為 1 分，依賴第 58 與 60 題先完成，因為沒有人工裁決回寫就沒有可信的季度校準集。

## 4. 上海與重慶廠區：CN-1 到 CN-4

**前提假設。** 對話中沒有說明組織是否有上海或重慶廠區。本表依報告第八部第 21.2 節與第十部第 26 章的情境（跨國 ODM/EMS，有上海浦東與重慶廠區）評估；若組織沒有這兩個廠區，本表整體不適用。

| 條目 | 內容摘要 | 是／否／不適用 | 證據與缺口 |
|---|---|---|---|
| CN-1 | 境內管線完全獨立：repo、runner、L0 工具、家族部署、報告全部在境內，原始碼／SARIF／校準資料／人工裁決不出境 | 否 | 唯一證據是 `config/examples/prc-site.yaml`（DeepSeek 與 Nemotron 皆 `on_prem`、無 Claude、`reduced_panel_reason` 引用 CSL/DSL/PIPL）並通過 `mara check-config`。這只是設定檔範例；repo 內沒有境內 runner、境內 GitHub Enterprise Server／GitLab、境內 L0 工具或報告不出境的任何實作或紀錄 |
| CN-2 | 境內自架的 DeepSeek 仍適用敏感詞校準（第 13 章第 14 項的配對樣本測試），結果留在境內 | 否 | `calib/samples/` 的五個樣本與 `scripts/gen_calib_samples.py` 沒有中性／敏感詞配對樣本；`calibrate.py` 沒有配對比較的邏輯；沒有境內獨立校準集 |
| CN-3 | 全球安全團隊只接收面向分數的彙總，不接收 finding 明細 | 否 | `report/markdown_out.py` 與 `sarif_out.py` 都輸出完整 finding 明細（檔案、行號、逐字引用）；沒有「只匯出 `dimensions` 與 `overall_score`」的彙總模式或跨境輸出開關 |
| CN-4 | 境內管線的稽核對應以中國標準為主（等保 2.0、GB/T），由境內團隊另行製作 | 不適用 | 報告第 26 章明示本報告不代為對應；本 repo 沒有也不預期有等保 2.0 對應。此項由中國區合規團隊另行產出，不在本 repo 範圍 |

## 5. 複算與驗收

`python3 scripts/score_assessment.py docs/assessment-2026-09-12.md` 會檢查：60 題編號齊全且不重複、每題分數在 0 到 4 且證據欄非空、六層加總與第 2 節的彙總表一致、CN 表四列齊全。`tests/test_assessment.py` 在 CI 中執行同一檢查。
