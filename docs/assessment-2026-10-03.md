# 六層差距評估（2026-10-03）

依附錄 D 的 60 題問卷（`docs/appendix-d-maturity.md`），對本組織目前的程式碼審查流程做差距評估。本檔是 `docs/assessment-2026-10-01.md` 的重跑；基準為 main 的 `ef77a4a`，涵蓋 v0.3.13（閘門驗證收口）、v0.3.14（CI 強化、G-4 排練、增量審查進管線）與 v0.3.15（semgrep 1.179.0 重鎖、掃描例外解套、佐證與 ID 指派修正）三個版本的變更，也就是本檔合併後的 repo 狀態。

## 0. 評估範圍、證據與規則

**評估對象。** 本 repo（`chinchiang/MultiAgentAlpha`）所代表的程式碼審查流程：MARA 雛型本身、它的四個 GitHub Actions workflow（`mara-review.yml`、`scorecard.yml`、`governance.yml`、`docs-check.yml`）、設定檔、L0 工具鎖定檔與校準工具。

**可用證據。** 只有本 repo 的檔案：`.github/workflows/`、`config/`、`src/mara/`、`tests/`、`scripts/`、`tools/`、`calib/`、`docs/`，以及本 repo 的 GitHub Actions 執行紀錄（`gh run list`）。對話中沒有提供任何關於組織其他 repo、工單系統、人力或流程的說明，因此凡是問「每個 repo」「定期」「接工單」「每季」的題目，若本 repo 內沒有對應證據，一律給 0 分並標「無證據」，不推測。已實作但從未實際執行的機制（真實家族校準、garak／CyberSecEval 評測、PSIRT 真實握手、live 換模演練、訓練登錄簿、政策核定）不計為執行紀錄；v0.3.14 起三個冷備家族各有一次 mock 排練（`ops/model-swap-drills.yaml`，kind: rehearsal），它證明備援設定可載入、流程不變，但不等同 live 演練，G-4 維持失敗。

**評分規則（附錄 D 的五級如何套到本 repo）。**

| 分數 | 附錄 D 定義 | 本次判定方式 |
|---|---|---|
| 0 | 沒有做 | repo 內找不到任何實作或執行紀錄 |
| 1 | 臨時或個案 | 只有設計文字（報告、prompt 檔、註解）或只有未接進管線的程式片段 |
| 2 | 有文件但未全面 | 程式已實作並有測試，但只在 mock 模式、或只涵蓋部分角色／工具、或未進 CI 阻擋、或目前被條件跳過而不執行 |
| 3 | 全面執行且有紀錄 | 程式強制執行、CI 每次 PR 都跑且為 main 的必要 check（`L0 deterministic tools`、`tests + mock review`）、輸出留在 `out/`、`bias_audit` 或 Actions artifact 中可查 |
| 4 | 全面執行、有量測、有持續改善 | 需要跨期量測與改善紀錄；本 repo 仍只有 mock 校準，無任何題目達此級 |

**三個必須先講的限制。** 第一，CI 仍只跑 mock 模式，三個真實家族（Claude、DeepSeek、Nemotron）從未在本 repo 執行過（校準報告有兩份：`docs/calibration-2026-09-11.md` 與 `docs/calibration-2026-10-03.md`，mode 皆為 mock；治理檢查 G-8、G-9 失敗），所以所有 L2 到 L5 的 3 分都是「機制由程式強制且在 mock 下驗證」，不是「真實模型上已驗證」。第二，本 repo 是唯一的 repo，「每個 repo」類題目的滿分上限實際上受限於樣本數為一。第三，本 repo 自 2026-09-21 起為私有：`scorecard.yml` 的 job 與 `mara-review.yml` 的 `code-scanning` job 都以 `!github.event.repository.private` 條件跳過，相關題目依「已實作、曾執行、目前不執行」給分。

## 1. 逐題評分

### L0 確定性錨定層

| # | 題目 | 分數 | 證據 |
|---|---|---:|---|
| 1 | 每個 repo 的 CI 都執行 SAST（semgrep 或 CodeQL）並輸出 SARIF | 3 | `mara-review.yml` 的 `deterministic-tools` job 以 `scripts/semgrep_ci.py` 跑兩步：對 `.` 全 repo 掃描，未在 `tools/semgrep-triage.yaml` 附理由判定的 finding 一律使 job 失敗；對 `fixtures/vuln-sample` 掃描並要求與 `fixtures/vuln-sample-sarif/semgrep.sarif` 完全一致（v0.3.15 起預錄檔為 semgrep 1.179.0 的真實輸出，15 個 finding，與 1.177.0 時完全相同）。規則為 `tools/versions.lock` 固定的 semgrep-rules，非零結束碼與 failed invocation 不當成清白（F07，`tests/test_security_regressions.py::test_semgrep_error_with_sarif_cannot_pass`）。`semgrep.sarif` 留在 `l0-sarif` artifact。「每個 repo」只有本 repo 一例 |
| 2 | 每個 repo 的 CI 都執行 secret scanner（gitleaks、TruffleHog 或 detect-secrets） | 3 | `scripts/gitleaks_ci.py` 以鎖定的 gitleaks 8.30.1 掃描 PR 的 merge-base..head 全部 commits（F08，`tests/test_security_regressions.py::test_git_range_includes_all_pr_commits_when_main_advances`），`.gitleaks.toml` 只豁免精確的教材假值（F27）；crash 或 leak 都使 job 失敗，已移除 `continue-on-error`。另在 live 模式以 `pipeline.py::run` 的 secret preflight 阻擋外送（`test_live_secret_preflight_stops_all_provider_requests`） |
| 3 | 每個 repo 的 CI 都執行 SCA（OSV-Scanner、Trivy 或 Grype）且以 OSV 而非只以 CPE 比對 | 3 | `scripts/osv_ci.py` 對 `tools/*-requirements.txt` 的 hash 鎖定閉包掃描（`tools/osv-scanner.toml` 無漏洞例外；model-eval 閉包另以 `tools/osv-model-eval.toml` 掃描），未忽略的 advisory 使 job 失敗，並須在 fixture 上抓到 `requests==2.19.0`；`scripts/trivy_ci.py` 以 `scripts/trivy_db.py` 記錄雜湊的離線資料庫掃描全 repo，未列於 `tools/trivyignore.yaml` 者使 job 失敗。v0.3.15：semgrep 閉包重鎖至 1.179.0（pyjwt 2.15.1）後，`tools/osv-semgrep.toml` 的 13 條 PyJWT 期限例外與 trivyignore 對應條目全數移除、兩檔現為零例外（本機以鎖定的 osv-scanner 2.5.1 與 trivy 0.74.0 對新閉包重掃驗證為乾淨），2026-12 的到期紅燈解除；garak 閉包僅剩 nltk／datasets 兩條。每週 `schedule` 另跑一次（F28） |
| 4 | 所有 GitHub Actions workflow 都經 zizmor 或 actionlint 檢查 | 3 | `scripts/zizmor_ci.py --target .github/workflows` 以 `tools/versions.lock` 鎖定的 zizmor 1.30.1 檢查全部四個 workflow，任何 finding 使 job 失敗；fixture 的 workflow 另一步單獨檢查，須與預錄 `zizmor.sarif` 一致；`tests/test_zizmor_ci.py` |
| 5 | OpenSSF Scorecard 定期對所有 repo 執行並追蹤分數 | 2 | `.github/workflows/scorecard.yml`（每週二 cron＋push main）以 `scripts/scorecard_ci.py` 執行鎖定的 scorecard 5.5.0，`tools/scorecard-policy.yaml` 對強制項設最低分；2026-09-14 到 09-21 在 main 上成功執行。但 repo 轉為私有後 job 以 `if: ${{ !github.event.repository.private }}` 跳過，目前沒有在追蹤分數；私有期間由 `scorecard-local` job（v0.3.1）以 `scorecard --local` 對 committed tree 維持六個檔案型強制項的把關 |
| 6 | CSP 政策以 csp-evaluator 自動檢查 | 3 | v0.3.11（PR #53）實作：`src/mara/tools/runner.py` 的 `TOOL_DIMENSIONS` 加 `csp-evaluator: ["csp"]`；`tools/versions.lock` 鎖定 Google csp-evaluator 1.1.8（npm tarball，SHA-256＋registry `dist.integrity` 下載後重算比對，解包檢查拒絕 symlink／路徑逃逸），`scripts/install_tools.py` 安裝 driver 後以 node ≥ 18 執行。`src/mara/tools/csp_eval.py` 從原始碼樹抽取 CSP 政策送驅動評分，severity 映射進 SARIF，解析失敗記 `CSP_PARSE_ERROR` 不當清白。`scripts/csp_ci.py` 對 seeded fixture 走 `--expect` 預錄漂移檢查、對本 repo 走 `--triage`（`tools/csp-triage.yaml` 6 條全數附理由）；`mara-review.yml` 兩個 csp 步驟在 `deterministic-tools` job 內阻擋；`tests/test_tools_csp.py` 11 例。v0.3.15 起工具佐證受 `TOOL_DIMENSIONS` 限定，csp-evaluator 的無 CWE 結果不再能佐證其他面向的 finding（`tests/test_pipeline_mock.py::test_tool_corroboration_respects_tool_dimensions`） |
| 7 | 工具版本固定並有簽章或雜湊驗證 | 3 | `tools/versions.lock` 固定九個工具（含驗證器 cosign、slsa-verifier）與 semgrep-rules（含 csp-evaluator 的 npm kind 與 semgrep 的 pip kind），`scripts/install_tools.py` 對每個資產驗 SHA-256，再驗發行者簽章／provenance（cosign keyless、SLSA、GitHub attestation、GPG commit 簽章；見 `docs/tools-provenance.md`）；`runner.py::tool_path` 只用 `.mara-tools/bin`、不查 PATH；Python 閉包全以 `--require-hashes` 安裝；全部 action 固定到完整 SHA。v0.3.15：semgrep 1.179.0 以 `pip download --only-binary` 在 CPython 3.11 × manylinux x86_64 重新解析閉包（66 個 wheel，pyjwt 2.15.1）後 `--relock-semgrep` 重寫雜湊檔。治理檢查 G-5 通過。缺口：gitleaks 與 semgrep 上游無簽章，只有雜湊 |
| 8 | 工具在隔離 runner 執行，與模型呼叫分屬不同 job | 3 | `deterministic-tools`、`code-scanning`、`tests-and-mock-review`、`human-queue` 四個 job 各自宣告最小權限、`persist-credentials: false`；有 `security-events: write` 的 job 不 checkout、不執行 repo 程式（F26，`tests/test_security_regressions.py::test_sarif_upload_job_has_no_repository_code_and_osv_scopes_are_separate`）。v0.3.14 起九個 job 全部設 `timeout-minutes`（45／30／20／10 分），卡住的步驟不會燒到 360 分鐘預設上限，`scripts/actions_inventory.py` 把缺 timeout 列為 Low finding、測試把關。備註同前次：模型 job 讀的是 repo 內預錄的 SARIF，不是 L0 job 的 artifact |
| 9 | 工具結果上傳至集中式 code scanning 或等效系統 | 2 | `code-scanning` job 以 `scripts/code_scanning_prep.py` 在唯讀 job 中預處理後用 `github/codeql-action/upload-sarif` 上傳六個工具的 SARIF（含 `mara-l0/csp/` category；`tests/test_code_scanning_prep.py`；v0.3.15 起 action 為 v4.38.2，SHA 經 `git ls-remote` 驗證為 tag 的 peeled commit）；但私有期間以 `!github.event.repository.private` 跳過，目前 SARIF 只留在 `l0-sarif`／`code-scanning` artifact |
| 10 | 工具結果作為模型審查的校準集使用 | 2 | v0.3.12（PR #54）實作：`scripts/calibration_run.py` 在 review 迴圈後對每個 `calib/samples/*` 以鎖定工具跑 semgrep／osv-scanner／gitleaks，SARIF 存 `calib-out/<sample>/tools/`（不進 repo）；`scripts/calibrate.py` 的 `load_tool_labels` 讀取（跳過 suppression）作為第二組參考標籤，`tool_recall` 以 ±3 行與 CWE 家族比對，報告 front matter 記 `tool_labels`、第 1a 節列每家族對工具 finding 的召回率；`tests/test_calibration.py` 涵蓋。v0.3.15 後完整迴圈已實跑一次（`docs/calibration-2026-10-03.md`：`tool_labels: 41`，§1a 列出 gitleaks 0.67–1.00、semgrep 0.37–0.81 的每家族召回率），機制在 mock 下端對端驗證。未達 3 分：校準迴圈不是 CI 必要 check，且沒有任何真實執行紀錄 |

### L1 情境建構層

| # | 題目 | 分數 | 證據 |
|---|---|---:|---|
| 11 | 審查前自動建立 repo 的入口點與信任邊界清單 | 3 | v0.3.10（PR #52）補上信任邊界：`repo_map.py::build_context` 的 `_ENTRY_PATTERNS` 抓 Flask/FastAPI/Express 入口點寫進 `RepoContext.entry_points`；`roles.context` 的 context agent 一次呼叫產生 C4-lite（containers、external_systems、trust_boundaries、data_stores），每個事實須通過與 finding 相同的逐字引文驗證（`verify_quote`），不過即丟棄並計數；architecture 與 authn_authz 面向的 reviewer 提示詞前置可信事實區塊。`config/mara.yaml` 與 `config/mara.mock.yaml` 皆已設定 `roles.context`，CI 的 mock review 每次執行 |
| 12 | 審查輸入剝除 commit message、作者與 PR 描述 | 3 | `repo_map.py::build_context` 只以 `git ls-files --cached` 取路徑、以 `git rev-parse HEAD` 取 commit SHA 作 `revision`，從不讀 commit message、作者或 PR 事件；`_common_system.md` 規則 7 禁止提及作者；`tests/test_agent_harness.py::test_context_strips_nothing_but_records_entry_points` |
| 13 | 依賴清單與 workflow 清單自動納入審查範圍 | 3 | `repo_map.py` 的 `MANIFESTS` 與 `.github/workflows/` 偵測寫入 `RepoContext.manifests`／`workflows`；`priority()` 讓 manifest 與程式碼先於 `.md`／`.txt`／`.html` 納入；`ctx.summary()` 列出兩者 |
| 14 | 增量審查會納入與變更相關的檔案而非只有 diff | 3 | v0.3.10（PR #52）實作：`mara review --base <git-ref>` 以 `git diff --name-only <base>...HEAD` 收斂 bundle 到變更檔、其一階 import 鄰居（Python 全名／裸名雙向、JS/TS 相對 specifier）與全部 manifest、workflow；其餘檔案以 `out_of_increment` 記入 coverage 的 excluded（不靜默保留），變更檔不在 bundle 時記 `changed_file_not_in_bundle` fail-closed，不可解析的 base ref 是使用錯誤。v0.3.14 起進管線常態執行：`tests + mock review` job（main 的必要 check）的 checkout 加 `fetch-depth: 0`，每次 PR 與 push 都以 `--base <merge-base 或前一 commit>` 對 seeded fixture 跑第二次 mock review（schedule／dispatch 無 base commit 時明確跳過），`out-incremental/` 併入 `mara-report` artifact；本機以 `--base origin/main` 實測（bundle 收斂至 manifests／workflows、5 檔 `out_of_increment`、exit 0） |
| 15 | bundle 有大小上限且超限時有明確的優先規則 | 3 | `repo_map.py` 有 `MAX_FILE_BYTES`、每請求 `MAX_TOTAL_CHARS`（`RepoContext.batches` 把全部納入內容分批送出）與整體 `MAX_REPOSITORY_CHARS`；`priority()` 為明確的納入順序；超限者寫入 `ctx.omitted`（`request_size_limit`／`repository_size_limit`／`unreadable_unsafe_or_oversize`），`ctx.complete` 為假時 `pipeline.py::run` 記 `context_coverage_incomplete`、gate 阻擋（F03）；`tests/test_security_regressions.py::test_context_batches_cover_all_sources_and_report_oversize` |
| 16 | 被審查內容以明確標籤包裹為不可信資料 | 3 | `src/mara/agents/base.py::untrusted_block` 以 `<untrusted_repository_data>` 與每檔 `<file path=...>`（路徑經 `html.escape`）包裹；reviewer、skeptic、redteam 三種呼叫都經此函式 |
| 17 | 每次審查植入 canary 並記錄回應率 | 3 | `base.py::Canary` 每次 review 產生隨機 token 植入；`pipeline.py::run_reviewers` 記錄 `canary_echoes` 與 `canary_echoes[family]`，任何 echo 使審查標為未完成（`incomplete_reasons` 含 `canary_echoes`）；`tests/test_agent_harness.py::test_canary_is_planted_and_detected`。v0.3.15 移除 Finding 上永遠為 False 的 `canary_echoed` 欄位（回應 canary 的呼叫整批丟棄，偏誤稽核走 `bias_audit["canary_echoes"]`），報告不再帶無意義欄位 |
| 18 | 審查內容的雜湊作為可重現性的種子 | 3 | `repo_map.py` 計算 `content_hash` 與 `revision`（commit＋原始內容雜湊）；`bias/blinding.py::blinded_batches` 以 `content_hash + family` 作種子；`tests/test_bias_and_scoring.py::test_reverse_pass_is_exact_mirror_and_seeded_order_is_deterministic`、`tests/test_security_regressions.py::test_line_number_overhead_is_bounded_and_redacted_changes_invalidate_revision` |
| 19 | C4 或等效的架構視圖由審查自動產生 | 3 | v0.3.10（PR #52）實作：`run_reviewers` 前由 `roles.context` 指定的單一家族呼叫一次，產出 schema 固定的 C4-lite（containers、external_systems、trust_boundaries、data_stores，每項附 file:line），每個事實經 `verify_quote` 驗證，不過即丟棄並計數；拒答、canary 回應或無可驗事實則不產生視圖，運行記 `context_view_incomplete`（fail-closed，絕不虛構架構）；`tests/test_pipeline_mock.py` 涵蓋產生與 fail-closed 兩條路徑。mock 的 `roles.context: mock-a` 讓 CI 每次執行 happy path |
| 20 | 情境建構的產出可被人工查閱 | 3 | `RepoContext.coverage()` 寫入 `out/report.json` 的 `coverage`（included、omitted、excluded、redacted、complete、content_hash、revision）；`pipeline.log` 的 `L1:` 行為 `ctx.summary()`；CI 每次以 `mara-report` artifact 保存（v0.3.14 起含增量模式的報告）。送給模型的 bundle 本身不存檔，但可由 `revision` 與 included 清單重建 |

### L2 專家審查層

| # | 題目 | 分數 | 證據 |
|---|---|---:|---|
| 21 | 十一個面向都有專屬的審查 prompt | 3 | `src/mara/prompts/reviewer_*.md` 共 11 個，`agents/reviewer.py::review_dimension` 以 `load_prompt(f"reviewer_{dimension}")` 載入；`config/mara.yaml` 的 `dimensions` 列 11 項（v0.3.15 起設定拒載空清單，`min_length=1`，零呼叫的「完整審查」不可能通過載入） |
| 22 | 每個面向至少由兩個不同模型家族獨立審查 | 3 | `pipeline.py::run_reviewers` 對每批、每面向逐一呼叫 `roles.reviewers` 全部；`policy.py` P3 要求 reviewer 家族數 ≥ 3；`tests/test_policy.py` |
| 23 | 審查者之間沒有任何通訊 | 3 | `run_reviewers` 每次呼叫只帶該批 context 與 prompt，不帶其他家族輸出；`pipeline.py` 檔頭註解明示 |
| 24 | 模型輸出限制為嚴格的 JSON schema 並經驗證 | 3 | `reviewer.py::FINDING_SCHEMA`、`judge.py::JUDGE_SCHEMA`、`skeptic.py::SKEPTIC_SCHEMA`、`redteam.py::REDTEAM_SCHEMA` 皆 `additionalProperties: false`；`base.py::parse_items` 以 pydantic 驗證；skeptic、redteam、judge 回覆缺漏或重複時整批拒收（F05，`tests/test_security_regressions.py::test_duplicate_judge_reply_is_not_counted`）；CVSS 向量在模型邊界完整解析（`test_invalid_cvss_is_rejected_at_model_boundary`）。v0.3.15：skeptic 的 `sanitizer_or_control` 與 redteam 的 `preconditions` 改為 parser 必填，與 schema 一致——不強制 schema 的自架端點缺鍵即 invalid item，不再有靜默預設值 |
| 25 | 每個 finding 都有檔案、行號與逐字引用 | 3 | `FINDING_SCHEMA.provenance` 為 `minItems: 1`，每項必填 `file`、`line`、`quote`；`schemas.py::Provenance` |
| 26 | 引用不存在於檔案的 finding 自動作廢 | 3 | `base.py::verify_quote` 只對實際 context 比對、拒絕目錄外與超界行號、不回退讀磁碟（F12，`test_quote_validation_never_falls_back_to_disk`）；`pipeline.py::score` 要求全部 provenance 皆已驗證（`test_one_verified_quote_cannot_launder_an_invalid_primary_location`）；`tiers.py::assign_tier` 對未驗證者給 D；`tests/test_pipeline_mock.py::test_fabricated_quote_is_rejected_as_tier_d` |
| 27 | 標準條文 ID 對照 pinned 的機器可讀清單驗證 | 3 | `scoring/idcheck.py::check_finding_refs` 對照 `src/mara/groundtruth/*.json`；`docs/groundtruth-diff-2026-09-21.md` 為首次季度核對並已套用 ASVS 5.0.0 V17；`tests/test_bias_and_scoring.py::test_idcheck_strips_nonexistent_refs`。v0.3.15：回傳改為 `RefCheck(finding, stripped, unknown_cwe)`，`standard_refs_stripped` 只計真正被剝除的 refs，未知 CWE 另計（`bias_audit["unknown_cwe"]`），計數不再混淆。只有一次核對，未達跨期量測 |
| 28 | 模型的自報信心不直接進入任何計算 | 3 | `schemas.py::Finding.model_confidence` 註解「never used directly」；`grep model_confidence src/mara` 只出現在 schema、reviewer 解析、mock 回覆與 `blinding.py` 的「deliberately absent」註解，`pipeline.py` 與 `scoring/` 皆未讀取 |
| 29 | 審查者拒答被記錄為棄權而非零 finding | 3 | v0.3.10（PR #52）實作：`agents/base.py::parse_items` 把 `refused_or_empty` 拆成拒答與空輸出分開計數；skeptic／redteam／judge／context 的 calls、refusals、invalid items 各有總數與 per-family 版本進 `bias_audit` 與 `incomplete_reasons`。拒答視為棄權：skeptic 拒答的 finding 不再靠它升 B 級（`skeptic_abstained` 原因進人工佇列），judge 任一 pass 拒答計 `judge_refusals`；reviewer 層的 `reviewer_refusals[family]`、`reviewer_truncations[family]` 維持使審查未完成、gate 阻擋。v0.3.15 起空回應的雙層語義（reviewer/context 記拒答、skeptic/judge/redteam 記無效）在 `parse_items` 文件化為刻意設計，兩者皆 fail-closed |
| 30 | 每個模型家族的無效輸出率被追蹤 | 3 | v0.3.10（PR #52）實作：`judge_invalid_items[family]`、`skeptic_invalid_items[family]`、`redteam_invalid_items[family]`（總數保留供 `incomplete_reasons`）與 reviewer 層既有計數一起進 `bias_audit`；`scripts/calibrate.py::audit_rates` 彙整全部角色的 per-family 拒答與無效率表，`suggest_weights` 對無效率超過 10% 的家族乘 0.8；`tests/test_calibration.py` 涵蓋表與折抵 |

### L3 對抗驗證層

| # | 題目 | 分數 | 證據 |
|---|---|---:|---|
| 31 | 每個 finding 都有一個否證者（Skeptic）嘗試推翻 | 3 | `pipeline.py::run_skeptics` 對去重後的全部 finding 分組送 skeptic；`skeptic.py::run_skeptic` 在回覆未逐一涵蓋每個 finding 時整批拒收，`skeptic_invalid_items` 使審查未完成 |
| 32 | 否證者的家族必須不同於發現者的家族且由程式強制 | 3 | `bias/diversity.py::pick_independent`（PR #39）對每個 finding 依 skeptic 角色、judges、reviewers 順序挑出不屬於任何 finder 家族（`finders[f.id]`）的模型；全部家族都是 finder 時回傳 `independent=False`，`run_skeptics` 記入 `bias_audit["skeptic_same_family"]` 並寫 log，該 finding 也沒有獨立 judge，由 quorum 規則送人工；`tests/test_security_regressions.py::test_l3_prefers_a_family_outside_every_finder_and_audits_the_fallback`；`policy.py` P3 拒絕 skeptic 與唯一 reviewer 同家族的設定 |
| 33 | 否證必須引用程式碼中的具體控制（檔案與行號） | 3 | v0.3.10（PR #52）實作：`skeptic.py::run_skeptic` 從 refuted 裁決的 `sanitizer_or_control` 解析 `path:line`，必須在 bundle 內可定位（檔案存在、行號在範圍內），否則把 `refuted` 降為 `weakened` 並計 `skeptic_unverified_controls[family]`；與 reviewer 層的 `verify_quote` 對稱；mock 對只有口說控制項的 refuted 裁決以 finding 證據位置補上可驗引用；`tests/test_calibration.py` 的 audit_rates 表含該欄 |
| 34 | 紅隊對存活的 finding 給出可利用性類別與前置條件 | 3 | `agents/redteam.py::REDTEAM_SCHEMA` 必填 `exploitable`（yes/conditional/no/unknown）與 `preconditions`；`pipeline.py::run` 只把未被否證者送 `run_redteam`，紅隊家族同樣經 `pick_independent` 挑選（fallback 記 `redteam_same_family`）；結果進 `tiers.py::ssvc_decision` |
| 35 | 紅隊禁止產出可執行的 exploit | 3 | v0.3.11（PR #53）實作：管線對 redteam 輸出套用程式碼樣式偵測，命中者剝除並計 `redteam_exploit_code_stripped`（`src/mara/pipeline.py`、`tests/test_redteam_strip.py`）；`prompts/redteam.md`「Do not write exploit code」與 `preconditions` 500 字元上限維持。剝除是防線之一，輸出仍進人工佇列可查 |
| 36 | 否證與紅隊的產出進入人工佇列的脈絡 | 3 | `src/mara/report/human_queue_out.py::build_queue` 每個 `HumanQueueItem` 帶 skeptic 的家族／`verdict`／`reason`／`sanitizer_or_control`、redteam 的家族／`exploitable`／`preconditions` 與每個 judge 兩個 pass 的裁決與理由；`render_human_queue` 寫出 `out/human_queue.md`／`.json`（文字經 `report/escaping.py::literal`）；CI 每次 mock review 產出並存入 artifact；`tests/test_human_queue.py::test_selection_reasons_and_full_context` |
| 37 | 被否證的 finding 不再進入阻擋邏輯 | 3 | v0.3.12（PR #54）收口：被否證而陪審團推翻者（tier 非 D）一律加 `skeptic_refuted_jury_overrode` 原因——不被接受、進人工佇列，沒有人工裁決就不會進入阻擋邏輯（`tests/test_pipeline_mock.py`）；`run()` 維持把被否證者排除在紅隊之外；`assign_tier` 在「被否證且共識低於門檻」時給 D。刻意不走靜默丟棄：任何被否證仍存活的 finding 必須有人看過，這是 fail-closed 的設計選擇 |
| 38 | 否證率按家族追蹤 | 3 | v0.3.10（PR #52）實作：`run_skeptics` 寫入 `skeptic_items[family]`、`skeptic_refuted[family]` 與 `finder_refuted[finder_family]`；`scripts/calibrate.py` 家族表加「被否證率」欄並納入 `suggest_weights`（先按被否證率折抵，該家族無效率>10% 再 ×0.8，G-8 未達門檻再乘懲罰係數）；`tests/test_calibration.py` |
| 39 | 否證者看不到發現者的身分 | 3 | `agents/skeptic.py::_view` 只給 `finding_id`、`claim`、`cwe`、`evidence`、`reachability_argument`，無 `source_family`／`source_model`；`skeptic.md` 明示。v0.3.15：finding ID 改為內容排序（file、line、cwe、dimension、title）指派，不再按 reviewer 呼叫順序連號——盲化視圖裡的連續 ID 不會再洩漏「哪些 finding 來自同一次呼叫」 |
| 40 | 對抗層的呼叫是單輪且自足的 | 3 | `run_skeptic` 與 `run_redteam` 各為一次 `base.call`，帶相關檔案的 bundle 與 finding 批次；`providers/base.py` 的 `complete` 介面無對話歷史 |

### L4 陪審裁決層

| # | 題目 | 分數 | 證據 |
|---|---|---:|---|
| 41 | judge 看不到模型身分、信心與 CVSS 向量 | 3 | `bias/blinding.py::blind_finding` 註解「deliberately absent: source_family, source_model, model_confidence, cvss vector」；`tests/test_bias_and_scoring.py::test_blinding_strips_identity_and_scores_and_clips_length`；治理檢查 G-2 通過 |
| 42 | judge 看到的文字有固定寬度上限 | 3 | `blinding.py::_clip` 與 `MAX_FIELD`；`JUDGE_SCHEMA.reason` 上限 400 |
| 43 | 每個 judge 以正序與倒序各裁決一次 | 3 | `blinding.py::blinded_batches` 回傳 forward 與 reverse；`pipeline.py::run_jury` 對每個 judge 各跑 `"forward"` 與 `"reverse"`；`pipeline.py::score` 只計「兩個 pass 各恰一票」的家族（`valid_families`） |
| 44 | 正反序不一致的裁決被標記並折減 | 3 | `consensus.py::weighted_consensus` 回傳 `position_consistent`，並取正反序平均；`pipeline.py::score` 對不一致者加 `position_inconsistent` 原因，使 `needs_human=True`、`accepted=False`、進人工佇列並使審查未完成；`bias_audit["position_flips"]` 計數；`tests/test_pipeline_mock.py::test_unstable_finding_is_not_accepted`、`test_bias_audit_captures_refusal_and_position_flip`。仍無可設定的折減係數 |
| 45 | 一個家族不裁決自己產出的 finding，或折半計票 | 3 | `run_jury` 排除自家 finding（`self_preference_exclusions`），獨立家族不足時以 `self_family=True` 投票並套 `gate.self_judge_discount`（`policy.py` P4 ≤ 0.5）；同家族票不補 quorum（F23，`tests/test_security_regressions.py::test_quorum_requires_two_independent_families_and_both_passes`） |
| 46 | judge 之間沒有通訊 | 3 | `run_jury` 每個 judge 各自收到盲化批次，投票獨立收集 |
| 47 | judge 家族至少三個且來自不同供應商 | 3 | `config/mara.yaml` 的 `judges` 為 anthropic、deepseek、nemotron；`policy.py` P3 強制 ≥ 3（`config/examples/prc-site.yaml` 需 `reduced_panel_reason`）。v0.3.14：三個生產家族各完成一次 mock 換模排練（`ops/model-swap-drills.yaml`，anthropic→mistral、deepseek→llama、nemotron→mistral，全數通過且 dimensions 不變），備援面板可跑同一流程已有本機紀錄；live 演練仍缺。真實三家族仍未在本 repo 執行過 |
| 48 | judge 家族的兩兩一致率被追蹤 | 3 | `bias/diversity.py::pairwise_family_agreement` 寫入 `bias_audit["judge_agreement[a~b]"]`；`scripts/calibrate.py::judge_agreement` 彙整 |
| 49 | Krippendorff's α 或等效指標對每次審查計算 | 3 | `consensus.py::krippendorff_alpha_nominal` 算語料層級 α 寫入 `bias_audit["global_krippendorff_alpha"]`；單一 finding 記 `pipeline.py::_agreement_proxy`（`ConsensusResult.agreement_proxy`；v0.3.15 起評審家族數 < 2 時回 None，單一家族自陪不再顯示「完美共識」）；`tests/test_bias_and_scoring.py::test_krippendorff_alpha_known_values`、`test_agreement_proxy_is_undefined_for_a_single_rater_family`。v0.3.12（PR #54）的跨期可比性機制（`calib/history.json` 僅 live 記錄、報告 §8 差值與紅字警告）在 2026-10-03 的 mock 校準中驗證了「mock 不追加、不比較」的路徑 |
| 50 | α 低於門檻的 finding 進入人工佇列而非投票決定 | 3 | `pipeline.py::score` 在 `agreement_proxy < human_alpha_threshold` 時加 `agreement_below_threshold`，該 finding 不被接受；`human_queue_out.py::build_queue` 產生 `ReviewReport.human_queue: list[HumanQueueItem]`，`sarif_out.py` 為其 result 設 `level: note` 與 `properties.humanQueue`。v0.3.14 修復收緊機制：`score()` 的 `tier_c_high` 原因改為尊重 `tighten_exclude_tier_c` 與 `queue_tier_c_min_severity`（先前無條件附加使收緊分支成為死碼、backlog 上限被架空），backlog 超量時 alpha 門檻提高、tier C 交由陪審共識決定且不再排入佇列，`tests/test_human_queue.py` 涵蓋收緊前後四種組合；`tightening` 只收緊不放寬（`test_tightening_only_when_backlog_is_over_the_limit`） |

### L5 評分與輸出層

| # | 題目 | 分數 | 證據 |
|---|---|---:|---|
| 51 | CVSS 4.0 分數由程式計算且計算器對照 FIRST 參考實作驗證 | 3 | `scoring/cvss4.py` 移植 FIRST `cvss-v4-calculator`；`tests/test_cvss4.py::test_matches_first_reference_implementation` 以 `tests/cvss4_reference.json` 逐向量比對；無效向量回退為 Unknown 並進人工（F06） |
| 52 | 每個 finding 都有證據層級 A 到 D 且規則公開 | 3 | `scoring/tiers.py::assign_tier` 為純函式；`tests/test_bias_and_scoring.py::test_tier_rules`。v0.3.15 起工具佐證受 dimension 限定，csp-evaluator 的無 CWE 結果不再把 ±3 行內的任何 finding 推上 A 級 |
| 53 | SSVC 或等效的行動決策自動產生 | 3 | `tiers.py::ssvc_decision`（Track / Track* / Attend / Act）；`tests/test_bias_and_scoring.py::test_ssvc_decisions` |
| 54 | 面向分數與整體分數的公式公開且可重算 | 3 | `scoring/dimension_score.py` 的 `PENALTY` 與 `TIER_FACTOR`；整體分數為面向平均，審查未完成時 `overall_score=null` 並列出 `incomplete_reasons`（F04）；`out/report.json` 含全部中間值 |
| 55 | 閘門只在 A 級與 B 級的 High 以上阻擋 | 2 | `config/mara.yaml` 的 `block_on_tiers: [A, B]`、`block_on_severity: [High, Critical]` 符合；C 級 High 以上送人工（`tier_c_high`，收緊時交由陪審共識並仍受 quorum 把關）；但仍有其他阻擋路徑：`min_dimension_score: 60`（已接受的 C 級以 0.4 係數扣分）與 `pipeline.py::run` 在審查未完成時一律阻擋。後者是刻意的 fail closed，但與題目字面不符。v0.3.13 補上設定驗證：`block_on_tiers`／`block_on_severity` 必須是非空合法清單、`accept_threshold` 限 0–1、`min_dimension_score` 限 0–100、`MaraConfig` 拒載未知鍵——拼字錯誤不可能再把阻擋閘門變成靜默空轉（`tests/test_policy.py::test_gate_rejects_out_of_bounds_unknown_and_empty_values`） |
| 56 | 輸出為 SARIF 2.1 並上傳 code scanning | 2 | `report/sarif_out.py` 產出 SARIF 2.1（v0.3.13 起不再輸出永遠為 null 的 `krippendorffAlpha`，agreement proxy 照常）；MARA 報告的 SARIF 只存於 `mara-report` artifact，`mara-review.yml` 註明 mock review 報告描述種子材料、不上傳；L0 的 code scanning 上傳在私有期間也跳過 |
| 57 | 每份報告含偏誤稽核區塊（拒答、canary、翻轉、折半票） | 3 | `markdown_out.py` 的「Bias and integrity audit」逐項列出 `bias_audit`：`reviewer_refusals`、`reviewer_truncations`、`canary_echoes`、`position_flips`、`self_family_fallback_votes`、`self_preference_exclusions`、`judge_agreement[*]`，發生時另有 `skeptic_same_family`／`redteam_same_family`；v0.3.10 起拒答與無效輸出按角色、按家族分列；`tests/test_pipeline_mock.py::test_reports_render` |
| 58 | 人工佇列接工單系統且裁決回寫校準集 | 2 | `scripts/human_queue_issues.py` 以 v2 key 為每項建立或更新 issue，`--sync-decisions` 重播 label 事件寫回 `calib/decisions/`（F18、F19）；`scripts/calibrate.py::load_decisions`／`apply_decisions` 讀取；`mara-review.yml` 的 `human-queue` job 在 push main 時執行；`tests/test_human_queue.py::test_tickets_are_created_once_and_decisions_come_back`、`test_calibration_uses_true_positive_decisions_as_labels`；治理檢查 G-11 通過。但 repo 變數 `MARA_HUMAN_QUEUE_ISSUES` 未設定，job 一直是 `--dry-run`，沒有任何 `mara-human-queue` issue；`calib/decisions/` 只有 README；`training/records.yaml` 0 筆而 `require_trained_adjudicator: true`，任何裁決都不會進校準 |
| 59 | 家族權重每季依校準更新 | 1 | `scripts/calibrate.py::suggest_weights` 產出建議權重且不改設定檔（v0.3.10 起先按被否證率折抵、無效率>10% 乘 0.8、G-8 未達門檻再乘懲罰係數）；現有兩次 mock 校準（`docs/calibration-2026-09-11.md`、`docs/calibration-2026-10-03.md`，後者 §5 已列建議權重），`config/mara.yaml` 三家族仍 `weight: 1.0`；沒有 live 校準，權重從未更新；治理檢查 G-9 失敗 |
| 60 | 校準通過統計檢定後才允許無監督的「不採納」 | 2 | v0.3.12（PR #54）實作：`scripts/calibrate.py::alternative_annotator_test` 以 `calib/decisions/` 的人工裁決為對照跑 Alternative Annotator Test（n ≥ 10、±3 行與 CWE 家族比對、排除未受訓裁決者），結果進 front matter `aat` 與報告 §7；`GateConfig.unsupervised_reject_allowed` 預設 `false`，`policy.py` P8 只允許在 `calib/latest.json` 記錄 90 天內檢定通過時設為 `true`（違反即 `mara check-config` ValueError；v0.3.13 起連未來日期的紀錄也拒絕）；為 `false` 時非 D 級的 `accepted=False` finding 一律進人工佇列（`unsupervised_reject_unverified`，`tests/test_human_queue.py`）。2026-10-03 的 mock 校準實跑了 AAT 路徑並正確回報「未通過（沒有可對照的人工裁決）」。未達 3 分：`calib/decisions/` 仍空，檢定從未在真實資料上通過（`calib/latest.json` 不存在），P8 目前不允許任何無監督不採納 |

## 2. 六層彙總

| 層 | 得分 | 滿分 | 百分比 | 低於 20？ |
|---|---:|---:|---:|---|
| L0 確定性錨定層 | 27 | 40 | 67.5% | 否 |
| L1 情境建構層 | 30 | 40 | 75.0% | 否 |
| L2 專家審查層 | 30 | 40 | 75.0% | 否 |
| L3 對抗驗證層 | 30 | 40 | 75.0% | 否 |
| L4 陪審裁決層 | 30 | 40 | 75.0% | 否 |
| L5 評分與輸出層 | 24 | 40 | 60.0% | 否 |
| 合計 | 171 | 240 | 71.3% | |

**附錄 D 的解讀。** 合計 171 仍在 120 到 180 的「單模型階段」區間，距 180 只差 9 分。相較 2026-10-01 的 170，本輪只有一題升分（第 14 題 2→3，增量審查進入 CI 常態執行），L1 因此與 L2／L3／L4 並列 30 分；L5（24）與 L0（27）仍是最低兩層。本輪的價值主要不在分數：閘門設定的越界值與未知鍵被拒載（第 55 題的靜默空轉風險消除）、semgrep 閉包重鎖後十三條到期例外全數移除（2026-12 的必然紅燈解除）、工具佐證加上面向限定（第 6、52 題的 A 級升級路徑收緊）、finding ID 改內容排序（第 39 題的盲化洩漏通道關閉）、以及 G-4 的三家族 mock 排練登錄——這些都是證據強化或風險消除，不跨過任何一條評分線。

一句話結論：**機制面已無已知死碼或靜默失效路徑，L1 到 L4 並列 30 分；但所有模型層的 3 分仍只是 mock 下的驗證，人工佇列只跑 dry-run，達 4 分所需的跨期量測一題都還沒有。** 下一個門檻不是分數，而是第一次真實家族執行（G-9）與影子模式啟動（G-10）。

## 3. 每層最低兩題的最小可行下一步

每段引用報告第十部的治理建議編號（G-1 到 G-13，見 `docs/parts/10_governance.md`）。2026-10-03 治理檢查（`docs/governance-check-2026-09-26.md`，當日重產）：G-2、G-3、G-5、G-6、G-11 通過；G-1、G-4、G-7、G-8、G-9、G-10、G-12、G-13 失敗。

### L0

**第 5 題（2 分）Scorecard。** 與第 9 題共用同一個解法：repo 恢復公開，或啟用 GitHub Advanced Security 並移除 `scorecard.yml` 與 `code-scanning` job 的 `!github.event.repository.private` 條件。程式與政策檔都已就緒，缺的只是執行環境。對應 **G-6**（已通過，但 Scorecard 是它的持續量測來源）。

**第 9 題（2 分）code scanning 上傳。** 同上：`code_scanning_prep.py` 與上傳步驟已就緒（六個工具的 SARIF，含 `mara-l0/csp/` category），私有期間跳過中。

同分備註：第 10 題（工具結果作為校準集）同為 2 分。2026-10-03 的 mock 校準已把 §1a 的工具召回率從 n/a 變成實值，機制端對端驗證；下一步是第一次 live 校準。對應 **G-9**（失敗；校準迴圈的參考集不應只有人工標籤）。

### L1

L1 十題全為 3 分；升到 4 分需要跨期量測（真實執行與多期紀錄），先決條件同 L2 到 L5 的「第一次真實家族執行」。第 14 題的增量模式已在 CI 常態執行，影子模式（G-10）在真實 repo 上啟動時，它就是成本前提。

### L2

L2 十題全為 3 分；升到 4 分都需要真實、跨期的量測。前提是第一次 live 校準：屆時 `scripts/calibrate.py::audit_rates` 的 per-family 拒答與無效率表（第 29、30 題）可直接支撐季度 False Refusal Rate 測試。對應 **G-8**（失敗）。

### L3

L3 十題全為 3 分。升到 4 分同樣需要真實執行與跨期紀錄；另有一項非程式前提：**G-1**（失敗）——審查政策仍為草案，需正式核定，否則否證與紅隊的裁決權限沒有制度依據。

### L4

L4 十題全為 3 分；升到 4 分都需要真實、跨期的量測，以下兩題是其餘各題的前提。

**第 47 題（3 分）真實三家族。** 以 `scripts/calibration_run.py --mode live` 對 `config/mara.yaml` 的三個真實家族跑一次完整校準，報告 front matter 記 `mode: live` 與 `families`；同時以 `scripts/model_swap_drill.py record` 對至少一個家族完成 live 換模演練——三個家族的 mock 排練（v0.3.14）已驗證備援面板跑同一流程，live 演練只差真實端點。對應 **G-9**（失敗）與 **G-4**（失敗；有排練、沒有 live 演練）。

**第 49 題（3 分）α 的跨期追蹤。** 機制已備（v0.3.12）且 mock 路徑已驗證：每次 live 執行把 α 與 `judge_agreement[*]` 追加到 `calib/history.json`，報告 §8 列差值並在降幅超過 0.1 時標紅。缺的是資料：第一期 live 校準寫入 baseline，季度重跑才產生可比較的差值。對應 **G-9**（失敗；季度重跑的價值在於可比較）。

### L5

**第 59 題（1 分）權重每季更新。** 依賴第 58 題真的有裁決：設定 `MARA_HUMAN_QUEUE_ISSUES=true` 讓 `human-queue` job 離開 dry-run，至少一位裁決者以 `scripts/training_register.py` 登錄 adjudicator 訓練，第一批裁決回寫後跑 live 校準，並以 PR 形式把 `suggest_weights` 的結果寫回 `config/mara.yaml`（附校準報告連結）。對應 **G-9**、**G-13**（皆失敗；未受訓者的裁決不進校準）與 **G-11**（已通過，但目前只有結構、沒有任何工單）。

**第 58 題（2 分）工單與裁決回寫。** 程式與測試齊全，缺的正是上一段的兩個開關（repo 變數與訓練紀錄）。

同分備註：第 55、56、60 題同為 2 分。第 60 題（無監督不採納的統計驗收）的下一步是第一批真實裁決回寫 `calib/decisions/` 後跑 live 校準，讓 AAT 通過並寫入 `calib/latest.json`，屆時才可依 G-9 證據把 `unsupervised_reject_allowed` 設為 `true`；在此之前 P8 會擋下任何嘗試。第 55 題在政策核定（G-1）後把阻擋路徑收斂到題目字面；第 56 題在 repo 公開或啟用 GHAS 後上傳 code scanning。

## 4. 上海與重慶廠區：CN-1 到 CN-4

**前提假設。** 對話中沒有說明組織是否有上海或重慶廠區。本表依報告第八部第 21.2 節與第十部第 26 章的情境（跨國 ODM/EMS，有上海浦東與重慶廠區）評估；若組織沒有這兩個廠區，本表整體不適用。

| 條目 | 內容摘要 | 是／否／不適用 | 證據與缺口 |
|---|---|---|---|
| CN-1 | 境內管線完全獨立：repo、runner、L0 工具、家族部署、報告全部在境內，原始碼／SARIF／校準資料／人工裁決不出境 | 否 | 證據仍是 `config/examples/prc-site.yaml`（DeepSeek 與 Nemotron 皆 `on_prem`、無 Claude、`reduced_panel_reason` 引用 CSL/DSL/PIPL）並通過 `mara check-config`。相關能力：L0 工具可由 `tools/versions.lock` 離線安裝驗證（含 npm kind 的 csp-evaluator），`scripts/trivy_db.py` 可匯出／匯入離線資料庫供無對外連線的 runner 使用。但 repo 內仍沒有境內 runner、境內 Git 服務或報告不出境的實作或紀錄；`human-queue` job 以 GitHub issue 為工單，本身就在境外 |
| CN-2 | 境內自架的 DeepSeek 仍適用敏感詞校準（第 13 章第 14 項的配對樣本測試），結果留在境內 | 否 | 未變：`calib/samples/` 的五個樣本與 `scripts/gen_calib_samples.py` 沒有中性／敏感詞配對樣本；`calibrate.py` 沒有配對比較邏輯；`scripts/model_eval.py` 的 garak／CyberSecEval 也不含此項，且從未執行 |
| CN-3 | 全球安全團隊只接收面向分數的彙總，不接收 finding 明細 | 否 | 未變：`report/markdown_out.py`、`sarif_out.py`、`human_queue_out.py` 都輸出完整 finding 明細（檔案、行號、逐字引用）；沒有只匯出 `dimensions` 與 `overall_score` 的彙總模式或跨境輸出開關 |
| CN-4 | 境內管線的稽核對應以中國標準為主（等保 2.0、GB/T），由境內團隊另行製作 | 不適用 | 報告第 26 章明示本報告不代為對應；本 repo 沒有也不預期有等保 2.0 對應。此項由中國區合規團隊另行產出，不在本 repo 範圍 |

## 5. 與 2026-10-01 比較

| 層 | 2026-10-01 | 2026-10-03 | 差值 |
|---|---:|---:|---:|
| L0 確定性錨定層 | 27 | 27 | 0 |
| L1 情境建構層 | 29 | 30 | +1 |
| L2 專家審查層 | 30 | 30 | 0 |
| L3 對抗驗證層 | 30 | 30 | 0 |
| L4 陪審裁決層 | 30 | 30 | 0 |
| L5 評分與輸出層 | 24 | 24 | 0 |
| 合計 | 170 | 171 | +1 |

**主要原因。**

- **L1（+1）**：第 14 題 2→3，增量審查自 v0.3.14 起在 `tests + mock review` job 常態執行（每次 PR 與 push 各跑一次 `--base` 模式，報告入 artifact），不再是選用旗標。
- **各層 0 分差的實質變化**（不跨評分線，但改變風險面）：v0.3.13 的閘門設定驗證消除第 55 題的靜默空轉風險；v0.3.15 的 semgrep 1.179.0 重鎖移除十三條到期例外（第 3 題的 2026-12 紅燈解除）、工具佐證加面向限定（第 6、52 題）、finding ID 內容排序（第 39 題）、skeptic／redteam parser 必填（第 24 題）；v0.3.14 的三家族 mock 換模排練登錄（第 47 題的 G-4 證據）。mock 校準第二次執行（2026-10-03）把第 10 題的 §1a 召回率與第 59 題的建議權重從 n/a 變成實值。
- **未變的根本限制**：CI 只跑 mock，真實家族、model-eval、live 校準、PSIRT 握手、live 換模演練、訓練紀錄、政策核定都沒有發生（G-1、G-4、G-7、G-8、G-9、G-10、G-12、G-13 失敗），因此沒有任何題目升到 4 分。

## 6. 複算與驗收

`python3 scripts/score_assessment.py docs/assessment-2026-10-03.md` 會檢查：60 題編號齊全且不重複、每題分數在 0 到 4 且證據欄非空、六層加總與第 2 節的彙總表一致、CN 表四列齊全。`tests/test_assessment.py` 在 CI 中對 `docs/assessment-*.md` 全部執行同一檢查。
