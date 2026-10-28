# 六層差距評估（2026-10-12）

> **後續狀態（2026-10-27）**：本評估保留當時的分數與證據，並非現況清單。其後已實作 CN-3 的分數彙總匯出
> （見 `docs/adr/0004-score-summary.md`），但這不代表 CN-1 的境內隔離已實地驗證。G-11 的檢查已要求真實工單同步
> 證據；2026-10-19 的治理追蹤改判失敗。本檔第 58、59 題及 CN-3 仍是當時紀錄。2026-10-08 校準數字的配對
> 限制與重算前提見 `docs/calibration-review-2026-10-27.md`。

依附錄 D 的 60 題問卷（`docs/appendix-d-maturity.md`），對本組織目前的程式碼審查流程做差距評估。本檔由 Claude Code 起草、owner 審閱定稿（2026-10-12；第 59 題由建議的 2 分改回 1 分）。2026-10-13 修訂：repo 已於 2026-10-12 恢復公開，第 5、9 題依公開後 Scorecard 與 code scanning 的實際執行紀錄由 2 分改為 3 分（owner 核定），第 56 題只更新證據、分數不變；L0 由 27 分變為 29 分，合計由 171 分變為 173 分。本檔是 `docs/assessment-2026-10-03.md` 的重跑；基準為 main 的 `a64e78c`（v0.4.14），涵蓋 v0.3.16 到 v0.4.14：正式面板改為 Bedrock 上的 Claude Opus 5.5、Gemini 3.8 Flash 與自架 GLM（v0.4.2），第一次對真實端點的 live 審查與其揭露缺陷的修正（v0.4.4、v0.4.5），G-8 接上正式面板（v0.4.6，尚未執行），第一次 live 校準（v0.4.8，G-9 通過），以及 2026-10-12 程式碼審查後的修正（v0.4.10–v0.4.14）。

## 0. 評估範圍、證據與規則

**評估對象。** 本 repo（`chinchiang/MultiAgentAlpha`）所代表的程式碼審查流程：MARA 雛型本身、它的四個 GitHub Actions workflow（`mara-review.yml`、`scorecard.yml`、`governance.yml`、`docs-check.yml`）、設定檔、L0 工具鎖定檔與校準工具。

**可用證據。** 只有本 repo 的檔案：`.github/workflows/`、`config/`、`src/mara/`、`tests/`、`scripts/`、`tools/`、`calib/`、`docs/`，以及本 repo 的 GitHub Actions 執行紀錄（`gh run list`）。對話中沒有提供任何關於組織其他 repo、工單系統、人力或流程的說明，因此凡是問「每個 repo」「定期」「接工單」「每季」的題目，若本 repo 內沒有對應證據，一律給 0 分並標「無證據」，不推測。已實作但從未實際執行的機制（garak／CyberSecEval 評測、PSIRT 真實握手、live 換模演練、訓練登錄簿、政策核定）不計為執行紀錄；真實家族的審查與校準已實際執行（2026-10-08 的 live 校準），計為一次執行紀錄。三個正式家族各有一次 mock 換模排練（`ops/model-swap-drills.yaml`，kind: rehearsal），它證明備援設定可載入、流程不變，但不等同 live 演練，G-4 維持失敗。

**評分規則（附錄 D 的五級如何套到本 repo）。**

| 分數 | 附錄 D 定義 | 本次判定方式 |
|---|---|---|
| 0 | 沒有做 | repo 內找不到任何實作或執行紀錄 |
| 1 | 臨時或個案 | 只有設計文字（報告、prompt 檔、註解）或只有未接進管線的程式片段 |
| 2 | 有文件但未全面 | 程式已實作並有測試，但只在 mock 模式、或只涵蓋部分角色／工具、或未進 CI 阻擋、或目前被條件跳過而不執行 |
| 3 | 全面執行且有紀錄 | 程式強制執行、CI 每次 PR 都跑且為 main 的必要 check（`L0 deterministic tools`、`tests + mock review`）、輸出留在 `out/`、`bias_audit` 或 Actions artifact 中可查 |
| 4 | 全面執行、有量測、有持續改善 | 需要跨期量測與改善紀錄；本 repo 只有一次 live 校準（尚無第二期可比較），無任何題目達此級 |

**三個必須先講的限制。** 第一，CI 仍只跑 mock 模式；真實三家族（Claude、Gemini、GLM）只在 2026-10-08 的 live 校準（五個合成樣本、51 個標籤）與其前的 live 審查中執行過，治理檢查 G-9 通過、G-8 失敗。L2 到 L5 的 3 分因此是「機制由程式強制、在 mock 下每次驗證，且在真實模型上執行過一次」，不是「真實 repo 上長期驗證」。第二，本 repo 是唯一的 repo，「每個 repo」類題目的滿分上限實際上受限於樣本數為一。第三，本 repo 在 2026-09-21 到 2026-10-12 為私有：期間 `scorecard.yml` 的 API job 與 `mara-review.yml` 的 `code-scanning` job 都以 `!github.event.repository.private` 條件跳過。repo 於 2026-10-12（06:17 到 08:06 UTC 之間）恢復公開後兩者恢復執行，第 5、9 題依公開後的執行紀錄給分（2026-10-13 修訂，紀錄以 `gh run list` 與 code scanning analyses API 查得）。

## 1. 逐題評分

### L0 確定性錨定層

| # | 題目 | 分數 | 證據 |
|---|---|---:|---|
| 1 | 每個 repo 的 CI 都執行 SAST（semgrep 或 CodeQL）並輸出 SARIF | 3 | `mara-review.yml` 的 `deterministic-tools` job 以 `scripts/semgrep_ci.py` 跑兩步：對 `.` 全 repo 掃描，未在 `tools/semgrep-triage.yaml` 附理由判定的 finding 一律使 job 失敗；對 `fixtures/vuln-sample` 掃描並要求與 `fixtures/vuln-sample-sarif/semgrep.sarif` 完全一致（v0.3.15 起預錄檔為 semgrep 1.179.0 的真實輸出，15 個 finding，與 1.177.0 時完全相同）。規則為 `tools/versions.lock` 固定的 semgrep-rules，非零結束碼與 failed invocation 不當成清白（F07，`tests/test_security_regressions.py::test_semgrep_error_with_sarif_cannot_pass`）。`semgrep.sarif` 留在 `l0-sarif` artifact。「每個 repo」只有本 repo 一例 |
| 2 | 每個 repo 的 CI 都執行 secret scanner（gitleaks、TruffleHog 或 detect-secrets） | 3 | `scripts/gitleaks_ci.py` 以鎖定的 gitleaks 8.30.1 掃描 PR 的 merge-base..head 全部 commits（F08，`tests/test_security_regressions.py::test_git_range_includes_all_pr_commits_when_main_advances`），`.gitleaks.toml` 只豁免精確的教材假值（F27）；crash 或 leak 都使 job 失敗，已移除 `continue-on-error`。另在 live 模式以 `pipeline.py::run` 的 secret preflight 阻擋外送（`test_live_secret_preflight_stops_all_provider_requests`） |
| 3 | 每個 repo 的 CI 都執行 SCA（OSV-Scanner、Trivy 或 Grype）且以 OSV 而非只以 CPE 比對 | 3 | `scripts/osv_ci.py` 對 `tools/*-requirements.txt` 的 hash 鎖定閉包掃描（`tools/osv-scanner.toml` 無漏洞例外；model-eval 閉包另以 `tools/osv-model-eval.toml` 掃描），未忽略的 advisory 使 job 失敗，並須在 fixture 上抓到 `requests==2.19.0`；`scripts/trivy_ci.py` 以 `scripts/trivy_db.py` 記錄雜湊的離線資料庫掃描全 repo，未列於 `tools/trivyignore.yaml` 者使 job 失敗。v0.4.11 起 `mara review` 本身在執行 trivy 前也跑與 `trivy_db.py status` 相同的檢查（trivy.db 的 SHA-256 與紀錄一致、`metadata.json` 的 UpdatedAt 與紀錄相同、不超過 `tools/trivy-db.yaml` 的 `max_age_hours`），不通過即記 trivy 未執行、審查不完整（`tests/test_base_ref_trivy_hf_token.py`）。待辦：garak 閉包的 nltk／fsspec／datasets 例外 2026-12-17 到期（`tools/osv-model-eval.toml`、`tools/trivyignore.yaml`）。每週 `schedule` 另跑一次（F28） |
| 4 | 所有 GitHub Actions workflow 都經 zizmor 或 actionlint 檢查 | 3 | `scripts/zizmor_ci.py --target .github/workflows` 以 `tools/versions.lock` 鎖定的 zizmor 1.30.1 檢查全部四個 workflow，任何 finding 使 job 失敗；fixture 的 workflow 另一步單獨檢查，須與預錄 `zizmor.sarif` 一致；`tests/test_zizmor_ci.py` |
| 5 | OpenSSF Scorecard 定期對所有 repo 執行並追蹤分數 | 3 | `.github/workflows/scorecard.yml`（每週二 02:00 UTC cron＋push main）以 `scripts/scorecard_ci.py` 執行鎖定的 scorecard 5.5.0，`tools/scorecard-policy.yaml` 對六個強制項設最低分，未達即使 job 失敗。repo 於 2026-10-12 恢復公開後，API job 不再被 `!github.event.repository.private` 跳過：自 10-12 08:06 UTC 起 main 上每次 push 都成功執行，10-13 02:30 的每週排程亦成功；最近一次（`29943f3`）總分 6.0，六個強制項全部達標（policy met），結果以 `scorecard` category 上傳 code scanning（10-12 起 main 上 27 筆分析），JSON 留在 `scorecard` artifact。私有期間（2026-09-21 到 10-12）由 `scorecard-local` job（v0.3.1）以 `scorecard --local` 對 committed tree 維持檔案型強制項的把關。未達 4 分：分數只在 job 日誌、artifact 與 code scanning 中，沒有跨期紀錄或依分數改善的紀錄。非強制項備註：Branch-Protection 為 -1（workflow token 讀不到 classic branch protection，未計分）；Vulnerabilities 為 0，14 筆中 11 筆來自 `fixtures/vuln-sample/` 與 `calib/samples/s4-flask-files/` 刻意埋的舊版套件，3 筆是 garak 閉包已登記於 `tools/osv-model-eval.toml`、2026-12-17 到期的例外（見第 3 題） |
| 6 | CSP 政策以 csp-evaluator 自動檢查 | 3 | v0.3.11（PR #53）實作：`src/mara/tools/runner.py` 的 `TOOL_DIMENSIONS` 加 `csp-evaluator: ["csp"]`；`tools/versions.lock` 鎖定 Google csp-evaluator 1.1.8（npm tarball，SHA-256＋registry `dist.integrity` 下載後重算比對，解包檢查拒絕 symlink／路徑逃逸），`scripts/install_tools.py` 安裝 driver 後以 node ≥ 18 執行。`src/mara/tools/csp_eval.py` 從原始碼樹抽取 CSP 政策送驅動評分，severity 映射進 SARIF，解析失敗記 `CSP_PARSE_ERROR` 不當清白。`scripts/csp_ci.py` 對 seeded fixture 走 `--expect` 預錄漂移檢查、對本 repo 走 `--triage`（`tools/csp-triage.yaml` 6 條全數附理由）；`mara-review.yml` 兩個 csp 步驟在 `deterministic-tools` job 內阻擋；`tests/test_tools_csp.py` 11 例。v0.3.15 起工具佐證受 `TOOL_DIMENSIONS` 限定，csp-evaluator 的無 CWE 結果不再能佐證其他面向的 finding（`tests/test_pipeline_mock.py::test_tool_corroboration_respects_tool_dimensions`） |
| 7 | 工具版本固定並有簽章或雜湊驗證 | 3 | `tools/versions.lock` 固定九個工具（含驗證器 cosign、slsa-verifier）與 semgrep-rules，`scripts/install_tools.py` 對每個資產驗 SHA-256，再驗發行者簽章／provenance（cosign keyless、SLSA、GitHub attestation、GPG commit 簽章；見 `docs/tools-provenance.md`）；`runner.py::tool_path` 只用工具目錄的 `bin`、不查 PATH；v0.4.14 起 `install_tools.py` 的預設安裝目錄與 runner 一致（`MARA_TOOLS_DIR`，否則 MARA 工作區下的 `.mara-tools`），先前設了 `MARA_TOOLS_DIR` 時工具會裝到 runner 不看的位置；Python 閉包全以 `--require-hashes` 安裝；全部 action 固定到完整 SHA（`docs/actions-inventory-2026-10-12.md`）。治理檢查 G-5 通過。缺口：gitleaks 與 semgrep 上游無簽章，只有雜湊；garak 閉包的 multidict 為手動套用的單條修補，待完整 relock |
| 8 | 工具在隔離 runner 執行，與模型呼叫分屬不同 job | 3 | `deterministic-tools`、`code-scanning`、`tests-and-mock-review`、`human-queue` 四個 job 各自宣告最小權限、`persist-credentials: false`；有 `security-events: write` 的 job 不 checkout、不執行 repo 程式（F26，`tests/test_security_regressions.py::test_sarif_upload_job_has_no_repository_code_and_osv_scopes_are_separate`）。v0.3.14 起九個 job 全部設 `timeout-minutes`（45／30／20／10 分），卡住的步驟不會燒到 360 分鐘預設上限，`scripts/actions_inventory.py` 把缺 timeout 列為 Low finding、測試把關。備註同前次：模型 job 讀的是 repo 內預錄的 SARIF，不是 L0 job 的 artifact |
| 9 | 工具結果上傳至集中式 code scanning 或等效系統 | 3 | `code-scanning` job 以 `scripts/code_scanning_prep.py` 在唯讀 job 中預處理後，用 `github/codeql-action/upload-sarif`（v4.38.3，SHA 固定）上傳六個工具的八份 SARIF（semgrep、osv-scanner 三份、trivy、gitleaks、zizmor、csp-evaluator，category `mara-l0/*`；`tests/test_code_scanning_prep.py`）。repo 於 2026-10-12 恢復公開後不再被私有條件跳過：每次 push main 與同 repo 的 PR 都上傳，10-12 到 10-13 main 上共 208 筆 `mara-l0/*` 分析，PR #109 的 merge ref 也有上傳。Fork 與 Dependabot 的 PR 依設計不上傳（唯讀 token 會得到 403），SARIF 仍留在 `l0-sarif`／`code-scanning` artifact；`code-scanning` 不是 main 的必要 check。私有期間（2026-09-21 到 10-12）沒有任何上傳 |
| 10 | 工具結果作為模型審查的校準集使用 | 2 | `scripts/calibration_run.py` 在 review 迴圈後對每個 `calib/samples/*` 以鎖定工具跑 semgrep／osv-scanner／gitleaks，`scripts/calibrate.py::load_tool_labels` 讀取作為第二組參考標籤，報告 §1a 列每家族對工具 finding 的召回率；`tests/test_calibration.py` 涵蓋。2026-10-08 第一次 live 校準實際使用（`docs/calibration-2026-10-08.md`：`tool_labels: 40`）。維持 2 分：校準迴圈不是 CI 必要 check，只有一次 live 執行、沒有跨期紀錄 |

### L1 情境建構層

| # | 題目 | 分數 | 證據 |
|---|---|---:|---|
| 11 | 審查前自動建立 repo 的入口點與信任邊界清單 | 3 | v0.3.10（PR #52）補上信任邊界：`repo_map.py::build_context` 的 `_ENTRY_PATTERNS` 抓 Flask/FastAPI/Express 入口點寫進 `RepoContext.entry_points`；`roles.context` 的 context agent 一次呼叫產生 C4-lite（containers、external_systems、trust_boundaries、data_stores），每個事實須通過與 finding 相同的逐字引文驗證（`verify_quote`），不過即丟棄並計數；architecture 與 authn_authz 面向的 reviewer 提示詞前置可信事實區塊。`config/mara.yaml` 與 `config/mara.mock.yaml` 皆已設定 `roles.context`，CI 的 mock review 每次執行 |
| 12 | 審查輸入剝除 commit message、作者與 PR 描述 | 3 | `repo_map.py::build_context` 只以 `git ls-files --cached` 取路徑、以 `git rev-parse HEAD` 取 commit SHA 作 `revision`，從不讀 commit message、作者或 PR 事件；`_common_system.md` 規則 7 禁止提及作者；`tests/test_agent_harness.py::test_context_strips_nothing_but_records_entry_points` |
| 13 | 依賴清單與 workflow 清單自動納入審查範圍 | 3 | `repo_map.py` 的 `MANIFESTS` 與 `.github/workflows/` 偵測寫入 `RepoContext.manifests`／`workflows`；`priority()` 讓 manifest 與程式碼先於 `.md`／`.txt`／`.html` 納入；`ctx.summary()` 列出兩者 |
| 14 | 增量審查會納入與變更相關的檔案而非只有 diff | 3 | `mara review --base <git-ref>` 以 `git diff --name-only <base>...HEAD` 收斂 bundle 到變更檔、其一階 import 鄰居與全部 manifest、workflow；其餘以 `out_of_increment` 記入 coverage，變更檔不在 bundle 時 fail-closed。v0.3.14 起在 `tests + mock review` job 每次 PR 與 push 常態執行。v0.4.12：鄰居改以模組比對（完整名或點分後綴；不再以字串前綴，`import re` 曾帶入 README.md、requirements.txt、report/），反向不因匯入整個套件而成立（`tests/test_core_review_fixes_8_13.py`）；v0.4.11：`--base` 拒絕以 `-` 開頭的值並在範圍前加 `--end-of-options`（`--base --output=<路徑>` 曾讓 git 寫任意檔案；`tests/test_base_ref_trivy_hf_token.py`） |
| 15 | bundle 有大小上限且超限時有明確的優先規則 | 3 | `repo_map.py` 有 `MAX_FILE_BYTES`、每請求 `MAX_TOTAL_CHARS`（`RepoContext.batches` 把全部納入內容分批送出）與整體 `MAX_REPOSITORY_CHARS`；`priority()` 為明確的納入順序；超限者寫入 `ctx.omitted`（`request_size_limit`／`repository_size_limit`／`unreadable_unsafe_or_oversize`），`ctx.complete` 為假時 `pipeline.py::run` 記 `context_coverage_incomplete`、gate 阻擋（F03）；`tests/test_security_regressions.py::test_context_batches_cover_all_sources_and_report_oversize` |
| 16 | 被審查內容以明確標籤包裹為不可信資料 | 3 | `src/mara/agents/base.py::untrusted_block` 以 `<untrusted_repository_data>` 與每檔 `<file path=...>`（路徑經 `html.escape`）包裹；reviewer、skeptic、redteam、context 的呼叫都經此函式。v0.4.12 起檔案內容中的圍欄標籤（`<file`、`</untrusted_repository_data`、`<context_facts` 等，不分大小寫）的 `<` 顯示為 `&lt;`（`repo_map.fence_safe`），檔案無法提早關閉不受信任區塊；`verify_quote` 接受原文或跳脫後的引文；context agent 的事實區塊同樣跳脫 `<>&` |
| 17 | 每次審查植入 canary 並記錄回應率 | 3 | `base.py::Canary` 每次呼叫植入隨機 token：reviewer、context、skeptic、redteam 都帶 canary。reviewer／context 以 `screen` 把引用植入檔的項目視為回報、其餘位置的 token 為回音；v0.4.8 起截斷的回答不算回音（第一次 live 校準中 GLM 的 4 次「回音」有 3 次是截斷）。skeptic／redteam（v0.4.10）以 `screen_verdicts` 讀截斷前的答案：判決各欄合起來同時寫出 token 與植入檔即為回報，判決保留但不能駁回發現（refuted→weakened）或判定不可利用（no→unknown），其他位置的 token 為回音、整批作廢；回報與回音按角色、按家族計入 `bias_audit`（`canary_echoes`、`canary_reports`、`skeptic_canary_reports`、`redteam_canary_reports` 等，v0.4.14）；任何回音使審查未完成（`tests/test_core_review_fixes.py`、`tests/test_agent_harness.py`） |
| 18 | 審查內容的雜湊作為可重現性的種子 | 3 | `repo_map.py` 計算 `content_hash` 與 `revision`（commit＋原始內容雜湊）；`bias/blinding.py::blinded_batches` 以 `content_hash + family` 作種子；`tests/test_bias_and_scoring.py::test_reverse_pass_is_exact_mirror_and_seeded_order_is_deterministic`、`tests/test_security_regressions.py::test_line_number_overhead_is_bounded_and_redacted_changes_invalidate_revision` |
| 19 | C4 或等效的架構視圖由審查自動產生 | 3 | v0.3.10（PR #52）實作：`run_reviewers` 前由 `roles.context` 指定的單一家族呼叫一次，產出 schema 固定的 C4-lite（containers、external_systems、trust_boundaries、data_stores，每項附 file:line），每個事實經 `verify_quote` 驗證，不過即丟棄並計數；拒答、canary 回應或無可驗事實則不產生視圖，運行記 `context_view_incomplete`（fail-closed，絕不虛構架構）；`tests/test_pipeline_mock.py` 涵蓋產生與 fail-closed 兩條路徑。mock 的 `roles.context: mock-a` 讓 CI 每次執行 happy path |
| 20 | 情境建構的產出可被人工查閱 | 3 | `RepoContext.coverage()` 寫入 `out/report.json` 的 `coverage`（included、omitted、excluded、redacted、complete、content_hash、revision）；`pipeline.log` 的 `L1:` 行為 `ctx.summary()`；CI 每次以 `mara-report` artifact 保存（v0.3.14 起含增量模式的報告）。送給模型的 bundle 本身不存檔，但可由 `revision` 與 included 清單重建 |

### L2 專家審查層

| # | 題目 | 分數 | 證據 |
|---|---|---:|---|
| 21 | 十一個面向都有專屬的審查 prompt | 3 | `src/mara/prompts/reviewer_*.md` 共 11 個，`agents/reviewer.py::review_dimension` 以 `load_prompt(f"reviewer_{dimension}")` 載入；`config/mara.yaml` 的 `dimensions` 列 11 項（v0.3.15 起設定拒載空清單，`min_length=1`，零呼叫的「完整審查」不可能通過載入） |
| 22 | 每個面向至少由兩個不同模型家族獨立審查 | 3 | `pipeline.py::run_reviewers` 對每批、每面向逐一呼叫 `roles.reviewers` 全部；`policy.py` P3 要求 reviewer 家族數 ≥ 3；`tests/test_policy.py` |
| 23 | 審查者之間沒有任何通訊 | 3 | `run_reviewers` 每次呼叫只帶該批 context 與 prompt，不帶其他家族輸出；`pipeline.py` 檔頭註解明示 |
| 24 | 模型輸出限制為嚴格的 JSON schema 並經驗證 | 3 | `reviewer.py::FINDING_SCHEMA`、`judge.py::JUDGE_SCHEMA`、`skeptic.py::SKEPTIC_SCHEMA`、`redteam.py::REDTEAM_SCHEMA` 皆 `additionalProperties: false`；`base.py::parse_items` 以 pydantic 驗證；skeptic、redteam、judge 回覆缺漏或重複時整批拒收並逐項計無效（v0.3.18 `coverage_errors`）。傳送方式依 provider：直接 Anthropic API 以 `output_config.format`、OpenAI 相容端點以 `response_format: json_schema`（`strict_schema: false` 時只作指引）、Gemini 以 `responseJsonSchema`、Bedrock 上的 Opus 5.5 以唯一的 `submit_result` 工具（v0.4.4；Bedrock 拒絕 `output_config.format`）——後兩者不受語法約束，一律由 pydantic 重新驗證；字串上限送為描述、回答後以 `clip_strings` 截斷。CVSS 向量在模型邊界完整解析 |
| 25 | 每個 finding 都有檔案、行號與逐字引用 | 3 | `FINDING_SCHEMA.provenance` 為 `minItems: 1`，每項必填 `file`、`line`、`quote`；`schemas.py::Provenance` |
| 26 | 引用不存在於檔案的 finding 自動作廢 | 3 | `base.py::verify_quote` 只對實際 context 比對、拒絕目錄外與超界行號、不回退讀磁碟（F12，`test_quote_validation_never_falls_back_to_disk`）；`pipeline.py::score` 要求全部 provenance 皆已驗證（`test_one_verified_quote_cannot_launder_an_invalid_primary_location`）；`tiers.py::assign_tier` 對未驗證者給 D；`tests/test_pipeline_mock.py::test_fabricated_quote_is_rejected_as_tier_d` |
| 27 | 標準條文 ID 對照 pinned 的機器可讀清單驗證 | 3 | `scoring/idcheck.py::check_finding_refs` 對照 `src/mara/groundtruth/*.json`；`docs/groundtruth-diff-2026-09-21.md` 為首次季度核對並已套用 ASVS 5.0.0 V17；`tests/test_bias_and_scoring.py::test_idcheck_strips_nonexistent_refs`。v0.3.15：回傳改為 `RefCheck(finding, stripped, unknown_cwe)`，`standard_refs_stripped` 只計真正被剝除的 refs，未知 CWE 另計（`bias_audit["unknown_cwe"]`），計數不再混淆。只有一次核對，未達跨期量測 |
| 28 | 模型的自報信心不直接進入任何計算 | 3 | `schemas.py::Finding.model_confidence` 註解「never used directly」；`grep model_confidence src/mara` 只出現在 schema、reviewer 解析、mock 回覆與 `blinding.py` 的「deliberately absent」註解，`pipeline.py` 與 `scoring/` 皆未讀取 |
| 29 | 審查者拒答被記錄為棄權而非零 finding | 3 | v0.3.10（PR #52）實作：`agents/base.py::parse_items` 把 `refused_or_empty` 拆成拒答與空輸出分開計數；skeptic／redteam／judge／context 的 calls、refusals、invalid items 各有總數與 per-family 版本進 `bias_audit` 與 `incomplete_reasons`。拒答視為棄權：skeptic 拒答的 finding 不再靠它升 B 級（`skeptic_abstained` 原因進人工佇列），judge 任一 pass 拒答計 `judge_refusals`；reviewer 層的 `reviewer_refusals[family]`、`reviewer_truncations[family]` 維持使審查未完成、gate 阻擋。v0.3.15 起空回應的雙層語義（reviewer/context 記拒答、skeptic/judge/redteam 記無效）在 `parse_items` 文件化為刻意設計，兩者皆 fail-closed |
| 30 | 每個模型家族的無效輸出率被追蹤 | 3 | `judge_invalid_items[family]`、`skeptic_invalid_items[family]`、`redteam_invalid_items[family]` 與 reviewer 層計數一起進 `bias_audit`；`scripts/calibrate.py::audit_rates` 彙整全部角色的 per-family 拒答與無效率表，`suggest_weights` 對無效率超過 10% 的家族乘 0.8。2026-10-08 的 live 校準第一次產生真實數字（GLM 無效率 10.80%，建議權重因此折抵；`docs/calibration-2026-10-08.md` §2、§5），v0.4.5 依該次觀察加上 L3／L4 格式錯誤時重試一次（`<role>_retries`）。已有一次量測並據以改善，但尚無跨期紀錄，維持 3 分 |

### L3 對抗驗證層

| # | 題目 | 分數 | 證據 |
|---|---|---:|---|
| 31 | 每個 finding 都有一個否證者（Skeptic）嘗試推翻 | 3 | `pipeline.py::run_skeptics` 對去重後的全部 finding 分組送 skeptic；`skeptic.py::run_skeptic` 在回覆未逐一涵蓋每個 finding 時整批拒收，`skeptic_invalid_items` 使審查未完成 |
| 32 | 否證者的家族必須不同於發現者的家族且由程式強制 | 3 | `bias/diversity.py::pick_independent`（PR #39）對每個 finding 依 skeptic 角色、judges、reviewers 順序挑出不屬於任何 finder 家族（`finders[f.id]`）的模型；全部家族都是 finder 時回傳 `independent=False`，`run_skeptics` 記入 `bias_audit["skeptic_same_family"]` 並寫 log，該 finding 也沒有獨立 judge，由 quorum 規則送人工；`tests/test_security_regressions.py::test_l3_prefers_a_family_outside_every_finder_and_audits_the_fallback`；`policy.py` P3 拒絕 skeptic 與唯一 reviewer 同家族的設定 |
| 33 | 否證必須引用程式碼中的具體控制（檔案與行號） | 3 | `skeptic.py::run_skeptic` 從 refuted 裁決的 `sanitizer_or_control` 解析 `path:line`，必須是本次送給 skeptic 的檔案且行號在範圍內、非空白行，否則把 `refuted` 降為 `weakened` 並計 `skeptic_unverified_controls[family]`。v0.4.10 起保留路徑開頭的點（`.github/workflows/deploy.yml:12` 可驗證，github_actions 面向的反駁不再一律降級）；v0.4.14 起只去掉散文中的刪節號，`../app.py` 不會被改寫成被展示的檔案（`tests/test_review_leftovers.py`） |
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
| 43 | 每個 judge 以正序與倒序各裁決一次 | 3 | `blinding.py::blinded_batches` 以一個種子排序；`pipeline.py::run_jury` 每個 judge 對每個批次各跑 `"forward"` 與 `"reverse"`（反序為該批的鏡像）；`pipeline.py::score` 只計「兩個 pass 各恰一票」的家族（`valid_families`）。v0.4.10 起評審批次有上限（每批最多 25 筆），v0.4.14 起平均分割（26 筆為 13＋13），不會出現正反兩輪位置相同的單筆批次（`tests/test_review_leftovers.py`） |
| 44 | 正反序不一致的裁決被標記並折減 | 3 | `consensus.py::weighted_consensus` 回傳 `position_consistent`，並取正反序平均；`pipeline.py::score` 對不一致者加 `position_inconsistent` 原因，使 `needs_human=True`、`accepted=False`、進人工佇列並使審查未完成；`bias_audit["position_flips"]` 計數；`tests/test_pipeline_mock.py::test_unstable_finding_is_not_accepted`、`test_bias_audit_captures_refusal_and_position_flip`。仍無可設定的折減係數 |
| 45 | 一個家族不裁決自己產出的 finding，或折半計票 | 3 | `run_jury` 排除自家 finding（`self_preference_exclusions`），獨立家族不足時以 `self_family=True` 投票並套 `gate.self_judge_discount`（`policy.py` P4 ≤ 0.5）；同家族票不補 quorum（F23）。v0.4.14 起 P3 拒絕兩位評審來自同一家族的設定（否則該家族每輪兩票、計分時整個家族被丟棄），`mara check-config` 在政策表中列出 |
| 46 | judge 之間沒有通訊 | 3 | `run_jury` 每個 judge 各自收到盲化批次，投票獨立收集 |
| 47 | judge 家族至少三個且來自不同供應商 | 3 | `config/mara.yaml` 的 `judges` 為 anthropic（Bedrock 上的 Claude Opus 5.5）、gemini（Gemini 3.8 Flash，付費 API）、glm（IEC 內網自架），三個不同供應商；`policy.py` P3 強制 ≥ 3 且各來自不同家族。v0.4.4 起真實三家族已對真實端點審查，2026-10-08 完成第一次 live 校準（`docs/calibration-2026-10-08.md`，治理檢查 G-9 通過）。三個家族各有冷備援設定（`config/examples/standby-for-*.yaml`，以閘道的 DeepSeek 替代）並各完成一次 mock 排練（`ops/model-swap-drills.yaml`）；live 換模演練仍缺（G-4 失敗） |
| 48 | judge 家族的兩兩一致率被追蹤 | 3 | `bias/diversity.py::pairwise_family_agreement` 寫入 `bias_audit["judge_agreement[a~b]"]`；`scripts/calibrate.py::judge_agreement` 彙整 |
| 49 | Krippendorff's α 或等效指標對每次審查計算 | 3 | `consensus.py::krippendorff_alpha_nominal` 算語料層級 α 寫入 `bias_audit["global_krippendorff_alpha"]`；單一 finding 記 `pipeline.py::_agreement_proxy`；跨期可比性機制（`calib/history.json` 僅 live 記錄、報告 §8 差值與紅字警告）。2026-10-08 的第一次 live 校準寫入第一期 baseline；尚無第二期可比較，維持 3 分 |
| 50 | α 低於門檻的 finding 進入人工佇列而非投票決定 | 3 | `pipeline.py::score` 在 `agreement_proxy < human_alpha_threshold` 時加 `agreement_below_threshold`，該 finding 不被接受；`human_queue_out.py::build_queue` 產生 `ReviewReport.human_queue: list[HumanQueueItem]`，`sarif_out.py` 為其 result 設 `level: note` 與 `properties.humanQueue`。v0.3.14 修復收緊機制：`score()` 的 `tier_c_high` 原因改為尊重 `tighten_exclude_tier_c` 與 `queue_tier_c_min_severity`（先前無條件附加使收緊分支成為死碼、backlog 上限被架空），backlog 超量時 alpha 門檻提高、tier C 交由陪審共識決定且不再排入佇列，`tests/test_human_queue.py` 涵蓋收緊前後四種組合；`tightening` 只收緊不放寬（`test_tightening_only_when_backlog_is_over_the_limit`） |

### L5 評分與輸出層

| # | 題目 | 分數 | 證據 |
|---|---|---:|---|
| 51 | CVSS 4.0 分數由程式計算且計算器對照 FIRST 參考實作驗證 | 3 | `scoring/cvss4.py` 移植 FIRST `cvss-v4-calculator`；`tests/test_cvss4.py::test_matches_first_reference_implementation` 以 `tests/cvss4_reference.json` 逐向量比對；無效向量回退為 Unknown 並進人工（F06） |
| 52 | 每個 finding 都有證據層級 A 到 D 且規則公開 | 3 | `scoring/tiers.py::assign_tier` 為純函式；`tests/test_bias_and_scoring.py::test_tier_rules`。v0.3.15 起工具佐證受 dimension 限定，csp-evaluator 的無 CWE 結果不再把 ±3 行內的任何 finding 推上 A 級 |
| 53 | SSVC 或等效的行動決策自動產生 | 3 | `tiers.py::ssvc_decision`（Track / Track* / Attend / Act）；`tests/test_bias_and_scoring.py::test_ssvc_decisions` |
| 54 | 面向分數與整體分數的公式公開且可重算 | 3 | `scoring/dimension_score.py` 的 `PENALTY` 與 `TIER_FACTOR`；整體分數為面向平均，審查未完成時 `overall_score=null` 並列出 `incomplete_reasons`（F04）；`out/report.json` 含全部中間值 |
| 55 | 閘門只在 A 級與 B 級的 High 以上阻擋 | 2 | `config/mara.yaml` 的 `block_on_tiers: [A, B]`、`block_on_severity: [High, Critical]` 符合；C 級 High 以上送人工（`tier_c_high`，收緊時交由陪審共識並仍受 quorum 把關）；但仍有其他阻擋路徑：`min_dimension_score: 60`（已接受的 C 級以 0.4 係數扣分）與 `pipeline.py::run` 在審查未完成時一律阻擋。後者是刻意的 fail closed，但與題目字面不符。v0.3.13 補上設定驗證：`block_on_tiers`／`block_on_severity` 必須是非空合法清單、`accept_threshold` 限 0–1、`min_dimension_score` 限 0–100、`MaraConfig` 拒載未知鍵——拼字錯誤不可能再把阻擋閘門變成靜默空轉（`tests/test_policy.py::test_gate_rejects_out_of_bounds_unknown_and_empty_values`） |
| 56 | 輸出為 SARIF 2.1 並上傳 code scanning | 2 | `report/sarif_out.py` 產出 SARIF 2.1（v0.3.13 起不再輸出永遠為 null 的 `krippendorffAlpha`，agreement proxy 照常）；MARA 報告的 SARIF 只存於 `mara-report` artifact，`mara-review.yml` 註明 mock review 報告描述種子材料、不上傳。repo 於 2026-10-12 恢復公開後，L0 的 SARIF 已上傳 code scanning（見第 9 題），但 MARA 自己的審查 SARIF 仍從未上傳：要等對真實 PR 的非 mock 審查（G-10 影子期）才有可上傳的輸出 |
| 57 | 每份報告含偏誤稽核區塊（拒答、canary、翻轉、折半票） | 3 | `markdown_out.py` 的「Bias and integrity audit」逐項列出 `bias_audit`：`reviewer_refusals`、`reviewer_truncations`、`canary_echoes`、`position_flips`、`self_family_fallback_votes`、`self_preference_exclusions`、`judge_agreement[*]`，發生時另有 `skeptic_same_family`／`redteam_same_family`；v0.3.10 起拒答與無效輸出按角色、按家族分列；`tests/test_pipeline_mock.py::test_reports_render` |
| 58 | 人工佇列接工單系統且裁決回寫校準集 | 2 | `scripts/human_queue_issues.py` 以 v2 key 為每項建立或更新 issue，`--sync-decisions` 重播 label 事件寫回 `calib/decisions/`（F18、F19）；`scripts/calibrate.py::load_decisions`／`apply_decisions` 讀取；`mara-review.yml` 的 `human-queue` job 在 push main 時執行；`tests/test_human_queue.py::test_tickets_are_created_once_and_decisions_come_back`、`test_calibration_uses_true_positive_decisions_as_labels`；治理檢查 G-11 通過。但 repo 變數 `MARA_HUMAN_QUEUE_ISSUES` 未設定，job 一直是 `--dry-run`，沒有任何 `mara-human-queue` issue；`calib/decisions/` 只有 README；`training/records.yaml` 0 筆而 `require_trained_adjudicator: true`，任何裁決都不會進校準 |
| 59 | 家族權重每季依校準更新 | 1 | `scripts/calibrate.py::suggest_weights` 產出建議權重且不改設定檔；2026-10-08 的 live 校準第一次以真實家族算出建議值（anthropic 1.37、gemini 1.34、glm 1.08；`docs/calibration-2026-10-08.md` §5），但 `config/mara.yaml` 三家族仍為 `weight: 1.0`：權重從未依校準更新，也沒有人工裁決參與。owner 審閱維持 1 分——有真實數據，但「更新」本身尚未發生 |
| 60 | 校準通過統計檢定後才允許無監督的「不採納」 | 2 | `scripts/calibrate.py::alternative_annotator_test` 以 `calib/decisions/` 的人工裁決為對照跑 Alternative Annotator Test，結果進 front matter `aat` 與報告 §7；`GateConfig.unsupervised_reject_allowed` 預設 `false`，`policy.py` P8 只允許在 `calib/latest.json` 記錄 90 天內檢定通過時設為 `true`；為 `false` 時非 D 級的 `accepted=False` finding 一律進人工佇列。2026-10-08 的 live 校準在真實資料上跑了 AAT，結果「未通過」（沒有可對照的人工裁決），`calib/latest.json` 如實記錄；P8 目前不允許任何無監督不採納。維持 2 分 |

## 2. 六層彙總

| 層 | 得分 | 滿分 | 百分比 | 低於 20？ |
|---|---:|---:|---:|---|
| L0 確定性錨定層 | 29 | 40 | 72.5% | 否 |
| L1 情境建構層 | 30 | 40 | 75.0% | 否 |
| L2 專家審查層 | 30 | 40 | 75.0% | 否 |
| L3 對抗驗證層 | 30 | 40 | 75.0% | 否 |
| L4 陪審裁決層 | 30 | 40 | 75.0% | 否 |
| L5 評分與輸出層 | 24 | 40 | 60.0% | 否 |
| 合計 | 173 | 240 | 72.1% | |

**附錄 D 的解讀。** 合計 173，比 2026-10-03 多 2 分（第 5、9 題在 repo 恢復公開後恢復執行，2026-10-13 修訂），仍在 120 到 180 的「單模型階段」區間。其餘各題的證據都因 live 執行與 v0.4.x 的修正而變強，但沒有跨過評分線：第 59 題雖有 live 校準算出的建議權重，權重本身從未更新，維持 1 分；所有 3 分仍缺跨期量測，無題目達 4 分。

一句話結論：**真實三家族已跑過一次完整校準（G-9 通過），但只有一期、沒有人工裁決、權重未套用；升到 4 分的前提是第二期 live 校準、人工佇列離開 dry-run 與受訓裁決者（G-13）。**

## 3. 每層最低兩題的最小可行下一步

每段引用報告第十部的治理建議編號（G-1 到 G-13，見 `docs/parts/10_governance.md`）。2026-10-12 治理檢查（`docs/governance-check-2026-10-12.md`）：G-2、G-3、G-5、G-6、G-9、G-11 通過；G-1、G-4、G-7、G-8、G-10、G-12、G-13 失敗。

### L0

**第 10 題（2 分）工具結果作為校準集。** 2026-10-08 的 live 校準已實際使用 40 個工具參考標籤；下一步是把校準納入定期執行（季度重跑）並保留跨期紀錄。對應 **G-9**（已通過）。

其餘九題皆為 3 分；第 5、9 題於 2026-10-13 修訂時由 2 分升為 3 分（repo 恢復公開後，Scorecard 與 code scanning 上傳都已恢復執行）。兩題升到 4 分都需要跨期量測：第 5 題從現有的每週排程開始保留 Scorecard 分數的歷史紀錄（目前只在 job 日誌、artifact 與 code scanning 中），並讓非強制項 Branch-Protection 可以計分（需要讀得到 branch protection 的 token）；第 9 題可考慮把 `code-scanning` 列為 main 的必要 check。對應 **G-6**（已通過，Scorecard 是它的持續量測來源）。

### L1

L1 十題全為 3 分；升到 4 分需要跨期量測（真實執行與多期紀錄），先決條件同 L2 到 L5 的「第一次真實家族執行」。第 14 題的增量模式已在 CI 常態執行，影子模式（G-10）在真實 repo 上啟動時，它就是成本前提。

### L2

L2 十題全為 3 分；升到 4 分都需要跨期的量測。第一次 live 校準已產生 per-family 拒答與無效率表（第 29、30 題；GLM 無效率 10.80%），第二期校準即可比較；另需 G-8 的 garak／CyberSecEval 執行以支撐季度 False Refusal Rate 測試。對應 **G-8**（失敗）與 **G-9**（已通過）。

### L3

L3 十題全為 3 分。升到 4 分同樣需要真實執行與跨期紀錄；另有一項非程式前提：**G-1**（失敗）——審查政策仍為草案，需正式核定，否則否證與紅隊的裁決權限沒有制度依據。

### L4

L4 十題全為 3 分；升到 4 分都需要真實、跨期的量測，以下兩題是其餘各題的前提。

**第 47 題（3 分）真實三家族。** 三個不同供應商的家族已在 live 校準中執行；缺的是 live 換模演練：以 `scripts/model_swap_drill.py record` 對至少一個家族完成一次，在 168 小時內讓備援面板審查一個真實 PR。對應 **G-4**（失敗；有排練、沒有 live 演練）。

**第 49 題（3 分）α 的跨期追蹤。** 第一期 baseline 已寫入 `calib/history.json`（2026-10-08）；第二期 live 校準（季度重跑或任何模型升級後）才產生可比較的差值，報告 §8 會在降幅超過 0.1 時標紅。對應 **G-9**（已通過；90 天內須重跑）。

### L5

**第 59 題（1 分）權重每季更新。** 決定是否把 2026-10-08 的建議權重（1.37／1.34／1.08）以 PR 寫回 `config/mara.yaml`（附校準報告連結）；51 個標籤只能視為方向，因此也可以決定等第二期與人工裁決。人工裁決的前提：設定 `MARA_HUMAN_QUEUE_ISSUES=true` 讓 `human-queue` job 離開 dry-run，至少一位裁決者以 `scripts/training_register.py` 登錄 adjudicator 訓練。對應 **G-9**（已通過）、**G-13**（失敗；未受訓者的裁決不進校準）與 **G-11**（已通過，但目前只有結構、沒有任何工單）。

**第 58 題（2 分）工單與裁決回寫。** 程式與測試齊全，缺的正是上一段的兩個開關（repo 變數與訓練紀錄）。

同分備註：第 55、56、60 題同為 2 分。第 60 題（無監督不採納的統計驗收）已在 live 資料上執行但未通過（沒有人工裁決）；下一步是第一批真實裁決回寫 `calib/decisions/` 後重跑 live 校準，讓 AAT 通過並寫入 `calib/latest.json`，屆時才可依 G-9 證據把 `unsupervised_reject_allowed` 設為 `true`；在此之前 P8 會擋下任何嘗試。第 55 題在政策核定（G-1）後把阻擋路徑收斂到題目字面；第 56 題：L0 的 SARIF 已在 repo 公開後上傳 code scanning（第 9 題），剩下的是 MARA 自己的審查 SARIF——mock 報告描述種子材料、刻意不上傳，要等 G-10 影子期在真實 PR 上產生非 mock 的審查輸出。

## 4. 上海與重慶廠區：CN-1 到 CN-4

**前提假設。** 對話中沒有說明組織是否有上海或重慶廠區。本表依報告第八部第 21.2 節與第十部第 26 章的情境（跨國 ODM/EMS，有上海浦東與重慶廠區）評估；若組織沒有這兩個廠區，本表整體不適用。

| 條目 | 內容摘要 | 是／否／不適用 | 證據與缺口 |
|---|---|---|---|
| CN-1 | 境內管線完全獨立：repo、runner、L0 工具、家族部署、報告全部在境內，原始碼／SARIF／校準資料／人工裁決不出境 | 否 | 證據仍是 `config/examples/prc-site.yaml`（DeepSeek 與 Nemotron 皆 `on_prem`、無 Claude、`reduced_panel_reason` 引用 CSL/DSL/PIPL）並通過 `mara check-config`。相關能力：L0 工具可由 `tools/versions.lock` 離線安裝驗證（含 npm kind 的 csp-evaluator），`scripts/trivy_db.py` 可匯出／匯入離線資料庫供無對外連線的 runner 使用。但 repo 內仍沒有境內 runner、境內 Git 服務或報告不出境的實作或紀錄；`human-queue` job 以 GitHub issue 為工單，本身就在境外。另：`config/examples/prc-site.yaml` 仍以 `deepseek-v3.2` 與 Nemotron 為面板，未改為閘道的 `deepseek`；正式面板的 GLM 為 IEC 內網自架，不代表境內管線 |
| CN-2 | 境內自架的 DeepSeek 仍適用敏感詞校準（第 13 章第 14 項的配對樣本測試），結果留在境內 | 否 | 未變（GLM 同屬中國關聯家族，同樣沒有配對樣本）：`calib/samples/` 的五個樣本與 `scripts/gen_calib_samples.py` 沒有中性／敏感詞配對樣本；`calibrate.py` 沒有配對比較邏輯；`scripts/model_eval.py` 的 garak／CyberSecEval 也不含此項，且從未執行 |
| CN-3 | 全球安全團隊只接收面向分數的彙總，不接收 finding 明細 | 否 | 未變：`report/markdown_out.py`、`sarif_out.py`、`human_queue_out.py` 都輸出完整 finding 明細（檔案、行號、逐字引用）；沒有只匯出 `dimensions` 與 `overall_score` 的彙總模式或跨境輸出開關 |
| CN-4 | 境內管線的稽核對應以中國標準為主（等保 2.0、GB/T），由境內團隊另行製作 | 不適用 | 報告第 26 章明示本報告不代為對應；本 repo 沒有也不預期有等保 2.0 對應。此項由中國區合規團隊另行產出，不在本 repo 範圍 |

## 5. 與 2026-10-03 比較

| 層 | 2026-10-03 | 2026-10-12 | 差值 |
|---|---:|---:|---:|
| L0 確定性錨定層 | 27 | 29 | +2 |
| L1 情境建構層 | 30 | 30 | 0 |
| L2 專家審查層 | 30 | 30 | 0 |
| L3 對抗驗證層 | 30 | 30 | 0 |
| L4 陪審裁決層 | 30 | 30 | 0 |
| L5 評分與輸出層 | 24 | 24 | 0 |
| 合計 | 171 | 173 | +2 |

**主要原因。**

- **L0 +2（2026-10-13 修訂）**：repo 於 2026-10-12 恢復公開，Scorecard 的 API job 與 code scanning 上傳恢復執行，第 5、9 題由 2 分升為 3 分。
- **其餘分數不變**：第 59 題起草時建議 1→2（live 校準第一次以真實家族算出建議權重），owner 審閱維持 1 分，因為權重尚未依校準更新。
- **不跨評分線的實質變化**（不跨評分線，但改變證據或風險面）：真實三家族的 live 審查與 live 校準（第 10、30、47、49、60 題有了真實數字）；Bedrock 與 Gemini provider、Bedrock 的 `submit_result` 工具路徑（第 24 題）；canary 的回報／回音區分延伸到 skeptic 與紅隊並計入稽核（第 17 題）；圍欄標籤跳脫（第 16 題）；增量審查的模組比對與 `--base` 注入修正（第 14 題）；審查時檢查 trivy 資料庫（第 3 題）；工具安裝目錄與 runner 一致（第 7 題）；評審批次平均分割（第 43 題）；一家族一評審納入 P3（第 45 題）；dotfile 控制點引用（第 33 題）。
- **未變的根本限制**：CI 只跑 mock；model-eval、PSIRT 握手、live 換模演練、訓練紀錄、政策核定都沒有發生（G-1、G-4、G-7、G-8、G-10、G-12、G-13 失敗）；live 校準只有一期，因此沒有任何題目升到 4 分。

## 6. 複算與驗收

`python3 scripts/score_assessment.py docs/assessment-2026-10-12.md` 會檢查：60 題編號齊全且不重複、每題分數在 0 到 4 且證據欄非空、六層加總與第 2 節的彙總表一致、CN 表四列齊全。`tests/test_assessment.py` 在 CI 中對 `docs/assessment-*.md` 全部執行同一檢查。
