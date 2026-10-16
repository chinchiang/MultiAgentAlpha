# 人工佇列、裁決與版本綁定（G-11）

2026-09-18 起，人工佇列直接使用 L5 的 `needs_human`／`human_reasons`，與 gate 共用已套用 backlog 收緊的結果。原因包括獨立評審不足、缺漏或重複回票、無效 CVSS、意見分歧、正反序不一致、以及高嚴重度 C 級 finding。待判項目會阻擋完整審查，不會因佇列超量而消失。

## 輸出與識別

`out/human_queue.json`、Markdown 與 SARIF 保留發現者、skeptic、red team、正反序評審及待判原因。單筆一致度使用 `agreement_proxy`（v0.3.13 起已移除舊的 `krippendorff_alpha` 欄位）。它不是統計上的 Krippendorff alpha；全語料的 alpha 在 bias audit 另行呈現。

每項使用 `v2-` 加 24 位 SHA-256 前綴，雜湊內容為 target ID、revision、context hash、檔案、行號與 CWE。target ID：已提交進 git 歷史的目錄，以正規化的 `origin` URL（https、ssh 與 scp 形式視為同一個）加上目標相對 repo 頂層的路徑命名，因此每個 clone、每台機器與 CI runner 對同一目標的命名都相同；其他目錄（沒有 git、尚未提交，或只是剛好位在家目錄 dotfiles repo 之類的上層 repo 裡）維持以絕對路徑命名。revision 結合目標目錄在 HEAD 的 tree id 與原始文字快照雜湊，不再綁整個 repo 的 commit：目標目錄以外的 commit（例如另一個樣本，或把裁決同步回 `calib/decisions/` 本身）不會讓既有裁決失效，改到被審查的程式碼才會；commit 本身仍記在報告 coverage 的 `commit` 欄供追溯。context hash 綁定實際遮罩後送入模型的內容。2026-10-05 之前的 key 以絕對路徑與 repo commit 計算，已不會再相符，需重跑審查與工單。不能用檔名或 basename 猜測關係。

舊 12 位 key 不自動同步或套用到新校準。請重新產生審查及工單，保留舊工單作歷史紀錄；不要手動把舊裁決改成 v2。

## 工單與裁決

```bash
python3 scripts/human_queue_issues.py --queue out/human_queue.json --repo owner/repo --dry-run
python3 scripts/human_queue_issues.py --repo owner/repo --sync-decisions --dry-run
```

移除 `--dry-run` 才會建立或同步真實工單。建立前先驗證全部項目的 v2 身分；工單正文將模型內容當成文字，並以 `mara-meta` metadata 保存機器可核對的原始身分。

人工裁決者只能留下其中一個 `decision:true-positive` 或 `decision:false-positive` label，再關閉工單。同步會分頁讀取 label 事件、重播加入與移除，將目前唯一仍存在的 label 綁定其 event ID、actor 與時間。兩種裁決同時存在、事件缺漏、舊 metadata 或身分不符都不匯入。資格依加上該存續 label 當日的訓練紀錄判定。

不匯入的工單不會默默消失：沒有或同時有兩個裁決 label、label 事件無法解析、`mara-meta` 缺漏或損壞、身分不符，每張都以 `UNRECORDED #編號: 原因` 列出，同步仍寫完其餘裁決與 backlog，但以 exit code 2 結束，CI job 因此失敗。處理方式是修正 label 後重新關閉，或重新開啟工單。刻意撤回（例如程式已改、finding 不再出現）請以「not planned」關閉且不加裁決 label，這只記錄在 log。

`scripts/human_queue_issues.py` 從設定（`--config`，預設 `<workspace>/config/mara.yaml`）讀取 `human_queue.label`、`backlog_file` 與 `ticketing`：`ticketing: none` 或停用時不開單也不同步；backlog 寫在 `<workspace>/<backlog_file>`，與 pipeline 讀取的位置相同。G-11 只在同步確實執行過（寫過 backlog 或回寫過裁決）時通過，dry-run 期間判定失敗。

同一個 key 只開一張工單：已有開啟中的工單、已關閉且不是撤回的工單（已裁決，或裁決 label 待修正），或 `calib/decisions/` 已有該 key 格式完整（well-formed）的裁決時，都不會再開單（裁決者是否受訓都一樣；格式不完整的紀錄不算回答過，該 key 會帶警告重新開單）；只有先前每一張工單都以「not planned」撤回的 key 才會重新開單。過去只比對開啟中的工單，所以 main 每次 push 都會替已裁決的 key 重新開單。同一個 key 有多張已關閉工單時只寫入一份裁決：各張的裁決一致時，優先寫入受訓裁決者的那一張，否則寫入最早的那一張；裁決互相矛盾時一份都不寫，既有檔案也不修改或刪除，每一張都以 `UNRECORDED` 列出、同步以 exit code 2 結束，須重新開啟這些工單，或只保留其中一張的裁決 label。過去會依清單順序逐一寫入，最後讀到的那一張蓋掉先前的裁決，即使它出自未受訓的裁決者，或是相反的裁決。GitHub API 讀取失敗時整個同步中止（exit 1），不會當成「沒有裁決」。

工單清單經 REST API 讀取並跟隨每一頁，沒有筆數上限；過去 `gh issue list --limit 500` 會在超過 500 張時重複建立工單、低估 backlog、漏讀已關閉工單的裁決。dry-run 也會讀取既有的開啟工單，顯示的就是實際會建立的工單。

重新審查同一份內容（target、revision 與 context hash 都相同）時，pipeline 讀回可用的裁決，直接定案對應的 finding（human-resolved finding，見 `docs/adr/0003-human-resolution.md`）：人工判定在兩個方向都優先於評審團，判為真陽性即採納（證據層級不變，閘門的阻擋規則與 PSIRT 觸發照常適用），判為誤報即不採納，並在 SARIF 中以 `suppressions`（`kind: external`，理由為工單編號與裁決者）輸出，讓 code scanning 記錄關閉的原因。兩種情況下 finding 都離開佇列，也不再使審查不完整（`unresolved_human_review`）。評審團的結論原樣留在 `accepted`／`needs_human`，校準與影子期基準讀的仍是它；工具結果不受影響。格式完整但不可用的裁決（例如裁決者未受訓）不定案任何東西，finding 留在佇列並帶 `decision_not_usable:<原因>`。完整審查與增量審查的 context hash 不同，彼此的裁決不互相套用。偏誤稽核記錄 `human_decisions_applied` 與 `human_decisions_not_usable[<原因>]`。

`calib/decisions/` 是工單的鏡像。一筆裁決何時算數只有一套規則（`mara.decisions`，見 `docs/adr/0002-usable-decisions.md`）：校準標籤、替代標註者測試與影子期的誤報率只採用「可用」（usable）的裁決，也就是格式完整、target、revision、context hash 都與該份報告相符、同一個 key 沒有矛盾的裁決，而且預設要求裁決者在裁決當天持有有效的訓練紀錄（使用時依登錄簿判定，不看紀錄裡的 `adjudicator_trained`）。某個有實際呼叫的模型完全沒產生 finding，仍會計入漏報與拒答。

## Backlog 與 CI

`human_queue.backlog_limit` 以上會提高 agreement proxy 的門檻；`tighten_exclude_tier_c: true`（預設）時，`queue_tier_c_min_severity` 以上的 C 級 finding 不再排入佇列，但既然沒有人會看，陪審團接受的這類 finding 會像 A／B 級一樣阻擋 gate（bias audit 記 `tier_c_blocked_while_tightened`），不會只憑單一家族加陪審共識就放行：收緊只減少人工負擔，從不放寬。審查報告的 `human_queue_tightening` 記錄當時的 backlog（未知時為 null）、是否收緊與生效的門檻，`report.md` 的 Human queue 一節列出同一行。歷史設定名 `gate.human_threshold_alpha`／`tighten_alpha_step` 暫保留相容性；待判結果始終保留在佇列中。`human_queue.enabled: false` 只關閉佇列檔案，不能關閉阻擋判定。

CI 的 human-queue job 僅於 main push、測試通過後執行，具 `issues: write` 而無 `contents: write`。除非儲存庫變數 `MARA_HUMAN_QUEUE_ISSUES=true`，它維持 dry-run。裁決 artifact 必須由負責人核對後保存；本次修正未建立對外工單或填造訓練紀錄。
