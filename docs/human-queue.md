# 人工佇列、裁決與版本綁定（G-11）

2026-09-18 起，人工佇列直接使用 L5 的 `needs_human`／`human_reasons`，與 gate 共用已套用 backlog 收緊的結果。原因包括獨立評審不足、缺漏或重複回票、無效 CVSS、意見分歧、正反序不一致、以及高嚴重度 C 級 finding。待判項目會阻擋完整審查，不會因佇列超量而消失。

## 輸出與識別

`out/human_queue.json`、Markdown 與 SARIF 保留發現者、skeptic、red team、正反序評審及待判原因。單筆一致度使用 `agreement_proxy`；舊 `krippendorff_alpha` 欄位保留為 null。它不是統計上的 Krippendorff alpha；全語料的 alpha 在 bias audit 另行呈現。

每項使用 `v2-` 加 24 位 SHA-256 前綴，雜湊內容為 target ID、revision、context hash、檔案、行號與 CWE。target ID 綁定正規化的本機目標路徑；revision 結合 Git HEAD（若有）與原始文字快照雜湊；context hash 綁定實際遮罩後送入模型的內容。更換工作目錄或版本需要重跑審查，不能用檔名或 basename 猜測關係。

舊 12 位 key 不自動同步或套用到新校準。請重新產生審查及工單，保留舊工單作歷史紀錄；不要手動把舊裁決改成 v2。

## 工單與裁決

```bash
python3 scripts/human_queue_issues.py --queue out/human_queue.json --repo owner/repo --dry-run
python3 scripts/human_queue_issues.py --repo owner/repo --sync-decisions --dry-run
```

移除 `--dry-run` 才會建立或同步真實工單。建立前先驗證全部項目的 v2 身分；工單正文將模型內容當成文字，並以 `mara-meta` metadata 保存機器可核對的原始身分。

人工裁決者只能留下其中一個 `decision:true-positive` 或 `decision:false-positive` label，再關閉工單。同步會分頁讀取 label 事件、重播加入與移除，將目前唯一仍存在的 label 綁定其 event ID、actor 與時間。兩種裁決同時存在、事件缺漏、舊 metadata 或身分不符都不匯入。資格依加上該存續 label 當日的訓練紀錄判定。

`calib/decisions/` 是工單的鏡像。校準僅套用 target、revision、context hash 與重新計算 key 全部符合的裁決；預設還要求具資格的裁決者。某個有實際呼叫的模型完全沒產生 finding，仍會計入漏報與拒答。

## Backlog 與 CI

`human_queue.backlog_limit` 以上會提高 agreement proxy 的門檻。歷史設定名 `gate.human_threshold_alpha`／`tighten_alpha_step` 暫保留相容性；待判結果始終保留在佇列中。`human_queue.enabled: false` 只關閉佇列檔案，不能關閉阻擋判定。

CI 的 human-queue job 僅於 main push、測試通過後執行，具 `issues: write` 而無 `contents: write`。除非儲存庫變數 `MARA_HUMAN_QUEUE_ISSUES=true`，它維持 dry-run。裁決 artifact 必須由負責人核對後保存；本次修正未建立對外工單或填造訓練紀錄。
