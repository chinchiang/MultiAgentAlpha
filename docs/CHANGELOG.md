# 變更紀錄　GSMD-RPT-2026-0908-01《多模型多代理資安審查》

每一版一列。欄位：日期、版本、變更摘要、變更者、查證狀態（附錄A 條目數／正文引用的不同編號數／附錄B 缺口數）。
數字由 `scripts/check_citations.py` 與附錄B 的條目數取得；`.github/workflows/docs-check.yml` 在每個 PR 上重建報告、檢查字數與引用。

| 日期 | 版本 | 變更摘要 | 變更者 | 查證狀態 |
|---|---|---|---|---|
| 2026-09-27 | v0.3.3 | 程式：provenance 引文除了在宣稱行 ±3 行內逐字存在，還必須能定位：至少 8 個非空白字元且含英數字，或正好是宣稱的那一整行（`flask`、`DEBUG = True` 仍可驗證，`}`、`if `、`def` 不行）。以 mock 與五個 calibration 樣本重跑，88 條既有引文的驗證結果全部不變。報告正文未變。 | chinchiang（Claude Code 協作） | 同 v0.3.0 |
| 2026-09-27 | v0.3.2 | 程式：provider 呼叫失敗（429、5xx、逾時、連線錯誤）改記為 `reviewer_errors`，不再算成模型拒答，偏誤稽核與 calibration 的拒答率不再受基礎設施問題影響，gate 照樣 fail-closed；OpenAI 相容 provider（vLLM、NIM）對暫時性失敗最多呼叫 3 次，指數退避加 jitter 或依 `Retry-After`（上限 30 秒）。報告正文未變。 | chinchiang（Claude Code 協作） | 同 v0.3.0 |
| 2026-09-27 | v0.3.1 | repo 私有期間補回 Scorecard 強制項：`scorecard.yml` 新增 `scorecard-local` job（只讀 token），`scripts/scorecard_ci.py --local` 以 `git archive` 匯出已提交的樹後跑 `scorecard --local`，六個強制項照 `tools/scorecard-policy.yaml` 把關；關閉 `docs/actions-inventory-2026-09-26.md` 6.4。報告正文未變。 | chinchiang（Claude Code 協作） | 同 v0.3.0 |
| 2026-09-26 | v0.3.0 | 正文第 14.1 節更正雛型 workflow 的描述：呼叫模型的 job 不執行 PR 程式碼是目標模式；雛型的第二個 job 以只讀 token 執行本 repo 自己的測試與 mock 審查，不呼叫真實模型、不貼 PR 評論，CI 沒有 `MARA_LIVE=1` 開關。附錄B 關閉 #74（L0 工具已固定並驗證，G-5 通過），#48 的函式名更新為 `pipeline._agreement_proxy`。新增 `docs/governance-check-2026-09-26.md`（5 通過、8 失敗、0 人工）、`docs/actions-inventory-2026-09-26.md`、`docs/assessment-2026-09-26.md`；`mara-review.yml` 註解更正。程式：PR #39（reviewer 回覆截斷時 gate 不再通過；L3 家族獨立規則統一並稽核）。 | chinchiang（Claude Code 協作） | 附錄A 213 條，引用 202 個編號；附錄B 缺口 74 項，7 項關閉；證據標記 已證實 46／廠商主張 21／第三方評論 38／尚未證實 96；30,340 字 |
| 2026-09-24 | v0.2.1 | 網頁版可及性修正（axe-core 4.11 0 違規，`scripts/build_html.py`，PR #38）；CyberSecEval 固定到 PurpleLlama `4be64c3a2444`（PR #38）；README／INSTALL.md（中英雙語，PR #31–#33）；repo 私有期間跳過 Code Scanning 上傳與 Scorecard、SECURITY.md 補私有期間回報管道（PR #32、#35）；F09 改記為接受風險（PR #36）；Pages 在 repo 私有期間仍公開（PR #37）；codeql-action upload-sarif 升 v4.38.1（PR #34）。報告正文未變。 | chinchiang（Claude Code 協作） | 同 v0.2.0 |
| 2026-09-21 | v0.2.0 | 2026-09-18 資安審查修正（F01–F30，PR #29，於 v0.1.2 之後合併）：附錄A 加核對規則並以 `docs/source-verification.json` 逐筆記錄核實狀態，僅見摘要者不再標「已證實」，正文 86 處「已證實」降為「尚未證實」；第四部（共識分數不是正確率或安全機率、`agreement_proxy` 與語料層級 α 分開）、第六、七、八、十部配合修正；網頁版改為 tag／attribute／URL allowlist 與 hash CSP。 | chinchiang（Claude Code 協作） | 附錄A 213 條，引用 202 個編號；附錄B 缺口 74 項，6 項關閉；證據標記 已證實 46／廠商主張 21／第三方評論 38／尚未證實 96（修正前 132／21／38／10）；30,200 字 |
| 2026-09-21 | v0.1.2 | Ground truth 季度更新（Appendix E prompt 2）：`docs/groundtruth-diff-2026-09-21.md`；五個 pinned JSON 只追加 `_source` 查證日期，內容未動；ASVS 5.0.0 正式版的 V17 WebRTC 與兩處節名差異經 owner 核准後同日套用進 `asvs_5_0.json`，測試與 mock fixtures 同步；附錄B 關閉 6 項（19、23、24、52、53、60）、部分核對 2 項（20、65）。 | chinchiang（Claude Code 協作） | 附錄A 213 條，引用 202 個編號；附錄B 缺口 74 項，6 項關閉；正文標記未變 |
| 2026-09-21 | v0.1.1 | repo 化收尾（Appendix E prompt 1）：新增本檔與 `docs-check.yml`（PR 上重建報告並要求逐位元相同、字數門檻 20,000、引用對照附錄A）。報告內容未變。 | chinchiang（Claude Code 協作） | 附錄A 213 條，引用 202 個編號，11 條未被引用；附錄B 缺口 74 項，0 項關閉；正文標記「尚未證實」10 處、「需覆核」4 處 |
| 2026-09-17 | v0.1.0 | 網頁版以 GitHub Pages 自 `docs/` 發布（`docs/index.html` 轉址、`docs/.nojekyll`）。報告內容未變。 | chinchiang（Claude Code 協作） | 同上 |
| 2026-09-10 | v0.1.0 | 取得登錄編號 GSMD-RPT-2026-0908-01，以 `scripts/assign_number.py` 取代 TBD 編號。 | chinchiang（Claude Code 協作） | 同上 |
| 2026-09-08 | v0.1.0 | 初版：報告 Markdown 與單檔 HTML、附錄A 到 E；拆成 `docs/parts/*.md`（順序在 `ORDER.txt`），`scripts/build_report.py` 串接、`scripts/check_citations.py` 與 `scripts/count_words.py` 檢查。合計 29,863 字（不含附錄A）。 | chinchiang（Claude Code 協作） | 附錄A 213 條，引用 202 個編號；附錄B 缺口 74 項，全部開放（研究環境代理封鎖，見附錄B 前言） |

## 版本規則

- 報告正文（第一到十部、附錄A、C、D、E）任何實質變更升 minor（v0.2.0）；附錄B 的缺口關閉、ground truth 查證日期、結構、腳本或 workflow 變更升 patch。
- 附錄B 的缺口被關閉（「已於 <日期> 關閉」）時，在查證狀態欄更新關閉數；ground truth 的季度更新（prompt 2）另產生 `docs/groundtruth-diff-<日期>.md` 並在此加一列。
