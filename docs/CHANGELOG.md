# 變更紀錄　GSMD-RPT-2026-0908-01《多模型多代理資安審查》

每一版一列。欄位：日期、版本、變更摘要、變更者、查證狀態（附錄A 條目數／正文引用的不同編號數／附錄B 缺口數）。
數字由 `scripts/check_citations.py` 與附錄B 的條目數取得；`.github/workflows/docs-check.yml` 在每個 PR 上重建報告、檢查字數與引用。

| 日期 | 版本 | 變更摘要 | 變更者 | 查證狀態 |
|---|---|---|---|---|
| 2026-09-21 | v0.1.2 | Ground truth 季度更新（Appendix E prompt 2）：`docs/groundtruth-diff-2026-09-21.md`；五個 pinned JSON 只追加 `_source` 查證日期，內容未動；ASVS 5.0.0 正式版的 V17 WebRTC 與兩處節名差異經 owner 核准後同日套用進 `asvs_5_0.json`，測試與 mock fixtures 同步；附錄B 關閉 6 項（19、23、24、52、53、60）、部分核對 2 項（20、65）。 | chinchiang（Claude Code 協作） | 附錄A 213 條，引用 202 個編號；附錄B 缺口 74 項，6 項關閉；正文標記未變 |
| 2026-09-21 | v0.1.1 | repo 化收尾（Appendix E prompt 1）：新增本檔與 `docs-check.yml`（PR 上重建報告並要求逐位元相同、字數門檻 20,000、引用對照附錄A）。報告內容未變。 | chinchiang（Claude Code 協作） | 附錄A 213 條，引用 202 個編號，11 條未被引用；附錄B 缺口 74 項，0 項關閉；正文標記「尚未證實」10 處、「需覆核」4 處 |
| 2026-09-17 | v0.1.0 | 網頁版以 GitHub Pages 自 `docs/` 發布（`docs/index.html` 轉址、`docs/.nojekyll`）。報告內容未變。 | chinchiang（Claude Code 協作） | 同上 |
| 2026-09-10 | v0.1.0 | 取得登錄編號 GSMD-RPT-2026-0908-01，以 `scripts/assign_number.py` 取代 TBD 編號。 | chinchiang（Claude Code 協作） | 同上 |
| 2026-09-08 | v0.1.0 | 初版：報告 Markdown 與單檔 HTML、附錄A 到 E；拆成 `docs/parts/*.md`（順序在 `ORDER.txt`），`scripts/build_report.py` 串接、`scripts/check_citations.py` 與 `scripts/count_words.py` 檢查。合計 29,863 字（不含附錄A）。 | chinchiang（Claude Code 協作） | 附錄A 213 條，引用 202 個編號；附錄B 缺口 74 項，全部開放（研究環境代理封鎖，見附錄B 前言） |

## 版本規則

- 報告正文（第一到十部、附錄A、C、D、E）任何實質變更升 minor（v0.2.0）；附錄B 的缺口關閉、ground truth 查證日期、結構、腳本或 workflow 變更升 patch。
- 附錄B 的缺口被關閉（「已於 <日期> 關閉」）時，在查證狀態欄更新關閉數；ground truth 的季度更新（prompt 2）另產生 `docs/groundtruth-diff-<日期>.md` 並在此加一列。
