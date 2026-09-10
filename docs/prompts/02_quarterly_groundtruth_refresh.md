# Prompt 2：每季更新 pinned ground truth 與來源查證

類別：repo 化與維護

```
請對 src/mara/groundtruth/*.json 做季度更新，規則如下：

1. 對每個檔案的 _source 欄位列出的 URL，抓取最新版本並與現有內容比對。ASVS 用官方 CSV；OWASP Top 10 用官方 repo 的檔案清單；API Security 與 LLM Top 10 用官方 repo；CWE 子集對照 CWE Top 25 的最新年度版與 OWASP A10 的 CWE 清單。
2. 任何差異都不要直接覆寫：產生 docs/groundtruth-diff-<日期>.md 列出新增、移除與改名的 ID，並在 JSON 的 _source 加上新的查證日期。
3. 對附錄B 中標「代理封鎖」或「尚未證實」的每一項，嘗試在目前環境開啟該 URL；能開啟者把結果寫進 docs/parts/B_gaps.md 的該項末尾（「已於 <日期> 關閉：…」），不能開啟者保留原狀。
4. 若 OWASP LLM Top 10 有 2026 版，新增 owasp_llm_top10_2026.json 但不刪 2025 版，並在 groundtruth/__init__.py 同時接受兩個年份。
5. 跑 pytest 確認 ground truth 變更沒有讓任何測試失敗；若失敗，說明是資料變了還是程式錯了。

產出物：更新後的 JSON、docs/groundtruth-diff-<日期>.md、更新後的 B_gaps.md。
驗收：pytest 全綠；diff 檔列出的每個變更都附來源 URL 與抓取日期。
```
