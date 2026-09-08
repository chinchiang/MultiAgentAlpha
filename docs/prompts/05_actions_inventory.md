# Prompt 5：對現有 GitHub Actions 做 pwn request 與 SHA pinning 盤點

類別：落地評估

```
請對本 repo（或我指定的 repo 清單）的 .github/workflows/*.yml 做盤點，只讀不改：

1. 對每個 workflow 列出：觸發事件；是否使用 pull_request_target；是否 checkout 了 PR head（ref 含 github.event.pull_request.head）；頂層與 job 層的 permissions；每個 uses: 是以 SHA、tag 還是 branch 引用；run: 步驟中是否直接內插 github.event.* 的欄位（列出欄位名與行號）；是否使用 actions/cache 且 key 含不可信的 ref。
2. 若環境有 zizmor，執行 zizmor --format sarif 並把結果附在報告；沒有就註明未執行。
3. 依報告第 10.7 節的判定準則給每個 workflow 一個嚴重度，pwn request 與標題注入為 Critical。
4. 對每個非 SHA 的 uses:，查出該 action 目前對應 tag 的完整 SHA（用 git ls-remote），列成「建議修改」表，但不要直接改檔案。
5. 輸出 docs/actions-inventory-<日期>.md。

產出物：docs/actions-inventory-<日期>.md。
驗收：每個 workflow 都有一列；每個非 SHA 引用都有建議的 SHA；Critical 項目在表格最上方。
```
