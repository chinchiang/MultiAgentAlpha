# Prompt 1：把本手冊 repo 化並建立版本控制

類別：repo 化與維護

```
你在一個 Git repo 中。請把 docs/ 下的 GSMD-RPT-2026-0908-TBD_多模型多代理資安審查.md 建立成可持續維護的文件結構：

1. 把報告拆成 docs/parts/ 下每部一個 Markdown 檔（若已存在則核對一致），並提供 scripts/build_report.py 把它們串接成單一檔案；串接順序寫在 docs/parts/ORDER.txt。
2. 建立 docs/CHANGELOG.md，記錄本次為 v0.1.0，欄位：日期、版本、變更摘要、變更者、查證狀態（引用了幾項、缺口幾項）。
3. 在 .github/workflows/ 加一個 docs-check.yml：對每個 PR 執行 scripts/count_words.py 並在字數低於 20,000 時失敗；執行 scripts/check_citations.py 確認正文中每個【…｜Xn】標記在附錄A 都有對應列；所有 action 以完整 SHA 固定，permissions 只讀。
4. 不要改動報告內容本身。

產出物：docs/parts/*.md、scripts/build_report.py、scripts/check_citations.py、docs/CHANGELOG.md、.github/workflows/docs-check.yml。
驗收：python scripts/build_report.py 產出的檔案與原報告逐位元相同；docs-check.yml 在本 PR 上通過。
```
