# Ground truth 季度更新　2026-11-23（附錄E prompt 2）

執行環境：Claude Code 的雲端工作階段。可連 `raw.githubusercontent.com`、公開 GitHub 倉庫的 `git ls-remote`／`git clone`、
`cwe.mitre.org`、`genai.owasp.org`、`owasp.org`；`cisa.gov` 回 403。上一次季度更新是 2026-09-21，這一次比到期日
（2026-12-21）早四週做，與同一天的 OSV 例外展延（`docs/osv-exception-review-2026-11-23.md`）放在同一個 PR。

結論：**五個 pinned 檔案的內容都與上游相同，沒有新增、移除或改名的 ID。** JSON 只在 `_source` 追加查證日期；
沒有需要 owner 另行核准的資料變更。附錄B 關閉 2 項（9、65）。

## 1. 來源

抓取日期都是 2026-11-23。commit 以 `git ls-remote` 與 `git clone --depth 1` 取得，檔案自 `raw.githubusercontent.com` 以 commit id 下載。

| 檔案 | 上游 | 版本 | 比對的內容 |
|---|---|---|---|
| `asvs_5_0.json` | `https://github.com/OWASP/ASVS` | master `6e40a85b553d2da9dba533c614de14f5ed79c20f`（2026-11-22） | `5.0/docs_en/OWASP_Application_Security_Verification_Standard_5.0.0_en.csv` |
| `owasp_top10_2025.json` | `https://github.com/OWASP/Top10` | master `3a31f35346c3f4e90f350395124382fa53af2afe`（2026-09-24） | `2025/docs/en` 的檔案清單與 `A10_2025-Mishandling_of_Exceptional_Conditions.md` |
| `owasp_api_top10_2023.json` | `https://github.com/OWASP/API-Security` | master `33cea37b2ffde3e2e62f6b5d79a029a22a846633`（2026-09-21） | `editions/2023/en/0x11-t10.md` |
| `owasp_llm_top10_2025.json` | `https://github.com/OWASP/www-project-top-10-for-large-language-model-applications` | `99f4395589bdbd120ae961f9cd179e79d7f9b27f`（2026-08-05，與 2026-09-21 同一 commit） | `2_0_vulns/` 的 LLM01 到 LLM10；另讀 `https://genai.owasp.org/llm-top-10/` |
| `cwe_known.json` | `https://cwe.mitre.org/top25/archive/2025/2025_cwe_top25.html` 與上列 Top10 的 A10 頁 | 2025 CWE Top 25 | 25 個 CWE 編號；A10:2025 的 24 個 CWE |

## 2. 比對

- **ASVS 5.0。** master 上的 CSV 的 SHA-256 是 `98c8fe911b9edb403af8ee05d3ce8201ecac2659e313b053890a62847cdcf680`，
  與 pinned commit `5cf9b03` 的檔案位元組相同（`_requirements_source` 記的就是這個值），所以 17 章、80 節、345 條需求都沒有變。
  倉庫頂層的版本目錄是 `1.0` 到 `5.0`，沒有 5.0 之後的版本。
- **OWASP Top 10:2025。** `2025/docs/en` 的 A01 到 A10 檔名與 pinned 的類別清單相同；A10 頁列出的 24 個 CWE 與 2026-09-21 相同。
  倉庫沒有 2025 之後的年份目錄。A10 頁的 SHA-256：`1e05837530582feb3e96d84160cd2286d5ba93348fedca2d8f8fb35eecc27ac4`。
- **OWASP API Security Top 10 2023。** `0x11-t10.md` 的十個類別與 pinned 相同
  （SHA-256 `c396a9fc70a64ea6bccba608b482a99750f00f0ad6c283d6fbdd5c4d936040a3`）；`editions/` 下只有 2019 與 2023。
- **OWASP LLM Top 10 2025。** 倉庫自 2026-08-05 起沒有新 commit，LLM01 到 LLM10 的標題相同，沒有 2026 版目錄。
  官網清單頁現在可讀（2026-09-21 時被封鎖）：只列 LLM01:2025 到 LLM10:2025，頁面上唯一的「2026」是活動公告。
  **沒有 2026 版**，所以 prompt 2 第 4 點（新增 `owasp_llm_top10_2026.json`、`groundtruth/__init__.py` 同時接受兩個年份）這次不適用。
- **CWE 子集。** 2025 CWE Top 25 頁面依序列出 CWE-79、89、352、862、787、22、416、125、78、94、120、434、476、121、502、122、863、20、
  284、200、306、918、77、639、770，共 25 個，全部在 `cwe_known.json`（頁面 SHA-256
  `49a375800fa9519129a7beda6233dab499addfbe7952bfaedb9051654d2ab0db`）。這是 2026-09-21 因 `cwe.mitre.org` 封鎖而沒做的那一項。
  A10:2025 的 24 個 CWE 也全部在子集裡。`https://cwe.mitre.org/top25/archive/2026/2026_cwe_top25.html` 回 404，
  Top 25 的索引頁最新的仍是 2025 版：**2026 版尚未發布**（2025 版是 2025-12-11 發布的）。
  `_source` 提到的 CISA 公告因 `cisa.gov` 回 403 沒有重讀；Top 25 的名單以 MITRE 的頁面為準。

新增、移除、改名的 ID：無。

## 3. 附錄B 缺口的關閉與部分核對

依 prompt 2 第 3 點。這次關閉 2 項，寫在 `docs/parts/B_gaps.md` 該項末尾；關閉數由 20 項變為 22 項（共 79 項）。

| 項 | 證據（一手，2026-11-23 抓取） |
|---|---|
| 9 gitleaks 與 Trivy 的官方 SARIF 文件 | `https://raw.githubusercontent.com/gitleaks/gitleaks/v8.30.1/README.md`（SHA-256 `022fd4d9fb53a8e7eb6b6e49875052e571f784bafab387deb484e28f8a1ea38b`）：用法列出 `-f, --report-format string   output format (json, csv, junit, sarif, template)`，並說明內建 sarif 報告格式。`https://raw.githubusercontent.com/aquasecurity/trivy/v0.74.0/docs/guide/configuration/reporting.md`（SHA-256 `c5c4335697936e6897551051209d4c558ee52fbc3a48382f8a995703ffa62d31`）：「SARIF」一節寫明 `--format sarif` 產生符合 SARIF 2.1.0 OASIS 標準的報告，可上傳 GitHub code scanning。兩個 tag 就是 `tools/versions.lock` 鎖定的版本 |
| 65 LLM Top 10 2026 版 | 見 §2：官網清單頁與官方倉庫都沒有 2026 版。原項的疑問是「疑似 2026-08-04 發布」，現在兩個一手來源都能讀，答案是沒有 |

沒有逐項重開的部分，如實記錄：

- 附錄B 前言列出的封鎖網域，這次只探測能否連線，沒有逐項重讀引用它們的條目（2026-10-06 的全面複核已在不受封鎖的環境讀過，
  結果寫在各項的「2026-10-06 部分核對」）。這次可連的有 arxiv.org、anthropic.com、openai.com、deepmind.google、github.blog、
  docs.github.com、nist.gov（含 csrc、nvlpubs）、owasp.org、genai.owasp.org、top10.owasp.org、cwe／capec／atlas.mitre.org、w3.org、first.org；
  `cisa.gov` 回 403。
- 其餘標「尚未證實」的項目多半是二手說法（發布日期、產品規格、廠商數字），要關閉需要找到並讀完一手來源，不是開一個已知的 URL
  就能核對；這次沒有做，各項保持原狀。
- 第 9 項關閉後，正文與附錄A 的證據標記沒有改（那是報告正文的變更，依 `docs/CHANGELOG.md` 的版本規則另案處理）。

## 4. pytest

JSON 的資料沒有變（每個檔案去掉 `_source` 後與更新前逐鍵相等，寫入時已斷言），所以沒有測試因資料而改變。
本機結果見本次 PR 的說明；`tests/test_pin_provenance.py` 仍通過（ASVS 的來源 commit 仍在 `_requirements_source`）。

## 5. 下次季更（2027-02 底前）待辦

- 2026 CWE Top 25 若已發布（往年在 11 月底到 12 月），列出與 2025 版的增減；增減依 prompt 2 第 2 點另行核准，不直接覆寫。
- 再看一次 `https://genai.owasp.org/llm-top-10/` 是否出現新年份。
- 在能連 `cisa.gov` 的環境重讀 `cwe_known.json` 的 `_source` 所引的 CISA 公告。
