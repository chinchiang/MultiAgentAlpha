# Ground truth 更新　2026-10-12：ASVS 5.0 需求層級資料（附錄E prompt 2）

執行環境：本機（Claude Code），可直接連 `github.com` 與 `raw.githubusercontent.com`。觸發原因：2026-10-12 的工具段程式碼審查第 9 項指出，`validate_ref` 對 `ASVS 5.0 V<章>.<節>.<需求>` 只驗到節，需求編號從未比對，捏造的 `ASVS 5.0 V1.2.99` 也會通過，與模組說明「只接受 pinned 清單中存在的 id」不符；`asvs_5_0.json` 本身沒有需求層級的資料。

規則（prompt 2 第 2 點）：差異不直接覆寫 pinned 集，須經人核准。本次變更已由 owner 於 2026-10-12 核准（見 §4），隨 PR #82（v0.4.18）套用。

## 1. 來源

| 項目 | 值 |
|---|---|
| 倉庫 | `OWASP/ASVS` |
| 版本 | tag `v5.0.0_release`（輕量 tag，指向 commit `5cf9b032440be53ce345ab3c130fda46ba1ce7a2`，2025-05-30；與 2026-09-21 核對時同一 commit） |
| 檔案 | `5.0/docs_en/OWASP_Application_Security_Verification_Standard_5.0.0_en.csv` |
| 取得方式 | 以 commit id 從 `raw.githubusercontent.com` 下載（以 tag 下載的檔案位元組相同） |
| SHA-256 | `98c8fe911b9edb403af8ee05d3ce8201ecac2659e313b053890a62847cdcf680` |
| 內容 | 345 列需求（欄位 `chapter_id, chapter_name, section_id, section_name, req_id, req_description, L`） |

## 2. 與既有 pinned 集的比對

- **章與節：無差異。** CSV 的 17 章、80 節與 `asvs_5_0.json` 現有的 `chapters`／`sections` 完全一致（2026-09-21 補上 V17 與兩處節名之後的狀態），每一列需求的章、節都在既有清單中，既有清單的每一節也都至少有一條需求。
- **需求：新增。** 345 條需求編號以 `requirements`（節 → 需求編號清單）寫入每一章，各章條數：V1 30、V2 13、V3 31、V4 16、V5 13、V6 47、V7 19、V8 13、V9 7、V10 36、V11 24、V12 12、V13 21、V14 13、V15 21、V16 17、V17 12。只收編號，不收需求內文與等級（`L`）。
- **出處欄位。** 新增 `_requirements_source`，記錄上述 commit、路徑、SHA-256 與取得日期；`_source` 不變。

## 3. 對程式與材料的影響

- `mara.groundtruth.validate_ref`：三段式引用的需求編號必須存在於該節，否則回傳 `ASVS 5.0 V<章>.<節> has no requirement …` 並由 `scoring/idcheck.py` 從 finding 剝除、計入 `standard_refs_stripped`。章或節層級的引用（`ASVS 5.0 V1`、`ASVS 5.0 V1.2`）照舊接受。
- 本 repo 內引用到需求層級的地方都已核對存在：`src/mara/schemas.py` 說明中的 V6.2.1、`src/mara/prompts/reviewer_architecture.md` 的 V15.2.3。mock fixtures、校準樣本與其產生器沒有三段式 ASVS 引用，不需重建。
- 回歸測試：`tests/test_pin_provenance.py`（345 條且不重複、每節皆有需求、來源 commit 寫在檔中；V6.2.1／V15.2.3／V17.3.2 接受，V1.2.99、V6.2.13、V18.1.1、V1.9.1 拒絕；捏造需求從 finding 剝除）。

## 4. 核准

owner（chinchiang）於 2026-10-12 核准把 ASVS 5.0.0 的需求層級資料加入 pinned 集，核准紀錄留在 PR #82 的留言。下次季度核對時，以同一份 CSV（或其後的修訂版）重新比對 `requirements`，差異依本程序另行核准。
