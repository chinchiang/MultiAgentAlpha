# 附錄E　落地 Prompt 套件（Claude Code + GitHub）

八組 prompt 的完整內容在 repo 的 `docs/prompts/` 目錄，每組一個檔案，可直接貼入 Claude Code 執行；每組都能單獨執行，不假設前一組已跑過。以下為索引與各組的產出物與驗收條件。

| 組 | 類別 | 名稱 | 產出物 | 驗收 |
|---|---|---|---|---|
| 1 | repo 化與維護 | 把本手冊 repo 化並建立版本控制 | `docs/parts/*.md`、`scripts/build_report.py`、`scripts/check_citations.py`、`docs/CHANGELOG.md`、`docs-check.yml` | 串接結果與原報告逐位元相同；workflow 通過 |
| 2 | repo 化與維護 | 每季更新 pinned ground truth 與來源查證 | 更新後的 `groundtruth/*.json`、`docs/groundtruth-diff-<日期>.md`、更新後的附錄B | pytest 全綠；每個變更附來源與日期 |
| 3 | 落地評估 | 對現況做六層差距評估 | `docs/assessment-<日期>.md` | 60 題都有分數與證據；CN 條目單獨成表 |
| 4 | 落地評估 | 以真實三家族跑第一次校準並產出權重 | `scripts/calibrate.py`、`docs/calibration-<日期>.md` | 每個數字可從輸出重算；權重附樣本數 |
| 5 | 落地評估 | 對現有 GitHub Actions 做 pwn request 與 SHA pinning 盤點 | `docs/actions-inventory-<日期>.md` | 每個 workflow 一列；每個非 SHA 引用有建議 SHA |
| 6 | 控制項即程式碼 | 把資料主權與家族多樣性規則寫成設定檔驗證 | 修改後的 `config.py`、`tests/test_policy.py` | 違規 YAML 使 `mara check-config` 非零結束 |
| 7 | 控制項即程式碼 | 固定 L0 工具版本並加上簽章驗證 | `tools/versions.lock`、`scripts/install_tools.py`、`docs/tools-provenance.md` | 改錯一個 SHA-256 時安裝失敗 |
| 8 | 控制項即程式碼 | 把治理建議 G-1 到 G-13 轉成可執行的合規檢查 | `scripts/governance_check.py`、`governance.yml`、`docs/governance-check-<日期>.md` | 每列有證據欄；失敗以非零結束碼表示 |

檔案：`docs/prompts/01_repo_ize_handbook.md`、`02_quarterly_groundtruth_refresh.md`、`03_gap_assessment.md`、`04_first_calibration.md`、`05_actions_inventory.md`、`06_policy_as_config.md`、`07_pin_tools.md`、`08_governance_checks.md`。
