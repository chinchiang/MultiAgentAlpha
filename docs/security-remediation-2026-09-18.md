# 2026-09-18 儲存庫資安審查修正紀錄

基準：`d80a9f43aa63741177ba814b1be51ef64b18ce16`。本紀錄對應同日審查 F01–F30。除 F01 已套用到 GitHub Pages 外，下列程式修正位於修正分支，必須經 PR 審查及合併才會進入 main／正式網站。沒有將模擬測試、草稿設定或缺少的治理紀錄當成正式驗收證據。

## 變更與驗證

| 編號 | 修正或狀態 | 主要證據 |
|---|---|---|
| F01 | Pages 來源已由 `main / (root)` 改為 `main /docs`；正式入口 200，兩個教材 HTML URL 均 404。根目錄增加限制發布的備援設定 | [Pages 成功部署](https://github.com/chinchiang/MultiAgentAlpha/actions/runs/35338353658)、`_config.yml` |
| F02 | Git tracked manifest、逐層禁止跟隨 symlink、秘密檔排除與遮罩；live 外送前必須完成目前目標的秘密掃描，舊 SARIF 不可授權外送 | `src/mara/context/repo_map.py`、`pipeline.py` |
| F03 | 全部納入範圍的文字分批審查；逐檔、請求及整體上限明列 omitted，缺漏使審查未完成 | coverage manifest、context 邊界回歸測試 |
| F04 | 拒答、無效輸出、掃描未完成、待人工或工具結果未解決時，`overall_score=null`、gate 阻擋；L0 finding 獨立保留 | `pipeline.py`、`report/markdown_out.py` |
| F05 | 每家族每 pass 每 finding 只能有一票；重複／缺漏整批拒收；CVSS 不再被 jury 嚴重度覆寫 | `agents/judge.py`、`pipeline.py` |
| F06 | CVSS 完整解析驗證；無效向量拒收，防禦性回退為 Unknown／null，必須人工處理 | `schemas.py`、惡意向量測試 |
| F07 | Semgrep 非零結束碼及 OSV 部分失敗皆失敗；SARIF failed invocation 不當成清白；只有 accepted suppression 才排除 | `scripts/semgrep_ci.py`、`osv_ci.py`、`code_scanning_prep.py` |
| F08 | PR 掃 merge-base 到 head 全部 commits；無可用 base 時掃 head 全部可達歷史 | `scripts/gitleaks_ci.py`、實際 Git 歷史回歸測試 |
| F09 | 已準備 main 的 PR、1 位獨立核准、stale approval 撤銷、最近一次 push 核准、分支更新及兩個必要 CI checks；GitHub 儲存時要求重新驗證，尚未宣稱生效 | 待 owner 完成 GitHub Confirm access，並重新讀回 protected 設定 |
| F10 | 自架模型 ML-BOM 的正常輸出路徑修正 TypeError | 含非空 ML-BOM 的 pipeline 測試 |
| F11 | 執行模式由 provider 設定核對；報告記錄 provider manifest、設定雜湊及版本；live calibration 拒絕 mock／身分缺漏 | `pipeline.py`、`scripts/calibrate.py` |
| F12 | 引用只對實際 context 核驗；拒絕目錄外、空白及超界行號，不回退讀磁碟 | `agents/base.py` |
| F13 | 遠端 inference 必須 HTTPS；僅 loopback 可 HTTP，禁止 URL 夾帶憑證等設定 | `config.py`、`config/examples/` |
| F14 | runtime／bootstrap／dev／Semgrep／build 使用無漏洞例外的 OSV config；G-8 例外只給單獨 model-eval 掃描 | `mara-review.yml`、`tools/osv-model-eval.toml` |
| F15 | repo editable install 與 G-8 sdist 的 build backend／closure 有版本及雜湊鎖定，使用 `--no-build-isolation` | `pyproject.toml`、`tools/build-requirements.*`、兩份 CI workflow |
| F16 | 不可信模型文字在 Markdown、人工作業報告及 GitHub 工單正文統一 literal encoding | `report/escaping.py`、`scripts/human_queue_issues.py` |
| F17 | 213 筆來源加入逐筆核實 ledger；搜尋摘要不能當原文確認；降級不符條件的「已證實」標示 | `docs/source-verification.json`、`check_citations.py`；原文逐項核實仍待執行 |
| F18 | 工單與校準使用 v2 key，綁定目標、版本、內容；拒絕舊 key 與 basename 猜測 | `human_queue_out.py`、`scripts/calibrate.py` |
| F19 | 分頁重播 label 加減事件，只接受唯一存續裁決，綁定其 event ID、actor 及當日資格 | `scripts/human_queue_issues.py` |
| F20 | 內部交接與法定通知分開；期限由 PSIRT 確認的事件起算點產生，可補登並保留歷史 | `psirt_out.py`、`psirt_ledger.py`、`docs/psirt-integration.md` |
| F21 | gate 與佇列共用有效判定原因；backlog 收緊後仍保留所有待判 finding | `pipeline.py`、`human_queue_out.py` |
| F22 | 實際被呼叫但零 finding 的模型家族仍計入漏報與拒答 | `scripts/calibrate.py` |
| F23 | 採納需達到實際有效的獨立家族數，每家族具正反序回票；同家族票不補 quorum | `pipeline.py`、quorum 回歸測試 |
| F24 | HTML tags／attributes／URL scheme allowlist；CSS／JS 精確 hash CSP，無 unsafe-inline 放行 | `scripts/build_html.py`、CSP／注入回歸測試 |
| F25 | 補 doctype、zh-Hant、charset、viewport、靜態 TOC、來源連結、鍵盤焦點與行動選單狀態 | HTML generator；瀏覽器端完整可及性驗收另列待辦 |
| F26 | SARIF preprocessing 移到唯讀 L0 job；有 security-events:write 的 job 不 checkout、不執行 repo script | `mara-review.yml`、workflow 邊界測試 |
| F27 | 移除整個教材目錄秘密豁免，改精準已知假值；同目錄新憑證仍使掃描失敗 | `.gitleaks.toml`、實際鎖定 gitleaks 回歸測試 |
| F28 | 加入每週與手動 SCA，使用同一套 runtime closure 及例外範圍 | `mara-review.yml` |
| F29 | provider 錯誤不帶遠端本文；PSIRT 握手只存固定回應碼 | `agents/base.py`、兩個 provider、`psirt_ledger.py` |
| F30 | 依既有 Apache-2.0 宣告補完整 LICENSE，保留 FIRST CVSS BSD 條款與 NOTICE | `LICENSE`、`LICENSE-CVSS`、`NOTICE` |

## 驗證範圍

- Python 3.11：從既有 hash lock 安裝 dev closure，另從新 build lock 安裝 backend，成功以 `--no-deps --no-build-isolation` 建置及安裝本專案。
- 本機完整測試：**227 passed、4 skipped**；最後一項 build-runbook／relock 調整再跑相關 42 項，全部通過。`ruff`、`git diff --check` 與引用檢查通過。
- `pytest` 涵蓋真實 Git 歷史／gitleaks、惡意模型回覆、context 邊界、gate、人工裁決、PSIRT 合成事件、HTML/CSP 與 workflow 權限。未安裝的其他 locked L0 工具整合測試會 skip；PR 的 L0 job 另安裝及執行全套工具。
- gitleaks 8.30.1 的資產雜湊與發行者 checksum 核對成功；live preflight 確實辨識教材假憑證並阻擋外送。上游未提供簽章，此限制維持揭露。
- 報告 Markdown／HTML 已重建；citation checker 核對 213 筆來源、202 個正文引用 ID，無失聯編號。這不等於 213 項研究聲明已查證。
- 本次未呼叫 live LLM、未傳送真實 PSIRT 事件、未建立人工裁決工單；相關測試使用模擬 provider、合成資料及 MockTransport。

## 相容性與後續負責事項

1. **合併與分支保護**：PR 必須經獨立審查；GitHub 的重新驗證完成後才能保存 main 保護。尚未合併的 CSP 與程式修正不能視為正式部署完成。
2. **報告消費端**：接受 `overall_score: null`、`review_status` 與 `incomplete_reasons`。單筆 `agreement_proxy` 與語料層級 Krippendorff alpha 分開，舊 alpha-named config 暫保留相容性。分數皆為排序啟發式，不是安全機率。
3. **目標識別與裁決遷移**：target ID 綁定正規化本機路徑；搬移 checkout 或更換 revision 必須重跑與重新裁決，舊紀錄不推測套用。
4. **自架服務**：部署端需提供有效 TLS 憑證、模型雜湊／簽章與真實 provider 證據。三家族在共同發現問題時可能不足兩個獨立評審，需增加合適家族或人工裁決，不能降低門檻掩蓋限制。
5. **G-8 評測建置**：model-eval 的兩個 sdist 已驗證能用 hash-pinned backend 建置，安裝及 relock 停用額外 build isolation。CyberSecEval 尚待選定 commit、產生專屬依賴閉包並執行真正評測；不能將建置成功當成評測通過。
6. **來源與治理**：逐筆原文核實、G-1 政策核准、G-4 live 換模演練、G-7 權重簽章、G-8／G-9 live 評測校準、G-10 rollout、G-12 真實握手、G-13 訓練紀錄均需要實際責任人與環境。本次沒有偽造這些紀錄。
7. **網站驗收**：hash CSP 以 meta 提供；GitHub Pages 的 HTTP header 管理能力不在 repo 控制內，`frame-ancestors` 不能靠 meta 生效。鍵盤、窄螢幕、螢幕閱讀器及無 JavaScript 情境需在部署版本另行確認，不能僅由靜態測試宣稱符合 WCAG。
