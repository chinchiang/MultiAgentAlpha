# L0 工具來源、授權與驗證方式（tools-provenance）

附錄 E prompt 7、治理建議 G-5 的落地。`tools/versions.lock` 是唯一的版本與雜湊來源；`scripts/install_tools.py` 依它下載、驗證、安裝到 `.mara-tools/bin`；`src/mara/tools/runner.py` 只從 `.mara-tools/bin` 執行工具，不再看 PATH。本頁說明每個工具「從哪裡來、什麼授權、我們驗到什麼程度、還缺什麼」。日期：2026-09-12。

## 1. 總表

| 工具 | 版本 | 來源 | 授權 | 我們驗證的內容 | 發布者提供的最強證據 | 缺口 |
|---|---|---|---|---|---|---|
| cosign（驗證器） | 3.1.3 | `sigstore/cosign` GitHub release，`cosign-linux-amd64` | Apache-2.0 | SHA-256（鎖定值與 `cosign_checksums.txt` 交叉核對）→ 安裝後以自身驗證 keyless bundle（`cosign-linux-amd64.sigstore.json`，身分 `keyless@projectsigstore.iam.gserviceaccount.com`，issuer `https://accounts.google.com`） | Sigstore keyless bundle；另有 GCP KMS 金鑰簽章（`*-kms.sigstore.json` 與 `release-cosign.pub`） | 自我驗證是「信任第一次固定」：第一次寫進 lock 的 SHA-256 是信任根，之後每次安裝都以它為準 |
| slsa-verifier（驗證器） | 2.7.1 | `slsa-framework/slsa-verifier` GitHub release，`slsa-verifier-linux-amd64` | Apache-2.0 | SHA-256（與 repo 主分支 `SHA256SUM.md` 的 v2.7.1 區段交叉核對）→ 安裝後以自身驗證自己的 SLSA provenance | SLSA v1 provenance（`slsa-github-generator`） | 同上，信任第一次固定 |
| gitleaks | 8.30.1 | `gitleaks/gitleaks` GitHub release，`gitleaks_8.30.1_linux_x64.tar.gz` | MIT | SHA-256，並與 `gitleaks_8.30.1_checksums.txt` 交叉核對 | 只有 checksum 檔（goreleaser 未設 signs、release workflow 無 attestation；2026-09-12 查證 `.goreleaser.yml`） | **無簽章、無 provenance**：checksum 檔與二進位同源同倉，攻擊者若能改 release 就能同時改兩者。只有我們鎖定的 SHA-256 提供跨時間的不變性 |
| osv-scanner | 2.5.1 | `google/osv-scanner` GitHub release，`osv-scanner_linux_amd64` | Apache-2.0 | SHA-256（與 `osv-scanner_SHA256SUMS` 交叉核對）→ `slsa-verifier verify-artifact --source-uri github.com/google/osv-scanner --source-tag v2.5.1` 對 `multiple.intoto.jsonl` | SLSA Build L3 provenance（`slsa-github-generator` generic generator v2.1.0） | 無 |
| zizmor | 1.30.1 | `zizmorcore/zizmor` GitHub release，`zizmor-x86_64-unknown-linux-gnu.tar.gz` | MIT | SHA-256（本次由下載計算並鎖定；release 未附 checksum 檔）→ `gh attestation verify --repo zizmorcore/zizmor` | GitHub artifact attestation（`release-binaries.yml` 使用 `actions/attest-build-provenance`） | 驗證需要 `gh` 與 GitHub token；PyPI 的 PEP 740 attestation 在其 release workflow 中仍是 TODO |
| trivy | 0.74.0 | `aquasecurity/trivy` GitHub release，`trivy_0.74.0_Linux-64bit.tar.gz` | Apache-2.0 | SHA-256（與 `trivy_0.74.0_checksums.txt` 交叉核對）→ `cosign verify-blob --bundle trivy_0.74.0_Linux-64bit.tar.gz.sigstore.json`，身分 `https://github.com/aquasecurity/trivy/.github/workflows/reusable-release.yaml@refs/tags/v0.74.0`，issuer `https://token.actions.githubusercontent.com` | Sigstore keyless bundle（goreleaser `signs:`）；release workflow 亦有 `attestations: write` | 無 |
| PyYAML（安裝器自身依賴） | 見 `tools/bootstrap-requirements.txt` | PyPI wheel | MIT | `pip --require-hashes`（安裝器唯一的非標準庫依賴，用來讀 lock） | 無 | 無簽章；與 semgrep 同樣只有 hash 鎖定 |
| semgrep | 1.177.0 | PyPI wheel（`manylinux_2_34_x86_64`）與其完整依賴閉包，共 66 個 wheel | LGPL-2.1（semgrep）；依賴各自授權 | `pip install --require-hashes --only-binary=:all:` 對 `tools/semgrep-requirements.txt`（每個 wheel 的 SHA-256） | PyPI 對 semgrep 1.177.0 無 PEP 740 provenance（`/integrity/.../provenance` 回 404，`/pypi/.../json` 無 `provenance` 欄位） | **無簽章**；hash 鎖定只保證「與我們第一次看到的相同」。閉包為 CPython 3.11 × manylinux x86_64 專用，換平台需重新鎖定 |

## 2. 兩層驗證的意義

1. **SHA-256（我們鎖定）**：保證每次安裝的位元組與 lock 寫入時完全相同。這擋得住「上游 tag 或 release 資產事後被改」（tj-actions/changed-files 型態的攻擊）。安裝腳本對每個資產一律執行，無法關閉。
2. **發布者簽章或 provenance**：保證那些位元組確實是由該專案的 release 流程產出的（Sigstore 憑證身分、SLSA provenance 的 builder 與 source、GitHub attestation 的 repo）。這擋得住「lock 寫入時就已經是被調包的檔案」。cosign 與 slsa-verifier 需要連到 Sigstore 的 TUF 根（`tuf-repo-cdn.sigstore.dev`）與 Rekor；`gh attestation verify` 需要 GitHub API。

`scripts/install_tools.py --no-signature-check` 只跳過第 2 層，第 1 層永遠執行；它存在是為了網路受限的開發環境（本 repo 的開發環境就擋住 TUF CDN），CI 從不使用它，manifest 會記錄 `signature_verified: false`。

## 3. 信任根與已知缺口

- **信任第一次固定。** 兩個驗證器（cosign、slsa-verifier）本身以 SHA-256 固定；第一次寫進 lock 時是人工從發布者 checksum 檔與獨立下載交叉核對的。之後 cosign 用自身驗證自己的 keyless bundle、slsa-verifier 驗證自己的 provenance，這是自證，只能證明「這個二進位與它宣稱的簽章一致」。
- **gitleaks 與 semgrep 沒有簽章。** 這兩個工具目前只有第 1 層。gitleaks 的 checksum 檔與二進位同源；semgrep 在 PyPI 沒有 provenance。升版時仍只能靠獨立下載交叉核對。
- **CI 的 secret scanning 已改用 lock 內的 gitleaks（2026-09-13）。** 原本的 `gitleaks/gitleaks-action` 自行下載 gitleaks 8.24.3（未驗雜湊），與 lock 的 8.30.1 是兩份不同的 gitleaks，還需要 `pull-requests: read` 與 `GITHUB_TOKEN`。現在 `scripts/gitleaks_ci.py` 只從 `.mara-tools/bin` 取（版本必須等於 lock），PR 掃 `--no-merges --first-parent base..head`、push 掃 `base..head`、無可用 base 時退回單一 commit；SARIF 上傳為 artifact，洩漏或崩潰都讓 job 紅。L0 job 不再需要 `pull-requests: read`，也不再有任何 action 自行下載工具。
- **TruffleHog 未納入。** Shai-Hulud 蠕蟲曾用 TruffleHog 採集憑證（報告 C6.13）；若日後加入，只能在無出口網路的 job 中執行，且其輸出不得回寫任何憑證存放處。
- **平台。** lock 只涵蓋 linux/x86_64 與 CPython 3.11。wheel 是 ABI 專用的：安裝器只會用 lock 指定的 `python3.11` 建 venv，找不到就中止（CI 的 `ubuntu-latest` 預設是 3.12，所以 L0 job 先以 `actions/setup-python` 裝 3.11）。其他平台或直譯器需另外鎖定。
- **未做 actions/cache。** 工具每次 CI 都重新下載並驗證（約 300 MB）。cache 是信任邊界（Ultralytics 事件，報告 C7.17），若日後加入，key 必須含 lock 檔的雜湊且 restore-keys 留空。

## 3a. 執行期的網路需求（與驗證無關，但決定工具在隔離環境能否產出結果）

| 工具 | 執行時需要的網路 | 隔離環境（無出口網路）的行為 |
|---|---|---|
| gitleaks | 無 | 正常（`detect --no-git`） |
| zizmor | 線上稽核（impostor-commit、known-vulnerable-actions）需 GitHub API 與 token；runner 預設 `--offline`，設 `MARA_ZIZMOR_ONLINE=1` 且有 token 才開 | 正常，少兩個線上稽核；CI 的 zizmor-action 對真實 workflow 另外跑線上稽核 |
| osv-scanner | 查詢 `api.osv.dev` | 無結果（不是錯誤）；可改用離線資料庫（`--offline` 加本地 DB）作為後續工作 |
| trivy | 首次下載漏洞資料庫（ghcr.io） | 無結果；可預先 `trivy image --download-db-only` 或自架 DB 鏡像 |
| semgrep | 規則集需從 semgrep 規則登錄（semgrep.dev）下載，預設 `p/default`，以 `MARA_SEMGREP_CONFIG=p/default,p/security-audit` 覆寫；runner 一律 `--metrics=off`，且不用 `--config auto`，因為 auto 強制開啟 metrics 並把專案識別送到 semgrep.dev（政策 P5） | 以 exit 2 結束、無 SARIF，runner 記錄為未執行（本 repo 的開發環境即如此：proxy 對 semgrep.dev 回 403）；離線需改用本地規則目錄（`MARA_SEMGREP_CONFIG=/path/to/rules`），後續工作 |

runner 對每個工具記錄「pinned <版本>」或「exit <code>, no SARIF produced: <stderr 尾>」，報告的 `tools_ran` 只列真正產出 SARIF 的工具。

## 4. 升版程序（變更管理）

1. 以 `git ls-remote --tags` 確認新 tag；下載新資產與發布者 checksum 檔，獨立計算 SHA-256 並交叉核對，兩者不一致即停止。
2. 更新 `tools/versions.lock` 的 `version`、`url`、`sha256`、`bundle_url`／`provenance_url`／`source_tag`，以及 cosign 身分正則裡的 tag。
3. semgrep：在 CPython 3.11 × manylinux 環境重新 `pip download`，以 `scripts/install_tools.py --relock-semgrep <wheel-dir>` 重寫 `tools/semgrep-requirements.txt`。
4. 本機 `python3 scripts/install_tools.py`（能連 Sigstore 的環境）或 CI 的 `deterministic-tools` job 必須全綠。
5. 更新本頁第 1 節，PR 內文列出每個工具的新舊版本與 SHA-256。

## 5. 對應

| 項目 | 對應 |
|---|---|
| 治理建議 | G-5（版本固定與簽章驗證）、G-6（workflow 硬化） |
| 差距評估 | 第 7 題「工具版本固定並有簽章或雜湊驗證」由 2 分升為 3 分（六個工具全部固定並驗證，執行紀錄在 CI 與 `.mara-tools/manifest.json`） |
| 標準 | ISO/IEC 27001:2022 A.8.8（標題待對照）；SLSA v1.2 Build L2 以上的消費端驗證；NIST SP 800-204D |
