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
| scorecard | 5.5.0 | `ossf/scorecard` GitHub release，`scorecard_5.5.0_linux_amd64.tar.gz` | Apache-2.0 | SHA-256（本次由下載計算並鎖定；release 未附 checksum 檔）→ `slsa-verifier verify-artifact --source-uri github.com/ossf/scorecard --source-tag v5.5.0` 對 `multiple.intoto.jsonl`（Sigstore bundle 格式，subject 的 sha256 與鎖定值一致） | SLSA Build L3 provenance（`slsa-github-generator`） | 2026-09-14 加入；本地環境的 proxy 擋 Sigstore TUF，只有 CI 真的驗 provenance。CLI 沒有 SARIF 輸出，由 `scripts/scorecard_ci.py` 轉換 |
| PyYAML（安裝器自身依賴） | 見 `tools/bootstrap-requirements.txt` | PyPI wheel | MIT | `pip --require-hashes`（安裝器唯一的非標準庫依賴，用來讀 lock） | 無 | 無簽章；與 semgrep 同樣只有 hash 鎖定 |
| semgrep | 1.177.0 | PyPI wheel（`manylinux_2_34_x86_64`）與其完整依賴閉包，共 66 個 wheel | LGPL-2.1（semgrep）；依賴各自授權 | `pip install --require-hashes --only-binary=:all:` 對 `tools/semgrep-requirements.txt`（每個 wheel 的 SHA-256） | PyPI 對 semgrep 1.177.0 無 PEP 740 provenance（`/integrity/.../provenance` 回 404，`/pypi/.../json` 無 `provenance` 欄位） | **無簽章**；hash 鎖定只保證「與我們第一次看到的相同」。閉包為 CPython 3.11 × manylinux x86_64 專用，換平台需重新鎖定 |
| mara 執行期＋dev 依賴閉包 | 見 `tools/dev-requirements.txt`（2026-09-17） | PyPI wheel，`pyproject.toml` 的 `dependencies` 加 `dev` extra 的完整閉包，37 個 wheel | 各自授權 | `pip install --require-hashes --only-binary=:all:`（每個 wheel 的 SHA-256 取自 PyPI 索引，由 `scripts/relock_requirements.py --from-pyproject dev` 以 `pip install --dry-run --report` 解析後寫入；CI 的 tests、human-queue、governance job 都用它，再以 `--no-deps -e .` 只裝本 repo 自己的程式） | 無 | 無簽章；只鎖 CPython 3.11 × linux x86_64。這條把 Scorecard Pinned-Dependencies 指出的 `pip install -e .` 缺口補上 |
| garak 閉包（G-8 評測工具） | 見 `tools/model-eval-requirements.txt`（2026-09-17） | PyPI，`garak==0.17.0`（`tools/model-eval-requirements.in`）的完整閉包，194 個 distribution（含 torch 2.14.0、transformers 5.17.0 與 nvidia-* CUDA wheel） | 各自授權 | `pip install --require-hashes`（同一套 relock；`--allow-sdist`，因為 langdetect 1.0.9 與 ecoji 0.1.1 沒有 wheel，兩者以 sdist 的 SHA-256 固定） | 無 | 兩個 sdist 安裝時要建置，pip 的隔離建置環境會另外抓 setuptools 且不驗 hash；只鎖 CPython 3.11 × linux x86_64，評測主機若是別的平台需重新 relock。這條把 `docs/model-eval-runbook.md` 原本列的「torch 級依賴未做 hash 固定」缺口補上。第一次鎖定時 trivy 對閉包內的 nltk 3.10.3 報 CVE-2026-81726（路徑穿越，無修正版；garak 要求 ≥3.10.3 且 3.10.3 是最新版），CI 的 osv-scanner 另報 datasets 3.6.0 的 CVE-2026-66007（garak 固定 `datasets<4.0`，3.6.0 是最新的 3.x）。兩者都無法以升版消除，`tools/trivyignore.yaml` 與 `tools/osv-scanner.toml` 各有兩條到 2026-12-17 為止的暫緩條目，理由寫在條目內；到期前要重查修正版或升級 garak |
| semgrep-rules（規則，非二進位） | `release` 分支 commit `5a8a6be`（2026-07-27） | `semgrep/semgrep-rules` GitHub repo，以 `git fetch --depth 1 origin <commit>`（`fetch.fsckObjects=true`）取出到 `.mara-tools/semgrep-rules`；只把 lock `paths` 列出的 12 個 security 規則目錄交給 semgrep | Semgrep Rules License v1.0（非 OSS；規則只在掃描時讀取，不複製進本 repo） | (1) 取出的 HEAD 必須等於 lock 的 `commit`；(2) 對 `paths` 下每個檔案算 `路徑\0sha256` 排序後的 SHA-256（`git_paths_digest`），必須等於 lock 的 `sha256`（與 git 的 SHA-1 命名無關）；(3) `git verify-commit`：該 merge commit 必須帶有 GitHub web-flow 金鑰（`B5690EEEBB952194`，自 `https://github.com/web-flow.gpg` 取得後以金鑰 ID 核對）的有效簽章 | GitHub web-flow 簽章（證明 commit 物件是 GitHub 的合併流程產生，樹雜湊因此被綁定） | 上游 release 分支不打 tag、不出 release 資產；web-flow 簽章證明「來自 GitHub 的合併」而非「semgrep 團隊審過」。2026-09-13 本地環境的 proxy 擋 `github.com/web-flow.gpg`，只有 CI 真的驗簽章 |

## 2. 兩層驗證的意義

1. **SHA-256（我們鎖定）**：保證每次安裝的位元組與 lock 寫入時完全相同。這擋得住「上游 tag 或 release 資產事後被改」（tj-actions/changed-files 型態的攻擊）。安裝腳本對每個資產一律執行，無法關閉。
2. **發布者簽章或 provenance**：保證那些位元組確實是由該專案的 release 流程產出的（Sigstore 憑證身分、SLSA provenance 的 builder 與 source、GitHub attestation 的 repo）。這擋得住「lock 寫入時就已經是被調包的檔案」。cosign 與 slsa-verifier 需要連到 Sigstore 的 TUF 根（`tuf-repo-cdn.sigstore.dev`）與 Rekor；`gh attestation verify` 需要 GitHub API。

`scripts/install_tools.py --no-signature-check` 只跳過第 2 層，第 1 層永遠執行；它存在是為了網路受限的開發環境（本 repo 的開發環境就擋住 TUF CDN），CI 從不使用它，manifest 會記錄 `signature_verified: false`。

## 3. 信任根與已知缺口

- **信任第一次固定。** 兩個驗證器（cosign、slsa-verifier）本身以 SHA-256 固定；第一次寫進 lock 時是人工從發布者 checksum 檔與獨立下載交叉核對的。之後 cosign 用自身驗證自己的 keyless bundle、slsa-verifier 驗證自己的 provenance，這是自證，只能證明「這個二進位與它宣稱的簽章一致」。
- **gitleaks 與 semgrep 沒有簽章。** 這兩個工具目前只有第 1 層。gitleaks 的 checksum 檔與二進位同源；semgrep 在 PyPI 沒有 provenance。升版時仍只能靠獨立下載交叉核對。semgrep 的規則（`semgrep-rules`）則有第 2 層：commit 的 GitHub web-flow 簽章。
- **CI 的 secret scanning 已改用 lock 內的 gitleaks（2026-09-13）。** 原本的 `gitleaks/gitleaks-action` 自行下載 gitleaks 8.24.3（未驗雜湊），與 lock 的 8.30.1 是兩份不同的 gitleaks，還需要 `pull-requests: read` 與 `GITHUB_TOKEN`。現在 `scripts/gitleaks_ci.py` 只從 `.mara-tools/bin` 取（版本必須等於 lock），PR 掃 `--no-merges --first-parent base..head`、push 掃 `base..head`、無可用 base 時退回單一 commit；SARIF 上傳為 artifact，洩漏或崩潰都讓 job 紅。L0 job 不再需要 `pull-requests: read`，也不再有任何 action 自行下載工具。
- **TruffleHog 未納入。** Shai-Hulud 蠕蟲曾用 TruffleHog 採集憑證（報告 C6.13）；若日後加入，只能在無出口網路的 job 中執行，且其輸出不得回寫任何憑證存放處。
- **平台。** lock 只涵蓋 linux/x86_64 與 CPython 3.11。wheel 是 ABI 專用的：安裝器只會用 lock 指定的 `python3.11` 建 venv，找不到就中止（CI 的 `ubuntu-latest` 預設是 3.12，所以 L0 job 先以 `actions/setup-python` 裝 3.11）。其他平台或直譯器需另外鎖定。
- **未做 actions/cache。** 工具每次 CI 都重新下載並驗證（約 300 MB）。cache 是信任邊界（Ultralytics 事件，報告 C7.17），若日後加入，key 必須含 lock 檔的雜湊且 restore-keys 留空。

## 3a. 執行期的網路需求（與驗證無關，但決定工具在隔離環境能否產出結果）

| 工具 | 執行時需要的網路 | 隔離環境（無出口網路）的行為 |
|---|---|---|
| gitleaks | 無 | 正常（`detect --no-git`） |
| zizmor | 線上稽核（impostor-commit、known-vulnerable-actions）需 GitHub API 與 token；runner 預設 `--offline`，設 `MARA_ZIZMOR_ONLINE=1` 且有 token 才開 | 正常，少兩個線上稽核；CI 的 zizmor-action 對真實 workflow 另外跑線上稽核 |
| osv-scanner | 查詢 `api.osv.dev`（只送套件名與版本，不送原始碼）；對 `requirements.txt` 之類的 manifest 預設還會向 `api.deps.dev` 做遞移解析，CI 的 `scripts/osv_ci.py` 以 `--no-resolve` 關掉 | 以 exit 127／128 結束、無 SARIF；`osv_ci.py` 視為崩潰（exit 1），runner 記錄為未執行。可改用離線資料庫（`--offline-vulnerabilities` 加預先下載的 DB）作為後續工作 |
| trivy | **無**（2026-09-13 起）：runner 與 `scripts/trivy_ci.py` 只對 `MARA_TRIVY_CACHE_DIR`（預設 `.mara-tools/trivy-cache`）內由 `scripts/trivy_db.py` 記錄的資料庫掃描，一律 `--skip-db-update --skip-java-db-update --skip-check-update --offline-scan`（misconfig 用內嵌檢查）。資料庫本身由 `trivy_db.py download` 事先自 `mirror.gcr.io`／`ghcr.io` 取得（見 3c） | 正常；資料庫不存在時 runner 不執行並記錄「no offline database」，不會嘗試下載 |
| semgrep | **無**（2026-09-13 起）：規則來自 lock 固定的 `.mara-tools/semgrep-rules` 本地目錄，runner 與 `scripts/semgrep_ci.py` 一律 `--metrics=off --disable-version-check`，環境變數 `SEMGREP_ENABLE_VERSION_CHECK=0`、`SEMGREP_SEND_METRICS=off`，且不用 `--config auto`（auto 強制開啟 metrics 並把專案識別送到 semgrep.dev，違反政策 P5）。`MARA_SEMGREP_CONFIG` 可覆寫（例如 `p/default` 就會回到需連 semgrep.dev 的登錄集） | 正常；規則未安裝時 runner 退回 `p/default`，在無網路環境會以 exit 2 結束、無 SARIF，記錄為未執行 |

runner 對每個工具記錄「pinned <版本>」或「exit <code>, no SARIF produced: <stderr 尾>」，報告的 `tools_ran` 只列真正產出 SARIF 的工具。

## 3b. CI 中的 semgrep 與 osv-scanner（2026-09-13）

`deterministic-tools` job 在安裝完 lock 內的工具後，依序執行四個步驟，任何一步非零即紅：

| 步驟 | 指令 | 判定 |
|---|---|---|
| semgrep 對 seeded fixture | `scripts/semgrep_ci.py --target fixtures/vuln-sample --expect fixtures/vuln-sample-sarif/semgrep.sarif` | 實掃的 (rule, file, line) 集合必須與預錄檔完全相同（預錄檔是 semgrep 1.177.0 的真實輸出，15 個 finding，規則 ID 已正規化）；少於 3 個 finding 視為規則沒載入。要更新預錄檔：看過差異後把 `--report` 的輸出複製過去 |
| semgrep 對本 repo | `scripts/semgrep_ci.py --target . --triage tools/semgrep-triage.yaml` | 排除 triage 檔 `exclude` 列的 seeded 目錄（`fixtures/`、`calib/samples/`）；`tests/` 照掃（自訂的 `.semgrepignore` 取代 semgrep 內建的排除清單）。每個 finding 必須被 triage 檔的一條（規則 ID＋路徑 glob＋理由）涵蓋，否則 exit 2；被涵蓋的 finding 留在 SARIF，加上 `suppressions`（`kind: external`，`justification` 為理由）；沒對到任何 finding 的條目印為 STALE。2026-09-13 的 47 個 finding 全部是 `dangerous-subprocess-use-audit`（audit 級，所有 argv 清單式的 subprocess 呼叫都會命中）、四個 `-tainted-env-args`（來源是 `sys.argv`）、產生校準樣本的 fake Stripe key、測試用的 AWS 文件範例 secret、安裝器的 `urllib` 下載（URL 來自 lock、下載後驗 SHA-256）；每條理由寫在 triage 檔 |
| osv-scanner 對 seeded fixture | `scripts/osv_ci.py --target fixtures/vuln-sample --expect-package requests` | fixture 固定 `requests==2.19.0`；掃描結果必須把 `requests` 列為有已知漏洞，否則 exit 2（掃描器、資料庫或 fixture 任一失效都會被看見） |
| osv-scanner 對本 repo 安裝的閉包 | `scripts/osv_ci.py --lockfile tools/bootstrap-requirements.txt --lockfile tools/dev-requirements.txt --lockfile tools/semgrep-requirements.txt --lockfile tools/model-eval-requirements.txt --config tools/osv-scanner.toml` | 2026-09-17 起四個閉包：PyYAML 1、mara 執行期＋dev 37、semgrep 66、garak 194（含 torch 與 CUDA wheel）。任何未被 `tools/osv-scanner.toml` 的 `[[IgnoredVulns]]`（需 `id`、`reason`、`ignoreUntil`）忽略的 advisory 都 exit 2；正確的處理是升版重新鎖定，忽略只是有期限的暫緩 |

兩個腳本都只從 `MARA_TOOLS_DIR/bin` 取二進位、manifest 版本必須等於 lock；`semgrep_ci.py` 另要求 `.mara-tools/semgrep-rules` 的 HEAD 等於 lock 的 commit。結束碼：0 乾淨、2 有未 triage 的 finding／漂移／未忽略的漏洞、1 工具崩潰或（osv）找不到任何套件。八個 SARIF（`semgrep`、`osv`、`trivy`、`gitleaks`、`zizmor` 各一份對本 repo 的掃描，加上 `fixture-semgrep`、`fixture-osv`、`fixture-trivy`）上傳為 `l0-sarif` artifact；其中對本 repo 的五份再由 3d 節的 job 送進 GitHub Code Scanning。

規則 ID 正規化：semgrep 對本地規則會把規則檔的路徑（轉成點）接在 ID 前面（`mara-tools.semgrep-rules.python.flask.security.injection.tainted-sql-string`），使 ID 隨安裝路徑而變；`mara.tools.semgrep_rules.normalize_sarif` 把 `semgrep-rules.` 之前的部分去掉，得到與登錄集相同的 ID，並移除沒有結果的規則描述（semgrep 會列出全部 271 條載入的規則）。順帶修正：`mara.tools.sarif.read_sarif` 原本把整個 tag 字串（`CWE-89: Improper Neutralization…`）當 CWE，與 finding 的 `CWE-89` 永遠不相等，手寫的舊 fixture 掩蓋了這個 bug；現在只取 ID，且保留規則列出的所有 CWE（`tainted-sql-string` 上游只標 `CWE-704`，同一行的 `sqlalchemy-execute-raw-query` 標 `CWE-89`），佐證比對任一相符即可。

## 3c. trivy 離線資料庫（2026-09-13）

trivy 原本在掃描時才下載漏洞資料庫（OCI artifact，約 110 MiB 壓縮、1.3 GB 解開），隔離主機會卡住，每次審查也都成了一次網路事件。現在資料庫是一個**事先取得、有紀錄、可搬運**的檔案：

| 步驟 | 指令 | 說明 |
|---|---|---|
| 取得 | `python3 scripts/trivy_db.py download` | 依 `tools/trivy-db.yaml` 的順序（`mirror.gcr.io/aquasec/trivy-db:2`，備援 `ghcr.io/aquasecurity/trivy-db:2`）先向 registry 匿名 HEAD manifest 取得 OCI manifest digest、layer digest 與 `org.opencontainers.image.created`，再 `trivy image --download-db-only`；寫 `<cache>/mara-trivy-db.json`：來源、兩個 digest、trivy 的 `metadata.json`（`Version`、`UpdatedAt`、`NextUpdate`）、`trivy.db` 的 SHA-256 與大小、trivy 版本、下載時間。`--pin-digest sha256:…` 以 manifest digest 取代 tag（已驗證 trivy 0.74.0 接受，且取得的 `trivy.db` 位元組相同） |
| 把關 | `python3 scripts/trivy_db.py status` | 資料庫不存在、`trivy.db` 的 SHA-256 與紀錄不符（被換掉）、或 `UpdatedAt` 超過 `max_age_hours`（預設 48 小時：離線不等於過期）都 exit 1。CI 與 `trivy_ci.py` 掃描前都先跑它 |
| 搬運 | `export --out trivy-db-<日期>.tar.gz` → `import --bundle … --bundle-sha256 …` | 給沒有出口網路的 runner（報告第八部的上海／重慶隔離管線）：bundle 只含 `db/trivy.db`、`db/metadata.json`、`mara-trivy-db.json`，另產 `.sha256` 旁檔；`import` 拒絕成員不對、路徑不安全、或 `trivy.db` 的 SHA-256 與同行紀錄不符的 bundle |
| 掃描 | `scripts/trivy_ci.py --target fixtures/vuln-sample --expect-package requests`；`--target . --ignorefile tools/trivyignore.yaml --skip-dirs …` | 前者要求 `requests==2.19.0` 被標為有漏洞（2026-09-13 實測：5 個 CVE，另有 Dockerfile 的 DS-0001／DS-0002／DS-0026）；後者掃本 repo，以 `--file-patterns pip:.*-requirements\.txt` 讓 `tools/` 下三個 hash 鎖定的 requirements 檔被解析（68 個套件，實測無 finding），任何未被 `tools/trivyignore.yaml`（`statement`＋`expired_at`）忽略的 vuln／misconfig 都 exit 2 |

**來源與缺口。** 上游 `aquasecurity/trivy-db` 的 cron workflow 只用 `oras push` 把 artifact 推到 ghcr.io、public.ecr.aws 與 Docker Hub（mirror.gcr.io 是 Docker Hub 的 Google 鏡像），**沒有 cosign 簽章、沒有 attestation**（2026-09-13 查證 `.github/workflows/cron.yml`）。因此資料庫不在 `tools/versions.lock`（它每六小時更新，無法固定），我們能做的是：記錄 manifest／layer digest 與 `trivy.db` 的 SHA-256（跨時間可比對、bundle 可驗）、要求新鮮度上限、以及 `--pin-digest` 讓兩台主機取得同一份。「這份資料庫真的是 Aqua 產生的」只能靠 registry 的 TLS 與 GitHub 帳號安全，列為缺口。trivy 的 misconfig 檢查同樣是 OCI artifact（`mirror.gcr.io/aquasec/trivy-checks:2`）；我們以 `--skip-check-update` 用 trivy 內嵌的那一份，版本隨 trivy 固定。

## 3d. Code Scanning 上傳與 OpenSSF Scorecard（2026-09-14）

repo 改成 public 之後 GitHub Code Scanning 免費，報告第三部 L5 設計的「SARIF 上傳」才接上。做法與邊界：

| 項目 | 做法 | 為什麼 |
|---|---|---|
| 上傳哪些 | `mara-review.yml` 新 job `code-scanning`（`needs: deterministic-tools`）把 `l0-sarif` artifact 裡對本 repo 的五份掃描（semgrep、osv-scanner、trivy、gitleaks、zizmor）經 `scripts/code_scanning_prep.py` 整理後，以 `github/codeql-action/upload-sarif`（v4.38.0，SHA 固定）一次上傳目錄 | 只有描述本 repo 的結果才該變成 Security 分頁的警報 |
| 不上傳哪些 | 四份 `fixture-*.sarif`（對 `fixtures/vuln-sample` 的漂移檢查）與 `mara review` 的 mock 報告 `out/report.sarif` | 它們描述的是刻意種下的漏洞材料，上傳只會製造假警報 |
| `code_scanning_prep.py` 做的事 | 丟掉帶 `suppressions` 的 result（triage 檔已接受的 finding，理由留在 repo 內，不依賴 GitHub 對該欄位的處理）、丟掉沒有檔案位置的 result、把 `uri` 正規化成 repo 相對路徑、每個 run 設 `automationDetails.id = mara-l0/<tool>/`、超過 GitHub 上限（25,000 個 result 或 10 MB）即拒絕 | `automationDetails.id` 就是 Code Scanning 的 category：五個工具各自一個分析，後一次上傳沒再回報的警報會被自動關閉；0 個結果的上傳也要送，這樣修掉的問題才會關 |
| 權限 | 只有 `code-scanning` job 有 `security-events: write`；它不執行任何 repo 內的掃描腳本，只讀 artifact。L0 job 維持 `contents: read` | 執行 PR 程式碼的 job 不該拿到能寫警報的 token |
| 誰不會上傳 | fork 來的 PR 與 Dependabot 的 PR（`if:` 條件），因為它們的 `GITHUB_TOKEN` 是唯讀，上傳會 403 | 這些 PR 仍完整跑 L0，只是結果留在 artifact |
| zizmor | `zizmorcore/zizmor-action` 已移除，改由 `scripts/zizmor_ci.py` 執行 lock 內驗過 attestation 的 zizmor 1.30.1（CI 帶 token 跑線上稽核：impostor commit、ref confusion、known-vulnerable actions），任何 finding 即紅；`--format sarif` 時 zizmor 有 finding 也 exit 0，所以判定讀 SARIF | 同 3b 對 gitleaks-action 的理由：不再有第二份未經驗證的工具副本 |
| Scorecard | `.github/workflows/scorecard.yml`（push 到 main、每週二、手動）以 lock 內的 scorecard CLI 5.5.0 跑 `--repo github.com/<owner>/<repo> --format json`（**不帶 `--commit`**：2026-09-14 第一次跑因為指定了 SHA，scorecard 只執行支援 commit 級分析的 9 個 check，Branch-Protection、Maintained、SAST、Dependency-Update-Tool、Signed-Releases 等被無聲略過；HEAD 在 push run 裡就是該 commit，2026-09-17 修正，腳本現在會印出 `not run by scorecard: …`），`scripts/scorecard_ci.py` 轉成 SARIF（每個 check 一條 rule；10 分不出 result、-1 出 note、低於 10 出 warning、低於 policy 出 error；位置取 details 內第一個 `path:line`，否則 `README.md:1`）上傳到 category `scorecard`，並依 `tools/scorecard-policy.yaml` 把關 | 不用 `ossf/scorecard-action`：它是 docker action、image 以可變 tag 引用、發布結果需要 `id-token: write`（治理 G-6 會失敗）；本 repo 的原則是工具只從 lock 來 |
| Scorecard policy | 2026-09-14 只強制 Dangerous-Workflow、Token-Permissions、Binary-Artifacts 三項為 10；License、Security-Policy（repo 無 `LICENSE`、`SECURITY.md`，由擁有者決定）、Dependency-Update-Tool（Dependabot 只管 github-actions）、Pinned-Dependencies（tests job 的 `pip install -e .` 無 hash，第一次跑 7 分）、SAST（Scorecard 不認得以腳本執行的 semgrep）、Branch-Protection（需 admin token 才看得全，可能 -1 或低分）、Code-Review（PR 都由作者自己合併，0 分）、**Vulnerabilities（0 分：Scorecard 對整個 repo 跑 osv-scanner、不能排除目錄，11 個 advisory 全是 `fixtures/vuln-sample` 與 `calib/samples` 刻意種下的舊套件；本 repo 真正安裝的閉包由 L0 的 osv-scanner 與 trivy 步驟把關且乾淨，所以只要種子材料存在這項就只回報）**只回報。2026-09-14 第一次跑總分 5.6、三個強制項皆 10 | 第一次真實跑出分數後再收緊；低於門檻是要修 workflow，不是放寬門檻 |
| Dependabot | `.github/dependabot.yml`：每週一檢查 `github-actions` 生態系，SHA 與 `# vX.Y.Z` 註解一起更新 | `tools/*-requirements.txt` 與 `tools/versions.lock` 不交給 Dependabot：它們的升版要重驗 hash、簽章與 provenance（第 4 節） |

本地能驗的：`zizmor_ci.py` 對真實 workflow 0 個 finding（default、auditor、pedantic 三種 persona）、對 fixture 5 個；`code_scanning_prep.py` 對本地產生的 semgrep（71 個 accepted 全部被丟、0 個留下）、zizmor、gitleaks SARIF 的輸出。只有 CI 能驗的：Code Scanning 是否接受上傳（job 紀錄的 `Uploading results`／`processing` 行與 Security 分頁）、scorecard `--repo` 的真實分數、scorecard 的 SLSA provenance 驗證。

## 4. 升版程序（變更管理）

1. 以 `git ls-remote --tags` 確認新 tag；下載新資產與發布者 checksum 檔，獨立計算 SHA-256 並交叉核對，兩者不一致即停止。
2. 更新 `tools/versions.lock` 的 `version`、`url`、`sha256`、`bundle_url`／`provenance_url`／`source_tag`，以及 cosign 身分正則裡的 tag。
3. semgrep：在 CPython 3.11 × manylinux 環境重新 `pip download`，以 `scripts/install_tools.py --relock-semgrep <wheel-dir>` 重寫 `tools/semgrep-requirements.txt`。
3b. Python 閉包：`scripts/relock_requirements.py --from-pyproject dev --out tools/dev-requirements.txt` 與 `--in tools/model-eval-requirements.in --out tools/model-eval-requirements.txt --allow-sdist`，在 CPython 3.11 × linux x86_64 上執行（腳本會拒絕其他主機）；它以 `pip install --dry-run --report` 解析、不安裝任何東西，SHA-256 來自 PyPI 索引。看過 diff（升了哪些版本）再提交；CI 的 osv-scanner 與 trivy 步驟會對新閉包掃描。
3a. semgrep-rules：`git clone --branch release https://github.com/semgrep/semgrep-rules.git`，看過 `git log <舊 commit>..HEAD -- <paths>` 的變更後，以 `scripts/install_tools.py --digest-git semgrep-rules <checkout>` 印出新的 `commit` 與 `sha256` 貼進 lock；重跑 `scripts/semgrep_ci.py --target fixtures/vuln-sample --expect …`，若 fixture 結果變了就更新預錄檔，再對本 repo 跑 `--triage` 補 triage 條目。
4. 本機 `python3 scripts/install_tools.py`（能連 Sigstore 的環境）或 CI 的 `deterministic-tools` job 必須全綠。
5. 更新本頁第 1 節，PR 內文列出每個工具的新舊版本與 SHA-256。

## 5. 對應

| 項目 | 對應 |
|---|---|
| 治理建議 | G-5（版本固定與簽章驗證）、G-6（workflow 硬化） |
| 差距評估 | 第 7 題「工具版本固定並有簽章或雜湊驗證」由 2 分升為 3 分（六個工具全部固定並驗證，執行紀錄在 CI 與 `.mara-tools/manifest.json`） |
| 標準 | ISO/IEC 27001:2022 A.8.8（標題待對照）；SLSA v1.2 Build L2 以上的消費端驗證；NIST SP 800-204D |
