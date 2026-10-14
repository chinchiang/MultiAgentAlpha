# 安裝指南 / Installation Guide

本文件說明如何在一台電腦上取得並安裝 MARA（Multi-Agent Review Architecture）雛型。安裝分三層：Python 套件（必要）、L0 掃描工具（要對真實 repo 掃描才需要）、live 模型端點（要用真實模型才需要）。只做離線示範與跑測試，完成第 2 節即可，不需要任何 API 金鑰。

This document explains how to obtain and install the MARA (Multi-Agent Review Architecture) prototype on a machine. There are three layers: the Python package (required), the L0 scanning tools (only for scanning a real repository), and the live model endpoints (only for reviews with real models). For the offline demonstration and the test suite, section 2 is enough and no API key is needed.

## 1. 取得原始碼 / Getting the source

repo 是私有的（2026-09-21 起），取得方式取決於對方有沒有 GitHub 帳號。

The repository is private (since 2026-09-21), so how someone obtains it depends on whether they have a GitHub account.

### 1.1 對方有 GitHub 帳號：加為 collaborator / With a GitHub account: add them as a collaborator

repo 擁有者到 **Settings → Collaborators → Add people** 邀請對方（Read 權限即可）。對方接受邀請後，三種方式擇一：

The repository owner invites them under **Settings → Collaborators → Add people** (Read permission is enough). Once they accept, any of the three ways below works:

```bash
# HTTPS: the first clone asks for the GitHub username and a personal access token (not the password; the token needs repo read scope)
# HTTPS：第一次 clone 會要求 GitHub 帳號與 personal access token（不是密碼；token 需有 repo 讀取權）
git clone https://github.com/chinchiang/MultiAgentAlpha.git

# SSH: add the public key to the account first (Settings → SSH and GPG keys)
# SSH：先把 SSH 公鑰加到 GitHub 帳號的 Settings → SSH and GPG keys
git clone git@github.com:chinchiang/MultiAgentAlpha.git

cd MultiAgentAlpha
```

沒有 git 的話，登入 GitHub 後到 <https://github.com/chinchiang/MultiAgentAlpha> 按 **Code → Download ZIP**，解壓縮後進入該資料夾。

Without git: sign in to GitHub, open <https://github.com/chinchiang/MultiAgentAlpha>, choose **Code → Download ZIP**, unpack it and enter the folder.

### 1.2 對方沒有 GitHub 帳號：交付壓縮檔 / Without a GitHub account: hand over an archive

擁有者在自己的 clone 裡打包目前的 main，只含追蹤的檔案，不含 `.git`、`.venv`、`.mara-tools`、`out/` 等本機產物：

The owner packs the current `main` from their own clone. Only tracked files are included, never `.git`, `.venv`, `.mara-tools`, `out/` or other local products:

```bash
git archive --format=zip --prefix=MultiAgentAlpha/ -o MultiAgentAlpha-$(git rev-parse --short HEAD).zip main
```

把 zip 用內部檔案伺服器或加密附件交給對方，對方解壓縮後進入 `MultiAgentAlpha/` 資料夾，從第 2 節開始。檔名裡的 commit id 讓對方回報問題時能對上版本。不要把 zip 放到公開位置：`fixtures/` 與 `calib/samples/` 含刻意植入的假憑證與漏洞程式碼。

Deliver the zip through an internal file server or an encrypted attachment. The recipient unpacks it, enters `MultiAgentAlpha/` and continues with section 2. The commit id in the file name lets them say which version a problem was seen on. Never place the zip anywhere public: `fixtures/` and `calib/samples/` contain deliberately planted fake credentials and vulnerable code.

### 1.3 私有化後的影響 / What changes while the repository is private

- **GitHub Pages 的線上報告仍然公開**：repo 私有後 Pages 照常在每次 push 到 `main` 時重新發布，<https://chinchiang.github.io/MultiAgentAlpha/> 不需登入即可讀取（2026-09-24 確認，owner 決定維持公開）。私有只保護原始碼、fixtures 與歷史紀錄，`docs/` 底下的所有檔案都是公開的，只能放可公開的文件。
- **Code Scanning 上傳會跳過**：免費的 Code Scanning 只涵蓋公開 repo，私有 repo 需要 GitHub Advanced Security。`mara-review.yml` 的 `code-scanning` job 在私有狀態下自動跳過，SARIF 仍以 `l0-sarif` artifact 保存；Scorecard 的唯讀 token 讀不到私有 repo 的 GraphQL，呼叫 API 的 Scorecard job 也一併跳過；改由 `scorecard-local` job 以同一個鎖定的 CLI 加 `--local` 掃描已提交的樹，六個以檔案判定的強制項照樣把關。
- **Private vulnerability reporting 無法使用**：GitHub 只對公開 repo 提供，`SECURITY.md` 的回報表單連結會回應 404；私有期間請直接私訊維護者，見 `SECURITY.md`。

- **The online report on GitHub Pages stays public**: Pages keeps republishing on every push to `main` after the repository became private, and <https://chinchiang.github.io/MultiAgentAlpha/> is readable without signing in (confirmed 2026-09-24; the owner decided to keep it public). Being private protects the source tree, the fixtures and the history; every file under `docs/` is public and must be fit for publication.
- **The Code Scanning uploads are skipped**: free Code Scanning covers public repositories only; private ones need GitHub Advanced Security. The `code-scanning` job of `mara-review.yml` skips itself while the repository is private and the SARIF files remain in the `l0-sarif` artifact; the API-based Scorecard job is skipped too, because its read-only token cannot run scorecard's GraphQL queries on a private repository; the `scorecard-local` job runs the same locked CLI with `--local` on the committed tree instead and still enforces the six file-based checks.
- **Private vulnerability reporting is unavailable**: GitHub offers it for public repositories only, so the form link in `SECURITY.md` returns 404; while private, contact the maintainer directly as `SECURITY.md` describes.

## 2. Python 套件（必要）/ Python package (required)

### 2.1 需求 / Requirements

- Python 3.11 或更新（`pyproject.toml` 的 `requires-python`）。
- 建議在虛擬環境安裝。hash 鎖定的安裝方式會拒絕系統 Python 已有的不同版本套件（例如 Debian 自帶的 PyYAML），在 venv 裡不會遇到這個問題。

- Python 3.11 or newer (`requires-python` in `pyproject.toml`).
- Install into a virtual environment. The hash-pinned install refuses packages the system Python already has at a different version (Debian's own PyYAML, for example); a venv avoids that.

### 2.2 hash 鎖定安裝（Linux x86_64 + CPython 3.11）/ Hash-pinned install (Linux x86_64 + CPython 3.11)

這是 CI 用的方式，每個 wheel 都以 SHA-256 核對，沒有任何未固定的 `pip install`：

This is what CI does: every wheel is checked against its SHA-256 and no `pip install` runs unpinned:

```bash
python3.11 -m venv .venv
source .venv/bin/activate
python -m pip install --require-hashes --only-binary=:all: -r tools/dev-requirements.txt   # runtime + dev closure / 執行期＋開發工具閉包
python -m pip install --require-hashes --only-binary=:all: -r tools/build-requirements.txt # pinned build backend / 固定版本的 build backend
python -m pip install --no-deps --no-build-isolation -e .                                    # this repository's own code only / 只裝本 repo 自己的程式碼
```

`tools/dev-requirements.txt` 是在 CPython 3.11／Linux x86_64 上解析的閉包，每個套件只有該平台的 wheel hash。CPython 3.12／Linux x86_64 請改用 `tools/dev-requirements-py312.txt`（版本與 3.11 閉包完全相同，只有 wheel 與 hash 不同，CI 的 `tests (CPython 3.12)` job 用的就是它），其餘兩行不變。在其他平台或 Python 版本上，`--require-hashes` 會因為 wheel 不同而失敗，這是預期行為，改用 2.3 節。

`tools/dev-requirements.txt` was resolved on CPython 3.11 / Linux x86_64 and carries only that platform's wheel hashes. On CPython 3.12 / Linux x86_64 use `tools/dev-requirements-py312.txt` instead (the same versions as the 3.11 closure, only the wheels and hashes differ; the CI job `tests (CPython 3.12)` installs it); the other two lines stay the same. On any other platform or Python version `--require-hashes` fails because the wheels differ; that is expected, use section 2.3.

### 2.3 一般安裝（macOS、Windows、其他 Python 版本）/ Plain install (macOS, Windows, other Python versions)

```bash
python -m venv .venv
source .venv/bin/activate            # Windows PowerShell: .venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
```

這樣安裝失去 hash 保護，pip 會依 `pyproject.toml` 的版本下限自行解析，適合個人試用，不適合當作受控環境。要在其他平台得到同等保護，可在該平台上執行 `python scripts/relock_requirements.py --from-pyproject dev --any-platform --out <檔名>` 自行產生該平台的閉包。

This loses the hash protection: pip resolves from the lower bounds in `pyproject.toml`. Fine for trying the tool out, not for a controlled environment. For the same protection elsewhere, run `python scripts/relock_requirements.py --from-pyproject dev --any-platform --out <file>` on that platform to produce its own closure.

### 2.4 驗證 / Verification

```bash
pytest -q
mara review fixtures/vuln-sample --provider mock --sarif-dir fixtures/vuln-sample-sarif --out out
```

第一行跑完整測試（沒裝 L0 工具時有幾個工具整合測試會 skip，屬正常）。第二行對內建的漏洞範例做一次離線審查，三個 mock 模型家族不需要網路，結果在 `out/report.md`、`out/report.sarif`、`out/human_queue.md` 與 `out/context.json`（context agent 產生、逐字引文驗證過的架構視圖）。預期輸出是 `overall unavailable (review incomplete)` 與 `gate BLOCKED`：自 2026-09-18 的修正起，只要有必要的 L0 工具沒安裝、有 reviewer 拒答或有待人工裁決的 finding，報告就標示 incomplete 且不給總分，`report.md` 的「incomplete reasons」會列出原因。這不是安裝失敗；裝好第 3 節的工具後再跑，`required_tool_incomplete` 就會消失。

型別檢查（`mypy`，設定在 `pyproject.toml`）不在 `dev` 依賴裡：CI 的 CPython 3.12 job 以 `tools/typecheck-requirements.txt` 的 hash 鎖定閉包安裝並執行。那份閉包是為 Linux runner 解析的，Windows 上雜湊不符；要在本機執行，在 Linux 或 WSL 以 `pip install --require-hashes -r tools/typecheck-requirements.txt` 後跑 `python3 -m mypy`。

Type checking (`mypy`, configured in `pyproject.toml`) is not in the `dev` dependencies: CI's CPython 3.12 job installs it from the hash-locked closure `tools/typecheck-requirements.txt` and runs it. That closure is resolved for the Linux runner and its hashes do not match on Windows; to run it locally, use Linux or WSL: `pip install --require-hashes -r tools/typecheck-requirements.txt`, then `python3 -m mypy`.

The first line runs the whole test suite (a few tool-integration tests skip while the L0 tools are not installed; that is normal). The second line reviews the built-in vulnerable sample offline; the three mock model families need no network, and the results are `out/report.md`, `out/report.sarif`, `out/human_queue.md` and `out/context.json` (the architecture view the context agent builds, every fact verified against a verbatim quote). Expect `overall unavailable (review incomplete)` and `gate BLOCKED`: since the 2026-09-18 remediation, a missing required L0 tool, a reviewer refusal or a finding awaiting human adjudication marks the review incomplete and withholds the overall score; "incomplete reasons" in `report.md` lists why. This is not a broken install. Once the tools from section 3 are installed, `required_tool_incomplete` disappears.

### 2.5 本機網頁工作台（可選）/ Local web workbench (optional)

裝好第 2 節後即可使用，不需要額外套件：

Available once section 2 is done; no further package is needed:

```bash
mara serve                 # 印出並開啟 http://127.0.0.1:8765/?token=… / prints and opens http://127.0.0.1:8765/?token=…
mara serve --no-browser    # 只印出網址（遠端主機、WSL）/ print the URL only (remote host, WSL)
```

從 repo 根目錄（或設好 `MARA_HOME` 後）執行。開啟印出的網址，在「新建評估」按「合成示範」，就能以內建的刻意弱點範例與三個 mock 模型家族離線跑完整流程，並在瀏覽器中看九個階段、發現、審查小組與驗證缺口；右上角可切換中文與英文。每次執行的報告都寫在 `out/runs/<run-id>/`。服務只聽本機位址（127.0.0.1、localhost 或 ::1），網址中的權杖就是這次服務的登入鑰匙，不要分享；要從另一台電腦使用，請用 SSH 通道（`ssh -L 8765:127.0.0.1:8765 主機`）。「工具與執行環境」頁的安裝與下載按鈕執行的就是第 3 節的 `scripts/install_tools.py` 與 `scripts/trivy_db.py`；實際評估需要的金鑰環境變數，要在啟動 `mara serve` 的終端機先設好（第 4 節）。細節見 README 的「Local web workbench」與 `docs/adr/0006-local-web-workbench.md`。

Run it from the repository root (or with `MARA_HOME` set). Open the printed URL, choose *Offline demo* under *New review*, and the built-in deliberately vulnerable sample runs through the whole pipeline offline with three mock model families; the browser shows the nine stages, the findings, the review panel and the verification gaps, and the switch at the top right changes between Chinese and English. Each run's reports are written to `out/runs/<run-id>/`. The server listens on a loopback address only (127.0.0.1, localhost or ::1), and the token in the URL is the key to this server: do not share it; from another machine, use an SSH tunnel (`ssh -L 8765:127.0.0.1:8765 host`). The install and download buttons on the *Tools & environment* page run section 3's `scripts/install_tools.py` and `scripts/trivy_db.py`; the key variables a live review needs must be set in the terminal that starts `mara serve` (section 4). See "Local web workbench" in the README and `docs/adr/0006-local-web-workbench.md`.

## 3. L0 掃描工具（可選）/ L0 scanning tools (optional)

要對自己的 repo 做真實的 semgrep、gitleaks、osv-scanner、zizmor、trivy、csp-evaluator 掃描才需要。工具版本、下載 URL 與 SHA-256 都固定在 `tools/versions.lock`，安裝器會核對雜湊並執行發行者的簽章或 provenance 驗證，裝進 `mara` 執行工具的同一個目錄：有設 `MARA_TOOLS_DIR` 就是它，否則是 MARA 工作區（`MARA_HOME`，未設時為目前目錄）下的 `.mara-tools/`；從 repo 根目錄執行時就是 repo 內的 `.mara-tools/`。程式只從那裡執行工具，永遠不看系統 PATH。目前只鎖定 Linux x86_64 的二進位；csp-evaluator 是 npm 套件，另外需要 node ≥ 18（直譯器路徑可用 `MARA_NODE` 覆寫）。

Needed only for real semgrep, gitleaks, osv-scanner, zizmor, trivy and csp-evaluator scans of your own repository. Versions, download URLs and SHA-256 digests are pinned in `tools/versions.lock`; the installer checks the digests, runs each publisher's signature or provenance verification and installs into the directory `mara` runs tools from: `MARA_TOOLS_DIR` when set, else `.mara-tools/` below the MARA workspace (`MARA_HOME`, or the working directory), which is the repository's `.mara-tools/` when run from its root. The code executes tools from there only and never consults PATH. Only Linux x86_64 binaries are locked; csp-evaluator is an npm package and additionally needs node ≥ 18 (override the interpreter with `MARA_NODE`).

```bash
python -m pip install --require-hashes --only-binary=:all: -r tools/bootstrap-requirements.txt
python scripts/install_tools.py
```

外部需求：zizmor 的 GitHub attestation 驗證需要 `gh` CLI；semgrep-rules 的 commit 簽章驗證需要 `gpg` 並能連到 `https://github.com/web-flow.gpg`。沒有 `gh` 的機器可以只裝一部分（semgrep-rules 仍需要 `gpg`）：

External requirements: zizmor's GitHub attestation check needs the `gh` CLI; the semgrep-rules commit signature check needs `gpg` and access to `https://github.com/web-flow.gpg`. A machine without `gh` can install a subset (semgrep-rules still needs `gpg`):

```bash
python scripts/install_tools.py --only gitleaks semgrep semgrep-rules
```

`--no-signature-check` 會跳過簽章驗證（SHA-256 仍會核對），只適合本機試用，CI 從不使用。

`--no-signature-check` skips the signature checks (SHA-256 is still enforced); it is for local trials only and CI never uses it.

trivy 需要另外抓一次離線漏洞資料庫，之後掃描時不再連網：

trivy needs its vulnerability database fetched once; scans then run offline:

```bash
python scripts/trivy_db.py download
python scripts/trivy_db.py status
```

安裝完成後 `pytest -q` 會多執行使用真實工具的測試：gitleaks（`test_gitleaks_ci.py`）、semgrep（`test_semgrep_ci.py`、`test_tool_target_config.py`），有 node 時另含 csp-evaluator（`test_tools_csp.py`）。

After that, `pytest -q` also runs the tests that use the real tools: gitleaks (`test_gitleaks_ci.py`), semgrep (`test_semgrep_ci.py`, `test_tool_target_config.py`) and, with node, csp-evaluator (`test_tools_csp.py`).

### 3.1 Windows

程式碼本身能在 Windows 上執行：2026-09-18 的修正把工具執行器、安裝器與測試都做了 Windows 相容處理（`.exe`／`.cmd` 解析、無 `O_DIRECTORY` 的目錄讀取），第 2.3 節的一般安裝與第 2.4 節的離線 mock 審查在 Windows 上可用。有兩個限制：

The code itself runs on Windows: the 2026-09-18 remediation made the tool runner, the installer and the tests Windows-aware (`.exe`/`.cmd` resolution, directory reads without `O_DIRECTORY`), so the plain install of section 2.3 and the offline mock review of section 2.4 work there. Two limits remain:

- **hash 鎖定安裝不適用**：`tools/dev-requirements.txt` 只含 Linux x86_64 的 wheel hash，Windows 上 `--require-hashes` 必定失敗，只能走 2.3 節。
- **L0 工具的 Windows 資產不齊**：`tools/versions.lock` 的二進位工具（cosign、slsa-verifier、gitleaks、osv-scanner、zizmor、trivy、scorecard）都是 `linux-amd64` 資產，Windows 上裝不起來，所以真實掃描做不到、`mara review` 對這些工具都會回報 "not installed"、報告永遠是 incomplete。唯一的例外是 npm 類型的 csp-evaluator：安裝器會寫 `.cmd` shim，只要有 node ≥ 18 就能在 Windows 上安裝並執行，但單靠它不足以完成審查。

- **The hash-pinned install does not apply**: `tools/dev-requirements.txt` holds Linux x86_64 wheel hashes only, so `--require-hashes` always fails on Windows; use section 2.3.
- **The L0 tool set has no Windows binaries**: the binary tools in `tools/versions.lock` (cosign, slsa-verifier, gitleaks, osv-scanner, zizmor, trivy and scorecard) are all `linux-amd64` assets and cannot be installed on Windows, so real scans are impossible, `mara review` reports every one of them as "not installed" and the review stays incomplete. The one exception is the npm-kind csp-evaluator: the installer writes a `.cmd` shim, so with node ≥ 18 it installs and runs on Windows — but on its own it is not enough for a complete review.

要在 Windows 機器上得到完整功能，用 **WSL 2**（Ubuntu）：在 WSL 裡照第 1 到 3 節做，就是 Linux x86_64 環境，hash 鎖定與工具安裝都能用。Docker Desktop 跑一個 `python:3.11` 容器也可以。

For the full feature set on a Windows machine use **WSL 2** (Ubuntu): following sections 1 to 3 inside WSL is a Linux x86_64 environment, so the hash-pinned install and the tool installer both work. A `python:3.11` container under Docker Desktop works too.

## 4. live 模型端點（可選）/ Live model endpoints (optional)

要用真實模型審查才需要。設定檔 `config/mara.yaml` 記錄的拓撲是：Amazon Bedrock 上的 Claude（AWS 預設憑證鏈，例如 `aws sso login` 後設 `AWS_PROFILE`）、付費層 Gemini API（金鑰放 `x-goog-api-key` 標頭）、IEC 網路內自架的 GLM（OpenAI 相容端點）。金鑰一律來自環境變數；原始碼只會送給標示為 `on_prem`、`vendor_api_zdr`，或附有該模型自己 `retention_approval_ref` 核准單號的 `vendor_api_retained` 模型。內部 CA 簽發的端點以 `ca_bundle` 指定 PEM 憑證鏈（只會加入信任清單，不會關閉驗證）；公司私有 DNS 區寫在 `private_dns_suffixes`。

Needed only for reviews with real models. `config/mara.yaml` documents the topology: Claude on Amazon Bedrock (the AWS default credential chain, e.g. `AWS_PROFILE` after `aws sso login`), the Gemini API on the paid tier (key in the `x-goog-api-key` header), and GLM self-hosted on the IEC network behind an OpenAI-compatible endpoint. All keys come from environment variables, and source code is sent only to models declared `on_prem` or `vendor_api_zdr`, or `vendor_api_retained` with that model's own `retention_approval_ref`. An endpoint signed by an internal CA names its PEM chain in `ca_bundle` (added to the trust store, never disabling verification); the organisation's private DNS zones go in `private_dns_suffixes`.

```bash
export AWS_PROFILE=...                      # Bedrock (after `aws sso login --profile ...`)
export GEMINI_API_KEY=... GLM_LOCAL_KEY=...
mara check-config config/mara.yaml          # the eight policy checks first / 先過八條政策檢查
mara review path/to/repo --config config/mara.yaml --out out
```

設定檔中已沒有暫定的模型 id：Gemini 與 GLM 的 id 已於 2026-10-07 對照各端點的模型清單確認（id 旁的註解有記錄），三個模型都在 2026-10-08 的 live 校準中實際回應。換成新的 id 時，第一次 live 執行前要同樣先確認。

No model id in the file is provisional any more: the Gemini and GLM ids were checked against their endpoints' model lists on 2026-10-07 (the comments next to them record it), and all three models answered in the live calibration of 2026-10-08. Check a new id the same way before its first live run.

非 loopback 的推論端點必須是 HTTPS 並驗證憑證，設定檔載入時就會拒絕 `http://`。細節見 README 的「Live mode」與「Policies enforced by the config」。

Non-loopback inference endpoints must be HTTPS with certificate validation; the config refuses `http://` at load time. See "Live mode" and "Policies enforced by the config" in the README.

## 5. 常見問題 / Troubleshooting

- **`--require-hashes` 失敗，訊息提到 hash 不符或找不到 wheel**：平台或 Python 版本與閉包不同，見 2.3 節。
- **系統 Python 上出現 `Cannot uninstall PyYAML`**：沒有用 venv。建 venv 後重來。
- **`mara review` 說某工具 "not installed"**：第 3 節沒做，或該工具不在 `.mara-tools/bin`。離線 mock 模式不需要。
- **防毒或 secret scanner 對 `fixtures/` 與 `calib/samples/` 告警**：那些是刻意植入漏洞與假憑證的教材，屬預期；不要部署它們。
- **`import mara` 讀到別的目錄**：`-e .` 是可編輯安裝，指向安裝時的 repo 路徑；搬移 repo 後重跑 `pip install --no-deps --no-build-isolation -e .`。

- **`--require-hashes` fails with a hash mismatch or no matching wheel**: the platform or Python version differs from the closure; see section 2.3.
- **`Cannot uninstall PyYAML` on the system Python**: no venv was used. Create one and start over.
- **`mara review` reports a tool as "not installed"**: section 3 was skipped, or the tool is not under `.mara-tools/bin`. The offline mock mode does not need it.
- **Antivirus or a secret scanner flags `fixtures/` and `calib/samples/`**: these are teaching materials with deliberately planted vulnerabilities and fake credentials; expected. Never deploy them.
- **`import mara` resolves to another directory**: `-e .` is an editable install pointing at the repository path at install time; after moving the repository, rerun `pip install --no-deps --no-build-isolation -e .`.

## 6. 授權 / Licence

程式碼採 Apache License 2.0（`LICENSE`）；CVSS 4.0 計算器的參照實作另見 `LICENSE-CVSS`；第三方聲明在 `NOTICE`。`.mara-tools/semgrep-rules` 在安裝時由 semgrep/semgrep-rules 的固定 commit 取出，受 Semgrep Rules License v1.0 約束，不隨本 repo 散布。

The code is under the Apache License 2.0 (`LICENSE`); the CVSS 4.0 reference implementation has its own terms in `LICENSE-CVSS`; third-party notices are in `NOTICE`. `.mara-tools/semgrep-rules` is checked out at install time from a pinned semgrep/semgrep-rules commit, is governed by the Semgrep Rules License v1.0, and is not distributed with this repository.
