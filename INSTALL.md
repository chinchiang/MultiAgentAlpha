# 安裝指南

本文件說明如何在一台電腦上取得並安裝 MARA（Multi-Agent Review Architecture）雛型。安裝分三層：
Python 套件（必要）、L0 掃描工具（要對真實 repo 掃描才需要）、live 模型端點（要用真實模型才需要）。
只做離線示範與跑測試，完成第 2 節即可，不需要任何 API 金鑰。

## 1. 取得原始碼

repo 是公開的，不需要 GitHub 帳號。

```bash
git clone https://github.com/chinchiang/MultiAgentAlpha.git
cd MultiAgentAlpha
```

沒有 git 的話，到 <https://github.com/chinchiang/MultiAgentAlpha> 按 **Code → Download ZIP**，解壓縮後進入該資料夾。

## 2. Python 套件（必要）

### 2.1 需求

- Python 3.11 或更新（`pyproject.toml` 的 `requires-python`）。
- 建議在虛擬環境安裝。hash 鎖定的安裝方式會拒絕系統 Python 已有的不同版本套件（例如 Debian 自帶的 PyYAML），在 venv 裡不會遇到這個問題。

### 2.2 hash 鎖定安裝（Linux x86_64 + CPython 3.11）

這是 CI 用的方式，每個 wheel 都以 SHA-256 核對，沒有任何未固定的 `pip install`：

```bash
python3.11 -m venv .venv
source .venv/bin/activate
python -m pip install --require-hashes --only-binary=:all: -r tools/dev-requirements.txt   # 執行期＋開發工具閉包
python -m pip install --require-hashes --only-binary=:all: -r tools/build-requirements.txt # 固定版本的 build backend
python -m pip install --no-deps --no-build-isolation -e .                                    # 只裝本 repo 自己的程式碼
```

`tools/dev-requirements.txt` 是在 CPython 3.11／Linux x86_64 上解析的閉包，每個套件只有該平台的 wheel hash。
在其他平台或 Python 版本上，`--require-hashes` 會因為 wheel 不同而失敗，這是預期行為，改用 2.3 節。

### 2.3 一般安裝（macOS、Windows、其他 Python 版本）

```bash
python -m venv .venv
source .venv/bin/activate            # Windows PowerShell: .venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
```

這樣安裝失去 hash 保護，pip 會依 `pyproject.toml` 的版本下限自行解析，適合個人試用，不適合當作受控環境。
要在其他平台得到同等保護，可在該平台上執行 `python scripts/relock_requirements.py --from-pyproject dev --any-platform --out <檔名>`
自行產生該平台的閉包。

### 2.4 驗證

```bash
pytest -q
mara review fixtures/vuln-sample --provider mock --sarif-dir fixtures/vuln-sample-sarif --out out
```

第一行跑完整測試（沒裝 L0 工具時有幾個工具整合測試會 skip，屬正常）。第二行對內建的漏洞範例做一次離線審查，
三個 mock 模型家族不需要網路，結果在 `out/report.md`、`out/report.sarif`、`out/human_queue.md`。
預期輸出是 `overall unavailable (review incomplete)` 與 `gate BLOCKED`：自 2026-09-18 的修正起，只要有必要的 L0 工具
沒安裝、有 reviewer 拒答或有待人工裁決的 finding，報告就標示 incomplete 且不給總分，`report.md` 的
「incomplete reasons」會列出原因。這不是安裝失敗；裝好第 3 節的工具後再跑，`required_tool_incomplete` 就會消失。

## 3. L0 掃描工具（可選）

要對自己的 repo 做真實的 semgrep、gitleaks、osv-scanner、zizmor、trivy 掃描才需要。工具版本、下載 URL 與 SHA-256 都固定在
`tools/versions.lock`，安裝器會核對雜湊並執行發行者的簽章或 provenance 驗證，裝進 repo 內的 `.mara-tools/`；程式只從那裡執行工具，
永遠不看系統 PATH。目前只鎖定 Linux x86_64 的二進位。

```bash
python -m pip install --require-hashes --only-binary=:all: -r tools/bootstrap-requirements.txt
python scripts/install_tools.py
```

外部需求：zizmor 的 GitHub attestation 驗證需要 `gh` CLI；semgrep-rules 的 commit 簽章驗證需要 `gpg` 並能連到
`https://github.com/web-flow.gpg`。沒有這些的機器可以只裝一部分：

```bash
python scripts/install_tools.py --only gitleaks semgrep semgrep-rules
```

`--no-signature-check` 會跳過簽章驗證（SHA-256 仍會核對），只適合本機試用，CI 從不使用。

trivy 需要另外抓一次離線漏洞資料庫，之後掃描時不再連網：

```bash
python scripts/trivy_db.py download
python scripts/trivy_db.py status
```

安裝完成後 `pytest -q` 會多執行 gitleaks 與 semgrep 的整合測試。

## 3.1 Windows

程式碼本身能在 Windows 上執行：2026-09-18 的修正把工具執行器、安裝器與測試都做了 Windows 相容處理（`.exe`／`.cmd` 解析、
無 `O_DIRECTORY` 的目錄讀取），第 2.3 節的一般安裝與第 2.4 節的離線 mock 審查在 Windows 上可用。有兩個限制：

- **hash 鎖定安裝不適用**：`tools/dev-requirements.txt` 只含 Linux x86_64 的 wheel hash，Windows 上 `--require-hashes` 必定失敗，只能走 2.3 節。
- **L0 工具安裝器沒有 Windows 版本**：`tools/versions.lock` 只鎖定 Linux x86_64 的二進位（cosign、gitleaks、osv-scanner、zizmor、trivy、scorecard 都是 `linux-amd64` 資產），
  `scripts/install_tools.py` 在 Windows 上無法安裝任何工具，所以真實掃描做不到，`mara review` 對所有工具都會回報 "not installed"，報告永遠是 incomplete。

要在 Windows 機器上得到完整功能，用 **WSL 2**（Ubuntu）：在 WSL 裡照第 1 到 3 節做，就是 Linux x86_64 環境，hash 鎖定與工具安裝都能用。
Docker Desktop 跑一個 `python:3.11` 容器也可以。

## 4. live 模型端點（可選）

要用真實模型審查才需要。設定檔 `config/mara.yaml` 記錄的拓撲是：Anthropic API（零資料保留協議）、自架的 DeepSeek 權重、
NVIDIA NIM 上的 Nemotron，三者都以環境變數提供金鑰，原始碼只會送給標示為 `on_prem` 或 `vendor_api_zdr` 的模型。

```bash
export ANTHROPIC_API_KEY=...
export DEEPSEEK_LOCAL_KEY=... NIM_LOCAL_KEY=...
mara check-config config/mara.yaml          # 先過七條政策檢查
mara review path/to/repo --config config/mara.yaml --out out
```

非 loopback 的推論端點必須是 HTTPS 並驗證憑證，設定檔載入時就會拒絕 `http://`。細節見 README 的「Live mode」與「Policies enforced by the config」。

## 5. 常見問題

- **`--require-hashes` 失敗，訊息提到 hash 不符或找不到 wheel**：平台或 Python 版本與閉包不同，見 2.3 節。
- **系統 Python 上出現 `Cannot uninstall PyYAML`**：沒有用 venv。建 venv 後重來。
- **`mara review` 說某工具 "not installed"**：第 3 節沒做，或該工具不在 `.mara-tools/bin`。離線 mock 模式不需要。
- **防毒或 secret scanner 對 `fixtures/` 與 `calib/samples/` 告警**：那些是刻意植入漏洞與假憑證的教材，屬預期；不要部署它們。
- **`import mara` 讀到別的目錄**：`-e .` 是可編輯安裝，指向安裝時的 repo 路徑；搬移 repo 後重跑 `pip install --no-deps -e .`。

## 6. 授權

程式碼採 Apache License 2.0（`LICENSE`）；CVSS 4.0 計算器的參照實作另見 `LICENSE-CVSS`；第三方聲明在 `NOTICE`。
`.mara-tools/semgrep-rules` 在安裝時由 semgrep/semgrep-rules 的固定 commit 取出，受 Semgrep Rules License v1.0 約束，不隨本 repo 散布。
