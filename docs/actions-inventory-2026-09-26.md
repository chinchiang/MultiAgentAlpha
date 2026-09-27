# GitHub Actions 盤點（2026-09-26）

依附錄 E 的 prompt 5，對本 repo 內所有 `.github/workflows/*.yml` 做 pwn request 與 SHA pinning 盤點。**只讀不改。** 本檔第 0 到 5 節由 `scripts/actions_inventory.py` 產生，第 6 節為人工補充。

## 0. 範圍、方法與判定準則

- 掃描根目錄：`MultiAgentAlpha/`，遞迴尋找所有 `.github/workflows/*.yml|yaml`（排除 `.git`、`node_modules`、`out/`、`calib-out/`）。共 6 個 workflow。
- 每個檔案先以 `yaml.safe_load` 驗證；不合法 YAML 的檔案仍以逐行比對盤點並標記，因為 GitHub 會拒絕執行它、zizmor 與 actionlint 也解析不了，這本身就是要回報的事實。
- `uses:` 的引用種類：40 字元十六進位為 **sha**；`v` 或數字開頭為 **tag**；其餘為 **branch**；`./` 為 local、`docker://` 為 docker。
- `run:` 內插：列出所有 `${{ github.event.* }}`、`github.head_ref`、`github.ref`；其中符合 GitHub Security Lab「不可信輸入」清單（PR 標題／內文／head ref／head label、issue 標題／內文、comment/review 內文、commit message 與作者、`github.head_ref`）者標為攻擊者可控。
- 非 SHA 引用以 `git ls-remote https://github.com/<owner>/<repo>` 解析目前 tag（優先取 peeled `^{}`）或分支的完整 SHA。
- SHA 引用若附 `# vX.Y.Z` 註解，一併驗證該 tag 目前是否仍指向這個 SHA。
- zizmor：已執行（`--offline`，線上稽核如 impostor-commit 與 known-vulnerable-actions 未跑；CI 的 `scripts/zizmor_ci.py` 以 workflow token 另跑線上稽核）。actionlint、poutine：未執行（不在 PATH）。

**判定準則（報告第 10.7 節）。** pwn request（`pull_request_target` 加 checkout PR head）為 Critical 且 reachable；攻擊者可控 context 內插到 `run:`（標題注入等）同為 Critical；以 tag 或分支引用第三方 action 為 High 但 conditional；`write-all` 為 High；缺 `permissions:`、cache key 含不可信 ref、self-hosted runner 為 Medium；未設 `persist-credentials: false` 為 Low。workflow 的嚴重度取其最高項。

## 1. 總表（Critical 在最上方）

| 嚴重度 | workflow | 用途 | 觸發 | PRT | checkout PR head | 頂層 permissions | job permissions | uses（sha/tag/branch） | run 內插（可控） | cache key 含 ref | 合法 YAML |
|---|---|---|---|---|---|---|---|---|---|---|---|
| **Critical** | `calib/samples/s3-django-orders/.github/workflows/ci.yml` | fixture／校準樣本（刻意含缺陷，不會執行） | pull_request_target | 是 | 是（第 11 行） | `write-all` | （缺失） | 0/1/1 | 2（1） | 無 cache | 是 |
| **Critical** | `fixtures/vuln-sample/.github/workflows/deploy.yml` | fixture／校準樣本（刻意含缺陷，不會執行） | pull_request_target | 是 | 是（第 12 行） | `write-all` | （缺失） | 0/1/1 | 1（1） | 無 cache | 是 |
| **None** | `.github/workflows/docs-check.yml` | **實際 CI** | pull_request, push, workflow_dispatch | 否 | 否 | `{}` | docs-check: {contents: read} | 2/0/0 | 0（0） | 無 cache | 是 |
| **None** | `.github/workflows/governance.yml` | **實際 CI** | schedule, workflow_dispatch | 否 | 否 | `{}` | governance: {contents: read, issues: write} | 2/0/0 | 0（0） | 無 cache | 是 |
| **None** | `.github/workflows/mara-review.yml` | **實際 CI** | pull_request, schedule, workflow_dispatch, push | 否 | 否 | `{}` | deterministic-tools: {contents: read}; code-scanning: {contents: read, security-events: write}; tests-and-mock-review: {contents: read}; human-queue: {contents: read, issues: write} | 12/0/0 | 0（0） | 無 cache | 是 |
| **None** | `.github/workflows/scorecard.yml` | **實際 CI** | push, schedule, workflow_dispatch | 否 | 否 | `{}` | scorecard: {contents: read, security-events: write} | 4/0/0 | 0（0） | 無 cache | 是 |

## 2. 逐一明細

### calib/samples/s3-django-orders/.github/workflows/ci.yml — Critical

**判定項目**

- **Critical** — pwn request：`pull_request_target` 加 checkout PR head（第 11 行）；前置條件只是能開一個 fork PR
- **Critical** — 攻擊者可控的 context 直接內插到 `run:`（第 13 行：`${{ github.event.pull_request.body }}`）
- **High** — 第 9 行 `actions/checkout@v4` 以 tag 而非 40 字元 SHA 引用（conditional：需上游 tag/分支被改指）
- **High** — 第 14 行 `acme/deploy@master` 以 分支 而非 40 字元 SHA 引用（conditional：需上游 tag/分支被改指）
- **High** — `permissions: write-all`：GITHUB_TOKEN 取得全部 scope
- **Low** — `run:` 內插了 context `${{ github.event.pull_request.user.login }}`（第 13 行）；非標準攻擊者可控欄位，仍建議改走 env
- **Low** — 1 個 actions/checkout 未設 `persist-credentials: false`（zizmor artipacked）

**`uses:` 引用**

| 行 | 引用 | 種類 | 註解 | 解析結果 |
|---|---|---|---|---|
| 9 | `actions/checkout@v4` | tag |  | 目前 tag → `11d5960a326750d5838078e36cf38b85af677262` |
| 14 | `acme/deploy@master` | branch |  | 無法解析（repo 不存在、私有或不可達） |

**`run:` 內插**

| 行 | 運算式 | 攻擊者可控 |
|---|---|---|
| 13 | `${{ github.event.pull_request.user.login }}` | 否 |
| 13 | `${{ github.event.pull_request.body }}` | **是** |

**zizmor**（zizmor 1.30.1，`--offline`，exit 0）

| 規則 | 等級 | 行 | 訊息 |
|---|---|---|---|
| zizmor/artipacked | warning | 9 | credential persistence through GitHub Actions artifacts: does not set persist-credentials: false |
| zizmor/dangerous-triggers | error | 2 | use of fundamentally insecure workflow trigger: pull_request_target is almost always used insecurely |
| zizmor/template-injection | error | 13 | code injection via template expansion: may expand into attacker-controllable code |
| zizmor/template-injection | error | 13 | code injection via template expansion: may expand into attacker-controllable code |
| zizmor/unpinned-uses | error | 9 | unpinned action reference: action is not pinned to a hash (required by blanket policy) |
| zizmor/unpinned-uses | error | 14 | unpinned action reference: action is not pinned to a hash (required by blanket policy) |

### fixtures/vuln-sample/.github/workflows/deploy.yml — Critical

**判定項目**

- **Critical** — pwn request：`pull_request_target` 加 checkout PR head（第 12 行）；前置條件只是能開一個 fork PR
- **Critical** — 攻擊者可控的 context 直接內插到 `run:`（第 15 行：`${{ github.event.pull_request.title }}`）
- **High** — 第 10 行 `actions/checkout@v4` 以 tag 而非 40 字元 SHA 引用（conditional：需上游 tag/分支被改指）
- **High** — 第 16 行 `some-org/deploy-action@main` 以 分支 而非 40 字元 SHA 引用（conditional：需上游 tag/分支被改指）
- **High** — `permissions: write-all`：GITHUB_TOKEN 取得全部 scope
- **Low** — 1 個 actions/checkout 未設 `persist-credentials: false`（zizmor artipacked）

**`uses:` 引用**

| 行 | 引用 | 種類 | 註解 | 解析結果 |
|---|---|---|---|---|
| 10 | `actions/checkout@v4` | tag |  | 目前 tag → `11d5960a326750d5838078e36cf38b85af677262` |
| 16 | `some-org/deploy-action@main` | branch |  | 無法解析（repo 不存在、私有或不可達） |

**`run:` 內插**

| 行 | 運算式 | 攻擊者可控 |
|---|---|---|
| 15 | `${{ github.event.pull_request.title }}` | **是** |

**zizmor**（zizmor 1.30.1，`--offline`，exit 0）

| 規則 | 等級 | 行 | 訊息 |
|---|---|---|---|
| zizmor/artipacked | warning | 10 | credential persistence through GitHub Actions artifacts: does not set persist-credentials: false |
| zizmor/dangerous-triggers | error | 2 | use of fundamentally insecure workflow trigger: pull_request_target is almost always used insecurely |
| zizmor/template-injection | error | 15 | code injection via template expansion: may expand into attacker-controllable code |
| zizmor/unpinned-uses | error | 10 | unpinned action reference: action is not pinned to a hash (required by blanket policy) |
| zizmor/unpinned-uses | error | 16 | unpinned action reference: action is not pinned to a hash (required by blanket policy) |

### .github/workflows/docs-check.yml — None

**判定項目**

- 無

**`uses:` 引用**

| 行 | 引用 | 種類 | 註解 | 解析結果 |
|---|---|---|---|---|
| 38 | `actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1` | sha | v7.0.1 | pin 與註解 v7.0.1 一致 |
| 41 | `actions/setup-python@5fda3b95a4ea91299a34e894583c3862153e4b97` | sha | v7.0.0 | pin 與註解 v7.0.0 一致 |

**`run:` 內插**

無。

**zizmor**（zizmor 1.30.1，`--offline`，exit 0）

無 finding。

### .github/workflows/governance.yml — None

**判定項目**

- 無

**`uses:` 引用**

| 行 | 引用 | 種類 | 註解 | 解析結果 |
|---|---|---|---|---|
| 25 | `actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1` | sha | v7.0.1 | pin 與註解 v7.0.1 一致 |
| 28 | `actions/setup-python@5fda3b95a4ea91299a34e894583c3862153e4b97` | sha | v7.0.0 | pin 與註解 v7.0.0 一致 |

**`run:` 內插**

無。

**zizmor**（zizmor 1.30.1，`--offline`，exit 0）

無 finding。

### .github/workflows/mara-review.yml — None

**判定項目**

- 無

**`uses:` 引用**

| 行 | 引用 | 種類 | 註解 | 解析結果 |
|---|---|---|---|---|
| 64 | `actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1` | sha | v7.0.1 | pin 與註解 v7.0.1 一致 |
| 68 | `actions/setup-python@5fda3b95a4ea91299a34e894583c3862153e4b97` | sha | v7.0.0 | pin 與註解 v7.0.0 一致 |
| 134 | `actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a` | sha | v7.0.1 | pin 與註解 v7.0.1 一致 |
| 140 | `actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a` | sha | v7.0.1 | pin 與註解 v7.0.1 一致 |
| 171 | `actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c` | sha | v8.0.1 | pin 與註解 v8.0.1 一致 |
| 175 | `github/codeql-action/upload-sarif@1c5b675653bb5c22dbe9b12b556ec555138e09fd` | sha | v4.38.1 | pin 與註解 v4.38.1 一致 |
| 187 | `actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1` | sha | v7.0.1 | pin 與註解 v7.0.1 一致 |
| 190 | `actions/setup-python@5fda3b95a4ea91299a34e894583c3862153e4b97` | sha | v7.0.0 | pin 與註解 v7.0.0 一致 |
| 219 | `actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a` | sha | v7.0.1 | pin 與註解 v7.0.1 一致 |
| 233 | `actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1` | sha | v7.0.1 | pin 與註解 v7.0.1 一致 |
| 236 | `actions/setup-python@5fda3b95a4ea91299a34e894583c3862153e4b97` | sha | v7.0.0 | pin 與註解 v7.0.0 一致 |
| 258 | `actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a` | sha | v7.0.1 | pin 與註解 v7.0.1 一致 |

**`run:` 內插**

無。

**zizmor**（zizmor 1.30.1，`--offline`，exit 0）

無 finding。

### .github/workflows/scorecard.yml — None

**判定項目**

- 無

**`uses:` 引用**

| 行 | 引用 | 種類 | 註解 | 解析結果 |
|---|---|---|---|---|
| 35 | `actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1` | sha | v7.0.1 | pin 與註解 v7.0.1 一致 |
| 38 | `actions/setup-python@5fda3b95a4ea91299a34e894583c3862153e4b97` | sha | v7.0.0 | pin 與註解 v7.0.0 一致 |
| 54 | `actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a` | sha | v7.0.1 | pin 與註解 v7.0.1 一致 |
| 62 | `github/codeql-action/upload-sarif@1c5b675653bb5c22dbe9b12b556ec555138e09fd` | sha | v4.38.1 | pin 與註解 v4.38.1 一致 |

**`run:` 內插**

無。

**zizmor**（zizmor 1.30.1，`--offline`，exit 0）

無 finding。

## 3. 建議修改（非 SHA 的 `uses:` → 完整 SHA；不直接改檔）

| workflow | 行 | 目前 | 建議改為 | 依據 | 備註 |
|---|---|---|---|---|---|
| `calib/samples/s3-django-orders/.github/workflows/ci.yml` | 9 | `actions/checkout@v4` | `actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4` | tag | fixture，刻意保留缺陷供 L0/L2 測試，不建議修改 |
| `calib/samples/s3-django-orders/.github/workflows/ci.yml` | 14 | `acme/deploy@master` | （無法解析；若為真實 action 需先確認來源） | 無法解析（repo 不存在、私有或不可達） | fixture，刻意保留缺陷供 L0/L2 測試，不建議修改 |
| `fixtures/vuln-sample/.github/workflows/deploy.yml` | 10 | `actions/checkout@v4` | `actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4` | tag | fixture，刻意保留缺陷供 L0/L2 測試，不建議修改 |
| `fixtures/vuln-sample/.github/workflows/deploy.yml` | 16 | `some-org/deploy-action@main` | （無法解析；若為真實 action 需先確認來源） | 無法解析（repo 不存在、私有或不可達） | fixture，刻意保留缺陷供 L0/L2 測試，不建議修改 |

**已固定 SHA 的引用：對照 tag 與最新版本**

| workflow | 行 | 引用 | 註解 tag 驗證 | 該 repo 目前最新 tag |
|---|---|---|---|---|
| `.github/workflows/docs-check.yml` | 38 | `actions/checkout@3d3c42e5aac5…` | pin 與註解 v7.0.1 一致 | v7.0.1 |
| `.github/workflows/docs-check.yml` | 41 | `actions/setup-python@5fda3b95a4ea…` | pin 與註解 v7.0.0 一致 | v7.0.0 |
| `.github/workflows/governance.yml` | 25 | `actions/checkout@3d3c42e5aac5…` | pin 與註解 v7.0.1 一致 | v7.0.1 |
| `.github/workflows/governance.yml` | 28 | `actions/setup-python@5fda3b95a4ea…` | pin 與註解 v7.0.0 一致 | v7.0.0 |
| `.github/workflows/mara-review.yml` | 64 | `actions/checkout@3d3c42e5aac5…` | pin 與註解 v7.0.1 一致 | v7.0.1 |
| `.github/workflows/mara-review.yml` | 68 | `actions/setup-python@5fda3b95a4ea…` | pin 與註解 v7.0.0 一致 | v7.0.0 |
| `.github/workflows/mara-review.yml` | 134 | `actions/upload-artifact@043fb46d1a93…` | pin 與註解 v7.0.1 一致 | v7.0.1 |
| `.github/workflows/mara-review.yml` | 140 | `actions/upload-artifact@043fb46d1a93…` | pin 與註解 v7.0.1 一致 | v7.0.1 |
| `.github/workflows/mara-review.yml` | 171 | `actions/download-artifact@3e5f45b2cfb9…` | pin 與註解 v8.0.1 一致 | v8.0.1 |
| `.github/workflows/mara-review.yml` | 175 | `github/codeql-action/upload-sarif@1c5b675653bb…` | pin 與註解 v4.38.1 一致 | v4.38.2 |
| `.github/workflows/mara-review.yml` | 187 | `actions/checkout@3d3c42e5aac5…` | pin 與註解 v7.0.1 一致 | v7.0.1 |
| `.github/workflows/mara-review.yml` | 190 | `actions/setup-python@5fda3b95a4ea…` | pin 與註解 v7.0.0 一致 | v7.0.0 |
| `.github/workflows/mara-review.yml` | 219 | `actions/upload-artifact@043fb46d1a93…` | pin 與註解 v7.0.1 一致 | v7.0.1 |
| `.github/workflows/mara-review.yml` | 233 | `actions/checkout@3d3c42e5aac5…` | pin 與註解 v7.0.1 一致 | v7.0.1 |
| `.github/workflows/mara-review.yml` | 236 | `actions/setup-python@5fda3b95a4ea…` | pin 與註解 v7.0.0 一致 | v7.0.0 |
| `.github/workflows/mara-review.yml` | 258 | `actions/upload-artifact@043fb46d1a93…` | pin 與註解 v7.0.1 一致 | v7.0.1 |
| `.github/workflows/scorecard.yml` | 35 | `actions/checkout@3d3c42e5aac5…` | pin 與註解 v7.0.1 一致 | v7.0.1 |
| `.github/workflows/scorecard.yml` | 38 | `actions/setup-python@5fda3b95a4ea…` | pin 與註解 v7.0.0 一致 | v7.0.0 |
| `.github/workflows/scorecard.yml` | 54 | `actions/upload-artifact@043fb46d1a93…` | pin 與註解 v7.0.1 一致 | v7.0.1 |
| `.github/workflows/scorecard.yml` | 62 | `github/codeql-action/upload-sarif@1c5b675653bb…` | pin 與註解 v4.38.1 一致 | v4.38.2 |

## 4. zizmor 結果（SARIF）

<details><summary><code>calib/samples/s3-django-orders/.github/workflows/ci.yml</code> — exit 0，6 個 finding</summary>

```json
{
 "$schema": "https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/schemas/sarif-schema-2.1.0.json",
 "runs": [
  {
   "invocations": [
    {
     "executionSuccessful": true
    }
   ],
   "results": [
    {
     "codeFlows": [
      {
       "threadFlows": [
        {
         "locations": [
          {
           "importance": "essential",
           "location": {
            "logicalLocations": [
             {
              "properties": {
               "symbolic": {
                "annotation": "does not set persist-credentials: false",
                "feature_kind": "Normal",
                "key": {
                 "Local": {
                  "verbatim_path": "/home/jungle/Documents/Github_local/MultiAgentAlpha/calib/samples/s3-django-orders/.github/workflows/ci.yml"
                 }
                },
                "kind": "Primary",
                "route": {
                 "route": [
                  {
                   "Key": "jobs"
                  },
                  {
                   "Key": "test"
                  },
                  {
                   "Key": "steps"
                  },
                  {
                   "Index": 0
                  }
                 ]
                }
               }
              }
             }
            ],
            "message": {
             "text": "does not set persist-credentials: false"
            },
            "physicalLocation": {
             "artifactLocation": {
              "uri": "calib/samples/s3-django-orders/.github/workflows/ci.yml"
             },
             "region": {
              "endColumn": 57,
              "endLine": 11,
              "snippet": {
               "text": "uses: actions/checkout@v4\n        with:\n          ref: ${{ github.event.pull_request.head.ref }}"
              },
              "sourceLanguage": "yaml",
              "startColumn": 9,
              "startLine": 9
             }
            }
           }
          }
         ]
        }
       ]
      }
     ],
     "kind": "fail",
     "level": "warning",
     "locations": [
      {
       "logicalLocations": [
        {
         "properties": {
          "symbolic": {
           "annotation": "does not set persist-credentials: false",
           "feature_kind": "Normal",
           "key": {
            "Local": {
             "verbatim_path": "/home/jungle/Documents/Github_local/MultiAgentAlpha/calib/samples/s3-django-orders/.github/workflows/ci.yml"
            }
           },
           "kind": "Primary",
           "route": {
            "route": [
             {
              "Key": "jobs"
             },
             {
              "Key": "test"
             },
             {
              "Key": "steps"
             },
             {
              "Index": 0
             }
            ]
           }
          }
         }
        }
       ],
       "message": {
        "text": "does not set persist-credentials: false"
       },
       "physicalLocation": {
        "artifactLocation": {
         "uri": "calib/samples/s3-django-orders/.github/workflows/ci.yml"
        },
        "region": {
         "endColumn": 57,
         "endLine": 11,
         "snippet": {
          "text": "uses: actions/checkout@v4\n        with:\n          ref: ${{ github.event.pull_request.head.ref }}"
         },
         "sourceLanguage": "yaml",
         "startColumn": 9,
         "startLine": 9
        }
       }
      }
     ],
     "message": {
      "text": "credential persistence through GitHub Actions artifacts: does not set persist-credentials: false"
     },
     "properties": {
      "zizmor/confidence": "Low",
      "zizmor/persona": "Regular",
      "zizmor/severity": "Medium"
     },
     "ruleId": "zizmor/artipacked"
    },
    {
     "codeFlows": [
      {
       "threadFlows": [
        {
         "locations": [
          {
           "importance": "essential",
           "location": {
            "logicalLocations": [
             {
              "properties": {
               "symbolic": {
                "annotation": "pull_request_target is almost always used insecurely",
                "feature_kind": "Normal",
                "key": {
                 "Local": {
                  "verbatim_path": "/home/jungle/Documents/Github_local/MultiAgentAlpha/calib/samples/s3-django-orders/.github/workflows/ci.yml"
                 }
                },
                "kind": "Primary",
                "route": {
                 "route": [
                  {
                   "Key": "on"
                  }
                 ]
                }
               }
              }
             }
            ],
            "message": {
             "text": "pull_request_target is almost always used insecurely"
            },
            "physicalLocation": {
             "artifactLocation": {
              "uri": "calib/samples/s3-django-orders/.github/workflows/ci.yml"
             },
             "region": {
              "endColumn": 23,
              "endLine": 3,
              "snippet": {
               "text": "on:\n  pull_request_target:"
              },
              "sourceLanguage": "yaml",
              "startColumn": 1,
              "startLine": 2
             }
            }
           }
          }
         ]
        }
       ]
      }
     ],
     "kind": "fail",
     "level": "error",
     "locations": [
      {
       "logicalLocations": [
        {
         "properties": {
          "symbolic": {
           "annotation": "pull_request_target is almost always used insecurely",
           "feature_kind": "Normal",
           "key": {
            "Local": {
             "verbatim_path": "/home/jungle/Documents/Github_local/MultiAgentAlpha/calib/samples/s3-django-orders/.github/workflows/ci.yml"
            }
           },
           "kind": "Primary",
           "route": {
            "route": [
             {
              "Key": "on"
             }
            ]
           }
          }
   
```

</details>

<details><summary><code>fixtures/vuln-sample/.github/workflows/deploy.yml</code> — exit 0，5 個 finding</summary>

```json
{
 "$schema": "https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/schemas/sarif-schema-2.1.0.json",
 "runs": [
  {
   "invocations": [
    {
     "executionSuccessful": true
    }
   ],
   "results": [
    {
     "codeFlows": [
      {
       "threadFlows": [
        {
         "locations": [
          {
           "importance": "essential",
           "location": {
            "logicalLocations": [
             {
              "properties": {
               "symbolic": {
                "annotation": "does not set persist-credentials: false",
                "feature_kind": "Normal",
                "key": {
                 "Local": {
                  "verbatim_path": "/home/jungle/Documents/Github_local/MultiAgentAlpha/fixtures/vuln-sample/.github/workflows/deploy.yml"
                 }
                },
                "kind": "Primary",
                "route": {
                 "route": [
                  {
                   "Key": "jobs"
                  },
                  {
                   "Key": "build"
                  },
                  {
                   "Key": "steps"
                  },
                  {
                   "Index": 0
                  }
                 ]
                }
               }
              }
             }
            ],
            "message": {
             "text": "does not set persist-credentials: false"
            },
            "physicalLocation": {
             "artifactLocation": {
              "uri": "fixtures/vuln-sample/.github/workflows/deploy.yml"
             },
             "region": {
              "endColumn": 57,
              "endLine": 12,
              "snippet": {
               "text": "uses: actions/checkout@v4\n        with:\n          ref: ${{ github.event.pull_request.head.sha }}"
              },
              "sourceLanguage": "yaml",
              "startColumn": 9,
              "startLine": 10
             }
            }
           }
          }
         ]
        }
       ]
      }
     ],
     "kind": "fail",
     "level": "warning",
     "locations": [
      {
       "logicalLocations": [
        {
         "properties": {
          "symbolic": {
           "annotation": "does not set persist-credentials: false",
           "feature_kind": "Normal",
           "key": {
            "Local": {
             "verbatim_path": "/home/jungle/Documents/Github_local/MultiAgentAlpha/fixtures/vuln-sample/.github/workflows/deploy.yml"
            }
           },
           "kind": "Primary",
           "route": {
            "route": [
             {
              "Key": "jobs"
             },
             {
              "Key": "build"
             },
             {
              "Key": "steps"
             },
             {
              "Index": 0
             }
            ]
           }
          }
         }
        }
       ],
       "message": {
        "text": "does not set persist-credentials: false"
       },
       "physicalLocation": {
        "artifactLocation": {
         "uri": "fixtures/vuln-sample/.github/workflows/deploy.yml"
        },
        "region": {
         "endColumn": 57,
         "endLine": 12,
         "snippet": {
          "text": "uses: actions/checkout@v4\n        with:\n          ref: ${{ github.event.pull_request.head.sha }}"
         },
         "sourceLanguage": "yaml",
         "startColumn": 9,
         "startLine": 10
        }
       }
      }
     ],
     "message": {
      "text": "credential persistence through GitHub Actions artifacts: does not set persist-credentials: false"
     },
     "properties": {
      "zizmor/confidence": "Low",
      "zizmor/persona": "Regular",
      "zizmor/severity": "Medium"
     },
     "ruleId": "zizmor/artipacked"
    },
    {
     "codeFlows": [
      {
       "threadFlows": [
        {
         "locations": [
          {
           "importance": "essential",
           "location": {
            "logicalLocations": [
             {
              "properties": {
               "symbolic": {
                "annotation": "pull_request_target is almost always used insecurely",
                "feature_kind": "Normal",
                "key": {
                 "Local": {
                  "verbatim_path": "/home/jungle/Documents/Github_local/MultiAgentAlpha/fixtures/vuln-sample/.github/workflows/deploy.yml"
                 }
                },
                "kind": "Primary",
                "route": {
                 "route": [
                  {
                   "Key": "on"
                  }
                 ]
                }
               }
              }
             }
            ],
            "message": {
             "text": "pull_request_target is almost always used insecurely"
            },
            "physicalLocation": {
             "artifactLocation": {
              "uri": "fixtures/vuln-sample/.github/workflows/deploy.yml"
             },
             "region": {
              "endColumn": 33,
              "endLine": 4,
              "snippet": {
               "text": "on:\n  pull_request_target:\n    types: [opened, synchronize]"
              },
              "sourceLanguage": "yaml",
              "startColumn": 1,
              "startLine": 2
             }
            }
           }
          }
         ]
        }
       ]
      }
     ],
     "kind": "fail",
     "level": "error",
     "locations": [
      {
       "logicalLocations": [
        {
         "properties": {
          "symbolic": {
           "annotation": "pull_request_target is almost always used insecurely",
           "feature_kind": "Normal",
           "key": {
            "Local": {
             "verbatim_path": "/home/jungle/Documents/Github_local/MultiAgentAlpha/fixtures/vuln-sample/.github/workflows/deploy.yml"
            }
           },
           "kind": "Primary",
           "route": {
            "route": [
             {
              "Key": "on"
             }
            ]
           }
          }
       
```

</details>

<details><summary><code>.github/workflows/docs-check.yml</code> — exit 0，0 個 finding</summary>

```json
{
 "$schema": "https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/schemas/sarif-schema-2.1.0.json",
 "runs": [
  {
   "invocations": [
    {
     "executionSuccessful": true
    }
   ],
   "results": [],
   "tool": {
    "driver": {
     "downloadUri": "https://github.com/zizmorcore/zizmor",
     "informationUri": "https://docs.zizmor.sh",
     "name": "zizmor",
     "semanticVersion": "1.30.1",
     "version": "1.30.1"
    }
   }
  }
 ],
 "version": "2.1.0"
}
```

</details>

<details><summary><code>.github/workflows/governance.yml</code> — exit 0，0 個 finding</summary>

```json
{
 "$schema": "https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/schemas/sarif-schema-2.1.0.json",
 "runs": [
  {
   "invocations": [
    {
     "executionSuccessful": true
    }
   ],
   "results": [],
   "tool": {
    "driver": {
     "downloadUri": "https://github.com/zizmorcore/zizmor",
     "informationUri": "https://docs.zizmor.sh",
     "name": "zizmor",
     "semanticVersion": "1.30.1",
     "version": "1.30.1"
    }
   }
  }
 ],
 "version": "2.1.0"
}
```

</details>

<details><summary><code>.github/workflows/mara-review.yml</code> — exit 0，0 個 finding</summary>

```json
{
 "$schema": "https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/schemas/sarif-schema-2.1.0.json",
 "runs": [
  {
   "invocations": [
    {
     "executionSuccessful": true
    }
   ],
   "results": [],
   "tool": {
    "driver": {
     "downloadUri": "https://github.com/zizmorcore/zizmor",
     "informationUri": "https://docs.zizmor.sh",
     "name": "zizmor",
     "semanticVersion": "1.30.1",
     "version": "1.30.1"
    }
   }
  }
 ],
 "version": "2.1.0"
}
```

</details>

<details><summary><code>.github/workflows/scorecard.yml</code> — exit 0，0 個 finding</summary>

```json
{
 "$schema": "https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/schemas/sarif-schema-2.1.0.json",
 "runs": [
  {
   "invocations": [
    {
     "executionSuccessful": true
    }
   ],
   "results": [],
   "tool": {
    "driver": {
     "downloadUri": "https://github.com/zizmorcore/zizmor",
     "informationUri": "https://docs.zizmor.sh",
     "name": "zizmor",
     "semanticVersion": "1.30.1",
     "version": "1.30.1"
    }
   }
  }
 ],
 "version": "2.1.0"
}
```

</details>

## 5. 驗收自檢

- 每個 workflow 都有一列：6 個檔案、6 列。
- 每個非 SHA 引用都有建議 SHA：2 / 4（未解析者為不存在的 fixture action）。
- Critical 項目在表格最上方：是。


## 6. 人工補充：與 2026-09-12 版的差異，以及靜態盤點看不出的事

第 0 到 5 節是 main 867e518（2026-09-26）上重新產生的結果；zizmor 為 `tools/versions.lock` 內驗過 attestation 的 1.30.1，本地以 `--offline` 執行。

| # | 觀察 | 嚴重度 | 依據 | 處置 |
|---|---|---|---|---|
| 6.1 | **實際 CI 由 3 個 workflow 增為 4 個**：新增 `docs-check.yml`（2026-09-21，PR 上重建報告、字數與引用檢查，`contents: read`）。`gitleaks/gitleaks-action` 與 `zizmorcore/zizmor-action` 已由 `scripts/gitleaks_ci.py`、`scripts/zizmor_ci.py` 執行 lock 內的二進位取代（2026-09-12 版 6.1b、6.4d），本次盤點中已無這兩個 action。`github/codeql-action/upload-sarif` 由 Dependabot 升到 v4.38.1（PR #34）。四個實際 workflow 的 `uses:` 全為 SHA 且與 tag 註解一致，`run:` 無內插，zizmor 0 finding，評為 None。 | None | 本檔第 1 到 4 節 | 不需修正 |
| 6.2 | **更正 2026-09-12 版 6.5 的「模型 job 不執行 repo 程式」。** 第二個 job（`tests + mock review`）以 `contents: read`、無 secret 的方式安裝並執行本 repo 的程式（pytest、對 seeded fixture 以 mock 家族與預錄 SARIF 跑 `mara review`），不呼叫模型；workflow 檔頭的同一句註解，以及「除非設定 `MARA_LIVE=1`」的說法（程式與 workflow 都沒有這個開關）也不正確。報告第 14.1 節有同樣的描述。 | Low（文件與事實不符，非弱點：`pull_request` 觸發、只讀 token） | `.github/workflows/mara-review.yml` 的 `tests-and-mock-review` job | 同一 PR 更正 workflow 檔頭註解與 `docs/parts/05_workflow.md` 第 14.1 節 |
| 6.3 | **push 到 main 的排隊 run 可能被取代。** `concurrency` 在 push 時 `cancel-in-progress: false`，但 GitHub 每個 group 只保留一個 pending run：一個 run 進行中時接連合併三個 PR，中間那個的 pending run 會被後一個取代，其 human-queue job 不會執行，gitleaks 的 push 範圍（`github.event.before..github.sha`）也跳過它。影響有限：main 只經 PR 合併（必要 checks 為 strict），被跳過的 commit 已由該 PR 的 gitleaks 掃過；human-queue 每次都重跑整份 fixture，下一個 run 以相同的 `file:line:cwe` key 補上。 | Low | `.github/workflows/mara-review.yml` 的 `concurrency:` | 更正同處註解（原寫「never skipped」）；不改行為 |
| 6.4 | **repo 私有期間，Scorecard 與 Code Scanning 上傳一律 skipped，skipped 視同通過。** `scorecard.yml` 自 2026-09-23 起每次 push 皆 skipped（run 35891099172、35938423654、35944036844、36251401913），`tools/scorecard-policy.yaml` 的六個強制項目前沒有被檢查；Dangerous-Workflow 與 Token-Permissions 由 CI 內的 zizmor（`dangerous-triggers`、`template-injection`、`excessive-permissions`，任何 finding 即失敗）部分補位；Pinned-Dependencies 在 workflow 的部分由 zizmor 的 `unpinned-uses`、治理檢查 G-6 與 `tests/test_relock_requirements.py`（每個 `pip install` 必須帶 `--require-hashes`）補位；Security-Policy 與 Dependency-Update-Tool 沒有替代檢查。 | Medium（控制暫停，非弱點） | `gh run list --workflow scorecard.yml`；README「Code Scanning and Scorecard」 | 未修正：可改用 `scorecard --local .`（不需 GraphQL）在私有期間跑 file-based checks，另開 PR。**2026-09-27 更新：已由 `scorecard.yml` 的 `scorecard-local` job 修正**（`scorecard_ci.py --local .`，`contents: read`，六個強制項照常把關；見 `docs/tools-provenance.md` 3d） |
| 6.5 | **PR 可修改判定它自己的規則。** `tools/semgrep-triage.yaml`、`tools/trivyignore.yaml`、`tools/osv-*.toml` 與 `scripts/*_ci.py` 都在同一個 PR 的 checkout 內讀取；repo 沒有 `CODEOWNERS`，也不要求 PR 核准（F09，單人維護的接受風險）。 | Low（單人維護下無外部 PR 作者） | `docs/security-remediation-2026-09-18.md` F09 | 未修正：有第二位維護者時加 `.github/CODEOWNERS` 覆蓋 `tools/`、`scripts/*_ci.py`、`.github/` 並要求 code owner 核准。**2026-09-27 更新：已新增 `.github/CODEOWNERS`**（上述路徑加 `config/`、`src/mara/policy.py`、`src/mara/config.py`、安裝與 code scanning 腳本、`SECURITY.md`，`tests/test_codeowners.py` 把關）；code owner 核准仍未要求（F09），有第二位維護者時再開啟 |

一句話結論：**四個實際 workflow 仍無 pwn request、注入或未固定 SHA 的問題；需要注意的是 repo 私有期間 Scorecard 強制項完全暫停，以及 2026-09-12 版對第二個 job「不執行 repo 程式」的描述不正確（已更正）。**
