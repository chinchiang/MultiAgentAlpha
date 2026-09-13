# GitHub Actions 盤點（2026-09-12）

依附錄 E 的 prompt 5，對本 repo 內所有 `.github/workflows/*.yml` 做 pwn request 與 SHA pinning 盤點。**只讀不改。** 本檔第 0 到 5 節由 `scripts/actions_inventory.py` 產生，第 6 節為人工補充。

## 0. 範圍、方法與判定準則

- 掃描根目錄：`MultiAgentAlpha/`，遞迴尋找所有 `.github/workflows/*.yml|yaml`（排除 `.git`、`node_modules`、`out/`、`calib-out/`）。共 3 個 workflow。
- 每個檔案先以 `yaml.safe_load` 驗證；不合法 YAML 的檔案仍以逐行比對盤點並標記，因為 GitHub 會拒絕執行它、zizmor 與 actionlint 也解析不了，這本身就是要回報的事實。
- `uses:` 的引用種類：40 字元十六進位為 **sha**；`v` 或數字開頭為 **tag**；其餘為 **branch**；`./` 為 local、`docker://` 為 docker。
- `run:` 內插：列出所有 `${{ github.event.* }}`、`github.head_ref`、`github.ref`；其中符合 GitHub Security Lab「不可信輸入」清單（PR 標題／內文／head ref／head label、issue 標題／內文、comment/review 內文、commit message 與作者、`github.head_ref`）者標為攻擊者可控。
- 非 SHA 引用以 `git ls-remote https://github.com/<owner>/<repo>` 解析目前 tag（優先取 peeled `^{}`）或分支的完整 SHA。
- SHA 引用若附 `# vX.Y.Z` 註解，一併驗證該 tag 目前是否仍指向這個 SHA。
- zizmor：已執行（`--offline`，線上稽核如 impostor-commit 與 known-vulnerable-actions 未跑；與 CI 中 zizmor-action 未帶 token 時的行為一致）。actionlint、poutine：未執行（不在 PATH）。

**判定準則（報告第 10.7 節）。** pwn request（`pull_request_target` 加 checkout PR head）為 Critical 且 reachable；攻擊者可控 context 內插到 `run:`（標題注入等）同為 Critical；以 tag 或分支引用第三方 action 為 High 但 conditional；`write-all` 為 High；缺 `permissions:`、cache key 含不可信 ref、self-hosted runner 為 Medium；未設 `persist-credentials: false` 為 Low。workflow 的嚴重度取其最高項。

## 1. 總表（Critical 在最上方）

| 嚴重度 | workflow | 用途 | 觸發 | PRT | checkout PR head | 頂層 permissions | job permissions | uses（sha/tag/branch） | run 內插（可控） | cache key 含 ref | 合法 YAML |
|---|---|---|---|---|---|---|---|---|---|---|---|
| **Critical** | `calib/samples/s3-django-orders/.github/workflows/ci.yml` | fixture／校準樣本（刻意含缺陷，不會執行） | pull_request_target | 是 | 是（第 11 行） | `write-all` | （缺失） | 0/1/1 | 2（1） | 無 cache | 是 |
| **Critical** | `fixtures/vuln-sample/.github/workflows/deploy.yml` | fixture／校準樣本（刻意含缺陷，不會執行） | pull_request_target | 是 | 是（第 12 行） | `write-all` | （缺失） | 0/1/1 | 1（1） | 無 cache | 是 |
| **None** | `.github/workflows/mara-review.yml` | **實際 CI** | pull_request, push | 否 | 否 | `{}` | deterministic-tools: {contents: read, pull-requests: read}; tests-and-mock-review: {contents: read} | 6/0/0 | 0（0） | 無 cache | 是 |

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

### .github/workflows/mara-review.yml — None

**判定項目**

- 無

**`uses:` 引用**

| 行 | 引用 | 種類 | 註解 | 解析結果 |
|---|---|---|---|---|
| 28 | `actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683` | sha | v4.2.2 | pin 與註解 v4.2.2 一致 |
| 33 | `zizmorcore/zizmor-action@cc914d7f3750a2d13d75c7f184a1060aa0e9d482` | sha | v0.6.4 | pin 與註解 v0.6.4 一致 |
| 58 | `gitleaks/gitleaks-action@ff98106e4c7b2bc287b24eaf42907196329070c7` | sha | v2.3.9 | pin 與註解 v2.3.9 一致 |
| 71 | `actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683` | sha | v4.2.2 | pin 與註解 v4.2.2 一致 |
| 74 | `actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065` | sha | v5.6.0 | pin 與註解 v5.6.0 一致 |
| 87 | `actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02` | sha | v4.6.2 | pin 與註解 v4.6.2 一致 |

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
| `.github/workflows/mara-review.yml` | 28 | `actions/checkout@11bd71901bbe…` | pin 與註解 v4.2.2 一致 | v7.0.1 |
| `.github/workflows/mara-review.yml` | 33 | `zizmorcore/zizmor-action@cc914d7f3750…` | pin 與註解 v0.6.4 一致 | v0.6.4 |
| `.github/workflows/mara-review.yml` | 58 | `gitleaks/gitleaks-action@ff98106e4c7b…` | pin 與註解 v2.3.9 一致 | v3.0.0 |
| `.github/workflows/mara-review.yml` | 71 | `actions/checkout@11bd71901bbe…` | pin 與註解 v4.2.2 一致 | v7.0.1 |
| `.github/workflows/mara-review.yml` | 74 | `actions/setup-python@a26af69be951…` | pin 與註解 v5.6.0 一致 | v7.0.0 |
| `.github/workflows/mara-review.yml` | 87 | `actions/upload-artifact@ea165f8d65b6…` | pin 與註解 v4.6.2 一致 | v7.0.1 |

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
                  "verbatim_path": "/home/user/MultiAgentAlpha/calib/samples/s3-django-orders/.github/workflows/ci.yml"
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
             "verbatim_path": "/home/user/MultiAgentAlpha/calib/samples/s3-django-orders/.github/workflows/ci.yml"
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
                  "verbatim_path": "/home/user/MultiAgentAlpha/calib/samples/s3-django-orders/.github/workflows/ci.yml"
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
             "verbatim_path": "/home/user/MultiAgentAlpha/calib/samples/s3-django-orders/.github/workflows/ci.yml"
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
        "text": "pull_request_target is almost alway
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
                  "verbatim_path": "/home/user/MultiAgentAlpha/fixtures/vuln-sample/.github/workflows/deploy.yml"
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
             "verbatim_path": "/home/user/MultiAgentAlpha/fixtures/vuln-sample/.github/workflows/deploy.yml"
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
                  "verbatim_path": "/home/user/MultiAgentAlpha/fixtures/vuln-sample/.github/workflows/deploy.yml"
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
             "verbatim_path": "/home/user/MultiAgentAlpha/fixtures/vuln-sample/.github/workflows/deploy.yml"
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
        "text": "pull_request_target is almost always us
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

## 5. 驗收自檢

- 每個 workflow 都有一列：3 個檔案、3 列。
- 每個非 SHA 引用都有建議 SHA：2 / 4（未解析者為不存在的 fixture action）。
- Critical 項目在表格最上方：是。


## 6. 人工補充：CI 實際執行紀錄的觀察，與本次修正

以下來自 PR #4 的 `L0 deterministic tools` job 紀錄（run 34663680947，job 103471178529，2026-09-12 01:04 UTC），不是靜態盤點能看出的事。第 0 到 5 節是**修正後**重新產生的結果；修正前的差異在各列的「修正紀錄」欄。

| # | 觀察（修正前） | 嚴重度 | 依據 | 修正紀錄（與本盤點同一個 PR） |
|---|---|---|---|---|
| 6.1 | **gitleaks 從未在 PR 上跑過。** `gitleaks/gitleaks-action` 在每次 `pull_request` 事件都以 HTTP 403「Resource not accessible by integration」崩潰（它要呼叫 `GET /repos/…/pulls/4/commits`，需要 `pull-requests: read`，而 job 只給 `contents: read`；PR 範圍掃描 `base^..head` 還需要完整歷史）。`continue-on-error: true` 把崩潰蓋成綠燈，PR #1 到 #4 皆如此。 | Medium（L0 覆蓋失效，非 workflow 弱點） | job 紀錄 `RequestError [HttpError]: Resource not accessible by integration … 'x-accepted-github-permissions': 'pull_requests=read'`；gitleaks-action 原始碼 `src/gitleaks.js` 的 `--log-opts=--no-merges --first-parent base^..head` 與 README 的 `fetch-depth: 0` 要求 | `deterministic-tools` job 加 `pull-requests: read`、checkout 加 `fetch-depth: 0`、`GITLEAKS_ENABLE_COMMENTS: "false"`（留言需 write 權限），**移除 `continue-on-error`**：崩潰或發現洩漏都變紅。新增 `.gitleaks.toml`，把 `fixtures/` 與 `calib/samples/` 的 seeded secrets 列入 allowlist（它們由預錄 SARIF 路徑與 pipeline 測試驗證），其餘路徑以預設規則掃描 |
| 6.1b | **後續（2026-09-13）：gitleaks-action 已由 lock 內的 gitleaks CLI 取代。** `scripts/gitleaks_ci.py` 只從 `.mara-tools/bin` 取 8.30.1（版本必須等於 `tools/versions.lock`），PR 掃 `--no-merges --first-parent base..head`、push 掃 `base..head`，SARIF 上傳為 artifact；job 不再需要 `pull-requests: read` 與 `GITHUB_TOKEN`。 | 已修正 | `.github/workflows/mara-review.yml`、`scripts/gitleaks_ci.py` |
| 6.2 | **zizmor 從未審過 fixture workflow。** CI 紀錄與本地重跑一致：`failed to parse input: mapping values are not allowed in this context at line 14 column 31`（`fixtures/vuln-sample/.github/workflows/deploy.yml`）與 `line 12 column 69`（`calib/samples/s3-django-orders/.github/workflows/ci.yml`）。兩個 fixture 的 `run:` 值含未加引號的 `: `，不是合法 YAML，GitHub 本身也不會執行它們。舊 workflow 第 30 行的註解「the seeded fixture workflow is meant to trip zizmor」與事實不符；`fixtures/vuln-sample-sarif/zizmor.sarif` 是手寫的（`tool.version` 為 `0.0.0`），`github_actions` 面向在 mock 端到端中的 A 級佐證來自一份 zizmor 從未產生過的檔案。 | Medium（測試材料失效） | job 紀錄 `WARN collect_inputs … failed to parse input` 兩行 | 兩個 fixture 的 `run:` 改為 block scalar（`run: \|`），成為合法 YAML（行數 +1；`scripts/gen_calib_samples.py` 與 `scripts/gen_mock_fixtures.py` 重跑，標籤與 mock 回應的行號同步更新）。`fixtures/vuln-sample-sarif/zizmor.sarif` 改由 zizmor 1.30.1 實際產生（5 個 finding，見第 2 節與第 4 節）。CI 的 zizmor-action 改為只審 `.github/workflows`（`inputs:`）且任何 finding 即失敗；另加一步在 CI 內對 fixture 跑 zizmor 1.30.1，斷言 (ruleId, line) 集合與預錄檔一致，預錄檔不得再漂移。`pipeline.py::_tool_corroborates` 改為容許工具回報 git 根目錄相對路徑（zizmor 從 repo 內執行時回報 `fixtures/vuln-sample/.github/…`），並修掉一個既有 bug：原本以 `str.lstrip("./")` 去前綴，會把 `.github` 的點也吃掉，手寫 SARIF 之所以「能對上」只是雙方同樣被切壞。修正後 `github_actions` 面向四個 finding 皆由真實 zizmor 輸出佐證為 A 級（`tests/test_pipeline_mock.py::test_tool_corroboration_matches_git_root_relative_paths`） |
| 6.3 | **CI 中的 zizmor 帶了 token，線上稽核有跑。** 本檔第 4 節的本地重跑用 `--offline`（本環境無 token，`artipacked` 稽核向 GitHub 列 tag 時 401）；CI 的 zizmor-action 完整跑完 `mara-review.yml` 且無 finding，兩者結論一致。 | 無 | job 紀錄 `completed ./.github/workflows/mara-review.yml` | 不需修正 |
| 6.4 | **兩個 action 已收到 Node 20 棄用警告。** `actions/checkout@11bd719…（v4.2.2）` 與 `gitleaks/gitleaks-action@ff98106…（v2.3.9）` 被強制在 Node 24 上執行。第 3 節列出各 repo 目前最新 tag：checkout v7.0.1、setup-python v7.0.0、upload-artifact v7.0.1、gitleaks-action v3.0.0、zizmor-action v0.6.4（已最新）。 | Low | job 紀錄末段 `##[warning]Node.js 20 is deprecated …` | 未修正：升版需重新固定 SHA 並走變更管理（治理建議 G-5，prompt 7 的範圍）；zizmor auditor persona 另提醒缺 `concurrency:`（Low） |
| 6.5 | **`mara-review.yml` 本身的硬化項目經本次盤點與 zizmor 雙重確認。** 觸發只有 `pull_request` 與 `push: main`，無 `pull_request_target`；頂層 `permissions: {}`、兩個 job 各自最小權限；六個 `uses:` 全部固定到完整 SHA 且 tag 註解與目前 tag 指向一致；`run:` 無任何 `github.event.*` 內插；兩個 checkout 都設 `persist-credentials: false`；job 間以 `needs` 串接、模型 job 不執行 repo 程式。 | None | 本檔第 1 到 4 節 | 修正後重跑第 1 到 4 節仍為 None；新增的 fixture 檢查步驟只用 `run:` 內的固定字串，沒有內插 |

一句話結論：**真正會執行的 workflow 沒有 pwn request、注入或未固定 SHA 的問題；但修正前它的兩個 L0 步驟一個因權限不足崩潰、一個因 fixture 不是合法 YAML 而審不到目標，而 `continue-on-error` 讓這兩件事在四個 PR 裡都沒有被看見。** 修正後兩個步驟都必須真的通過才會綠燈。差距評估（`docs/assessment-2026-09-12.md`）第 2 題「CI 執行 secret scanner」在修正前實際只值 1 分；修正後維持 2 分（仍非阻擋式全面部署）。
