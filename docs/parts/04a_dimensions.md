# 第四部　核心功能與能力

## 第 10 章　十一個審查面向

每個面向的結構相同：對應的標準與 CWE、L0 的確定性工具、L2 agent 的職責、vibe-coded 程式碼的典型缺陷、以及判定準則。標準版本以本次查證為準；三個常見的錯誤先在此糾正，因為它們正是流暢的 LLM 會自信地重複的錯誤：ASVS 5.0（2025 年 5 月發布）沒有「V1 架構」章，架構要求在 V15，輸入驗證在 V2，編碼與注入防護在 V1，V5 是檔案處理而非輸入驗證【已證實（官方 CSV 直接讀取）｜C1.1、C9.3】；OWASP Top 10:2025 的十個類別依序是 A01 Broken Access Control、A02 Security Misconfiguration、A03 Software Supply Chain Failures、A04 Cryptographic Failures、A05 Injection、A06 Insecure Design、A07 Authentication Failures、A08 Software or Data Integrity Failures、A09 Security Logging and Alerting Failures、A10 Mishandling of Exceptional Conditions，許多部落格的順序是錯的【已證實（官方 repo 直接讀取）｜C2.1】；CISA 的 BOD 22-01 已被 2026 年 6 月 10 日的 BOD 26-04 取代【已證實｜C2.8】。雛型把這些事實存成 pinned JSON，finding 引用的 ID 必須存在於其中。

### 10.1 Application architecture

**標準。** ASVS 5.0 V15 Secure Coding and Architecture，尤其 V15.2.1（元件未逾越更新與修補時限）、V15.2.3（正式環境不含測試碼、範例片段與開發功能）、V15.2.4（第三方元件與其傳遞依賴來自預期的倉庫，無 dependency confusion 風險）【已證實｜C1.2】；OWASP A06:2025 Insecure Design；OWASP SAMM 2.0 的 Design 業務功能作為成熟度尺【已證實｜C1.3】；NIST SP 800-160 Vol. 1 Rev. 1 提供把安全視為系統湧現性質的工程語彙【已證實｜C1.4】；Threat Modeling Manifesto 的四個價值作為反清單式的護欄【已證實｜C1.5】；C4 model 作為固定的抽象階梯，讓不同產品的架構審查產出可比較【已證實（日期不可驗證）｜C1.10】。

**工具。** 沒有確定性工具能直接審架構；OWASP Threat Dragon 的 JSON 威脅模型格式與 CycloneDX 威脅模型 BOM 是可供 agent 讀寫的機器可讀產物【已證實｜C1.6】。因此本面向的 finding 最高只能到 B 級，除非它同時被其他面向的工具佐證。

**Agent 職責。** 從 L1 的入口點與信任邊界出發，找：不可信輸入與特權操作之間缺少信任邊界；假設用戶端會強制執行的業務邏輯；權限超過需要的元件；正式環境可達的測試、範例與除錯功能；未固定或來自非預期倉庫的依賴；以及 vibe-coded 程式碼特有的「佔位式邏輯」（TODO auth、永遠回傳 True 的權限檢查、硬編碼的租戶 ID）【第三方評論｜A136】。每個 finding 必須在可達性論證中說明違反的是哪一條設計原則（最小權限、完全仲裁、失效安全預設、關注點分離）。

**判定準則。** 「以用戶端可控的標頭決定授權」是 High；「TODO 標記的未完成安全控制在可達路徑上」依路徑是 Medium 或 High；「除錯功能可達」依是否綁定公開介面判定。

### 10.2 Security vulnerabilities（一般弱點）

**標準。** 2025 年 CWE Top 25（CISA 於 2025 年 12 月 11 日發布，資料窗為 2024 年 6 月至 2025 年 6 月、逾 39,000 個 CVE；前四名為 CWE-79 XSS、CWE-89 SQL injection、CWE-352 CSRF、CWE-862 Missing Authorization）【已證實（頁面被擋，依 CISA alert 摘要）｜C2.5】；OWASP Top 10:2025；CISA KEV 與 BOD 26-04【已證實｜C2.8】。NVD 自 2026 年 4 月 15 日起的 enrichment 政策變更意味著多數新 CVE 沒有官方 CVSS 分數，系統必須能從 CNA 向量自算或優雅降級【已證實｜C2.7】。

**工具。** semgrep（含 `--config auto` 的社群規則集）、CodeQL（若組織有授權）。Semgrep 另提供 MCP server，讓代理以 `security_check`、`semgrep_scan` 等工具直接呼叫確定性掃描【已證實｜A41】。

**Agent 職責。** 涵蓋其他專門面向不管的部分：SQL、NoSQL、命令與模板注入（CWE-89、78、94、1336）、路徑穿越（CWE-22）、SSRF（CWE-918）、CSRF（CWE-352）、不安全的反序列化（CWE-502）、弱密碼學（CWE-327、328、330）、競態（CWE-362）、不安全的檔案上傳（CWE-434）、open redirect（CWE-601）、IDOR（CWE-639）、無上限的資源配置（CWE-770）。XSS、CSP、認證授權、機密、依賴、workflow、輸入驗證與錯誤處理由其他 agent 負責，本面向只在問題橫跨多面向時報告。

**判定準則。** 字串串接的 SQL 且來源為請求參數是 Critical（CVSS 4.0 基礎向量 AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:L 算得 9.x）；open redirect 若需先通過登入且僅用於 phishing 是 Low，且依 Anthropic Action 的排除慣例【B84】通常不阻擋。

### 10.3 XSS

**標準。** CWE-79（2025 年 CWE Top 25 第一名）；OWASP XSS Prevention Cheat Sheet 的六種輸出情境（HTML body、HTML attribute、URL、JavaScript、CSS、DOM）與「CSP 是縱深防禦而非主要控制」的原則【已證實（直接讀取官方 repo）｜C3.1】；DOM based XSS Prevention Cheat Sheet【已證實｜C3.2】；W3C Trusted Types 於 2026 年 6 月 23 日發布的 Working Draft，透過 CSP 的 `require-trusted-types-for 'script'` 把 DOM XSS 從程式碼審查問題變成執行期強制的型別問題【已證實｜C3.3】。要注意 OWASP 的 cheat sheet 用的是情境表格而非編號規則，agent 不得幻覺出「Rule #3」之類的引用。

**工具。** semgrep 的 XSS 規則、CodeQL 的 taint tracking。

**Agent 職責。** 追蹤不可信資料到 sink（innerHTML、outerHTML、document.write、eval、字串形式的 setTimeout、location 指派、jQuery 的 .html()）且中間沒有情境適當的編碼或 DOMPurify 等消毒；檢查模板自動跳脫是否被關閉（`|safe`、`Markup()`、`autoescape False`、`dangerouslySetInnerHTML`、`v-html`、`[innerHTML]`）；記錄 Trusted Types 是否啟用，其缺席不是 finding 但降低可達性的門檻。

**判定準則。** 反射型 XSS 於公開端點是 Medium（AV:N/AC:L/AT:N/PR:N/UI:P/VC:L/VI:L 算得 5.3）；儲存型且影響管理介面升為 High。參考事件：CVE-2025-48700 是 Zimbra 的 XSS，CVSS 僅 6.1 卻因實際遭利用而進入 KEV【第三方評論（KEV 日期未直接驗證）｜C3.7】，說明 XSS 的分流不能只看 CVSS。

### 10.4 CSP

**標準。** W3C CSP Level 3 至今仍是 Working Draft，不是 Recommendation，只有 Level 2 是 REC【已證實｜C4.1、C4.2】，因此 agent 引用時必須寫「WD」；OWASP CSP Cheat Sheet 的規範政策是 `script-src 'nonce-{RANDOM}' 'strict-dynamic'; object-src 'none'; base-uri 'none'`，並警告 allowlist 式政策「很可能導致繞過」、`'unsafe-inline'` 與 `'unsafe-eval'` 會重新引入 CSP 要防的弱點、以及不要寫一個把所有 `<script>` 自動加上 nonce 的 middleware（攻擊者注入的腳本也會拿到 nonce）【已證實（直接讀取）｜C4.4】；ASVS 5.0 V3.4 Browser Security Mechanism Headers。

**工具。** Google csp-evaluator：其內建繞過清單源自 CCS 2016 的研究，該研究發現 15 個最常被允許的腳本網域中有 14 個含不安全端點、75.81% 使用腳本 allowlist 的政策可被繞過、94.68% 試圖限制腳本執行的政策無效，主要透過 JSONP 端點與 AngularJS gadget【第三方評論（同儕審查）｜C4.5、C4.6】。csp-evaluator 是本面向的確定性 oracle：agent 解釋，evaluator 決定。

**Agent 職責。** 報告：HTML 回應完全沒有 CSP；`script-src` 含 `'unsafe-inline'` 或 `'unsafe-eval'` 且無 nonce 或 hash；allowlist 含已知 JSONP 或 AngularJS 的 CDN；缺 `object-src 'none'`；缺 `base-uri`（允許 `<base>` 注入劫持相對路徑的腳本）；nonce 跨回應重用；middleware 自動加 nonce；有 DOM sink 卻無 Trusted Types 指令；只有 report-only 沒有強制。

**判定準則。** 「完全沒有 CSP」單獨只是 Low（它是縱深防禦的缺口，不是漏洞），但當同一個頁面同時有 DOM sink 或 `eval` 時，它把 XSS 面向的 finding 從 conditional 推向 reachable。

### 10.5 Authentication and authorization

**標準。** ASVS 5.0 V6 Authentication、V7 Session Management、V8 Authorization、V9 Self-contained Tokens、V10 OAuth and OIDC【已證實｜C5.1】；NIST SP 800-63-4 於 2025 年 7 月定稿，取代 800-63-3，以 Digital Identity Risk Management 取代清單式的 AAL，並納入抗釣魚 MFA 與 passkeys【已證實｜C5.2】；OAuth 2.1 至今仍是 Internet-Draft（draft-ietf-oauth-v2-1-15）而非 RFC，規範性引用應用 RFC 6749、6750 與 RFC 9700【已證實｜C5.3】；WebAuthn Level 3 於 2026 年 8 月 25 日成為 W3C Recommendation【已證實｜C5.4】；OWASP Authorization Cheat Sheet 的三條硬規則：預設拒絕、每個請求都在伺服器端驗證（「只驗大多數請求是不夠的」）、IDOR/BOLA 靠逐物件檢查而非隱藏 ID【已證實（直接讀取）｜C5.5】；OWASP API Security Top 10 2023 的 API1 BOLA、API3、API5 BFLA【已證實｜C5.7】。

**工具。** semgrep 的認證規則有限；本面向主要靠 L2 的語意推理與 L3 的否證。

**Agent 職責。** 報告：以請求中的 ID 讀寫資源卻無所有權檢查（CWE-639、862）；管理或功能層級的檢查缺失或做在用戶端（CWE-285）；預設允許的授權；密碼未以慢速加鹽雜湊儲存（CWE-916）；登入無暴力破解防護（CWE-307）；session token 可預測、登入不輪替、缺 Secure/HttpOnly/SameSite（CWE-384、614）；JWT 的 alg none、共用 HMAC 密鑰在程式碼中、不驗過期（CWE-347）；OAuth 無 PKCE 或 redirect URI 鬆散比對。

**判定準則。** BOLA 於需要任何有效帳號的端點是 High（PR:L）；session cookie 直接是使用者名稱是 High 且 reachable；密碼明文比對是 High 但 conditional（需先取得資料庫）。這個面向是 Apiiro 所稱「權限提升路徑上升」的主戰場【A140】，也是三家族分歧最常出現的地方，第 13 章的稽核指標對它特別重要。

### 10.6 Dependency and supply-chain security（依賴）

**標準。** OWASP A03:2025 Software Supply Chain Failures 對應 CWE-1104、1395、1329、447，其防護文字要求集中式 SBOM（含傳遞依賴）、監控 CVE/NVD/OSV、簽章套件與分階段推出【已證實（直接讀取）｜C2.3】；ASVS 5.0 V15.2；FIRST 的 EPSS v4（2025 年 3 月）估計 30 天內被利用的機率，只能作為「可能性」軸而非嚴重度【已證實（FIRST 公告頁未驗）｜C6.7】；CVSS 4.0（2023 年 11 月 1 日）與 CISA SSVC【已證實｜C6.8、C6.9】。

**工具。** OSV-Scanner v2（2025 年 3 月，支援容器分層掃描與引導式修補）【已證實｜C6.3】、Trivy、Grype（新版支援 CVSS v4 計算與 VEX 比對，可用於誤報抑制）【已證實｜C6.6】、Dependabot。OWASP Dependency-Check 以 CPE 比對 NVD，在 NVD 縮編後準確度下降，應與 OSV 類工具並用【已證實｜C6.1】。

**Agent 職責。** 只從 manifest 與 lockfile 推論，不得從記憶宣稱 CVE：報告缺 lockfile、安全敏感套件的浮動版本、從 URL、git ref 或非預設 registry 安裝（dependency confusion，CWE-427）、看起來像 typosquat 或幻覺的套件名稱（slopsquatting，第 2.3 節）、manifest 中的安裝腳本、由 manifest 本身可證明的廢棄套件。對具體版本只能寫「套件 X 版本 Y，需由掃描器確認」。

**判定準則。** 工具確認的 KEV 條目是 Act；EPSS 高但無 KEV 是 Attend；純 hygiene（未固定版本、無 lockfile）是 Low 且通常進入「不採納」。參考事件：xz-utils 後門 CVE-2024-3094（CVSS 10.0，tarball 與 git tree 不一致，build 腳本必須在審查範圍內）【已證實｜C6.11】；polyfill.io 2024 年 6 月影響逾十萬個網站，是第三方腳本即傳遞信任的教材【廠商主張｜C6.12】；Shai-Hulud npm 蠕蟲（CISA 2025 年 9 月 23 日 alert）從 CI/CD 環境變數與雲端 metadata 端點採集憑證並自我複製【已證實｜C6.13】；chalk/debug 等 18 個 npm 套件於 2025 年 9 月 8 日因維護者遭釣魚而被植入加密貨幣劫持程式【廠商主張｜C6.14】。

### 10.7 GitHub Actions security

**標準。** GitHub 官方的 Security hardening 文件：不得把不可信資料插入 `run:`、第三方 action 必須固定到完整的 commit SHA（「目前唯一把 action 當成不可變版本的方式」）、最小化 `permissions:`、以 OIDC 取代長效雲端憑證【已證實（頁面被擋）｜C7.1】；GitHub Security Lab 的 pwn request 定義（`pull_request_target` 加 checkout PR head）與可控 context 欄位清單（PR 標題、內文、分支名、作者、評論）【已證實｜C7.4、C7.5】；GitHub 於 2025 年 8 月 15 日推出組織層級的 SHA pinning 強制政策【已證實｜C7.8】；OpenSSF Scorecard 的 Dangerous-Workflow、Token-Permissions、Pinned-Dependencies 檢查【已證實｜C7.13】。

**工具。** zizmor（模板注入、憑證持久化、過度授權、impostor commit）、actionlint（語法與注入檢查）、poutine（跨 GitHub、GitLab、Azure DevOps、Tekton，支援自訂 Rego 規則，適合工具鏈異質的跨國組織）【已證實｜C7.9、C7.10、C7.11】；StepSecurity Harden-Runner 提供 runner 的出口網路監控與檔案完整性監控【廠商主張｜C7.12】。

**Agent 職責。** 報告：`pull_request_target` 加 checkout PR head；`${{ }}` 內插攻擊者可控的 context 到 `run:`；以標籤或分支而非 40 字元 SHA 引用第三方 action；缺失或 `write-all` 的 permissions；OIDC 可用卻用長效憑證；cache key 來自不可信 ref；公開倉庫用自架 runner；secrets 被 echo 或在步驟間傳遞；不可信 build 的 artifact 被信任地消費。

**判定準則。** pwn request 是 Critical 且 reachable（前置條件只是「能開一個 fork PR」）；標題注入同樣 Critical；未固定 SHA 是 High 但 conditional。參考事件：CVE-2025-30066 tj-actions/changed-files（CVSS 8.6、CWE-506、逾 23,000 個倉庫、入 KEV）【已證實｜C7.14】；其上游 reviewdog CVE-2025-30154 構成兩跳的 action 鏈【已證實｜C7.15】；Nx s1ngularity（2025 年 8 月 26 日）的根因正是 `pull_request_target` 加 PR 標題注入，導致 npm 發布 token 被竊【已證實（官方 post-mortem）｜C7.16】；Ultralytics（2024 年 12 月）透過 Actions cache poisoning 把挖礦程式塞進 PyPI 發布，證明 cache 是信任邊界【廠商主張｜C7.17】。

### 10.8 Secret exposure

**標準。** CWE-798 硬編碼憑證、CWE-312 明文儲存、CWE-532 敏感資訊進日誌；ASVS 5.0 V13.3 Secret Management；OWASP Secrets Management Cheat Sheet：CI/CD 工具視為正式環境、不讓 secret 穿過 pipeline 而由消費端自行取得、記錄所有存取、自動輪替（「人工維護不只增加外洩風險，也引入人為錯誤」）、IDE 與 CI 雙層偵測【已證實（直接讀取）｜C8.5】；GitHub 的 secret scanning 與 push protection 是本面向唯一「預防型」而非「偵測型」的控制【已證實｜C8.1】。

**工具。** gitleaks（離線、regex 與 Shannon entropy）、TruffleHog（800 個以上類型、700 個以上驗證器）、detect-secrets（baseline 模式適合當非回歸閘門）【已證實｜C8.2、C8.3、C8.4】。

**Agent 職責。** 報告原始碼、設定、測試、fixture、Dockerfile、CI 檔與 .env 中的 API key、token、密碼、私鑰、連線字串、雲端憑證與 webhook secret；符合已知供應商格式的高熵值（AKIA、ghp_、sk-、xoxb-、PRIVATE KEY）；寫進日誌或錯誤訊息的 secret；以命令列參數或 URL query 傳遞的 secret；未更換的預設憑證。Prompt 明文要求 agent 在引用時只保留 secret 的前後四個字元、中間以星號遮蔽，避免審查報告本身成為外洩管道。

**判定準則。** 任何看起來有效的雲端或 SCM 憑證都是 Critical；密碼進日誌是 High 但 conditional（需先取得日誌）。規模感：GitGuardian 宣稱 2025 年公開 GitHub 上新增 2,900 萬個硬編碼 secret（年增 34%），AI 服務相關的 secret 達 1,275,105 個（年增 81%），且 2022 年確認有效的 secret 有 64% 到 2026 年 1 月仍有效，受害系統中 59% 是 CI/CD runner【廠商主張｜C8.7】；Microsoft 的 38 TB 曝露事件（2023 年）源於一個範圍涵蓋整個儲存帳戶、具完全控制權且無到期的 SAS token【已證實（MSRC 官方）｜C8.8】。

### 10.9 Input validation

**標準。** OWASP Input Validation Cheat Sheet：allowlist 驗證適用於所有使用者輸入欄位、區分語法與語意驗證、必須在伺服器端且在任何處理之前、regex 要以 `^` 與 `$` 錨定完整輸入、檔案上傳要改名且不使用任何使用者可控文字【已證實（直接讀取）｜C9.1】；ASVS 5.0 V2.2 Input Validation 與 V1.2 Injection Prevention（不是 V5）【已證實｜C9.3】；CWE-20、89、78、918、22、94、502；OWASP LLM01:2025 把 prompt injection 定義為一種輸入驗證類別【已證實｜C9.6】；MITRE 於 2024 年新增的 CWE-1427（Improper Neutralization of Input Used for LLM Prompting）是目前最貼切的 CWE。

**工具。** semgrep 的 taint 規則；CodeQL。

**Agent 職責。** 報告：信任用戶端驗證的伺服器端 handler；缺乏型別、長度、範圍與格式的 allowlist 驗證；未錨定的 regex；保留用戶端檔名或信任用戶端 content-type 的上傳；無界限的數值 ID；直接綁定到模型的 JSON body（mass assignment，CWE-915）；未分離資料與指令就把不可信輸入拼進 LLM prompt；反序列化不可信輸入；未檢查路徑的壓縮檔解壓（zip slip）。輸出端的編碼問題歸 XSS 面向，純 sink 歸一般弱點面向，本面向只在根因是「缺少驗證層而影響多個 sink」時報告。

**判定準則。** 本面向的 finding 多為 Medium，其價值在於解釋其他面向 finding 的共同根因；但「README 或註解中針對自動審查者的指令」是本面向獨有的 finding，它同時是 prompt injection 的證據，也是 vibe-coded 程式碼的特徵。

### 10.10 Insecure error handling

**標準。** OWASP A10:2025 Mishandling of Exceptional Conditions 明列 24 個 CWE（209、215、234、235、248、252、274、280、369、390、391、394、396、397、460、476、478、484、550、636、703、754、755、756），是本面向的確定性範圍界定【已證實（直接讀取）｜C2.4】；A09:2025 從 2021 版的「Monitoring」改為「Alerting」，重點從記錄轉向告警【已證實｜C10.5】；OWASP Error Handling Cheat Sheet：非預期錯誤回傳泛用回應、細節記錄在伺服器端、API 錯誤用 RFC 7807 Problem Details、5xx 只給真正的伺服器錯誤【已證實（直接讀取）｜C10.1】；Logging Cheat Sheet 的必記與禁記清單（禁記密碼、session ID、token、加密金鑰、卡號、PII、連線字串、原始碼）與 CR/LF 清理（CWE-117）【已證實｜C10.2】；ASVS 5.0 V16.1.1（記錄清單文件）、V16.2.2（UTC 或明示時區）、V16.2.4（機器可關聯的共同格式）、V16.3.x（認證、授權與繞過嘗試都要記錄）【已證實（逐字讀取）｜C10.3】。

**工具。** semgrep 的 debug-enabled 與 traceback 規則。

**Agent 職責。** 報告：堆疊追蹤、SQL 錯誤、檔案路徑或框架除錯頁回傳給用戶端（DEBUG=True、app.run(debug=True)）；吞掉錯誤並在不安全狀態繼續的 catch-all（CWE-390、755）；錯誤時 fail-open（例如 try/except 內的授權檢查在例外時回傳 True）；密碼、token、PII、卡號進日誌（CWE-532）；未清理 CR/LF 的日誌注入（CWE-117）；登入失敗、存取拒絕、管理操作完全沒有記錄（CWE-778）；日誌缺時間戳、行為者與來源；錯誤訊息洩漏使用者名稱是否存在。

**判定準則。** Flask 的 `debug=True` 綁定 0.0.0.0 不只是資訊洩漏，Werkzeug 除錯器允許程式碼執行，是 High 且 conditional；回傳完整 traceback 是 Medium。

### 10.11 Supply-chain security（廣義）

**標準。** SLSA 目前是 v1.2（2025 年 11 月 24 日，新增 Source Track；v1.1 為 2025 年 4 月 21 日），Build L1 到 L3 仍是 ODM 的實務階梯【已證實｜C11.1】；CycloneDX 1.6 於 2024 年 6 月成為 ECMA-424 第一版，1.7（2025 年 10 月 21 日）成為 2025 年 12 月的第二版，支援 HBOM、CBOM、SaaSBOM 與 ML-BOM，這是 ODM/EMS 通常選 CycloneDX 而非 SPDX 的理由【已證實｜C11.2】；SPDX 3.0（2024 年 4 月 16 日）目前處於 ISO/IEC DIS 5962 階段，ISO/IEC 5962:2021 對應的是 SPDX 2.2.1，不得寫「SPDX 3.0 = ISO 5962」【已證實｜C11.3】；Sigstore cosign v3（2025 年 10 月 8 日）與 in-toto attestation v1【已證實｜C11.4、C11.5】；NIST SP 800-204D（2024 年 2 月）提供 CI/CD 供應鏈策略與 SSDF 實務的對應表【已證實｜C11.6】；NIST SP 800-218 SSDF v1.1 的 PO/PS/PW/RV 四組實務【已證實｜C11.7】；CISA Secure by Design 三原則與 2024 年 5 月的 Pledge【已證實｜C11.8】；EU CRA（Regulation (EU) 2024/2847）Annex I Part II (1) 要求以常用的機器可讀格式製作至少涵蓋頂層依賴的 SBOM，第 14 條對主動遭利用漏洞的 24 小時預警義務自 2026 年 9 月 11 日適用，其餘義務自 2027 年 12 月 11 日適用【已證實｜C11.9】；OpenSSF S2C2F v1.1 的八個實務領域（Ingest、Scan、Inventory、Update、Audit、Enforce、Rebuild、Fix+Upstream）與四個成熟度等級，是 OSS 消費側最乾淨的階梯【已證實（直接讀取）｜C11.10】。

**工具。** Scorecard（Signed-Releases、Pinned-Dependencies）、Trivy 的 misconfig 掃描（Dockerfile）、cosign verify、SBOM 產生器。

**Agent 職責。** 報告：build 或 deploy 腳本以 curl | sh 或下載未驗證的二進位（無 checksum 或簽章）；Dockerfile 用可變的基底標籤（latest）或未驗證的 URL ADD；build 中沒有任何 SBOM 產生；artifact 發布無 provenance attestation 或簽章；執行期從 CDN 載入第三方腳本卻無 Subresource Integrity（polyfill.io 模式，CWE-829）；無簽章檢查的自動更新；無記錄上游版本的 submodule 或 vendored code；lockfile 缺完整性雜湊。套件版本的 CVE 歸依賴面向。

**判定準則。** curl | sh 是 High 且 conditional（前置條件是攻擊者控制該網域或中間人）；latest 標籤是 Low。參考事件：SolarWinds SUNBURST（CISA ED 21-01，2020 年 12 月 13 日發布、2026 年 1 月 8 日結案；約 18,000 個客戶下載了受影響的版本）【已證實｜C11.11】；Codecov（2021 年 4 月）的根因是從 Codecov 自己發布的公開 Docker image 中抽出的 GCP 服務帳戶 HMAC 金鑰，且只因客戶比對 shasum 才被發現【已證實（官方 post-mortem）｜C11.12】；3CX（2023 年）是首個由供應鏈攻擊引發的供應鏈攻擊【廠商主張（Mandiant）｜C11.13】。

### 10.12 十一個面向的交叉關係

十一個面向不是互斥的分類，而是十一個「視角」。同一段程式碼在 fixture 中被三個面向同時報告是正常的：`static/index.html` 第 5 行從 CDN 載入 AngularJS，在 CSP 面向是 allowlist gadget，在供應鏈面向是缺 SRI 的第三方腳本，兩者的 CWE 都是 829 但面向不同，L5 不會把它們合併。這個設計是刻意的：每個面向的 prompt 都告訴 agent「其他面向由別的 agent 負責」，以減少重複，但不強制去重，因為不同視角的重複本身就是一種佐證。真正的去重發生在同一面向內：不同家族在同一檔案、±3 行、同一 CWE 的 finding 會合併，合併後的「發現者家族集合」是 B 級的依據。
