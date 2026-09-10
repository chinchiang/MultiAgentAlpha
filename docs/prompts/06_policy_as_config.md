# Prompt 6：把資料主權與家族多樣性規則寫成設定檔驗證

類別：控制項即程式碼

```
src/mara/config.py 已強制兩條規則：原始碼只送 on_prem 或 vendor_api_zdr 的模型；reviewer 與 judge 至少跨兩個家族。請擴充為以下政策，全部以 pydantic validator 實作並加測試：

1. 禁止名單：model 名稱含 "fable" 或 "mythos" 的 Anthropic 模型不得用於任何角色（Covered Models 不可 ZDR），除非設定檔明示 anthropic_covered_models_authorized: true 並附授權參考編號。
2. DeepSeek 家族的 provider 只能是 openai_compatible 且 base_url 必須是 RFC 1918 私有位址或 .internal 網域；任何指向 deepseek.com 的 base_url 一律拒絕。
3. judges 至少三個家族；reviewers 至少三個家族；若只有兩個，需明示 reduced_panel_reason 字串（例如「中國廠區境內管線」）。
4. gate.self_judge_discount 不得高於 0.5；gate.human_threshold_alpha 不得低於 0.3。
5. 新增 mara check-config 的輸出：列出每條政策的通過／失敗與理由。

產出物：修改後的 src/mara/config.py、tests/test_policy.py、更新的 README 段落。
驗收：pytest 全綠；用一個故意違規的 YAML 跑 mara check-config 會以非零結束碼列出所有違規。
```
