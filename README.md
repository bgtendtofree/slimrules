# slimrules

精簡、零依賴、可自動構建的 **Surge** 與 **Mihomo (Clash.Meta)** 雙端分流規則倉庫。

## 設計原則

- **源碼與產物分離**：`main` 分支只保留規則定義（`rules.json`）、本地補充（`custom/`）與零依賴 Python 構建腳本；GitHub Actions 每日自動編譯並推送到 `release` 分支。
- **Google 統一出口、`ai` 自動排除 Google**：`google` 包含完整 Google 生態（含 YouTube、Gemini、Google AI Studio、DeepMind、Antigravity）；構建時透過反向標籤前綴樹將 `google` 從 `ai` 中自動扣除，避免 Google AI 登入驗證與 API 跨節點跳變觸發 429 風控。
- **雙端最佳原生格式**：
  - **Surge**：域名全部輸出為不觸發 DNS 解析的 `DOMAIN-SET`（`surge/domainset/*.list`），IP 輸出為 `RULE-SET`（`surge/ip/*.list`）。
  - **Mihomo**：同時輸出純淨無註釋 `.txt` 與二進制編譯產物 **`.mrs`**（`mihomo/domain/*.mrs`、`mihomo/ip/*.mrs`），低記憶體佔用、高速匹配。
- **可重複確定性輸出**：產物不包含易變時間戳，僅在規則實質變更時才提交更新至 `release` 分支。

---

## 規則集一覽（依匹配順序排列）

| 順序 | 名稱 | 類型 | 建議策略 | 上游來源 | 說明 |
| :---: | :--- | :--- | :--- | :--- | :--- |
| 1 | `private` | `domain` | `DIRECT` | `MetaCubeX/meta-rules-dat` (`geosite/private`) + `custom/direct.txt` | 內網、本機保留域名與自訂直連域名 |
| 2 | `apple_intelligence` | `domain` | `US` / `AI` | `geosite/apple-intelligence` + `custom/apple_intelligence.txt` | Apple Intelligence 中繼與地區校驗域名（Surge 建議加 `extended-matching`） |
| 3 | `apple_cdn` | `domain` | `DIRECT` | `felixonmars/dnsmasq-china-list` (`apple.china.conf`) | 蘋果中國大陸 CDN（自動剔除 `.apps.apple.com` 與 `.push.apple.com`） |
| 4 | `google` | `domain` | `Google` | `geosite/google` + `geosite/google-deepmind` + `custom/google.txt` | Google 全生態（含 YouTube、Gemini、AI Studio、DeepMind 等） |
| 5 | `ai` | `domain` | `AI` | `geosite/category-ai-!cn` + `custom/ai.txt`（扣除 `google`） | 非 Google 系海外 AI（OpenAI、Claude、Perplexity、Grok、Cursor 等） |
| 6 | `cn` | `domain` | `DIRECT` | `geosite/cn` | 中國大陸常見域名 |
| 7 | `proxy` | `domain` | `Proxy` | `geosite/geolocation-!cn` + `custom/proxy.txt` | 常見海外域名（於域名層攔截，避免落到 `cn_ip` 觸發 DNS 污染） |
| 8 | `private_ip` | `ip` | `DIRECT` | `geoip/private` | 私有 / 保留網段（Surge 帶 `no-resolve`；Surge 亦可改用內建 `LAN`） |
| 9 | `telegram_ip` | `ip` | `Proxy` | `https://core.telegram.org/resources/cidr.txt` | Telegram 官方 IP 段（Surge 帶 `no-resolve`） |
| 10 | `ai_ip` | `ip` | `AI` | `https://openai.com/chatgpt-voice.json` + `custom/ai_ip.txt` | ChatGPT Voice 官方即時語音 IP 段（Surge 帶 `no-resolve`） |
| 11 | `cn_ip` | `ip` | `DIRECT` | `misakaio/chnroutes2` + `gaoyifan/china-operator-ip` | 中國大陸 IPv4 + IPv6 段（**不帶 `no-resolve`**，負責兜底未收錄的國內網站） |

> **關鍵規則紀律**：所有域名規則（`domainset` / `domain`）**必須**放在全部 `ip` 規則之前；`google` 必須放在 `ai` 之前。

---

## 快速配置範例

直接複製以下規則訂閱配置（若需在國內加速，可自行在 URL 前套用反代或鏡像）：

### Surge

```ini
[Rule]
# 1. 純域名層（不觸發 DNS）
DOMAIN-SET,https://raw.githubusercontent.com/bgtendtofree/slimrules/release/surge/domainset/private.list,DIRECT
DOMAIN-SET,https://raw.githubusercontent.com/bgtendtofree/slimrules/release/surge/domainset/apple_intelligence.list,US,extended-matching
DOMAIN-SET,https://raw.githubusercontent.com/bgtendtofree/slimrules/release/surge/domainset/apple_cdn.list,DIRECT
DOMAIN-SET,https://raw.githubusercontent.com/bgtendtofree/slimrules/release/surge/domainset/google.list,Google
DOMAIN-SET,https://raw.githubusercontent.com/bgtendtofree/slimrules/release/surge/domainset/ai.list,AI
DOMAIN-SET,https://raw.githubusercontent.com/bgtendtofree/slimrules/release/surge/domainset/cn.list,DIRECT
DOMAIN-SET,https://raw.githubusercontent.com/bgtendtofree/slimrules/release/surge/domainset/proxy.list,Proxy

# 2. IP 層（置於全部域名規則之後）
RULE-SET,LAN,DIRECT
RULE-SET,https://raw.githubusercontent.com/bgtendtofree/slimrules/release/surge/ip/telegram_ip.list,Proxy
RULE-SET,https://raw.githubusercontent.com/bgtendtofree/slimrules/release/surge/ip/ai_ip.list,AI
RULE-SET,https://raw.githubusercontent.com/bgtendtofree/slimrules/release/surge/ip/cn_ip.list,DIRECT

# 3. 兜底
FINAL,Proxy,dns-failed
```

### Mihomo（推薦 `.mrs` 格式）

```yaml
rule-providers:
  private:
    type: http
    behavior: domain
    format: mrs
    interval: 43200
    url: https://raw.githubusercontent.com/bgtendtofree/slimrules/release/mihomo/domain/private.mrs
    path: ./slimrules/private.mrs
  apple_intelligence:
    type: http
    behavior: domain
    format: mrs
    interval: 43200
    url: https://raw.githubusercontent.com/bgtendtofree/slimrules/release/mihomo/domain/apple_intelligence.mrs
    path: ./slimrules/apple_intelligence.mrs
  apple_cdn:
    type: http
    behavior: domain
    format: mrs
    interval: 43200
    url: https://raw.githubusercontent.com/bgtendtofree/slimrules/release/mihomo/domain/apple_cdn.mrs
    path: ./slimrules/apple_cdn.mrs
  google:
    type: http
    behavior: domain
    format: mrs
    interval: 43200
    url: https://raw.githubusercontent.com/bgtendtofree/slimrules/release/mihomo/domain/google.mrs
    path: ./slimrules/google.mrs
  ai:
    type: http
    behavior: domain
    format: mrs
    interval: 43200
    url: https://raw.githubusercontent.com/bgtendtofree/slimrules/release/mihomo/domain/ai.mrs
    path: ./slimrules/ai.mrs
  cn:
    type: http
    behavior: domain
    format: mrs
    interval: 43200
    url: https://raw.githubusercontent.com/bgtendtofree/slimrules/release/mihomo/domain/cn.mrs
    path: ./slimrules/cn.mrs
  proxy:
    type: http
    behavior: domain
    format: mrs
    interval: 43200
    url: https://raw.githubusercontent.com/bgtendtofree/slimrules/release/mihomo/domain/proxy.mrs
    path: ./slimrules/proxy.mrs
  private_ip:
    type: http
    behavior: ipcidr
    format: mrs
    interval: 43200
    url: https://raw.githubusercontent.com/bgtendtofree/slimrules/release/mihomo/ip/private_ip.mrs
    path: ./slimrules/private_ip.mrs
  telegram_ip:
    type: http
    behavior: ipcidr
    format: mrs
    interval: 43200
    url: https://raw.githubusercontent.com/bgtendtofree/slimrules/release/mihomo/ip/telegram_ip.mrs
    path: ./slimrules/telegram_ip.mrs
  ai_ip:
    type: http
    behavior: ipcidr
    format: mrs
    interval: 43200
    url: https://raw.githubusercontent.com/bgtendtofree/slimrules/release/mihomo/ip/ai_ip.mrs
    path: ./slimrules/ai_ip.mrs
  cn_ip:
    type: http
    behavior: ipcidr
    format: mrs
    interval: 43200
    url: https://raw.githubusercontent.com/bgtendtofree/slimrules/release/mihomo/ip/cn_ip.mrs
    path: ./slimrules/cn_ip.mrs

rules:
  # 1. 純域名層
  - RULE-SET,private,DIRECT
  - RULE-SET,apple_intelligence,US
  - RULE-SET,apple_cdn,DIRECT
  - RULE-SET,google,Google
  - RULE-SET,ai,AI
  - RULE-SET,cn,DIRECT
  - RULE-SET,proxy,Proxy

  # 2. IP 層
  - RULE-SET,private_ip,DIRECT,no-resolve
  - RULE-SET,telegram_ip,Proxy,no-resolve
  - RULE-SET,ai_ip,AI,no-resolve
  - RULE-SET,cn_ip,DIRECT

  # 3. 兜底
  - MATCH,Proxy
```

> 若在未支援 `.mrs` 的舊版客戶端使用，將 `format: mrs` 改為 `format: text`，並把 URL 副檔名由 `.mrs` 改為 `.txt` 即可。

---

## 自訂規則與本地構建

### 1. 修改自訂補充規則

直接編輯 [`custom/`](custom/) 目錄下的對應檔案（`#` 開頭為註釋）：

- `custom/direct.txt`：追加到 `private`（內網 NAS、PT 等）
- `custom/apple_intelligence.txt`：Apple Intelligence 中繼與地區校驗域名
- `custom/google.txt`：追加到 `google`，**並自動從 `ai` 中扣除**
- `custom/ai.txt`：追加到 `ai`
- `custom/ai_ip.txt`：追加到 `ai_ip`
- `custom/proxy.txt`：追加到 `proxy`

### 2. 本地測試與構建

僅需 **Python 3.9+**（無任何第三方依賴）：

```bash
# 執行單元測試
python3 -m unittest discover -s tests -v

# 拉取上游並構建至 dist/
python3 scripts/build.py --output dist

# 若本機裝有 mihomo，可一併編譯 .mrs
python3 scripts/build.py --output dist --mihomo-bin /path/to/mihomo
```

### 3. 上傳到 GitHub 自動發佈

1. 在 GitHub 建立新倉庫（例如 `slimrules`），將本倉庫 `main` 分支推送上去：
   ```bash
   git remote add origin https://github.com/bgtendtofree/slimrules.git
   git push -u origin main
   ```
2. `push` 後會自動觸發 `.github/workflows/build.yml`（需確保倉庫 Settings → Actions → General 中 Workflow permissions 允許 **Read and write permissions**，且 workflow 本身已宣告 `contents: write`）。
3. 執行完成後會自動建立並更新 `release` 分支，即可透過上方 Raw URL 訂閱使用；之後每天 UTC 04:17 / 16:17 會自動檢查上游並僅在有變更時更新。
