# LatencyDesk (`open_desk`)

> **安全 Alpha——尚未達到正式產品就緒。** 預設產品路徑現在使用 exact-leaf
> TLS 1.3 雙向驗證（mTLS）與 QUIC，但原生平台矩陣、codec、WAN 連線、復原、
> 打包及 App 層證據仍不完整。LatencyDesk 目前尚未達到或超越 AnyDesk、RustDesk。

LatencyDesk 是以 Rust 開發的遠端桌面專案，核心包含 fail-closed 對端身分、
有界佇列、可靠控制／輸入 lane，以及具期限概念的 QUIC media DATAGRAM。第一條
如實可描述的產品切面，是受信任低延遲 LAN 上的 Linux X11 Host 與 Windows
Client。

## 目前能力

| 項目 | 現行實作 | 狀態 |
| --- | --- | --- |
| 安全傳輸 | Quinn QUIC 上僅允許 TLS 1.3 的 mTLS；雙方 pin 並逐 byte 檢查預期 leaf certificate；不會自動降級 UDP | 預設產品路徑；in-process 測試通過 |
| 裝置身分 | `latencydesk-identity` 產生持久的 self-signed certificate DER 與 PKCS#8 private-key DER，且不覆寫現有身分 | 已實作；certificate 仍須手動交換 |
| 控制與輸入 | 已驗證的產品握手、帶 session stamp 的可靠 QUIC lane；input 優先權高於 control；Client／Host 會明確協商 capability，Linux opt-in probe 只在 XTEST 加後續 X11 sync reply 完成後取得完整 stamp ACK | 已有單 target 與同時多 target 的 application-ACK 程序證據；實體 input-to-photon 仍待完成 |
| 同時連線多台 Host | 可重複使用 `--target <ADDR>,<PEER_CERT>`，以 2–16 個隔離的安全 Client 子程序同時開啟多台 exact-pinned Host | 單機 2／4 target gate 每台保留 256 筆、8／16 target 每台保留 1024 筆互相重疊的 raw input-ACK 與精確 process-group／資源快照；壞 target 不會中止健康 target，Ctrl-C 會以有界 kill／reap 及 output-forwarder join 收尾；跨機器 soak 仍待完成 |
| Linux Host | 真實 X11 root 擷取、CPU BGRA-to-NV12 轉換，以及在獨立連線／task 中執行、不受擷取與軟體編碼阻塞的 XTEST 輸入 | 安全 Alpha 路徑；X11 到 headless 的 process loopback 已驗證，可見輸入延遲與跨機器呈現仍待完成 |
| Successor session | Linux X11 Host 可保留同一個 endpoint，依序接受 1–16 個 exact-pinned session；headless Client 支援 clean sequence，亦可對已驗證 QUIC reset／idle timeout 做有界恢復；每個 successor 都在 ReleaseAll 後取得新 identity 與嚴格遞增 epoch | Clean 與 loopback blackhole recovery 已實作；互動式 reconnect、Windows Host persistence、實體 handoff 與跨機器 soak 仍待完成 |
| Windows Client | 嚴格 raw-NV12 驗證、Direct3D 11 Viewer、有界 latest-frame 呈現及原生輸入轉送；`--frames` 可 headless 執行 | 安全 Alpha 路徑；Windows Viewer 跨機器 E2E 證據仍待完成 |
| 其他 Client | 已有可攜式軟體 Viewer（OpenH264／raw NV12 顯示與輸入轉送），並保留 headless 收幀及 input probe | Alpha 實作；跨機器與原生 UX 證據仍待完成 |
| Windows Host | 因真實 capture/input provider 尚未接線，安全 Host 會在開 socket 前拒絕執行 | 不支援 |
| 媒體 | raw NV12 分片後以 QUIC DATAGRAM 傳輸；沒有正式 H.264／AV1 encode/decode 路徑 | 僅適合低解析 LAN preview |
| WAN 連線 | Direct IP，並可為同一台 exact-pinned Host 競速最多 4 個已知位址；opt-in RFC 8489 Binding 會在之後交給 Quinn 的同一 UDP socket 發現一個 srflx 位址；診斷 probe 可在 exact-mTLS 與產品握手後交換有界 candidate advertisement | 已有 same-socket discovery 與 authenticated advertisement 證據；candidate 不會改變 active route。尚無 ICE check／nomination／consent、rendezvous、TURN／relay、自動 Internet traversal、互動式 recovery 或 QUIC path migration |
| 發行 | 沒有受支援的簽章安裝程式、更新器或正式服務 | 未實作 |
| 舊傳輸 | 明文自製 UDP，必須明確加入 `--unsafe-udp-lab` | 僅限本機相容性測試 |

Raw NV12 不能宣稱為 WAN 解法。以資料量估算，640×360、15 fps 在傳輸額外
成本前約為 41.5 Mbit/s；預設擷取上限 1280×720、60 fps 則約為 664 Mbit/s。
請在有線 LAN 上先使用下方低解析 preview 設定。

## 建置與限定範圍驗證

倉庫固定使用 Rust **1.88.0**。Windows 原生 C++ 檢查另需 Visual Studio 2022
Build Tools、C++20 與 Windows SDK。安全 Host 需要 Linux 上正在執行的 X11
session，並設定 `DISPLAY`。

```bash
cargo build --workspace --locked
cargo test --workspace --all-targets --locked
cargo test --workspace --doc --locked
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo fmt --all -- --check
```

下列較小範圍的測試命令目前通過，涵蓋 identity 檔案處理、exact-peer mTLS
成功／失敗案例、QUIC 產品 lane 與分片，以及安全預設 CLI parser：

```bash
cargo test --locked -p latencydesk-socket-transport -p latencydesk-identity -p latencydesk-host -p latencydesk-client
```

確定性的壓力 gate 會同時啟動 8 個彼此獨立的模擬 session，每個 session 跑完
4 種網路 profile，並驗證每個 session 的 realtime-video queue 完全飽和時，input
仍會在第一次 scheduler pop 被服務：

```bash
cargo run --locked -p latencydesk-stress
```

這只能證明 queue 隔離與帳務不變量，不是光學延遲結果，也不能取代真實多機測試。

倉庫另有 Linux X11 的程序級安全 loopback gate。它會產生拋棄式 identity，
證明 rogue certificate 先被拒絕、之後仍可接受 pinned Client，完成 TLS 1.3
mTLS 與產品握手，並在 headless 模式接收真實 X11 畫面：

```bash
cargo build --locked -p latencydesk-host -p latencydesk-client -p latencydesk-identity
xvfb-run -a python3 scripts/secure_connect_test.py \
  --host-bin target/debug/latencydesk-host \
  --client-bin target/debug/latencydesk-client \
  --identity-bin target/debug/latencydesk-identity \
  --frames 3 --fps 10 --max-width 320 --max-height 180 \
  --pairing-timeout 30 --output artifacts/secure-connect.json
```

這項證據僅涵蓋單機 Xvfb／WSL2 類型的 X11 到 headless process loopback，
**不能**證明 Linux 到 Windows 的畫面呈現、可見 XTEST 輸入效果、封包擷取的
機密性、跨機器操作或長時間網路可靠度。這些項目在
[產品就緒度](docs/PRODUCT_READINESS.md)仍為 Pending。

same-socket STUN 程序 gate 會啟動嚴格的本機 fake RFC 8489 Binding server，發現
Client reflexive address，把該 UDP socket 原封不動交給 Quinn，接著完成
exact-mTLS、雙向 opt-in 有界 candidate advertisement 與一個真實 X11 frame：

```bash
xvfb-run -a python3 scripts/stun_same_socket_test.py \
  --host-bin target/debug/latencydesk-host \
  --client-bin target/debug/latencydesk-client \
  --identity-bin target/debug/latencydesk-identity \
  --frames 3 --timeout 45 \
  --output artifacts/stun-same-socket.json
```

artifact 要求 fake server 觀察到的 STUN source、Client local／reflexive address，
以及 Host 觀察到的 authenticated QUIC source 完全一致；兩端 candidate record
還必須在 exact-mTLS 後出現、exchange ID 等於 active random session ID、generation
從 1 開始、candidate 數量互相吻合，且 authenticated Host route 完全不變。這是
authenticated advertisement，不是可用的 ICE checklist；沒有 connectivity check、
nomination、consent、TURN，也不能宣稱已穿透 NAT。

同時多目標輸入 gate 會由一個 supervisor 啟動 2、4、8 或 16 個 exact-pinned
child，要求所有已 flush 的 start marker 都先於任一 stop marker，再分別保留每台
Host 的 256 筆 raw application-ACK RTT：

```bash
xvfb-run -a python3 scripts/multi_target_input_latency_test.py \
  --host-bin target/debug/latencydesk-host \
  --client-bin target/debug/latencydesk-client \
  --identity-bin target/debug/latencydesk-identity \
  --target-count 2 --samples 256 --timeout 45 \
  --output artifacts/multi-target-input-latency.json
```

CI 以 256 samples 重跑 `--target-count 4`，並以 1024 samples 重跑 `8`、`16`，
讓快速 child 在兩次 fail-closed `/proc` snapshot 完成前保持存活。Host 使用 OS 分配的 loopback port；
Linux `/proc` 必須證明一個 supervisor、恰好 N 個 Client child 與 N 個隔離 Host
process group，PID／start-time／執行檔身分保持穩定。RSS、CPU tick、FD、thread
只作當下觀測，不設武斷的通用上限。Host／Client 每個隔離 process 固定使用兩個
Tokio worker，gate 會限制對應 thread 拓撲，避免 target 數再乘上機器 CPU 數。

這仍是單機控制面的 ACK 與資源證據，不是實體 input-to-photon、WAN、跨機資源
或競品成績。

## 安全 LAN Preview 快速開始

此流程需要 Linux X11 Host，以及 Windows 互動式 Client 或 headless Client。
兩台機器應使用相同 source revision 與受信任的有線 LAN。請把
`192.168.1.20` 換成 Linux Host 位址，且只對受信任 LAN 開放 UDP 9000。

### 1. 在兩台機器各產生一組持久身分

Linux Host：

```bash
cargo run --locked -p latencydesk-identity -- generate \
  --name "Linux X11 host" \
  --out-dir "$HOME/.local/share/latencydesk/host"
```

Windows Client（PowerShell）：

```powershell
cargo run --locked -p latencydesk-identity -- generate `
  --name "Windows client" `
  --out-dir "$env:LOCALAPPDATA\LatencyDesk\client"
```

每個目錄都會有 `identity.cert.der` 與 `identity.key.der`。只能透過受信任管道
交換 `identity.cert.der`；禁止複製或分享 `identity.key.der`。請另用獨立的
受信任管道比對輸出的 SHA-256 fingerprint，之後也可用下列命令檢查：

```bash
cargo run --locked -p latencydesk-identity -- fingerprint --cert /path/to/identity.cert.der
```

下方命令中的 `peers/windows-client.cert.der` 是複製到 Host 的 Client
certificate；`peers/linux-host.cert.der` 則是複製到 Client 的 Host
certificate。

### 2. 啟動 Linux X11 Host

```bash
cargo run --locked -p latencydesk-host -- \
  --listen 0.0.0.0:9000 \
  --identity-cert "$HOME/.local/share/latencydesk/host/identity.cert.der" \
  --identity-key "$HOME/.local/share/latencydesk/host/identity.key.der" \
  --peer-cert "$HOME/.local/share/latencydesk/peers/windows-client.cert.der" \
  --max-width 640 --max-height 360 --fps 15
```

Host 只接受完全相符的 pinned Client certificate；驗證對端成功後才會開啟
capture 與 XTEST。

Linux X11 若要使用有限度的 persistent listener，可加入 `--max-sessions 2`（上限
16）。Host 會先拆除所有 session-owned state 並完成 `ReleaseAll`，才接受下一條
exact-pinned 連線。Windows 在 native provider restart 完成獨立 soak 前仍只允許預設值 `1`。
headless Client 可加入 `--frames 3 --session-count 2` 執行有界驗證序列；它會關閉
每個 ProductSession、保留 Client endpoint，並要求每個 successor 都具備新 identity
與嚴格更新的所有 lifecycle epoch。
若只要對可恢復的 QUIC reset／idle timeout 進行重試，可在 headless Client 加上
`--reconnect-attempts 3`（上限 8），並為 Host 配置足夠的 `--max-sessions`。
authentication、protocol、codec、provider 與明確 application-close 錯誤仍是 terminal；
退避含 jitter、單次上限 2 秒；總 monotonic budget 是 pairing timeout 與 15 秒中較小者。

### 3. 啟動互動式 Viewer

```powershell
cargo run --locked -p latencydesk-client -- `
  --connect 192.168.1.20:9000 `
  --identity-cert "$env:LOCALAPPDATA\LatencyDesk\client\identity.cert.der" `
  --identity-key "$env:LOCALAPPDATA\LatencyDesk\client\identity.key.der" `
  --peer-cert "$env:LOCALAPPDATA\LatencyDesk\peers\linux-host.cert.der"
```

Linux 或 macOS 可用同一個 Client 命令且不加 `--frames`，開啟可攜式軟體
Viewer（請依環境調整 identity 路徑）：

```bash
cargo run --locked -p latencydesk-client -- \
  --connect 192.168.1.20:9000 \
  --identity-cert "$HOME/.local/share/latencydesk/client/identity.cert.der" \
  --identity-key "$HOME/.local/share/latencydesk/client/identity.key.der" \
  --peer-cert "$HOME/.local/share/latencydesk/peers/linux-host.cert.der"
```

若要在支援的 Client 平台做有限次數 headless 收幀檢查，可加入
`--frames 60`。可攜式 Viewer 仍是 Alpha 軟體路徑；跨機器呈現、可見輸入
效果、resize／DPI 與長時間復原仍是產品就緒度 gate，不能視為已驗證支援。

`--fallback-address` 為選用參數，最多可重複 3 次。所有位址都必須是同一張 Host
certificate；Client 會同時競速，只採用第一條完成 exact-pinned TLS 驗證的路徑。
這是已知位址 failover，不是 ICE／TURN，也不是未驗證的 proxy。選用的
`--stun-server <IP:PORT>` 只會在同一 socket 發現／記錄一個 srflx 位址；在後續
加上 `--candidate-exchange-probe` 可在已驗證的產品 session 中傳送該有界集合，
但接收端只把它視為不受信任的 connectivity metadata，不會新增或切換 route。
ICE check、nomination、consent 與 relay 仍是後續 gate。

### 4. 同時開啟多台 exact-pinned Host

每台 Host 各加入一組可重複的 `--target`。所有 Host 都必須信任同一張 Client
identity certificate，而每一組 target 都要提供該 Host 自己的 exact certificate
pin。Supervisor 會為每台 Host 啟動隔離的子程序，因此某一台的 Viewer、queue
或連線故障不會和其他台共用 runtime 狀態。這個 Alpha CLI 不接受含逗號的路徑。

```bash
cargo run --locked -p latencydesk-client -- \
  --identity-cert "$HOME/.local/share/latencydesk/client/identity.cert.der" \
  --identity-key "$HOME/.local/share/latencydesk/client/identity.key.der" \
  --target "192.168.1.20:9000,$HOME/.local/share/latencydesk/peers/host-a.cert.der" \
  --target "192.168.1.21:9000,$HOME/.local/share/latencydesk/peers/host-b.cert.der"
```

目前上限是 16 組不重複的 address／certificate，且 local bind port 必須為 0。
此功能是「一個 Client 控制多台 Host」，不代表單一 Host 可接受多個 controller。

Supervisor 會在啟動第一個 child 前安裝 Ctrl-C handler。取消時會停止所有仍在
執行的直接 child、最多等待 5 秒完成 reap，並只在 process EOF 後 join captured
output forwarder，最後以非零狀態退出。Linux 程序 gate 會在 4 條 probe session
互相重疊時只對 supervisor PID 發 SIGINT，接著要求 4 個 child 都已 reap、8 個
forwarder 都已 join、PID／start-time／執行檔身分全部消失，且各 Host 完成
ReleaseAll。這還不代表任意 grandchild process tree 或跨機器 GUI soak 已通過。

這是預期的安全操作流程。倉庫已保留成功的單機 X11 到 headless process
結果，但尚未有跨機器 Windows Viewer 結果。請把失敗視為 Alpha 缺陷，
而非正式部署支援事件。

## 不安全的舊版 Loopback Smoke

舊 harness 只保留用來檢查相容性行為。它會明確加入 `--unsafe-udp-lab`、使用
公開的內建測試 secret，並以明文傳送 media/input。即使提供
`--shared-secret`，也不會讓這套自製協定變安全。

```powershell
cargo build --workspace --locked
python scripts/remote_connect_test.py --mode loopback --frames 8 --host-frames 16 --fps 30
```

只能使用 loopback。禁止選擇 `lan-bind`、綁定外部介面、轉送連接埠或傳送真實
敏感桌面內容。

## 效能與競品宣稱

`scripts/compare-latency.py` 是開發工具，不是產品優勢證據。任何與 AnyDesk、
RustDesk 或其他產品的比較，都必須使用相同內容、codec／品質、解析度、fps、
硬體、display mode 與網路條件，並提供重複試驗、raw data 及第三方重現。
缺漏或為零的指標不能當作證據。量化門檻請見
[產品就緒度](docs/PRODUCT_READINESS.md)。

只有 `scripts/optical_latency_benchmark.py superiority-gate` 可以把延遲門檻標為
通過。它要求 LAN 與 WAN 的 matched raw physical samples，預設至少改善 20% p95、
p95 confidence interval 不重疊，且 p99 不得退步。

## 安全與授權

交換 identity 或執行任一傳輸前，請先閱讀 [SECURITY.md](SECURITY.md)。
倉庫：<https://github.com/1122-gggggg/open_desk>

採用 Apache-2.0 或 MIT 授權。
