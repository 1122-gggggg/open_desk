# LatencyDesk 原生低延遲遠端桌面系統

**專為區域網路 Direct LAN 1080p120 打造的超低延遲原生遠端桌面引擎**

LatencyDesk 是一套強調極致硬體效能、無累積排隊延遲（Zero-Unbounded-Queue）與高安全等級的原生跨平台遠端桌面系統。

---

## 核心技術亮點

- **Direct-LAN 1080p120 設定檔**：端到端硬體加速管線，專為高更新率、超低抖動之有線區域網路互動設計。
- **QUIC / TLS 1.3 傳輸架構**：單一 Quinn QUIC 連線，承載可靠有序的控制／輸入串流，以及具備生命週期截止時間（Deadline-Expiring）的媒體 DATAGRAMs。
- **零無界佇列設計（Zero-Unbounded-Queue）**：管線各階段皆有靜態容量限制（在途 Frame 數限制在 1..=4 幀），過期幀主動丟棄，杜絕排隊積壓造成的延遲劣化。
- **Windows 原生硬體加速管線**：
  - **螢幕擷取**：DXGI Desktop Duplication (DDA) 與 Windows Graphics Capture (WGC)，具備受保護內容遮罩與 Display Epoch 輪替機制。
  - **色彩轉換**：Direct3D 11 Video Processor 硬體 BGRA $\to$ NV12 轉換，嚴格遵守 SDR BT.709 色彩空間契約。
  - **硬體編碼**：Media Foundation 硬體 H.264 編碼器，設定為超低延遲即時模式、0 B-frames、動態強制 IDR 關鍵幀復原。
  - **安全輸入與呈現**：UIPI 完整性閘門防護之 `SendInput`、獨立緊急釋放機制（Release-All），以及 D3D11 Swap Chain 呈現與 GPU 查詢柵欄（Fence）。
- **Linux 原生管線**：XDG Desktop Portal ScreenCast/RemoteDesktop、PipeWire DMA-BUF 零拷貝緩衝區匯入、Wayland 呈現計時與 libei 安全輸入。
- **密碼學裝置身分鎖定**：TLS SPKI 憑證指紋永久鎖定與 6 位數短驗證碼（SAS）配對確認。

---

## 架構全覽

```
 ┌───────────────────────────────────────────────────────────────────────────┐
 │                                 HOST 端                                   │
 │                                                                           │
 │  ┌───────────────────────┐         ┌───────────────────────────────────┐  │
 │  │ DXGI 桌面輸出擷取     │         │ D3D11 Video Processor             │  │
 │  │ (DDA / WGC 原生擷取)  │────────▶│ (硬體 BGRA -> NV12 色彩轉換)      │  │
 │  └───────────────────────┘         └─────────────────┬─────────────────┘  │
 │                                                      │                    │
 │  ┌───────────────────────┐         ┌─────────────────▼─────────────────┐  │
 │  │ Win32 SendInput       │         │ Media Foundation H.264 編碼器     │  │
 │  │ (UIPI / 安全防護閘門) │         │ (超低延遲、無 B 幀、IDR 強制復原)  │  │
 │  └───────────▲───────────┘         └─────────────────┬─────────────────┘  │
 └──────────────┼───────────────────────────────────────┼────────────────────┘
                │ 控制 / 輸入串流                       │ 媒體 DATAGRAMs
                │ (可靠傳輸)                            │ (過期主動拋棄)
                ▼                                       ▼
 ┌───────────────────────────────────────────────────────────────────────────┐
 │                     QUINN QUIC / TLS 1.3 傳輸層                           │
 └───────────────────────────────────────────────────────────────────────────┘
                │                                       │
                ▼                                       ▼
 ┌───────────────────────────────────────────────────────────────────────────┐
 │                                CLIENT 端                                  │
 │                                                                           │
 │  ┌───────────────────────┐         ┌───────────────────────────────────┐  │
 │  │ 用戶端原生輸入        │         │ H.264 硬體解碼器                  │  │
 │  │ (狀態協調與同調)      │         │ (連續性追蹤與關鍵幀復原)          │  │
 │  └───────────────────────┘         └─────────────────┬─────────────────┘  │
 │                                                      │                    │
 │                                    ┌─────────────────▼─────────────────┐  │
 │                                    │ Direct3D 11 / Wayland 交換鏈      │  │
 │                                    │ (呈現完成柵欄與畫面同步)          │  │
 │                                    └───────────────────────────────────┘  │
 └───────────────────────────────────────────────────────────────────────────┘
```

---

## 建置與打包

### 前置需求
- **Rust**：1.78+ (`rustup toolchain install stable`)
- **Windows**：Visual Studio 2022 / Build Tools（具備 C++20 與 Windows 11 SDK）
- **Linux**：GCC/Clang（支援 C++20）、CMake 3.20+、`libx11-dev`、`libpipewire-0.3-dev`

### 編譯與測試
```bash
# 建置整個工作區
cargo build --release --workspace

# 執行全工作區測試
cargo test --workspace --all-targets

# 執行靜態檢查與格式驗證
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo fmt --all -- --check
```

### 產出發行打包成品
- **Windows**：
  ```powershell
  pwsh -File scripts/package.ps1
  ```
  產出 `artifacts/release/windows-x86_64/` 目錄，包含 `latencydesk-host.exe`、`latencydesk-client.exe`、`release-manifest.json` 與 `LatencyDesk-windows-x86_64.zip`。

- **Linux**：
  ```bash
  ./scripts/package.sh
  ```
  產出 `artifacts/release/linux-x86_64/` 目錄，包含 `latencydesk-host`、`latencydesk-client`、`release-manifest.json` 與 `LatencyDesk-linux-x86_64.tar.gz`。

---

## 快速使用指南

### 1. 啟動 Host 端
```bash
# 監聽所有網路介面，啟用 1080p120 傳輸設定檔
latencydesk-host --listen 0.0.0.0:9000 --1080p120-profile
```

### 2. 連線 Client 端
```bash
# 連線至遠端 Host
latencydesk-client --connect 192.168.1.100:9000 --1080p120-profile
```

### 3. 安全配對與驗證
首次連線時，雙方控制台將計算並顯示 6 位數短驗證碼（SAS），雙方確認後即永久鎖定彼此 TLS 憑證指紋，後續連線無須再次配對。

---

## 延遲基準比較方法

為了提供嚴謹、可重現的效能驗證：

1. **嚴格後設資料比對**：比較雙方必須在完全相同的解析度（1920x1080）、更新率（120 fps 或 60 fps）、色彩空間（SDR BT.709）與有線網路環境下進行。
2. **比較工具**：
   ```bash
   python scripts/compare-latency.py path/to/baseline.json path/to/latencydesk.json
   ```
3. 報告分析各階段的 p50、p95 與 p99 延遲：
   - 螢幕擷取至色彩轉換（Capture to Color Convert）
   - 色彩轉換至送入編碼（Convert to Encode Submit）
   - 硬體視訊編碼（Hardware Video Encode）
   - QUIC 網路傳輸（QUIC Transport Delivery）
   - 接收至送入解碼（Receive to Decode）
   - 解碼至畫面呈現完成（Decode to Present Fence）
   - 總體端到端處理延遲（Total Pipeline Processing）

---

## 授權條款

採用 Apache-2.0 或 MIT 授權條款。
