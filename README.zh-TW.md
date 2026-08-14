# LatencyDesk

LatencyDesk 是一個處於 pre-alpha 階段、以低延遲為首要目標的 **Windows ↔ Linux 雙向遠端桌面引擎**。目前倉庫包含經過技術審查的 M0 架構、可執行 Rust 核心骨架、協定邊界、風險 gate 與具體開發里程碑；它還不是可供日常使用的遠端桌面產品。

> 在可重現 benchmark 通過以前，本專案不宣稱效能超過 AnyDesk、RustDesk、Moonlight 或 Parsec。

## 已確認的可行範圍

| 能力 | v0.1 規劃 |
|---|---|
| Windows 被控端／控制端 | 已登入的 Windows 10/11 互動工作階段 |
| Linux 被控端／控制端 | 已登入的 GNOME/KDE Wayland 工作階段，走 Portal 授權 |
| 雙向互通 | Windows → Linux、Linux → Windows |
| 網路 | 先做 LAN 直連，再做 Internet NAT traversal／relay |
| 影像 | 先完成低延遲硬體 H.264，再做稀疏無損 tile 精修 |
| GPU | NVIDIA 作第一條參考管線，之後補 Intel／AMD provider |
| 通用 Wayland 無人值守登入 | 不列入 v0.1 承諾 |
| DRM／受保護畫面 | 明確不支援 |

## 審查後修正的技術路線

原先「一開始就針對不同畫面區域同時跑多種 codec」風險太高，會讓同步、依賴、封包遺失恢復與效能歸因都變得困難。因此正式路線改為：

```text
完整低延遲 H.264 baseline
        ↓
稀疏、精確、可丟棄的 tile 更新
        ↓
影片底層 + 靜態文字區域漸進式精修
```

其他必須遵守的工程條件：

- DXGI／PipeWire capture buffer 不可被非同步 encoder 無限制持有；capture callback 內必須完成安全 import，否則複製到有上限的 encoder-owned pool。
- D3D11 與 DMA-BUF 零拷貝只能是 capability 路徑，不能是唯一可用路徑；跨 GPU、格式不相容與 driver 限制時必須有可量測 copy fallback。
- H.264 P-frame 不能因為過期就任意丟棄；若後續 frame 依賴它，必須停止解碼並請求 IDR／recovery point。
- Windows service 不直接在 Session 0 擷取桌面；採 system service + 每使用者 agent。
- Wayland v0.1 走 XDG RemoteDesktop／ScreenCast Portal、PipeWire、libei，意味著標準模式是已登入且經使用者授權的 session。
- host 與 client 的 monotonic clock 不可直接相減。軟體內部只報各自 clock domain 的 stage latency；真正 input-to-photon 使用光學量測。
- 不假設「非 GPL FFmpeg」就自帶可散布的軟體 H.264 encoder。正式 baseline 先走硬體 provider；OpenH264 僅列選配 provider，專利與 binary 發布責任另外處理。

## 開發順序

```text
M0  架構、協定、安全、可測核心骨架（目前）
M1  fake capture + exact test codec + loopback transport
M2  safe surface/UDP foundation + Windows DDA → H.264 → Windows client，先證明 native pipeline
M3  Windows host → Linux Wayland client
M4  Linux Wayland host → Windows client，完成雙向互通
M5  QUIC、弱網恢復、NVIDIA/Intel/AMD provider matrix
M6  sparse exact tiles 與 static refinement
M7  relay、安裝包、平台受限的 unattended 模式
```

每個 milestone 的 entry/exit gate 在 [`docs/ROADMAP.md`](docs/ROADMAP.md)，完整逐項技術審查在 [`docs/TECHNICAL_AUDIT.md`](docs/TECHNICAL_AUDIT.md)。

## 目前程式骨架

M0 已包含：

- 固定 44 bytes、具 frame/fragment 上限驗證的 media header；
- session state machine；
- 有 deadline、priority、item/byte capacity 的 scheduler；
- decoder continuity tracker；
- 不混用跨機器時鐘的逐幀 telemetry；
- CI、靜態驗證、benchmark 規格、threat model、授權政策。

本機驗證：

```bash
python3 scripts/static_validate.py
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-targets
```

若環境沒有 Rust toolchain，只能視為結構驗證通過，不能宣稱編譯與測試通過。
