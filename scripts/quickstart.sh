#!/usr/bin/env bash
# LatencyDesk one-click quickstart — fetches from GitHub, builds, and handles cert exchange over LAN HTTP.
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/1122-gggggg/open_desk/main/scripts/quickstart.sh | bash -s -- --host
#   curl -fsSL https://raw.githubusercontent.com/1122-gggggg/open_desk/main/scripts/quickstart.sh | bash -s -- --client 192.168.50.201
set -euo pipefail

REPO_URL="https://github.com/1122-gggggg/open_desk.git"
REPO_DIR="${HOME}/open_desk"
HOST_PORT=9000
EXCHANGE_PORT=18080
MODE="host"
HOST_IP=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --host) MODE="host"; shift ;;
    --client) MODE="client"; HOST_IP="${2:-}"; shift 2 ;;
    --repo-dir) REPO_DIR="$2"; shift 2 ;;
    -h|--help) echo "Usage: $0 [--host|--client <HOST_IP>]"; exit 0 ;;
    *) echo "unknown arg $1" >&2; exit 1 ;;
  esac
done

need() { command -v "$1" >/dev/null 2>&1 || { echo "缺 $1，請先安裝" >&2; exit 1; }; }

# 1. 拉倉
if [[ -d "$REPO_DIR/.git" ]]; then
  echo "[1/5] 更新倉庫 $REPO_DIR"
  git -C "$REPO_DIR" fetch origin
  git -C "$REPO_DIR" checkout main
  git -C "$REPO_DIR" reset --hard origin/main
else
  if [[ -d "$REPO_DIR" ]]; then
    echo "目錄 $REPO_DIR 已存在但非 git，移至 ${REPO_DIR}.bak" >&2
    mv "$REPO_DIR" "${REPO_DIR}.bak.$(date +%s)"
  fi
  echo "[1/5] 克隆 $REPO_URL -> $REPO_DIR"
  git clone "$REPO_URL" "$REPO_DIR"
fi
cd "$REPO_DIR"

# 2. 依賴檢查
need cargo
need git
need python3

# 3. 編譯
echo "[2/5] 編譯 host/client/identity（首次約 1-2 分鐘）"
cargo build --locked -p latencydesk-host -p latencydesk-client -p latencydesk-identity

HOST_CERT="$HOME/.local/share/latencydesk/host/identity.cert.der"
HOST_KEY="$HOME/.local/share/latencydesk/host/identity.key.der"
CLIENT_CERT="$HOME/.local/share/latencydesk/client/identity.cert.der"
CLIENT_KEY="$HOME/.local/share/latencydesk/client/identity.key.der"

fingerprint() {
  target/debug/latencydesk-identity fingerprint --cert "$1" 2>/dev/null | awk '{print $NF}' || sha256sum "$1" | awk '{print $1}'
}

if [[ "$MODE" == "host" ]]; then
  echo "[3/5] Host 身份"
  mkdir -p "$(dirname "$HOST_CERT")" ~/peers
  if [[ ! -f "$HOST_CERT" ]]; then
    cargo run --locked -p latencydesk-identity -- generate --name "Linux X11 host" --out-dir "$HOME/.local/share/latencydesk/host"
  else
    echo "已存在 Host 身份，跳過生成"
  fi
  echo "Host 指紋: $(fingerprint "$HOST_CERT")"
  echo "Host IP: $(ip -4 addr | grep -oP '192\.168\.\d+\.\d+' | head -1 || hostname -I | awk '{print $1}')"
  echo ""
  echo "[4/5] 啟動 LAN 憑證交換服務 http://: $EXCHANGE_PORT (等待 Windows Client 上傳)..."
  echo "  在 Windows 執行： curl -fsSL https://raw.githubusercontent.com/1122-gggggg/open_desk/main/scripts/quickstart.ps1 | powershell - -Client <此IP>"
  # 簡易 HTTP 交換：GET /cert 送 host cert，POST /upload 收 client cert
  python3 - "$HOST_CERT" ~/peers/windows-client.cert.der "$EXCHANGE_PORT" << 'PY' &
import http.server, pathlib, sys
host_cert = pathlib.Path(sys.argv[1])
peer_path = pathlib.Path(sys.argv[2])
port = int(sys.argv[3])
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/cert":
            data = host_cert.read_bytes()
            self.send_response(200); self.send_header("Content-Type","application/octet-stream"); self.send_header("Content-Length",str(len(data))); self.end_headers(); self.wfile.write(data)
        else:
            self.send_response(404); self.end_headers()
    def do_POST(self):
        if self.path == "/upload":
            n = int(self.headers.get("Content-Length",0))
            data = self.rfile.read(n)
            peer_path.parent.mkdir(parents=True, exist_ok=True)
            peer_path.write_bytes(data)
            self.send_response(200); self.end_headers(); self.wfile.write(b"ok")
            print(f"[exchange] 已收到 client cert {len(data)} bytes -> {peer_path}", flush=True)
        else:
            self.send_response(404); self.end_headers()
    def log_message(self, fmt, *args): print(f"[http] {fmt % args}", flush=True)
http.server.ThreadingHTTPServer(("0.0.0.0", port), H).serve_forever()
PY
  HTTP_PID=$!
  trap 'kill $HTTP_PID 2>/dev/null; exit' INT TERM
  echo "等待 Windows 上傳 ~/peers/windows-client.cert.der ..."
  for i in $(seq 1 300); do
    if [[ -s ~/peers/windows-client.cert.der ]]; then
      echo "收到！指紋: $(fingerprint ~/peers/windows-client.cert.der)"
      break
    fi
    sleep 1
    if (( i % 10 == 0 )); then echo "  仍等待 $i/300 秒..."; fi
  done
  if [[ ! -s ~/peers/windows-client.cert.der ]]; then
    echo "超時未收到 client cert，請確認 Windows 已執行 quickstart.ps1 -Client <此IP>" >&2
    kill $HTTP_PID 2>/dev/null || true
    exit 1
  fi
  kill $HTTP_PID 2>/dev/null || true
  wait $HTTP_PID 2>/dev/null || true
  echo "[5/5] 啟動 Host :$HOST_PORT (640x360@15)"
  echo "  對端指紋已綁定，XTEST 於認證後才開啟"
  exec cargo run --locked -p latencydesk-host -- --listen 0.0.0.0:$HOST_PORT --identity-cert "$HOST_CERT" --identity-key "$HOST_KEY" --peer-cert ~/peers/windows-client.cert.der --max-width 640 --max-height 360 --fps 15
else
  # client mode
  if [[ -z "$HOST_IP" ]]; then echo "--client 需要 <HOST_IP>" >&2; exit 1; fi
  echo "[3/5] Client 身份"
  mkdir -p "$(dirname "$CLIENT_CERT")" "$HOME/.local/share/latencydesk/peers"
  if [[ ! -f "$CLIENT_CERT" ]]; then
    cargo run --locked -p latencydesk-identity -- generate --name "Linux client" --out-dir "$HOME/.local/share/latencydesk/client"
  else
    echo "已存在 Client 身份，跳過生成"
  fi
  echo "Client 指紋: $(fingerprint "$CLIENT_CERT")"
  echo "[4/5] 與 Host 交換憑證 http://$HOST_IP:$EXCHANGE_PORT"
  mkdir -p /tmp
  echo "  下載 Host cert..."
  curl -fsSL "http://$HOST_IP:$EXCHANGE_PORT/cert" -o /tmp/linux-host.cert.der
  echo "  上傳 Client cert..."
  curl -fsSL -X POST --data-binary "@$CLIENT_CERT" "http://$HOST_IP:$EXCHANGE_PORT/upload" -o /dev/null
  echo "Host 指紋: $(fingerprint /tmp/linux-host.cert.der)"
  cp /tmp/linux-host.cert.der "$HOME/.local/share/latencydesk/peers/linux-host.cert.der"
  echo "[5/5] 連線 Host $HOST_IP:$HOST_PORT"
  exec cargo run --locked -p latencydesk-client -- --connect "$HOST_IP:$HOST_PORT" --identity-cert "$CLIENT_CERT" --identity-key "$CLIENT_KEY" --peer-cert "$HOME/.local/share/latencydesk/peers/linux-host.cert.der"
fi
