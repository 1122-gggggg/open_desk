# LatencyDesk Windows one-click — 從 GitHub 拉取並與 Linux Host 交換憑證
# 用法:
#   irm https://raw.githubusercontent.com/1122-gggggg/open_desk/main/scripts/quickstart.ps1 | iex
#   # Client 一鍵 (此 Windows 控 Linux)
#   powershell -ExecutionPolicy Bypass -File quickstart.ps1 -Client 192.168.50.201
param(
  [switch]$RunAsHost,
  [string]$Client
)
$ErrorActionPreference = "Stop"
$RepoUrl = "https://github.com/1122-gggggg/open_desk.git"
$RepoDir = "C:\tmp\open_desk"
\$ExchangePort = 18080
$HostPort = 9000

function Need($cmd) { if (-not (Get-Command $cmd -ErrorAction SilentlyContinue)) { throw "缺 $cmd，請先安裝" } }

# 1. 拉倉
if (Test-Path "$RepoDir\.git") {
  Write-Host "[1/5] 更新 $RepoDir"
  git -C $RepoDir fetch origin
  git -C $RepoDir checkout main
  git -C $RepoDir reset --hard origin/main
} else {
  if (Test-Path $RepoDir) { Move-Item $RepoDir "$RepoDir.bak.$(Get-Date -Format yyyyMMddHHmmss)" }
  Write-Host "[1/5] 克隆 $RepoUrl"
  git clone $RepoUrl $RepoDir
}
Set-Location $RepoDir

Need cargo; Need git
Write-Host "[2/5] 編譯"
cargo build --locked -p latencydesk-host -p latencydesk-client -p latencydesk-identity

$ClientCert = "$env:LOCALAPPDATA\LatencyDesk\client\identity.cert.der"
$ClientKey  = "$env:LOCALAPPDATA\LatencyDesk\client\identity.key.der"
$PeerDir    = "$env:LOCALAPPDATA\LatencyDesk\peers"
$LinuxHostCert = "$PeerDir\linux-host.cert.der"

function Fingerprint($path) {
  try { $out = & .\target\debug\latencydesk-identity.exe fingerprint --cert $path 2>$null; ($out -split " ")[-1] }
  catch { (Get-FileHash $path -Algorithm SHA256).Hash.ToLower() }
}

if ($RunAsHost) {
  Write-Host "Host 模式請在 Linux 執行 quickstart.sh --host，Windows Host 尚不支援可靠擷取"
  exit 1
}
if ($Client) {
  $HostIp = $Client
  Write-Host "[3/5] Client 身份"
  New-Item -ItemType Directory -Force (Split-Path $ClientCert) | Out-Null
  New-Item -ItemType Directory -Force $PeerDir | Out-Null
  if (-not (Test-Path $ClientCert)) {
    cargo run --locked -p latencydesk-identity -- generate --name "Windows client" --out-dir "$env:LOCALAPPDATA\LatencyDesk\client"
  } else { Write-Host "已存在 Client 身份" }
  Write-Host "Client 指紋: $(Fingerprint $ClientCert)"
  Write-Host "[4/5] 交換憑證 http://$HostIp`:$ExchangePort"
  Write-Host "  下載 Host cert..."
  Invoke-WebRequest "http://$HostIp`:$ExchangePort/cert" -OutFile $LinuxHostCert -UseBasicParsing
  Write-Host "  上傳 Client cert..."
  Invoke-WebRequest "http://$HostIp`:$ExchangePort/upload" -Method Post -InFile $ClientCert -UseBasicParsing | Out-Null
  Write-Host "Host 指紋: $(Fingerprint $LinuxHostCert)"
  Write-Host "[5/5] 連線 $HostIp`:$HostPort"
  cargo run --locked -p latencydesk-client -- --connect "$HostIp`:$HostPort" --identity-cert $ClientCert --identity-key $ClientKey --peer-cert $LinuxHostCert
} else {
  Write-Host "用法: quickstart.ps1 -Client <Linux Host IP>"
  Write-Host "或 Linux Host: curl -fsSL https://raw.githubusercontent.com/1122-gggggg/open_desk/main/scripts/quickstart.sh | bash -s -- --host"
}
