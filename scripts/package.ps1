# LatencyDesk Windows Packaging Script
# Generates release binaries, SHA-256 checksums, release-manifest.json, and distribution ZIP.

param (
    [string]$OutDir = "artifacts/release/windows-x86_64",
    [string]$Target = "x86_64-pc-windows-msvc"
)
$ErrorActionPreference = "Stop"

if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) {
    $env:PATH = "$env:USERPROFILE\.cargo\bin;$env:PATH"
}

Write-Host "=== LatencyDesk Windows Packaging ===" -ForegroundColor Cyan
Write-Host "Target: $Target"
Write-Host "Output Directory: $OutDir"

# 1. Build release binaries
Write-Host "`n[1/4] Building release binaries..." -ForegroundColor Yellow
cargo build --release --target $Target -p latencydesk-host -p latencydesk-client
if ($LASTEXITCODE -ne 0) {
    Write-Error "Cargo build failed"
    exit $LASTEXITCODE
}

# 2. Ensure output directories
if (-not (Test-Path $OutDir)) {
    New-Item -ItemType Directory -Path $OutDir -Force | Out-Null
}

$HostBin = "target/$Target/release/latencydesk-host.exe"
if (-not (Test-Path $HostBin)) {
    $HostBin = "target/release/latencydesk-host.exe"
}
$ClientBin = "target/$Target/release/latencydesk-client.exe"
if (-not (Test-Path $ClientBin)) {
    $ClientBin = "target/release/latencydesk-client.exe"
}

Copy-Item $HostBin -Destination "$OutDir/latencydesk-host.exe" -Force
Copy-Item $ClientBin -Destination "$OutDir/latencydesk-client.exe" -Force

# 3. Calculate SHA-256 checksums
Write-Host "`n[2/4] Computing SHA-256 checksums..." -ForegroundColor Yellow
$HostHash = (Get-FileHash "$OutDir/latencydesk-host.exe" -Algorithm SHA256).Hash.ToLower()
$ClientHash = (Get-FileHash "$OutDir/latencydesk-client.exe" -Algorithm SHA256).Hash.ToLower()
$HostSize = (Get-Item "$OutDir/latencydesk-host.exe").Length
$ClientSize = (Get-Item "$OutDir/latencydesk-client.exe").Length

Write-Host "Host:   $HostHash ($HostSize bytes)"
Write-Host "Client: $ClientHash ($ClientSize bytes)"

# 4. Generate release manifest
Write-Host "`n[3/4] Generating release manifest..." -ForegroundColor Yellow
$GitCommit = (git rev-parse HEAD).Trim()
$IsoDate = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")

$Manifest = [ordered]@{
    schema_version = 1
    product = "LatencyDesk"
    version = "0.1.0-alpha.2"
    commit = $GitCommit
    target_triple = $Target
    created_at = $IsoDate
    provider_matrix = [ordered]@{
        capture = "dxgi_desktop_duplication_d3d11"
        encoder = "media_foundation_hardware_h264"
        renderer = "d3d11_swap_chain_present"
        input = "win32_sendinput_integrity_gated"
    }
    default_profile = [ordered]@{
        resolution = "1920x1080"
        fps = 120
        color_space = "SDR_BT709"
        transport = "quinn_quic_tls13_direct_lan"
    }
    artifacts = @(
        [ordered]@{
            name = "latencydesk-host.exe"
            path = "latencydesk-host.exe"
            sha256 = $HostHash
            size_bytes = $HostSize
        },
        [ordered]@{
            name = "latencydesk-client.exe"
            path = "latencydesk-client.exe"
            sha256 = $ClientHash
            size_bytes = $ClientSize
        }
    )
}

$ManifestJson = $Manifest | ConvertTo-Json -Depth 10
$ManifestPath = "$OutDir/release-manifest.json"
[System.IO.File]::WriteAllText($ManifestPath, $ManifestJson)
Write-Host "Manifest written to $ManifestPath"

# 5. Create distribution ZIP archive
Write-Host "`n[4/4] Creating ZIP distribution archive..." -ForegroundColor Yellow
$ZipPath = "artifacts/release/LatencyDesk-windows-x86_64.zip"
if (Test-Path $ZipPath) { Remove-Item $ZipPath -Force }
Compress-Archive -Path "$OutDir/*" -DestinationPath $ZipPath -Force
Write-Host "Distribution archive created: $ZipPath" -ForegroundColor Green
Write-Host "`nPackaging completed successfully!" -ForegroundColor Green
