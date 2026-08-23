<#
.SYNOPSIS
Creates a Windows LatencyDesk lab-preview archive.

.DESCRIPTION
Builds the complete locked workspace for one supported Windows target, then
creates an exact-allowlist archive and external SHA-256 checksum. Production
packaging is intentionally disabled until the product data path is complete.

.PARAMETER LabPreview
Required explicit acknowledgement that the output is non-production.

.PARAMETER OutDir
Destination directory for the archive and adjacent checksum.

.PARAMETER Target
Supported Windows Rust target triple.

.EXAMPLE
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/package.ps1 -LabPreview
#>

[CmdletBinding()]
param (
    [switch]$LabPreview,
    [ValidateNotNullOrEmpty()]
    [string]$OutDir = "artifacts/release",
    [string]$Target = "x86_64-pc-windows-msvc"
)

$ErrorActionPreference = "Stop"

function Get-LatencyDeskSourceState {
    param (
        [Parameter(Mandatory = $true)]
        [string]$RepositoryRoot
    )

    $StateTempDir = Join-Path ([System.IO.Path]::GetTempPath()) (
        "latencydesk-source-state-" + [Guid]::NewGuid().ToString("N")
    )
    $StateLocationPushed = $false
    $Utf8NoBom = New-Object System.Text.UTF8Encoding($false)

    try {
        New-Item -ItemType Directory -Path $StateTempDir | Out-Null
        Push-Location $RepositoryRoot
        $StateLocationPushed = $true

        $HeadOutput = @(& git rev-parse --verify HEAD)
        if ($LASTEXITCODE -ne 0 -or $HeadOutput.Count -ne 1) {
            throw "Unable to resolve exactly one Git HEAD for source provenance."
        }
        $GitHead = ([string]$HeadOutput[0]).Trim()

        $TrackedDiffPath = Join-Path $StateTempDir "tracked.diff"
        & git diff --binary --full-index --no-ext-diff --no-color `
            "--output=$TrackedDiffPath" HEAD
        if ($LASTEXITCODE -ne 0) {
            throw "Unable to capture the tracked Git diff for source provenance."
        }
        $TrackedDiffHash = (
            Get-FileHash -LiteralPath $TrackedDiffPath -Algorithm SHA256
        ).Hash.ToLowerInvariant()

        [string[]]$UntrackedPaths = @(
            & git -c core.quotePath=false ls-files --others --exclude-standard
        )
        if ($LASTEXITCODE -ne 0) {
            throw "Unable to enumerate untracked files for source provenance."
        }
        $UntrackedPaths = @($UntrackedPaths | Where-Object { $_.Length -gt 0 })
        [Array]::Sort($UntrackedPaths, [System.StringComparer]::Ordinal)

        $DescriptorLines = New-Object System.Collections.Generic.List[string]
        $DescriptorLines.Add("format=latencydesk-source-diff-v1")
        $DescriptorLines.Add("head=$GitHead")
        $DescriptorLines.Add("tracked_diff_sha256=$TrackedDiffHash")
        foreach ($RelativePath in $UntrackedPaths) {
            if ($RelativePath -match "[`t`r`n]") {
                throw "Untracked path contains a tab or newline and cannot be represented safely."
            }
            $PlatformPath = $RelativePath.Replace(
                '/',
                [System.IO.Path]::DirectorySeparatorChar
            )
            $AbsolutePath = Join-Path $RepositoryRoot $PlatformPath
            if (-not (Test-Path -LiteralPath $AbsolutePath -PathType Leaf)) {
                throw "Untracked provenance input is not a regular file: $RelativePath"
            }
            $FileHash = (
                Get-FileHash -LiteralPath $AbsolutePath -Algorithm SHA256
            ).Hash.ToLowerInvariant()
            $DescriptorLines.Add("untracked=$RelativePath`tsha256=$FileHash")
        }

        $DescriptorPath = Join-Path $StateTempDir "source-diff-descriptor.txt"
        [System.IO.File]::WriteAllText(
            $DescriptorPath,
            ([string]::Join("`n", $DescriptorLines) + "`n"),
            $Utf8NoBom
        )
        $DiffHash = (
            Get-FileHash -LiteralPath $DescriptorPath -Algorithm SHA256
        ).Hash.ToLowerInvariant()

        $StatusLines = @(
            & git status --porcelain=v1 --untracked-files=all --no-renames
        )
        if ($LASTEXITCODE -ne 0) {
            throw "Unable to inspect Git working-tree status for source provenance."
        }
        $IsDirty = $StatusLines.Count -gt 0
        $Attribution = if ($IsDirty) {
            "git_head_plus_worktree_changes"
        } else {
            "clean_git_head"
        }

        return [pscustomobject]@{
            GitHead = $GitHead
            Dirty = $IsDirty
            Attribution = $Attribution
            DiffSha256 = $DiffHash
            DiffHashFormat = "latencydesk-source-diff-v1"
            TrackedDiffSha256 = $TrackedDiffHash
            UntrackedFileCount = $UntrackedPaths.Count
            StatusEntryCount = $StatusLines.Count
        }
    } finally {
        if ($StateLocationPushed) {
            Pop-Location
        }
        if ($StateTempDir -and
            (Test-Path -LiteralPath $StateTempDir) -and
            ([System.IO.Path]::GetFileName($StateTempDir) -like "latencydesk-source-state-*")) {
            Remove-Item -LiteralPath $StateTempDir -Recurse -Force
        }
    }
}

if (-not $LabPreview) {
    [Console]::Error.WriteLine(
        "Packaging refused: production wiring is incomplete. " +
        "Use -LabPreview only to create an explicitly labelled, non-production archive."
    )
    exit 2
}

$SupportedTargets = @{
    "x86_64-pc-windows-msvc" = "x86_64"
    "aarch64-pc-windows-msvc" = "aarch64"
}
if (-not $SupportedTargets.ContainsKey($Target)) {
    throw "Unsupported Windows target '$Target'. Supported targets: $($SupportedTargets.Keys -join ', ')."
}
$Architecture = $SupportedTargets[$Target]

if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) {
    throw "cargo was not found on PATH. Install the pinned Rust toolchain before packaging."
}
if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
    throw "git was not found on PATH; verifiable source provenance is required for packaging."
}
$RepoRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))
$OutputRoot = if ([System.IO.Path]::IsPathRooted($OutDir)) {
    [System.IO.Path]::GetFullPath($OutDir)
} else {
    [System.IO.Path]::GetFullPath((Join-Path $RepoRoot $OutDir))
}

$StagingDir = $null
$LocationPushed = $false
$ArchivePath = $null
$ChecksumPath = $null
$PackageComplete = $false

try {
    Push-Location $RepoRoot
    $LocationPushed = $true

    Write-Host "=== LatencyDesk lab-preview packaging (Windows) ===" -ForegroundColor Cyan
    Write-Host "Target triple: $Target"
    Write-Host "Architecture:  $Architecture"
    Write-Host "Output root:   $OutputRoot"

    $SourceStateBefore = Get-LatencyDeskSourceState -RepositoryRoot $RepoRoot

    Write-Host "`n[1/5] Reading workspace metadata..." -ForegroundColor Yellow
    $MetadataRaw = & cargo metadata --format-version 1 --locked --no-deps
    if ($LASTEXITCODE -ne 0) {
        throw "cargo metadata failed with exit code $LASTEXITCODE."
    }
    $Metadata = ($MetadataRaw -join "`n") | ConvertFrom-Json

    $ProductPackageNames = @(
        "latencydesk-host",
        "latencydesk-client",
        "latencydesk-identity"
    )
    $ProductPackages = @(
        $Metadata.packages | Where-Object { $ProductPackageNames -contains $_.name }
    )
    foreach ($PackageName in $ProductPackageNames) {
        $Matches = @($ProductPackages | Where-Object { $_.name -eq $PackageName })
        if ($Matches.Count -ne 1) {
            throw "cargo metadata must contain exactly one '$PackageName' package."
        }
    }
    $HostPackage = @($ProductPackages | Where-Object { $_.name -eq "latencydesk-host" })[0]
    $Version = [string]$HostPackage.version
    foreach ($Package in $ProductPackages) {
        if (-not [string]::Equals(
            $Version,
            [string]$Package.version,
            [System.StringComparison]::Ordinal
        )) {
            throw "Host, client, and identity package versions differ; refusing to create an ambiguous release."
        }
    }
    if ($Version -notmatch '^[0-9A-Za-z][0-9A-Za-z.+-]*$') {
        throw "Cargo metadata returned an unsafe version string: '$Version'."
    }
    $CargoTargetDirectory = [System.IO.Path]::GetFullPath([string]$Metadata.target_directory)

    Write-Host "`n[2/5] Building the complete locked workspace..." -ForegroundColor Yellow
    & cargo build --release --workspace --locked --target $Target
    if ($LASTEXITCODE -ne 0) {
        throw "cargo build failed with exit code $LASTEXITCODE."
    }

    $SourceStateAfter = Get-LatencyDeskSourceState -RepositoryRoot $RepoRoot
    if ($SourceStateBefore.GitHead -cne $SourceStateAfter.GitHead -or
        $SourceStateBefore.DiffSha256 -cne $SourceStateAfter.DiffSha256 -or
        $SourceStateBefore.Dirty -ne $SourceStateAfter.Dirty) {
        throw "Source state changed during the release build; refusing to package mismatched provenance."
    }
    $SourceState = $SourceStateAfter
    $GitCommit = $SourceState.GitHead

    # Only target-qualified build products are accepted. There is deliberately no
    # target/release fallback because it can select a stale or wrong-architecture binary.
    $TargetReleaseDir = Join-Path (Join-Path $CargoTargetDirectory $Target) "release"
    $HostBin = Join-Path $TargetReleaseDir "latencydesk-host.exe"
    $ClientBin = Join-Path $TargetReleaseDir "latencydesk-client.exe"
    $IdentityBin = Join-Path $TargetReleaseDir "latencydesk-identity.exe"
    foreach ($Binary in @($HostBin, $ClientBin, $IdentityBin)) {
        if (-not (Test-Path -LiteralPath $Binary -PathType Leaf)) {
            throw "Expected target-qualified build product is missing: $Binary"
        }
    }

    Write-Host "`n[3/5] Creating a fresh allowlisted staging directory..." -ForegroundColor Yellow
    $StagingDir = Join-Path ([System.IO.Path]::GetTempPath()) (
        "latencydesk-package-" + [Guid]::NewGuid().ToString("N")
    )
    New-Item -ItemType Directory -Path $StagingDir | Out-Null

    $HostName = "latencydesk-host.exe"
    $ClientName = "latencydesk-client.exe"
    $IdentityName = "latencydesk-identity.exe"
    $HostStage = Join-Path $StagingDir $HostName
    $ClientStage = Join-Path $StagingDir $ClientName
    $IdentityStage = Join-Path $StagingDir $IdentityName
    Copy-Item -LiteralPath $HostBin -Destination $HostStage
    Copy-Item -LiteralPath $ClientBin -Destination $ClientStage
    Copy-Item -LiteralPath $IdentityBin -Destination $IdentityStage

    $DocumentationFiles = @(
        [pscustomobject]@{
            SourcePath = "docs/PACKAGE_RUNBOOK.md"
            ArchivePath = "PACKAGE_RUNBOOK.md"
        },
        [pscustomobject]@{ SourcePath = "README.md"; ArchivePath = "README.md" },
        [pscustomobject]@{
            SourcePath = "README.zh-TW.md"
            ArchivePath = "README.zh-TW.md"
        },
        [pscustomobject]@{ SourcePath = "SECURITY.md"; ArchivePath = "SECURITY.md" },
        [pscustomobject]@{ SourcePath = "LICENSE"; ArchivePath = "LICENSE" },
        [pscustomobject]@{
            SourcePath = "LICENSE-APACHE"
            ArchivePath = "LICENSE-APACHE"
        },
        [pscustomobject]@{ SourcePath = "LICENSE-MIT"; ArchivePath = "LICENSE-MIT" },
        [pscustomobject]@{
            SourcePath = "docs/PRODUCT_READINESS.md"
            ArchivePath = "docs/PRODUCT_READINESS.md"
        },
        [pscustomobject]@{
            SourcePath = "docs/THREAT_MODEL.md"
            ArchivePath = "docs/THREAT_MODEL.md"
        }
    )
    foreach ($Document in $DocumentationFiles) {
        $Source = Join-Path $RepoRoot $Document.SourcePath
        if (-not (Test-Path -LiteralPath $Source -PathType Leaf)) {
            throw "Required package document is missing: $Source"
        }
        $Destination = Join-Path $StagingDir $Document.ArchivePath
        $DestinationDirectory = Split-Path -Parent $Destination
        if (-not (Test-Path -LiteralPath $DestinationDirectory -PathType Container)) {
            New-Item -ItemType Directory -Path $DestinationDirectory | Out-Null
        }
        Copy-Item -LiteralPath $Source -Destination $Destination
    }

    $SourceStateStaged = Get-LatencyDeskSourceState -RepositoryRoot $RepoRoot
    if ($SourceState.GitHead -cne $SourceStateStaged.GitHead -or
        $SourceState.DiffSha256 -cne $SourceStateStaged.DiffSha256 -or
        $SourceState.Dirty -ne $SourceStateStaged.Dirty) {
        throw "Source state changed while staging release documents; refusing mixed provenance."
    }

    $HostHash = (Get-FileHash -LiteralPath $HostStage -Algorithm SHA256).Hash.ToLowerInvariant()
    $ClientHash = (Get-FileHash -LiteralPath $ClientStage -Algorithm SHA256).Hash.ToLowerInvariant()
    $IdentityHash = (Get-FileHash -LiteralPath $IdentityStage -Algorithm SHA256).Hash.ToLowerInvariant()
    $HostSize = (Get-Item -LiteralPath $HostStage).Length
    $ClientSize = (Get-Item -LiteralPath $ClientStage).Length
    $IdentitySize = (Get-Item -LiteralPath $IdentityStage).Length

    $ArchiveFileNames = @(
        $HostName,
        $ClientName,
        $IdentityName,
        "release-manifest.json"
    ) + @($DocumentationFiles | ForEach-Object { $_.ArchivePath })
    $ManifestCommit = if ($SourceState.Dirty) { $null } else { $GitCommit }
    $Manifest = [ordered]@{
        schema_version = 2
        product = "LatencyDesk"
        release_tier = "lab-preview"
        production_ready = $false
        version = $Version
        commit = $ManifestCommit
        source_state = [ordered]@{
            git_head = $SourceState.GitHead
            dirty = [bool]$SourceState.Dirty
            attribution = $SourceState.Attribution
            diff_sha256 = $SourceState.DiffSha256
            diff_hash_format = $SourceState.DiffHashFormat
            tracked_diff_sha256 = $SourceState.TrackedDiffSha256
            untracked_file_count = $SourceState.UntrackedFileCount
            status_entry_count = $SourceState.StatusEntryCount
        }
        target_triple = $Target
        operating_system = "windows"
        architecture = $Architecture
        created_at = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
        packaged_roles = @("host", "client")
        packaged_tools = @("identity")
        capabilities = [ordered]@{
            transport = [ordered]@{
                default = "quic_v1_tls13_exact_peer_mtls"
                control = "independent_reliable_streams"
                input = "independent_reliable_streams"
                media = "quic_datagram_bounded_reassembly"
                legacy = "plaintext_udp_requires_explicit_unsafe_udp_lab"
            }
            host = [ordered]@{
                windows = [ordered]@{
                    secure = "unsupported_fail_closed"
                    legacy = [ordered]@{
                        capture = "synthetic_frames_only"
                        input_injection = "no_op"
                    }
                }
                linux = "x11_capture_cpu_raw_nv12_xtest_input"
            }
            client = [ordered]@{
                windows = "strict_raw_nv12_d3d11_viewer"
                linux = "headless_only"
            }
            identity = "persistent_self_signed_der_exact_leaf_pin"
        }
        known_limitations = [ordered]@{
            video_codec = "none_raw_nv12_only"
            nat_traversal_relay = "unavailable"
            reconnect = "unavailable"
            installer = "unavailable"
        }
        artifacts = @(
            [ordered]@{
                name = $HostName
                path = $HostName
                sha256 = $HostHash
                size_bytes = $HostSize
            },
            [ordered]@{
                name = $ClientName
                path = $ClientName
                sha256 = $ClientHash
                size_bytes = $ClientSize
            },
            [ordered]@{
                name = $IdentityName
                path = $IdentityName
                sha256 = $IdentityHash
                size_bytes = $IdentitySize
            }
        )
        archive_contents = $ArchiveFileNames
    }

    $ManifestPath = Join-Path $StagingDir "release-manifest.json"
    $ManifestJson = $Manifest | ConvertTo-Json -Depth 12
    $Utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText(
        $ManifestPath,
        $ManifestJson + [Environment]::NewLine,
        $Utf8NoBom
    )

    Write-Host "`n[4/5] Creating the allowlisted archive..." -ForegroundColor Yellow
    New-Item -ItemType Directory -Path $OutputRoot -Force | Out-Null
    $ArchiveName = "LatencyDesk-$Version-lab-preview-windows-$Architecture.zip"
    $ArchivePath = Join-Path $OutputRoot $ArchiveName
    $ChecksumPath = "$ArchivePath.sha256"
    foreach ($OldOutput in @($ArchivePath, $ChecksumPath)) {
        if (Test-Path -LiteralPath $OldOutput) {
            Remove-Item -LiteralPath $OldOutput -Force
        }
    }

    Add-Type -AssemblyName System.IO.Compression
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $Zip = [System.IO.Compression.ZipFile]::Open(
        $ArchivePath,
        [System.IO.Compression.ZipArchiveMode]::Create
    )
    try {
        foreach ($ArchiveEntryName in $ArchiveFileNames) {
            $ArchiveEntryPath = Join-Path $StagingDir $ArchiveEntryName
            [void][System.IO.Compression.ZipFileExtensions]::CreateEntryFromFile(
                $Zip,
                $ArchiveEntryPath,
                $ArchiveEntryName.Replace('\', '/'),
                [System.IO.Compression.CompressionLevel]::Optimal
            )
        }
    } finally {
        $Zip.Dispose()
    }

    $Zip = [System.IO.Compression.ZipFile]::OpenRead($ArchivePath)
    try {
        $ActualEntries = @($Zip.Entries | ForEach-Object { $_.FullName })
    } finally {
        $Zip.Dispose()
    }
    $ArchiveDiff = @(
        Compare-Object -CaseSensitive `
            -ReferenceObject ($ArchiveFileNames | Sort-Object -CaseSensitive) `
            -DifferenceObject ($ActualEntries | Sort-Object -CaseSensitive)
    )
    if ($ActualEntries.Count -ne $ArchiveFileNames.Count -or
        $ArchiveDiff.Count -ne 0) {
        Remove-Item -LiteralPath $ArchivePath -Force
        throw "Archive contents differ from the packaging allowlist."
    }

    Write-Host "`n[5/5] Writing the external SHA-256 checksum..." -ForegroundColor Yellow
    $ArchiveHash = (Get-FileHash -LiteralPath $ArchivePath -Algorithm SHA256).Hash.ToLowerInvariant()
    [System.IO.File]::WriteAllText(
        $ChecksumPath,
        "$ArchiveHash  $ArchiveName`n",
        $Utf8NoBom
    )

    $SourceStateFinal = Get-LatencyDeskSourceState -RepositoryRoot $RepoRoot
    if ($SourceState.GitHead -cne $SourceStateFinal.GitHead -or
        $SourceState.DiffSha256 -cne $SourceStateFinal.DiffSha256 -or
        $SourceState.Dirty -ne $SourceStateFinal.Dirty) {
        foreach ($Output in @($ArchivePath, $ChecksumPath)) {
            if (Test-Path -LiteralPath $Output) {
                Remove-Item -LiteralPath $Output -Force
            }
        }
        throw "Source state changed while creating the archive; removed outputs with mismatched provenance."
    }

    $PackageComplete = $true

    Write-Host "Archive:  $ArchivePath" -ForegroundColor Green
    Write-Host "Checksum: $ChecksumPath" -ForegroundColor Green
    Write-Warning "This is a lab-preview package. Production wiring is still incomplete."
} finally {
    if ($LocationPushed) {
        Pop-Location
    }
    if (-not $PackageComplete) {
        foreach ($IncompleteOutput in @($ArchivePath, $ChecksumPath)) {
            if ($IncompleteOutput -and (Test-Path -LiteralPath $IncompleteOutput)) {
                Remove-Item -LiteralPath $IncompleteOutput -Force
            }
        }
    }
    if ($StagingDir -and
        (Test-Path -LiteralPath $StagingDir) -and
        ([System.IO.Path]::GetFileName($StagingDir) -like "latencydesk-package-*")) {
        Remove-Item -LiteralPath $StagingDir -Recurse -Force
    }
}
