#!/usr/bin/env bash
# LatencyDesk Linux lab-preview packaging.
# Production packaging is intentionally disabled until the product data path is complete.

set -euo pipefail

usage() {
    cat <<'EOF'
Usage: bash scripts/package.sh --lab-preview [--out-dir DIR] [--target TRIPLE]

Creates an explicitly labelled, non-production lab-preview archive.
Production packaging remains disabled because the product wiring is incomplete.
EOF
}

die() {
    printf 'error: %s\n' "$*" >&2
    exit 1
}

LAB_PREVIEW=false
OUT_DIR="artifacts/release"
TARGET="x86_64-unknown-linux-gnu"

while (($# > 0)); do
    case "$1" in
        --lab-preview)
            LAB_PREVIEW=true
            shift
            ;;
        --out-dir)
            (($# >= 2)) || die "--out-dir requires a directory argument"
            OUT_DIR="$2"
            shift 2
            ;;
        --out-dir=*)
            OUT_DIR="${1#*=}"
            shift
            ;;
        --target)
            (($# >= 2)) || die "--target requires a target triple"
            TARGET="$2"
            shift 2
            ;;
        --target=*)
            TARGET="${1#*=}"
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            die "unknown argument '$1'; run with --help for usage"
            ;;
    esac
done

if [[ "$LAB_PREVIEW" != true ]]; then
    die "packaging refused: production wiring is incomplete; use --lab-preview only for an explicitly labelled, non-production archive"
fi
[[ -n "$OUT_DIR" ]] || die "--out-dir must not be empty"

case "$TARGET" in
    x86_64-unknown-linux-gnu)
        ARCHITECTURE="x86_64"
        ;;
    aarch64-unknown-linux-gnu)
        ARCHITECTURE="aarch64"
        ;;
    *)
        die "unsupported Linux target '$TARGET'"
        ;;
esac

command -v cargo >/dev/null 2>&1 || die "cargo was not found on PATH"
command -v git >/dev/null 2>&1 || \
    die "git was not found on PATH; verifiable source provenance is required"
command -v tar >/dev/null 2>&1 || die "tar was not found on PATH"
command -v mktemp >/dev/null 2>&1 || die "mktemp was not found on PATH"

if command -v python3 >/dev/null 2>&1; then
    PYTHON_BIN="python3"
elif command -v python >/dev/null 2>&1 && python -c 'import sys; raise SystemExit(sys.version_info < (3, 8))'; then
    PYTHON_BIN="python"
else
    die "Python 3.8 or newer is required to parse cargo metadata and write the manifest"
fi

"$PYTHON_BIN" -c 'import sys; raise SystemExit(sys.version_info < (3, 8))' || \
    die "Python 3.8 or newer is required"

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd -- "$SCRIPT_DIR/.." && pwd)
if [[ "$OUT_DIR" = /* ]]; then
    OUTPUT_ROOT="$OUT_DIR"
else
    OUTPUT_ROOT="$REPO_ROOT/$OUT_DIR"
fi

cd -- "$REPO_ROOT"

sha256_file() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum -- "$1" | awk '{print $1}'
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 -- "$1" | awk '{print $1}'
    else
        die "sha256sum or shasum is required"
    fi
}

compute_source_state() {
    local state_temp tracked_diff_path untracked_path_list sorted_untracked_path_list
    local descriptor_path status_path relative_path file_hash
    local untracked_count=0

    state_temp=$(mktemp -d -t latencydesk-source-state.XXXXXXXX)
    tracked_diff_path="$state_temp/tracked.diff"
    untracked_path_list="$state_temp/untracked-paths"
    sorted_untracked_path_list="$state_temp/untracked-paths-sorted"
    descriptor_path="$state_temp/source-diff-descriptor.txt"
    status_path="$state_temp/status"

    SOURCE_GIT_HEAD=$(git rev-parse --verify HEAD) || {
        rm -rf -- "$state_temp"
        die "unable to resolve Git HEAD for source provenance"
    }
    [[ "$SOURCE_GIT_HEAD" =~ ^[0-9a-fA-F]{40,64}$ ]] || {
        rm -rf -- "$state_temp"
        die "Git HEAD returned an invalid object id"
    }

    git diff --binary --full-index --no-ext-diff --no-color \
        --output="$tracked_diff_path" HEAD || {
        rm -rf -- "$state_temp"
        die "unable to capture the tracked Git diff for source provenance"
    }
    SOURCE_TRACKED_DIFF_SHA256=$(sha256_file "$tracked_diff_path")

    git -c core.quotePath=false ls-files --others --exclude-standard -z \
        > "$untracked_path_list" || {
        rm -rf -- "$state_temp"
        die "unable to enumerate untracked files for source provenance"
    }
    LC_ALL=C sort -z -- "$untracked_path_list" > "$sorted_untracked_path_list" || {
        rm -rf -- "$state_temp"
        die "unable to sort untracked paths for source provenance"
    }

    {
        printf 'format=latencydesk-source-diff-v1\n'
        printf 'head=%s\n' "$SOURCE_GIT_HEAD"
        printf 'tracked_diff_sha256=%s\n' "$SOURCE_TRACKED_DIFF_SHA256"
        while IFS= read -r -d '' relative_path; do
            if [[ "$relative_path" == *$'\n'* || "$relative_path" == *$'\t'* ]]; then
                rm -rf -- "$state_temp"
                die "untracked path contains a tab or newline and cannot be represented safely"
            fi
            [[ -f "$REPO_ROOT/$relative_path" ]] || {
                rm -rf -- "$state_temp"
                die "untracked provenance input is not a regular file: $relative_path"
            }
            file_hash=$(sha256_file "$REPO_ROOT/$relative_path")
            printf 'untracked=%s\tsha256=%s\n' "$relative_path" "$file_hash"
            ((untracked_count += 1))
        done < "$sorted_untracked_path_list"
    } > "$descriptor_path"

    SOURCE_DIFF_SHA256=$(sha256_file "$descriptor_path")
    SOURCE_UNTRACKED_FILE_COUNT=$untracked_count

    git status --porcelain=v1 -z --untracked-files=all --no-renames \
        > "$status_path" || {
        rm -rf -- "$state_temp"
        die "unable to inspect Git working-tree status for source provenance"
    }
    SOURCE_STATUS_ENTRY_COUNT=$(tr -cd '\000' < "$status_path" | wc -c | tr -d '[:space:]')
    if [[ -s "$status_path" ]]; then
        SOURCE_DIRTY=true
        SOURCE_ATTRIBUTION="git_head_plus_worktree_changes"
    else
        SOURCE_DIRTY=false
        SOURCE_ATTRIBUTION="clean_git_head"
    fi
    SOURCE_DIFF_HASH_FORMAT="latencydesk-source-diff-v1"

    rm -rf -- "$state_temp"
}

source_state_matches_build() {
    [[ "$SOURCE_GIT_HEAD" == "$BUILD_SOURCE_GIT_HEAD" &&
       "$SOURCE_DIFF_SHA256" == "$BUILD_SOURCE_DIFF_SHA256" &&
       "$SOURCE_DIRTY" == "$BUILD_SOURCE_DIRTY" ]]
}

printf '=== LatencyDesk lab-preview packaging (Linux) ===\n'
printf 'Target triple: %s\n' "$TARGET"
printf 'Architecture:  %s\n' "$ARCHITECTURE"
printf 'Output root:   %s\n' "$OUTPUT_ROOT"

compute_source_state
BUILD_SOURCE_GIT_HEAD="$SOURCE_GIT_HEAD"
BUILD_SOURCE_DIFF_SHA256="$SOURCE_DIFF_SHA256"
BUILD_SOURCE_DIRTY="$SOURCE_DIRTY"

printf '\n[1/5] Reading workspace metadata...\n'
METADATA_JSON=$(cargo metadata --format-version 1 --locked --no-deps)
IFS=$'\t' read -r VERSION CARGO_TARGET_DIRECTORY < <(
    printf '%s' "$METADATA_JSON" | "$PYTHON_BIN" -c '
import json
import re
import sys

metadata = json.load(sys.stdin)
wanted = ("latencydesk-host", "latencydesk-client", "latencydesk-identity")
packages = {name: [] for name in wanted}
for package in metadata.get("packages", []):
    if package.get("name") in packages:
        packages[package["name"]].append(package)
for name, matches in packages.items():
    if len(matches) != 1:
        raise SystemExit(f"cargo metadata must contain exactly one {name!r} package")
versions = {matches[0]["version"] for matches in packages.values()}
if len(versions) != 1:
    raise SystemExit("host, client, and identity package versions differ")
version = versions.pop()
if not re.fullmatch(r"[0-9A-Za-z][0-9A-Za-z.+-]*", version):
    raise SystemExit(f"unsafe package version: {version!r}")
target_directory = metadata.get("target_directory")
if not isinstance(target_directory, str) or not target_directory:
    raise SystemExit("cargo metadata did not return target_directory")
print(f"{version}\t{target_directory}")
'
)
[[ -n "$VERSION" && -n "$CARGO_TARGET_DIRECTORY" ]] || \
    die "failed to obtain version and target directory from cargo metadata"

printf '\n[2/5] Building the complete locked workspace...\n'
cargo build --release --workspace --locked --target "$TARGET"

compute_source_state
source_state_matches_build || \
    die "source state changed during the release build; refusing mismatched provenance"
GIT_COMMIT="$SOURCE_GIT_HEAD"

# Only the target-qualified build product is accepted. There is deliberately no
# target/release fallback because it can select a stale or wrong-architecture binary.
HOST_BIN="$CARGO_TARGET_DIRECTORY/$TARGET/release/latencydesk-host"
CLIENT_BIN="$CARGO_TARGET_DIRECTORY/$TARGET/release/latencydesk-client"
IDENTITY_BIN="$CARGO_TARGET_DIRECTORY/$TARGET/release/latencydesk-identity"
for binary in "$HOST_BIN" "$CLIENT_BIN" "$IDENTITY_BIN"; do
    [[ -f "$binary" ]] || die "expected target-qualified build product is missing: $binary"
done

printf '\n[3/5] Creating a fresh allowlisted staging directory...\n'
STAGING_DIR=$(mktemp -d -t latencydesk-package.XXXXXXXX)
PACKAGE_COMPLETE=false
cleanup() {
    if [[ "${PACKAGE_COMPLETE:-false}" != true ]]; then
        for incomplete_output in "${ARCHIVE_PATH:-}" "${CHECKSUM_PATH:-}"; do
            if [[ -n "$incomplete_output" ]]; then
                rm -f -- "$incomplete_output"
            fi
        done
    fi
    if [[ -n "${STAGING_DIR:-}" &&
          -d "$STAGING_DIR" &&
          "$(basename -- "$STAGING_DIR")" == latencydesk-package.* ]]; then
        rm -rf -- "$STAGING_DIR"
    fi
}
trap cleanup EXIT

HOST_NAME="latencydesk-host"
CLIENT_NAME="latencydesk-client"
IDENTITY_NAME="latencydesk-identity"
cp -- "$HOST_BIN" "$STAGING_DIR/$HOST_NAME"
cp -- "$CLIENT_BIN" "$STAGING_DIR/$CLIENT_NAME"
cp -- "$IDENTITY_BIN" "$STAGING_DIR/$IDENTITY_NAME"
chmod 0755 \
    "$STAGING_DIR/$HOST_NAME" \
    "$STAGING_DIR/$CLIENT_NAME" \
    "$STAGING_DIR/$IDENTITY_NAME"

DOCUMENTATION_SOURCES=(
    "docs/PACKAGE_RUNBOOK.md"
    "README.md"
    "README.zh-TW.md"
    "SECURITY.md"
    "LICENSE"
    "LICENSE-APACHE"
    "LICENSE-MIT"
    "docs/PRODUCT_READINESS.md"
    "docs/THREAT_MODEL.md"
)
DOCUMENTATION_DESTINATIONS=(
    "PACKAGE_RUNBOOK.md"
    "README.md"
    "README.zh-TW.md"
    "SECURITY.md"
    "LICENSE"
    "LICENSE-APACHE"
    "LICENSE-MIT"
    "docs/PRODUCT_READINESS.md"
    "docs/THREAT_MODEL.md"
)
[[ "${#DOCUMENTATION_SOURCES[@]}" -eq "${#DOCUMENTATION_DESTINATIONS[@]}" ]] || \
    die "internal documentation source/destination allowlists differ in length"
for index in "${!DOCUMENTATION_SOURCES[@]}"; do
    source_name="${DOCUMENTATION_SOURCES[$index]}"
    destination_name="${DOCUMENTATION_DESTINATIONS[$index]}"
    [[ -f "$REPO_ROOT/$source_name" ]] || \
        die "required package document is missing: $REPO_ROOT/$source_name"
    mkdir -p -- "$(dirname -- "$STAGING_DIR/$destination_name")"
    cp -- "$REPO_ROOT/$source_name" "$STAGING_DIR/$destination_name"
done

compute_source_state
source_state_matches_build || \
    die "source state changed while staging release documents; refusing mixed provenance"

HOST_HASH=$(sha256_file "$STAGING_DIR/$HOST_NAME")
CLIENT_HASH=$(sha256_file "$STAGING_DIR/$CLIENT_NAME")
IDENTITY_HASH=$(sha256_file "$STAGING_DIR/$IDENTITY_NAME")
HOST_SIZE=$(wc -c < "$STAGING_DIR/$HOST_NAME" | tr -d '[:space:]')
CLIENT_SIZE=$(wc -c < "$STAGING_DIR/$CLIENT_NAME" | tr -d '[:space:]')
IDENTITY_SIZE=$(wc -c < "$STAGING_DIR/$IDENTITY_NAME" | tr -d '[:space:]')
ISO_DATE=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

ARCHIVE_CONTENTS=(
    "$HOST_NAME"
    "$CLIENT_NAME"
    "$IDENTITY_NAME"
    "release-manifest.json"
    "${DOCUMENTATION_DESTINATIONS[@]}"
)

"$PYTHON_BIN" - \
    "$STAGING_DIR/release-manifest.json" \
    "$VERSION" \
    "$GIT_COMMIT" \
    "$SOURCE_DIRTY" \
    "$SOURCE_ATTRIBUTION" \
    "$SOURCE_DIFF_SHA256" \
    "$SOURCE_DIFF_HASH_FORMAT" \
    "$SOURCE_TRACKED_DIFF_SHA256" \
    "$SOURCE_UNTRACKED_FILE_COUNT" \
    "$SOURCE_STATUS_ENTRY_COUNT" \
    "$TARGET" \
    "$ARCHITECTURE" \
    "$ISO_DATE" \
    "$HOST_NAME" \
    "$HOST_HASH" \
    "$HOST_SIZE" \
    "$CLIENT_NAME" \
    "$CLIENT_HASH" \
    "$CLIENT_SIZE" \
    "$IDENTITY_NAME" \
    "$IDENTITY_HASH" \
    "$IDENTITY_SIZE" \
    "${ARCHIVE_CONTENTS[@]}" <<'PY'
import json
import pathlib
import sys

(
    manifest_path,
    version,
    commit,
    source_dirty,
    source_attribution,
    source_diff_hash,
    source_diff_hash_format,
    source_tracked_diff_hash,
    source_untracked_count,
    source_status_count,
    target,
    architecture,
    created_at,
    host_name,
    host_hash,
    host_size,
    client_name,
    client_hash,
    client_size,
    identity_name,
    identity_hash,
    identity_size,
    *archive_contents,
) = sys.argv[1:]

manifest = {
    "schema_version": 2,
    "product": "LatencyDesk",
    "release_tier": "lab-preview",
    "production_ready": False,
    "version": version,
    "commit": None if source_dirty == "true" else commit,
    "source_state": {
        "git_head": commit,
        "dirty": source_dirty == "true",
        "attribution": source_attribution,
        "diff_sha256": source_diff_hash,
        "diff_hash_format": source_diff_hash_format,
        "tracked_diff_sha256": source_tracked_diff_hash,
        "untracked_file_count": int(source_untracked_count),
        "status_entry_count": int(source_status_count),
    },
    "target_triple": target,
    "operating_system": "linux",
    "architecture": architecture,
    "created_at": created_at,
    "packaged_roles": ["host", "client"],
    "packaged_tools": ["identity"],
    "capabilities": {
        "transport": {
            "default": "quic_v1_tls13_exact_peer_mtls",
            "control": "independent_reliable_streams",
            "input": "independent_reliable_streams",
            "media": "quic_datagram_bounded_reassembly",
            "legacy": "plaintext_udp_requires_explicit_unsafe_udp_lab",
        },
        "host": {
            "windows": {
                "secure": "unsupported_fail_closed",
                "legacy": {
                    "capture": "synthetic_frames_only",
                    "input_injection": "no_op",
                },
            },
            "linux": "x11_capture_cpu_raw_nv12_xtest_input",
        },
        "client": {
            "windows": "strict_raw_nv12_d3d11_viewer",
            "linux": "headless_only",
        },
        "identity": "persistent_self_signed_der_exact_leaf_pin",
    },
    "known_limitations": {
        "video_codec": "none_raw_nv12_only",
        "nat_traversal_relay": "unavailable",
        "reconnect": "unavailable",
        "installer": "unavailable",
    },
    "artifacts": [
        {
            "name": host_name,
            "path": host_name,
            "sha256": host_hash,
            "size_bytes": int(host_size),
        },
        {
            "name": client_name,
            "path": client_name,
            "sha256": client_hash,
            "size_bytes": int(client_size),
        },
        {
            "name": identity_name,
            "path": identity_name,
            "sha256": identity_hash,
            "size_bytes": int(identity_size),
        },
    ],
    "archive_contents": archive_contents,
}

pathlib.Path(manifest_path).write_text(
    json.dumps(manifest, indent=2) + "\n",
    encoding="utf-8",
)
PY

printf '\n[4/5] Creating the allowlisted archive...\n'
mkdir -p -- "$OUTPUT_ROOT"
ARCHIVE_NAME="LatencyDesk-$VERSION-lab-preview-linux-$ARCHITECTURE.tar.gz"
ARCHIVE_PATH="$OUTPUT_ROOT/$ARCHIVE_NAME"
CHECKSUM_PATH="$ARCHIVE_PATH.sha256"
rm -f -- "$ARCHIVE_PATH" "$CHECKSUM_PATH"
tar -czf "$ARCHIVE_PATH" -C "$STAGING_DIR" "${ARCHIVE_CONTENTS[@]}"

ACTUAL_CONTENTS=$(tar -tzf "$ARCHIVE_PATH" | LC_ALL=C sort)
EXPECTED_CONTENTS=$(printf '%s\n' "${ARCHIVE_CONTENTS[@]}" | LC_ALL=C sort)
if [[ "$ACTUAL_CONTENTS" != "$EXPECTED_CONTENTS" ]]; then
    rm -f -- "$ARCHIVE_PATH"
    die "archive contents differ from the packaging allowlist"
fi

printf '\n[5/5] Writing the external SHA-256 checksum...\n'
ARCHIVE_HASH=$(sha256_file "$ARCHIVE_PATH")
printf '%s  %s\n' "$ARCHIVE_HASH" "$ARCHIVE_NAME" > "$CHECKSUM_PATH"

compute_source_state
if ! source_state_matches_build; then
    rm -f -- "$ARCHIVE_PATH" "$CHECKSUM_PATH"
    die "source state changed while creating the archive; removed outputs with mismatched provenance"
fi
PACKAGE_COMPLETE=true

printf 'Archive:  %s\n' "$ARCHIVE_PATH"
printf 'Checksum: %s\n' "$CHECKSUM_PATH"
printf 'WARNING: this is a lab-preview package; production wiring is incomplete.\n' >&2
