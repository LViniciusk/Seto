#!/usr/bin/env bash
#
# Prepare the open external tools Seto needs, then prove what they can do.
#
# Seto never bundles or redistributes a toolchain.  This script prepares the
# *open* tools a matching workflow needs (splat, m2c, a MIPS objdump, Ghidra
# with the Allegrex processor, and optionally REA), and then hands the result to
# `seto toolchain --smoke`, which is the only thing allowed to say what a tool
# can do.
#
# Three modes, and the safe one is the default:
#
#     (nothing)      detect, verify and report.  Changes nothing.
#     --dry-run      print every command that would run.  Changes nothing.
#     --install      run those commands.
#
# What it never does: download the proprietary Metrowerks compiler, edit PATH or
# a shell profile, or run anything through `eval`.  A download without a sha256
# in config/toolchain.lock is refused, and a step that needs root prints the
# exact command instead of elevating silently.
#
# Usage:
#     scripts/bootstrap_toolchain.sh [--dry-run | --install]
#                                    [--tool NAME]... [--report PATH]
#                                    [--workspace DIR] [--config PATH]
#
# Examples:
#     scripts/bootstrap_toolchain.sh --dry-run
#     scripts/bootstrap_toolchain.sh --install --tool splat --tool m2c

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LOCK_FILE="$REPO_ROOT/config/toolchain.lock"
CONFIG_INPUT="config/seto.toml"
CONFIG_PATH=""
BOOTSTRAP_CONFIG=""
TOOLS_ROOT="${SETO_TOOLS:-$HOME/.seto}"

#: Every tool this script knows how to prepare.  `mwccpsp` is listed so the
#: report and the summary can mention it, but it is never downloaded.
KNOWN_TOOLS="splat m2c objdump ghidra rea wibo wine mwccpsp"

DRY_RUN=0
INSTALL=0
REPORT="build/toolchain-report.json"
WORKSPACE=""
SELECTED=()

usage() {
    cat <<'TEXT'
Prepare the open external tools Seto needs, then prove what they can do.

Usage:
    scripts/bootstrap_toolchain.sh [--dry-run | --install]
                                   [--tool NAME]... [--report PATH]
                                   [--workspace DIR] [--config PATH]

Modes (the safe one is the default):
    (nothing)   detect, verify and report.  Changes nothing.
    --dry-run   print every command that would run.  Changes nothing.
    --install   run those commands.

Tools: splat m2c objdump ghidra rea wibo wine mwccpsp
TEXT
}

while [ $# -gt 0 ]; do
    case "$1" in
        --dry-run) DRY_RUN=1 ;;
        --install) INSTALL=1 ;;
        --tool) shift; SELECTED+=("$1") ;;
        --tool=*) SELECTED+=("${1#--tool=}") ;;
        --report) shift; REPORT="$1" ;;
        --report=*) REPORT="${1#--report=}" ;;
        --lock-file) shift; LOCK_FILE="$1" ;;
        --lock-file=*) LOCK_FILE="${1#--lock-file=}" ;;
        --workspace) shift; WORKSPACE="$1" ;;
        --workspace=*) WORKSPACE="${1#--workspace=}" ;;
        --config) shift; CONFIG_INPUT="$1" ;;
        --config=*) CONFIG_INPUT="${1#--config=}" ;;
        -h | --help) usage; exit 0 ;;
        *) printf 'unknown option: %s\n' "$1" >&2; exit 1 ;;
    esac
    shift
done

if [ "$DRY_RUN" -eq 1 ] && [ "$INSTALL" -eq 1 ]; then
    printf -- '--dry-run and --install are mutually exclusive\n' >&2
    exit 1
fi

if [ "${#SELECTED[@]}" -eq 0 ]; then
    read -r -a SELECTED <<<"$KNOWN_TOOLS"
fi
# Accept `--tool a,b` as well as `--tool a --tool b`.
SPLIT_TOOLS=()
for name in "${SELECTED[@]}"; do
    IFS=',' read -r -a parts <<<"$name"
    SPLIT_TOOLS+=("${parts[@]}")
done
SELECTED=("${SPLIT_TOOLS[@]}")
for name in "${SELECTED[@]}"; do
    case " $KNOWN_TOOLS " in
        *" $name "*) ;;
        *) printf 'unknown tool: %s\n' "$name" >&2; exit 1 ;;
    esac
done

# ------------------------------------------------------------------- helpers

lock_value() {
    sed -n "s/^$1=//p" "$LOCK_FILE" | tr -d '\r' | head -n 1
}

find_python() {
    local candidate
    for candidate in "${SETO_PYTHON:-}" python3 python; do
        [ -n "$candidate" ] || continue
        if command -v "$candidate" >/dev/null 2>&1 &&
            "$candidate" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 11) else 1)' \
                >/dev/null 2>&1; then
            printf '%s' "$candidate"
            return 0
        fi
    done
    return 1
}

resolve_config_path() {
    "$PYTHON" - "$REPO_ROOT" "$CONFIG_INPUT" <<'PY'
import sys
import os
from pathlib import Path

root = Path(sys.argv[1]).resolve()
requested = Path(sys.argv[2])
candidate = requested if requested.is_absolute() else root / requested
config_root = root / "config"
candidate = Path(os.path.abspath(candidate))
if not candidate.is_relative_to(config_root):
    raise SystemExit(f"config must be a regular file under {config_root}: {candidate}")
for component in (candidate, *candidate.parents):
    if component.is_symlink():
        raise SystemExit(f"refusing symlinked config path: {component}")
try:
    resolved = candidate.resolve(strict=True)
    config_root = config_root.resolve(strict=True)
except OSError as exc:
    raise SystemExit(f"cannot resolve config path: {exc}") from exc
if not resolved.is_relative_to(config_root) or not resolved.is_file():
    raise SystemExit(f"config must be a regular file under {config_root}: {candidate}")
print(resolved)
PY
}

#: Print a step, and run it only when --install was asked for.
run_step() {
    local description="$1"
    shift
    printf '  - %s\n' "$description"
    if [ "$INSTALL" -eq 1 ]; then "$@"; fi
}

#: Run a command that needs root: as root, or through sudo when sudo can work
#: without a password, otherwise print the exact command and change nothing.
run_as_root() {
    if [ "$(id -u)" -eq 0 ]; then
        "$@"
    elif command -v sudo >/dev/null 2>&1; then
        printf '    NOTICE: checking non-interactive sudo before running: sudo %s\n' "$*"
        if sudo -n true >/dev/null 2>&1; then
            printf '    NOTICE: running the package install with sudo (root privileges)\n'
            sudo "$@"
        else
            printf '    needs root; run this yourself:\n      sudo %s\n' "$*"
        fi
    else
        printf '    needs root; run this yourself:\n      sudo %s\n' "$*"
    fi
}

require_sha256() {
    local url="$1" sha="$2"
    if [ -z "$sha" ] || [ "$sha" = "PLACEHOLDER" ]; then
        printf 'refusing to download %s: config/toolchain.lock carries no sha256 for it\n' \
            "$url" >&2
        exit 1
    fi
}

download_verified() {
    local url="$1" destination="$2" sha="$3"
    require_sha256 "$url" "$sha"
    mkdir -p "$(dirname "$destination")"
    if [ -f "$destination" ] && \
        "$PYTHON" "$REPO_ROOT/scripts/safe_extract.py" --verify-sha256 "$destination" "$sha"; then
        printf '    cached and verified: %s\n' "$destination"
        return 0
    fi
    rm -f "$destination"
    printf '    downloading %s\n' "$url"
    curl -fsSL -o "$destination" "$url"
    if ! "$PYTHON" "$REPO_ROOT/scripts/safe_extract.py" --verify-sha256 "$destination" "$sha"; then
        rm -f "$destination"
        printf 'checksum mismatch for %s\n' "$url" >&2
        exit 1
    fi
    printf '    sha256 verified\n'
}

new_pip_environment() {
    local name="$1"
    local venv="$TOOLS_ROOT/venvs/$name"
    if [ ! -x "$venv/bin/python" ]; then
        printf '    creating an isolated environment at %s\n' "$venv" >&2
        "$PYTHON" -m venv "$venv"
    fi
    printf '%s' "$venv"
}

LOCAL_ENTRIES="$(mktemp)"
trap 'rm -f "$LOCAL_ENTRIES"' EXIT

record_path() {
    printf '%s=%s\n' "$1" "$2" >>"$LOCAL_ENTRIES"
}

write_local_config() {
    [ -s "$LOCAL_ENTRIES" ] || return 0
    "$PYTHON" - "$LOCAL_ENTRIES" "$BOOTSTRAP_CONFIG" <<'PY'
import json
import sys
from pathlib import Path

entries = {}
for line in Path(sys.argv[1]).read_text(encoding="utf-8").splitlines():
    name, value = line.split("=", 1)
    entries[name] = value

lines = [
    "# Generated by scripts/bootstrap_toolchain.sh - machine-local tool paths.",
    "# Not committed (see .gitignore); user overrides belong in seto.local.toml.",
]
for name, value in sorted(entries.items()):
    lines.extend(("", f"[tools.{name}]", f"path = {json.dumps(value)}"))
Path(sys.argv[2]).write_text("\n".join(lines) + "\n", encoding="utf-8")
PY
    printf '  wrote %s\n' "$BOOTSTRAP_CONFIG"
}

load_local_config() {
    [ -f "$BOOTSTRAP_CONFIG" ] || return 0
    "$PYTHON" - "$BOOTSTRAP_CONFIG" >>"$LOCAL_ENTRIES" <<'PY'
import sys
import tomllib
from pathlib import Path

data = tomllib.loads(Path(sys.argv[1]).read_text(encoding="utf-8-sig"))
for name, settings in sorted(data.get("tools", {}).items()):
    path = settings.get("path")
    if path:
        print(f"{name}={path}")
PY
}

# ------------------------------------------------------------------ the plans

install_splat() {
    local venv
    venv="$(new_pip_environment splat)"
    "$venv/bin/python" -m pip install --disable-pip-version-check --quiet \
        --index-url "$(lock_value pypi_index)" \
        "splat64[mips]==$(lock_value splat)"
    record_path splat "$venv/bin/splat"
}

plan_splat() {
    run_step "create an isolated environment and install splat64[mips]==$(lock_value splat)" \
        install_splat
}

install_m2c() {
    local venv
    venv="$(new_pip_environment m2c)"
    "$venv/bin/python" -m pip install --disable-pip-version-check --quiet \
        --index-url "$(lock_value pypi_index)" \
        "m2c @ git+$(lock_value m2c_url)@$(lock_value m2c_commit)"
    record_path m2c "$venv/bin/m2c"
}

plan_m2c() {
    run_step "create an isolated environment and install m2c from commit $(lock_value m2c_commit | cut -c1-12)" \
        install_m2c
}

install_objdump_apt() {
    run_as_root apt-get install -y binutils-mipsel-linux-gnu
}

install_objdump_dnf() {
    run_as_root dnf install -y llvm
}

install_objdump_brew() {
    brew install llvm
    record_path objdump "$(brew --prefix llvm)/bin/llvm-objdump"
}

plan_objdump() {
    if command -v apt-get >/dev/null 2>&1; then
        run_step "install the MIPS GNU binutils with apt (binutils-mipsel-linux-gnu)" \
            install_objdump_apt
    elif command -v dnf >/dev/null 2>&1; then
        run_step "install LLVM with dnf (a MIPS-capable llvm-objdump)" install_objdump_dnf
    elif command -v brew >/dev/null 2>&1; then
        run_step "install LLVM with Homebrew (a MIPS-capable llvm-objdump)" \
            install_objdump_brew
    else
        printf '  - NOTE: no MIPS objdump found and no package manager to install one; provide one and set [tools.objdump] path\n'
    fi
}

install_ghidra() {
    local zip="$TOOLS_ROOT/downloads/$(lock_value ghidra_zip)"
    local home="$TOOLS_ROOT/tools/ghidra_$(lock_value ghidra)_PUBLIC"
    download_verified "$(lock_value ghidra_url)" "$zip" "$(lock_value ghidra_sha256)"
    if [ ! -f "$home/support/analyzeHeadless" ] && \
        [ ! -f "$home/support/analyzeHeadless.bat" ]; then
        mkdir -p "$TOOLS_ROOT/tools"
        "$PYTHON" "$REPO_ROOT/scripts/safe_extract.py" "$zip" "$TOOLS_ROOT/tools"
    fi
    # ZIP permissions from Windows-created release archives can lose Unix
    # executable bits. Restore only the user bit on Ghidra's POSIX launchers.
    for launcher in "$home/support/analyzeHeadless" "$home/support/launch.sh" "$home/ghidraRun"; do
        if [ -f "$launcher" ]; then chmod u+x "$launcher"; fi
    done
    record_path ghidra "$home"
}

plan_ghidra() {
    run_step "download and verify Ghidra $(lock_value ghidra) into $TOOLS_ROOT/tools" \
        install_ghidra
    run_step "download, verify and install the Allegrex processor module $(lock_value ghidra_allegrex)" \
        install_allegrex
}

install_allegrex() {
    local zip="$TOOLS_ROOT/downloads/$(lock_value ghidra_allegrex_zip)"
    local target="$TOOLS_ROOT/tools/ghidra_$(lock_value ghidra)_PUBLIC/Ghidra/Extensions"
    local marker="$target/ghidra-allegrex/data/languages/allegrex.ldefs"
    if [ -f "$marker" ]; then
        printf '    Allegrex extension already present\n'
        return 0
    fi
    local staging
    mkdir -p "$TOOLS_ROOT/staging"
    staging="$(mktemp -d "$TOOLS_ROOT/staging/ghidra-allegrex.XXXXXXXX")"
    download_verified "$(lock_value ghidra_allegrex_url)" "$zip" \
        "$(lock_value ghidra_allegrex_sha256)"
    "$PYTHON" "$REPO_ROOT/scripts/safe_extract.py" "$zip" "$staging"
    mkdir -p "$target"
    cp -R "$staging/ghidra-allegrex" "$target/"
    rm -rf "$staging"
}

install_rea() {
    local prefix="$TOOLS_ROOT/npm/rea"
    npm install --prefix "$prefix" --no-save --ignore-scripts \
        --registry "$(lock_value npm_registry)" \
        "rea-agents@$(lock_value rea)"
    record_path rea "$prefix/node_modules/.bin/rea"
}

plan_rea() {
    run_step "install pinned rea-agents in an isolated npm prefix under $TOOLS_ROOT (opt-in)" \
        install_rea
}

wibo_release() {
    local os arch
    os="$(uname -s)"
    arch="$(uname -m)"
    case "$os:$arch" in
        Linux:x86_64 | Linux:amd64) printf '%s' linux_x86_64 ;;
        Linux:i386 | Linux:i686) printf '%s' linux_i686 ;;
        Darwin:x86_64) printf '%s' macos_x86_64 ;;
        *) return 1 ;;
    esac
}

install_wibo() {
    local key url sha name destination
    key="$(wibo_release)" || {
        printf '    no pinned wibo 1.2.0 binary for this host; use Wine or build from the official source\n'
        return 0
    }
    url="$(lock_value "wibo_${key}_url")"
    sha="$(lock_value "wibo_${key}_sha256")"
    name="${url##*/}"
    download_verified "$url" "$TOOLS_ROOT/downloads/$name" "$sha"
    destination="$TOOLS_ROOT/bin/wibo"
    mkdir -p "$(dirname "$destination")"
    cp "$TOOLS_ROOT/downloads/$name" "$destination"
    chmod 755 "$destination"
    record_path wibo "$destination"
}

plan_wibo() {
    local key
    if key="$(wibo_release)"; then
        run_step "download pinned wibo $(lock_value wibo) from the official decompals release, verify sha256 and install under $TOOLS_ROOT" \
            install_wibo
    else
        printf '  - NOTE: no pinned wibo release asset for this host; use Wine or build wibo from its official source\n'
    fi
}

plan_wine() {
    printf '  - NOTE: Wine is an alternative loader; wibo is preferred and no Wine package is installed automatically\n'
}

plan_mwccpsp() {
    printf '  - NOTE: the Metrowerks PSP compiler is proprietary and is never downloaded; supply it and set SETO_MWCCPSP or [tools.mwccpsp] path\n'
}

# ------------------------------------------------------------------------ main

[ -f "$LOCK_FILE" ] || {
    printf 'missing %s\n' "$LOCK_FILE" >&2
    exit 1
}

if ! PYTHON="$(find_python)"; then
    printf 'no Python 3.11+ interpreter found; install one or set SETO_PYTHON\n' >&2
    exit 1
fi
CONFIG_PATH="$(resolve_config_path)" || exit 1
BOOTSTRAP_CONFIG="$(dirname "$CONFIG_PATH")/seto.bootstrap.toml"
if [ -L "$BOOTSTRAP_CONFIG" ] || { [ -e "$BOOTSTRAP_CONFIG" ] && [ ! -f "$BOOTSTRAP_CONFIG" ]; }; then
    printf 'refusing unsafe bootstrap overlay: %s\n' "$BOOTSTRAP_CONFIG" >&2
    exit 1
fi
load_local_config

printf 'seto toolchain bootstrap\n'
printf '  repository : %s\n' "$REPO_ROOT"
printf '  tools root : %s\n' "$TOOLS_ROOT"
printf '  config     : %s\n' "$CONFIG_PATH"
printf '  python     : %s\n' "$PYTHON"
if [ "$INSTALL" -eq 1 ]; then
    printf '  mode       : install\n'
elif [ "$DRY_RUN" -eq 1 ]; then
    printf '  mode       : dry run\n'
else
    printf '  mode       : report only\n'
fi
printf '\nThis script never edits PATH or a shell profile and never downloads the\n'
printf 'proprietary compiler.\n\n'

case "$(uname -s)" in
    MINGW* | MSYS* | CYGWIN*)
        printf 'note: this is a Windows shell; the PowerShell variant\n'
        printf '      (scripts/bootstrap_toolchain.ps1) is the one that installs on Windows.\n\n'
        ;;
esac

for name in "${SELECTED[@]}"; do
    printf '%s\n' "$name"
    "plan_$name"
done
if [ "$INSTALL" -eq 1 ]; then write_local_config; fi

# --------------------------------------------------------------- verification

case "$REPORT" in
    /*) REPORT_PATH="$REPORT" ;;
    *) REPORT_PATH="$REPO_ROOT/$REPORT" ;;
esac
mkdir -p "$(dirname "$REPORT_PATH")"

SMOKE_ARGUMENTS=(--config "$CONFIG_PATH" toolchain --smoke --json --out "$REPORT_PATH")
for name in "${SELECTED[@]}"; do SMOKE_ARGUMENTS+=(--tool "$name"); done
if [ -n "$WORKSPACE" ]; then SMOKE_ARGUMENTS+=(--smoke-workspace "$WORKSPACE"); fi

printf '\nverifying with: seto %s\n' "${SMOKE_ARGUMENTS[*]}"
PYTHONPATH="$REPO_ROOT/src" "$PYTHON" -m seto "${SMOKE_ARGUMENTS[@]}" >/dev/null

printf '\ncapabilities\n'
UNUSABLE=()
FAILED_CAPABILITIES=()
UNPROVEN=()
while IFS=$'\t' read -r kind name state detail; do
    case "$kind" in
        T)
            printf '  %-9s %s\n' "$name" "$state"
            case "$state" in
                MISSING | INCOMPATIBLE | UNSUPPORTED | BLOCKED) UNUSABLE+=("$name") ;;
            esac
            ;;
        C)
            printf '    %s\n' "$detail"
            case "$state" in
                INCOMPATIBLE | UNSUPPORTED | BLOCKED) UNPROVEN+=("$name") ;;
            esac
            case "$state" in
                MISSING | INCOMPATIBLE | UNSUPPORTED) FAILED_CAPABILITIES+=("$name") ;;
            esac
            ;;
    esac
done < <("$PYTHON" - "$REPORT_PATH" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    report = json.load(handle)
for entry in report["tools"]:
    print(f'T\t{entry["name"]}\t{entry["capability"]}\t{entry["reason"] or ""}')
    for capability in entry["capabilities"]:
        print(
            f'C\t{entry["name"]}/{capability["name"]}\t{capability["state"]}\t'
            f'{capability["name"]:<16} {capability["state"]}  {capability["detail"]}'
        )
PY
)

printf '\n'
if [ "${#UNPROVEN[@]}" -gt 0 ]; then
    printf 'capabilities nobody has demonstrated here: %s\n' "$(IFS=', '; echo "${UNPROVEN[*]}")"
fi
if [ "${#UNUSABLE[@]}" -eq 0 ] && [ "${#FAILED_CAPABILITIES[@]}" -eq 0 ]; then
    printf 'all demonstrated core capabilities passed; see the report for blocked/unproven capabilities\n'
    printf 'report: %s\n' "$REPORT_PATH"
    exit 0
fi
if [ "${#UNUSABLE[@]}" -gt 0 ]; then
    printf 'still not usable: %s\n' "$(IFS=', '; echo "${UNUSABLE[*]}")"
fi
if [ "${#FAILED_CAPABILITIES[@]}" -gt 0 ]; then
    printf 'failed capabilities: %s\n' "$(IFS=', '; echo "${FAILED_CAPABILITIES[*]}")"
fi
printf 'report: %s\n' "$REPORT_PATH"
exit 4
