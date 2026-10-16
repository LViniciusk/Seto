<#
.SYNOPSIS
    Prepare the open external tools Seto needs, then prove what they can do.

.DESCRIPTION
    Seto never bundles or redistributes a toolchain.  This script prepares the
    *open* tools a matching workflow needs (splat, m2c, a MIPS objdump, Ghidra
    with the Allegrex processor, and optionally REA), and then hands the result
    to `seto toolchain --smoke`, which is the only thing allowed to say what a
    tool can do.

    Three modes, and the safe one is the default:

        (nothing)     detect, verify and report.  Changes nothing.
        -DryRun       print every command that would run.  Changes nothing.
        -Install      run those commands.

    What it never does: download the proprietary Metrowerks compiler, edit PATH
    or the registry, elevate privileges, or run anything through a shell string.
    A download without a sha256 in `config/toolchain.lock` is refused.

.PARAMETER DryRun
    Print the plan and stop.

.PARAMETER Install
    Execute the plan.

.PARAMETER Tool
    Restrict everything to these tools (repeatable).  Default: all of them.

.PARAMETER Report
    Where to write the JSON capability report (default: build/toolchain-report.json).

.PARAMETER Workspace
    Keep the smoke test's synthetic inputs and artefacts here.

.EXAMPLE
    pwsh scripts/bootstrap_toolchain.ps1 -DryRun

.EXAMPLE
    pwsh scripts/bootstrap_toolchain.ps1 -Install -Tool splat -Tool m2c -Tool objdump
#>
[CmdletBinding()]
param(
    [switch]$DryRun,
    [switch]$Install,
    [string[]]$Tool = @(),
    [string]$Report = "build/toolchain-report.json",
    [string]$Workspace = "",
    [string]$LockFile = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

#: Every tool this script knows how to prepare.  `mwccpsp` is listed so the
#: report and the summary can mention it, but it is never downloaded.
$KnownTools = @("splat", "m2c", "objdump", "ghidra", "rea", "wibo", "wine", "mwccpsp")

if ($DryRun -and $Install) {
    throw "-DryRun and -Install are mutually exclusive"
}

$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$LockPath = if ($LockFile) {
    $LockFile
}
else {
    Join-Path $RepoRoot "config/toolchain.lock"
}
$BootstrapConfigPath = Join-Path $RepoRoot "config/seto.bootstrap.toml"
$ToolsRoot = if ($env:SETO_TOOLS) { $env:SETO_TOOLS } else { Join-Path $HOME ".seto" }
$DownloadsRoot = Join-Path $ToolsRoot "downloads"
$InstallRoot = Join-Path $ToolsRoot "tools"
$script:PacmanCommand = $null

function Read-Lock {
    param([string]$Path)
    $lock = @{}
    foreach ($line in Get-Content -LiteralPath $Path) {
        $trimmed = $line.Trim()
        if (-not $trimmed -or $trimmed.StartsWith("#")) { continue }
        $index = $trimmed.IndexOf("=")
        if ($index -lt 1) { continue }
        $lock[$trimmed.Substring(0, $index).Trim()] = $trimmed.Substring($index + 1).Trim()
    }
    return $lock
}

function Resolve-Python {
    $candidates = @()
    if ($env:SETO_PYTHON) { $candidates += @{ exe = $env:SETO_PYTHON; args = @() } }
    $candidates += @(
        @{ exe = "py"; args = @("-3.12") },
        @{ exe = "py"; args = @("-3.11") },
        @{ exe = "py"; args = @("-3") },
        @{ exe = "python3"; args = @() },
        @{ exe = "python"; args = @() }
    )
    foreach ($candidate in $candidates) {
        $probe = $null
        try {
            $probe = & $candidate.exe @($candidate.args + @(
                    "-c", "import sys; print('%d %d' % sys.version_info[:2])"
                )) 2>$null
        }
        catch { continue }
        if ($LASTEXITCODE -ne 0 -or -not $probe) { continue }
        $parts = @($probe -split "\s+" | Where-Object { $_ })
        if ($parts.Count -lt 2) { continue }
        if ([int]$parts[0] -eq 3 -and [int]$parts[1] -ge 11) { return $candidate }
    }
    throw "no Python 3.11+ interpreter found; install one or set PATH to include it"
}

function Invoke-Python {
    param([string[]]$Arguments, [switch]$Quiet)
    if ($Quiet) {
        & $Python.exe @($Python.args + $Arguments) | Out-Null
    }
    else {
        & $Python.exe @($Python.args + $Arguments)
    }
    return $LASTEXITCODE
}

function Invoke-Seto {
    param([string[]]$Arguments)
    $env:PYTHONPATH = Join-Path $RepoRoot "src"
    return Invoke-Python (@("-m", "seto") + $Arguments)
}

function Test-Sha256 {
    param([string]$Path, [string]$Expected)
    if (-not $Expected -or $Expected -eq "PLACEHOLDER") { return $false }
    $code = Invoke-Python @(
        (Join-Path $RepoRoot "scripts/safe_extract.py"), "--verify-sha256", $Path, $Expected
    ) -Quiet
    return $code -eq 0
}

function Get-VerifiedDownload {
    param([string]$Url, [string]$Destination, [string]$Sha256)
    if (-not $Sha256 -or $Sha256 -eq "PLACEHOLDER") {
        throw "refusing to download $Url`: config/toolchain.lock carries no sha256 for it"
    }
    if (Test-Path -LiteralPath $Destination) {
        if (Test-Sha256 -Path $Destination -Expected $Sha256) {
            Write-Host "    cached and verified: $Destination"
            return
        }
        Write-Host "    cached copy failed its checksum; downloading again"
        Remove-Item -LiteralPath $Destination -Force
    }
    New-Item -ItemType Directory -Force -Path (Split-Path -Parent $Destination) | Out-Null
    Write-Host "    downloading $Url"
    Invoke-WebRequest -Uri $Url -OutFile $Destination -UseBasicParsing
    if (-not (Test-Sha256 -Path $Destination -Expected $Sha256)) {
        Remove-Item -LiteralPath $Destination -Force
        throw "checksum mismatch for $Url"
    }
    Write-Host "    sha256 verified"
}

function Expand-Zip {
    param([string]$Path, [string]$Destination)
    $code = Invoke-Python @(
        (Join-Path $RepoRoot "scripts/safe_extract.py"), $Path, $Destination
    ) -Quiet
    if ($code -ne 0) { throw "safe extraction rejected or could not extract $Path" }
}

function New-PipEnvironment {
    param([string]$Name)
    $venv = Join-Path $ToolsRoot "venvs/$Name"
    if (-not (Test-Path -LiteralPath (Join-Path $venv "Scripts/python.exe"))) {
        Write-Host "    creating an isolated environment at $venv"
        [void](Invoke-Python @("-m", "venv", $venv))
    }
    return $venv
}

function Add-LocalToolPath {
    param([hashtable]$Settings, [string]$Name, [string]$Value)
    $Settings[$Name] = $Value
}

function Write-LocalConfig {
    param([hashtable]$Settings)
    if ($Settings.Count -eq 0) { return }
    $lines = @(
        "# Generated by scripts/bootstrap_toolchain.ps1 - machine-local tool paths.",
        "# Not committed (see .gitignore).  `seto` merges this over config/seto.toml."
    )
    foreach ($name in ($Settings.Keys | Sort-Object)) {
        $lines += ""
        $lines += "[tools.$name]"
        $pathText = $Settings[$name].Replace('\', '/')
        $escapedPath = ConvertTo-Json -InputObject $pathText -Compress
        $lines += "path = $escapedPath"
    }
    # No BOM: the file is TOML, and tomllib rejects a byte-order mark.
    $encoding = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($BootstrapConfigPath, ($lines -join "`n"), $encoding)
    Write-Host "  wrote $BootstrapConfigPath"
}

function Read-LocalConfig {
    param([hashtable]$Settings)
    if (-not (Test-Path -LiteralPath $BootstrapConfigPath)) { return }
    $section = $null
    foreach ($line in Get-Content -LiteralPath $BootstrapConfigPath) {
        if ($line -match '^\s*\[tools\.([a-zA-Z0-9_-]+)\]\s*$') {
            $section = $Matches[1]
        }
        elseif ($section -and $line -match '^\s*path\s*=\s*"(.*)"\s*$') {
            $Settings[$section] = $Matches[1]
        }
    }
}

function Get-Plan {
    param([hashtable]$Lock, [string]$Name, [hashtable]$LocalSettings)

    $plan = @()
    switch ($Name) {
        "splat" {
            $venv = Join-Path $ToolsRoot "venvs/splat"
            $binary = Join-Path $venv "Scripts/splat.exe"
            $plan += @{
                Describe = "create an isolated environment and install splat64[mips]==$($Lock['splat'])"
                Run      = {
                    $venv = New-PipEnvironment -Name "splat"
                    $python = Join-Path $venv "Scripts/python.exe"
                    & $python -m pip install --disable-pip-version-check --quiet `
                        --index-url $Lock["pypi_index"] `
                        "splat64[mips]==$($Lock['splat'])"
                    if ($LASTEXITCODE -ne 0) { throw "pip could not install splat64[mips]" }
                    Add-LocalToolPath -Settings $LocalSettings -Name "splat" `
                        -Value (Join-Path $venv "Scripts/splat.exe")
                }
            }
        }
        "m2c" {
            $plan += @{
                Describe = "create an isolated environment and install m2c from commit $($Lock['m2c_commit'].Substring(0, 12))"
                Run      = {
                    $venv = New-PipEnvironment -Name "m2c"
                    $python = Join-Path $venv "Scripts/python.exe"
                    & $python -m pip install --disable-pip-version-check --quiet `
                        --index-url $Lock["pypi_index"] `
                        "m2c @ git+$($Lock['m2c_url'])@$($Lock['m2c_commit'])"
                    if ($LASTEXITCODE -ne 0) { throw "pip could not install m2c" }
                    Add-LocalToolPath -Settings $LocalSettings -Name "m2c" `
                        -Value (Join-Path $venv "Scripts/m2c.exe")
                }
            }
        }
        "objdump" {
            $pacman = Get-Command pacman -ErrorAction SilentlyContinue
            if ($pacman) {
                $script:PacmanCommand = $pacman.Source
            }
            else {
                $msysRoot = if ($env:MSYS2_ROOT) { $env:MSYS2_ROOT } else { "C:\msys64" }
                $candidate = Join-Path $msysRoot "usr/bin/pacman.exe"
                if (Test-Path -LiteralPath $candidate) { $script:PacmanCommand = $candidate }
            }
            if ($script:PacmanCommand) {
                $plan += @{
                    Describe = "install pinned LLVM $($Lock['msys2_llvm']) from the MSYS2 UCRT64 repository (then smoke-test MIPS compatibility)"
                    Run      = {
                        & $script:PacmanCommand -S --noconfirm --needed `
                            "mingw-w64-ucrt-x86_64-llvm=$($Lock['msys2_llvm'])"
                        if ($LASTEXITCODE -ne 0) { throw "pacman could not install llvm" }
                    }
                }
            }
            else {
                $plan += @{
                    Describe = "NOTE: no MIPS objdump found and no package manager to install one; provide one and set [tools.objdump] path"
                    Run      = { }
                }
            }
        }
        "ghidra" {
            $plan += @{
                Describe = "download and verify Ghidra $($Lock['ghidra']) into $InstallRoot"
                Run      = {
                    Get-VerifiedDownload -Url $Lock["ghidra_url"] `
                        -Destination (Join-Path $DownloadsRoot $Lock["ghidra_zip"]) `
                        -Sha256 $Lock["ghidra_sha256"]
                    $ghidraHome = Join-Path $InstallRoot "ghidra_$($Lock['ghidra'])_PUBLIC"
                    if (
                        -not (Test-Path -LiteralPath (Join-Path $ghidraHome "support/analyzeHeadless.bat")) -and
                        -not (Test-Path -LiteralPath (Join-Path $ghidraHome "support/analyzeHeadless"))
                    ) {
                        Expand-Zip -Path (Join-Path $DownloadsRoot $Lock["ghidra_zip"]) -Destination $InstallRoot
                    }
                    Add-LocalToolPath -Settings $LocalSettings -Name "ghidra" `
                        -Value $ghidraHome
                }
            }
            $plan += @{
                Describe = "download, verify and install the Allegrex processor module $($Lock['ghidra_allegrex'])"
                Run      = {
                    $target = Join-Path $InstallRoot "ghidra_$($Lock['ghidra'])_PUBLIC/Ghidra/Extensions"
                    $marker = Join-Path $target "ghidra-allegrex/data/languages/allegrex.ldefs"
                    if (Test-Path -LiteralPath $marker) {
                        Write-Host "    Allegrex extension already present"
                    }
                    else {
                        $staging = Join-Path $ToolsRoot ("staging/ghidra-allegrex-" + [guid]::NewGuid().ToString("N"))
                        Get-VerifiedDownload -Url $Lock["ghidra_allegrex_url"] `
                            -Destination (Join-Path $DownloadsRoot $Lock["ghidra_allegrex_zip"]) `
                            -Sha256 $Lock["ghidra_allegrex_sha256"]
                        Expand-Zip -Path (Join-Path $DownloadsRoot $Lock["ghidra_allegrex_zip"]) -Destination $staging
                        New-Item -ItemType Directory -Force -Path $target | Out-Null
                        Copy-Item -Recurse -Force (Join-Path $staging "ghidra-allegrex") $target
                        Remove-Item -Recurse -Force $staging
                    }
                }
            }
        }
        "rea" {
            $plan += @{
                Describe = "install pinned rea-agents in an isolated npm prefix under $ToolsRoot (opt-in)"
                Run      = {
                    $prefix = Join-Path $ToolsRoot "npm/rea"
                    & npm install --prefix $prefix --no-save --ignore-scripts `
                        --registry $Lock["npm_registry"] "rea-agents@$($Lock['rea'])"
                    if ($LASTEXITCODE -ne 0) { throw "npm could not install rea-agents" }
                    Add-LocalToolPath -Settings $LocalSettings -Name "rea" `
                        -Value (Join-Path $prefix "node_modules/.bin/rea.cmd")
                }
            }
        }
        "wibo" {
            $plan += @{
                Describe = "NOT_APPLICABLE on native Windows; use WSL2 for wibo or Wine"
                Run      = { }
            }
        }
        "wine" {
            $plan += @{
                Describe = "NOT_APPLICABLE on native Windows; Wine is only a Linux/macOS compatibility layer"
                Run      = { }
            }
        }
        "mwccpsp" {
            $plan += @{
                Describe = "NOTE: the Metrowerks PSP compiler is proprietary and is never downloaded; supply it and set SETO_MWCCPSP or [tools.mwccpsp] path"
                Run      = { }
            }
        }
        default { throw "unknown tool: $Name" }
    }
    return $plan
}

# ------------------------------------------------------------------------ main

if (-not (Test-Path -LiteralPath $LockPath)) { throw "missing $LockPath" }
$Lock = Read-Lock -Path $LockPath
$Python = Resolve-Python

$selected = if ($Tool.Count -gt 0) {
    @($Tool | ForEach-Object { $_ -split "," } | Where-Object { $_ })
}
else { $KnownTools }
foreach ($name in $selected) {
    if ($KnownTools -notcontains $name) { throw "unknown tool: $name" }
}

Write-Host "seto toolchain bootstrap"
Write-Host "  repository : $RepoRoot"
Write-Host "  tools root : $ToolsRoot"
Write-Host "  python     : $($Python.exe) $($Python.args -join ' ')"
Write-Host "  mode       : $(if ($Install) { 'install' } elseif ($DryRun) { 'dry run' } else { 'report only' })"
Write-Host ""
Write-Host "This script never edits PATH or the registry, never elevates privileges and"
Write-Host "never downloads the proprietary compiler."
Write-Host ""

$LocalSettings = @{}
Read-LocalConfig -Settings $LocalSettings
foreach ($name in $selected) {
    Write-Host "$name"
    foreach ($step in (Get-Plan -Lock $Lock -Name $name -LocalSettings $LocalSettings)) {
        Write-Host "  - $($step.Describe)"
        if ($Install) { & $step.Run }
    }
}
if ($Install) { Write-LocalConfig -Settings $LocalSettings }

# ------------------------------------------------------------------- verification

$reportPath = if ([System.IO.Path]::IsPathRooted($Report)) { $Report } else { Join-Path $RepoRoot $Report }
New-Item -ItemType Directory -Force -Path (Split-Path -Parent $reportPath) | Out-Null

$smokeArguments = @("toolchain", "--smoke", "--json", "--out", $reportPath)
foreach ($name in $selected) { $smokeArguments += @("--tool", $name) }
if ($Workspace) { $smokeArguments += @("--smoke-workspace", $Workspace) }

Write-Host ""
Write-Host "verifying with: seto $($smokeArguments -join ' ')"
$code = Invoke-Python (@("-m", "seto") + $smokeArguments) -Quiet
if ($code -ne 0) { throw "seto toolchain --smoke failed (exit $code)" }

$capabilities = Get-Content -LiteralPath $reportPath -Raw | ConvertFrom-Json
$unusable = @()
$failedCapabilities = @()
$unproven = @()
Write-Host ""
Write-Host "capabilities"
foreach ($entry in $capabilities.tools) {
    Write-Host ("  {0,-9} {1}" -f $entry.name, $entry.capability)
    foreach ($capability in $entry.capabilities) {
        Write-Host ("    {0,-16} {1}  {2}" -f $capability.name, $capability.state, $capability.detail)
        if ($capability.state -in @("INCOMPATIBLE", "UNSUPPORTED", "BLOCKED")) {
            $unproven += "$($entry.name)/$($capability.name)"
        }
        if ($capability.state -in @("MISSING", "INCOMPATIBLE", "UNSUPPORTED")) {
            $failedCapabilities += "$($entry.name)/$($capability.name)"
        }
    }
    if ($entry.capability -in @("MISSING", "INCOMPATIBLE", "UNSUPPORTED", "BLOCKED")) {
        $unusable += $entry.name
    }
}

Write-Host ""
if ($unproven.Count -gt 0) {
    Write-Host "capabilities nobody has demonstrated here: $($unproven -join ', ')"
}
if ($unusable.Count -eq 0 -and $failedCapabilities.Count -eq 0) {
    Write-Host "all demonstrated core capabilities passed; see the report for blocked/unproven capabilities"
    Write-Host "report: $reportPath"
    exit 0
}
if ($unusable.Count -gt 0) { Write-Host "still not usable: $($unusable -join ', ')" }
if ($failedCapabilities.Count -gt 0) {
    Write-Host "failed capabilities: $(($failedCapabilities | Select-Object -Unique) -join ', ')"
}
Write-Host "report: $reportPath"
exit 4
