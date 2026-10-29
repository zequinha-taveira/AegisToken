# Builds the Universal RP2350 Firmware in release mode and converts it to UF2.
#
# Usage:  powershell -File scripts/build-uf2.ps1 [-Board universal|rp2350a|rp2350b|rp2354a|rp2354b]
#                                                [-BoardProfile <name>]
# Output: AegisToken-<version>.uf2 for `-Board universal` (single image for all
#         four variants: RP2350A/B + RP2354A/B), otherwise
#         AegisToken_<product>-<version>.uf2 (repository root), where <version>
#         is the workspace version from Cargo.toml and the RP2350A target uses
#         the `pico2` codename (e.g. AegisToken_pico2-0.1.0.uf2). A non-generic
#         board profile is appended to the product name.
#
# -BoardProfile selects the carrier identity and USB VID/PID (build.rs reads it
# from AEGIS_BOARD). Defaults to `generic`; see BoardProfile in
# board-generic-rp2350 for the supported third-party names
# (e.g. waveshare-rp2350-zero, pimoroni-tiny-2350). The authorized
# `yubikey5-lab` uses 1050:0407 (OTP+FIDO+CCID); its OTP HID protocol is an
# experimental read-only lab transport, NOT Yubico OTP/ykman otp. Laboratory-only;
# never distribute this identity.
#
# RP2354A/B share the RP2350A/B die and package and add 2 MiB in-package flash.
# For a production image, set AEGIS_UPDATE_VENDOR_PUBKEY to the release key
# (65-byte SEC1 hex, from scripts/gen-update-key.py) before running. Otherwise a
# development update key is embedded and a warning is printed.
#
# -Release builds a distributable image: it fails before compiling when
# AEGIS_UPDATE_VENDOR_PUBKEY is missing, malformed or the development key, and
# it turns the build-time gate on (AEGIS_RELEASE=1) for the firmware build.
# Without it the script builds a development image, which is not safe to ship.
#
# UF2 conversion needs picotool >= 2.0 (`uf2 convert` and RP2350 images do not
# exist in 1.x). The script resolves a converter before compiling and fails when
# none is usable, so it can never print `Wrote ...` for a stale UF2 left by a
# previous build. When picotool is absent or too old it falls back to elf2uf2-rs
# built from git (the published 2.2.0 is RP2040-only). Set PICOTOOL or ELF2UF2
# to the full path when the tool is not on PATH.

param(
    [ValidateSet("universal", "rp2350a", "rp2350b", "rp2354a", "rp2354b")]
    [string]$Board = "universal",
    [string]$BoardProfile = "generic",
    [switch]$Release
)

$ErrorActionPreference = "Stop"

if ($BoardProfile -eq "yubikey5-lab") {
    Write-Warning "yubikey5-lab uses Yubico VID 0x1050 / PID 0x0407 (OTP+FIDO+CCID). Its OTP HID is experimental, not compatible with Yubico OTP / ykman otp. Authorized lab only; do not distribute."
}

# Resolve a UF2 converter up front: a missing or 1.x tool would otherwise be
# discovered only after the firmware build, and a failed native command does
# not set $LASTEXITCODE, so an old check could report success while leaving a
# stale UF2 in place. picotool >= 2.0 is preferred (`uf2 convert` and RP2350
# support); the fallback is elf2uf2-rs built from git, because the published
# 2.2.0 only knows RP2040. Set PICOTOOL/ELF2UF2 to use a binary outside PATH.
$family = "rp2350-arm-s"
$picotoolProblem = $null
$picotool = if ($env:PICOTOOL) { $env:PICOTOOL } else { "picotool" }
$picotoolCmd = Get-Command $picotool -CommandType Application -ErrorAction SilentlyContinue
if (-not $picotoolCmd) {
    $picotoolProblem = "picotool not found"
} else {
    $picotool = $picotoolCmd.Source
    $picotoolVersion = (& $picotool version | Out-String)
    $picotoolMatch = [regex]::Match($picotoolVersion, "v(\d+)\.(\d+)")
    if (-not $picotoolMatch.Success -or [int]$picotoolMatch.Groups[1].Value -lt 2) {
        $picotoolProblem = "picotool >= 2.0 is required for 'uf2 convert' and RP2350 images; found: " +
            $picotoolVersion.Trim()
    }
}

$converter = $null
if (-not $picotoolProblem) {
    $converter = "picotool"
} elseif ($env:PICOTOOL) {
    # An explicit PICOTOOL is a configuration decision: do not silently switch.
    throw ("PICOTOOL is set but unusable: " + $picotoolProblem)
} else {
    $elf2uf2 = if ($env:ELF2UF2) { $env:ELF2UF2 } else { "elf2uf2-rs" }
    $elf2uf2Cmd = Get-Command $elf2uf2 -CommandType Application -ErrorAction SilentlyContinue
    if (-not $elf2uf2Cmd) {
        throw ("no UF2 converter found: " + $picotoolProblem + "; elf2uf2-rs is not on PATH " +
            "either. Install picotool >= 2.0, or elf2uf2-rs from git (the published 2.2.0 is " +
            "RP2040-only): cargo install --git https://github.com/JoNil/elf2uf2-rs elf2uf2-rs")
    }
    $elf2uf2 = $elf2uf2Cmd.Source
    $elf2uf2Help = (& $elf2uf2 convert --help | Out-String)
    if ($elf2uf2Help -notmatch [regex]::Escape($family)) {
        throw ("elf2uf2-rs does not support '$family' (RP2350); install the git build with " +
            "'cargo install --git https://github.com/JoNil/elf2uf2-rs elf2uf2-rs'. " + $picotoolProblem)
    }
    $converter = "elf2uf2-rs"
}

$target = "thumbv8m.main-none-eabihf"
$bin = "firmware-universal-rp2350"
$elf = "target/$target/release/$bin"

# Read the workspace version from the root Cargo.toml.
$manifest = Join-Path $PSScriptRoot "..\Cargo.toml"
$match = Select-String -LiteralPath $manifest -Pattern '^version\s*=\s*"([^"]+)"' |
    Select-Object -First 1
if (-not $match) { throw "could not read version from $manifest" }
$version = $match.Matches[0].Groups[1].Value

# `universal` produces the single unified image AegisToken-<version>.uf2 that
# runs on all four variants (RP2350A/B + RP2354A/B: same die, runtime package
# detection, same QSPI flash driver with a conservative 2 MiB layout).
# Per-variant targets keep the legacy AegisToken_<product>-<version>.uf2 names.
if ($Board -eq "universal") {
    if ($BoardProfile -eq "generic") {
        $out = "AegisToken-$version.uf2"
    } else {
        $out = "AegisToken-$BoardProfile-$version.uf2"
    }
} else {
    # RP2350A maps to the Pico 2 product codename; other boards keep the board name.
    $product = if ($Board -eq "rp2350a") { "pico2" } else { $Board }
    if ($BoardProfile -ne "generic") { $product = "$product-$BoardProfile" }
    $out = "AegisToken_$product-$version.uf2"
}

if ($Release) {
    # A distributable image may not embed the development update key: its
    # private key is the number 1, so anyone could sign an accepted update.
    if (-not $env:AEGIS_UPDATE_VENDOR_PUBKEY) {
        throw ("AEGIS_UPDATE_VENDOR_PUBKEY is not set: a release image may not embed the " +
            "DEVELOPMENT firmware-update key. Set it to the release key (65-byte SEC1 hex, " +
            "from scripts/gen-update-key.py) and run again.")
    }
    # Same policy as the build script (crates/aegis-build-support): a malformed
    # key or the development key is rejected before the firmware is compiled.
    # vendor-key-check explains the rejection on stderr, so keep the error
    # stream non-terminating here and report that reason with context.
    $previousErrorAction = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        $check = & cargo run --quiet -p aegis-build-support --bin vendor-key-check 2>&1 |
            ForEach-Object { $_.ToString() }
        $checkExit = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $previousErrorAction
    }
    if ($checkExit -ne 0) {
        throw ("release gate: " + (($check -join "`n").Trim()))
    }
} elseif (-not $env:AEGIS_UPDATE_VENDOR_PUBKEY) {
    Write-Warning ("AEGIS_UPDATE_VENDOR_PUBKEY is not set: this image embeds a " +
        "DEVELOPMENT firmware-update key. Do not ship it.")
}

$env:AEGIS_BOARD = $BoardProfile
$featureArgs = if ($Board -eq "rp2350a") { @() } else { @("--no-default-features", "--features", $Board) }
$previousRelease = $env:AEGIS_RELEASE
try {
    if ($Release) { $env:AEGIS_RELEASE = "1" }
    cargo build -p $bin --target $target --release @featureArgs
    if ($LASTEXITCODE -ne 0) { throw "cargo build failed ($LASTEXITCODE)" }
} finally {
    $env:AEGIS_RELEASE = $previousRelease
}

$LASTEXITCODE = 0
if ($converter -eq "picotool") {
    & $picotool uf2 convert $elf -t elf $out
} else {
    # -v off suppresses the per-block progress bar of elf2uf2-rs.
    & $elf2uf2 -v off convert -f $family $elf $out
}
if ($LASTEXITCODE -ne 0) { throw "$converter conversion failed ($LASTEXITCODE)" }
$uf2 = Get-Item -LiteralPath $out -ErrorAction SilentlyContinue
if (-not $uf2) { throw "picotool reported success but $out was not written" }
if ($uf2.LastWriteTime -lt (Get-Item -LiteralPath $elf).LastWriteTime) {
    throw "$out is older than ${elf}: the UF2 conversion did not run"
}

Write-Output "Wrote $out"
