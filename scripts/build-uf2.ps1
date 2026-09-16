# Builds the Universal RP2350 Firmware in release mode and converts it to UF2.
#
# Usage:  powershell -File scripts/build-uf2.ps1 [-Board rp2350a|rp2350b|rp2354a|rp2354b]
#                                                [-BoardProfile <name>]
# Output: AegisToken_<product>-<version>.uf2 (repository root), where <version>
#         is the workspace version from Cargo.toml and the RP2350A target uses
#         the `pico2` codename (e.g. AegisToken_pico2-0.1.0.uf2). A non-generic
#         board profile is appended to the product name.
#
# -BoardProfile selects the carrier identity and USB VID/PID (build.rs reads it
# from AEGIS_BOARD). Defaults to `generic`; see BoardProfile in
# board-generic-rp2350 for the supported third-party names
# (e.g. waveshare-rp2350-zero, pimoroni-tiny-2350).
#
# RP2354A/B share the RP2350A/B die and package and add 2 MiB in-package flash.
# For a production image, set AEGIS_UPDATE_VENDOR_PUBKEY to the release key
# (65-byte SEC1 hex, from scripts/gen-update-key.py) before running. Otherwise a
# development update key is embedded and a warning is printed.

param(
    [ValidateSet("rp2350a", "rp2350b", "rp2354a", "rp2354b")]
    [string]$Board = "rp2350a",
    [string]$BoardProfile = "generic"
)

$target = "thumbv8m.main-none-eabihf"
$bin = "firmware-universal-rp2350"
$elf = "target/$target/release/$bin"

# Read the workspace version from the root Cargo.toml.
$manifest = Join-Path $PSScriptRoot "..\Cargo.toml"
$match = Select-String -LiteralPath $manifest -Pattern '^version\s*=\s*"([^"]+)"' |
    Select-Object -First 1
if (-not $match) { throw "could not read version from $manifest" }
$version = $match.Matches[0].Groups[1].Value

# RP2350A maps to the Pico 2 product codename; other boards keep the board name.
$product = if ($Board -eq "rp2350a") { "pico2" } else { $Board }
if ($BoardProfile -ne "generic") { $product = "$product-$BoardProfile" }
$out = "AegisToken_$product-$version.uf2"

if (-not $env:AEGIS_UPDATE_VENDOR_PUBKEY) {
    Write-Warning ("AEGIS_UPDATE_VENDOR_PUBKEY is not set: this image embeds a " +
        "DEVELOPMENT firmware-update key. Do not ship it.")
}

$env:AEGIS_BOARD = $BoardProfile
$featureArgs = if ($Board -eq "rp2350a") { @() } else { @("--no-default-features", "--features", $Board) }
cargo build -p $bin --target $target --release @featureArgs
if ($LASTEXITCODE -ne 0) { throw "cargo build failed ($LASTEXITCODE)" }

picotool uf2 convert $elf -t elf $out
if ($LASTEXITCODE -ne 0) { throw "picotool conversion failed ($LASTEXITCODE)" }

Write-Output "Wrote $out"
