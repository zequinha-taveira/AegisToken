# Builds the Universal RP2350 Firmware in release mode and converts it to UF2.
#
# Usage:  powershell -File scripts/build-uf2.ps1 [-Board rp2350a|rp2350b|rp2354a|rp2354b]
# Output: <board>-universal.uf2 (repository root; the RP2350A target keeps the
#         historical rp2350-universal.uf2 name)
#
# RP2354A/B share the RP2350A/B die and package and add 2 MiB in-package flash.
# For a production image, set AEGIS_UPDATE_VENDOR_PUBKEY to the release key
# (65-byte SEC1 hex, from scripts/gen-update-key.py) before running. Otherwise a
# development update key is embedded and a warning is printed.

param(
    [ValidateSet("rp2350a", "rp2350b", "rp2354a", "rp2354b")]
    [string]$Board = "rp2350a"
)

$target = "thumbv8m.main-none-eabihf"
$bin = "firmware-universal-rp2350"
$elf = "target/$target/release/$bin"
$out = if ($Board -eq "rp2350a") { "rp2350-universal.uf2" } else { "$Board-universal.uf2" }

if (-not $env:AEGIS_UPDATE_VENDOR_PUBKEY) {
    Write-Warning ("AEGIS_UPDATE_VENDOR_PUBKEY is not set: this image embeds a " +
        "DEVELOPMENT firmware-update key. Do not ship it.")
}

$featureArgs = if ($Board -eq "rp2350a") { @() } else { @("--no-default-features", "--features", $Board) }
cargo build -p $bin --target $target --release @featureArgs
if ($LASTEXITCODE -ne 0) { throw "cargo build failed ($LASTEXITCODE)" }

picotool uf2 convert $elf -t elf $out
if ($LASTEXITCODE -ne 0) { throw "picotool conversion failed ($LASTEXITCODE)" }

Write-Output "Wrote $out"
