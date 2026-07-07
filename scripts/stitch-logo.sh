#!/usr/bin/env bash
# Stitch two ascii-image-converter outputs:
#   - v2 (dense chars + color) for the hat region (top rows)
#   - v3 (braille + color) for the face/body region (bottom rows)
#
# Both must be generated from the same source image at the same --width.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(dirname "$SCRIPT_DIR")"
AIC="${AIC:-}"
if [ -z "$AIC" ]; then
  AIC="$(command -v ascii-image-converter || true)"
fi
if [ -z "$AIC" ] && [ -x "${HOME}/go/bin/ascii-image-converter" ]; then
  AIC="${HOME}/go/bin/ascii-image-converter"
fi
if [ -z "$AIC" ] || [ ! -x "$AIC" ]; then
  echo "Could not find ascii-image-converter. Install it or set AIC=/path/to/ascii-image-converter." >&2
  exit 127
fi
DEFAULT_LOGO_SOURCE="${ROOT}/kuzushi-logo.png"
ENHANCED="${1:-${KUZUSHI_LOGO_SOURCE:-$DEFAULT_LOGO_SOURCE}}"
if [ ! -f "$ENHANCED" ]; then
  echo "Logo source not found: $ENHANCED" >&2
  echo "Usage: $0 [source-image] or set KUZUSHI_LOGO_SOURCE=/path/to/image" >&2
  exit 2
fi
OUT="${ROOT}/assets/ascii/logo-color.txt"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/kuzushi-stitch-logo.XXXXXX")"
trap 'rm -rf "$TMP_DIR"' EXIT

# Where the hat ends and face begins (1-indexed)
HAT_END=4

# Generate both versions from the enhanced (contrast-boosted, cropped) image
echo "Generating hat layer (dense chars + color)..."
"$AIC" "$ENHANCED" --width 24 --color --map " .,;:!vlIJ#@" > "${TMP_DIR}/stitch-hat.txt"

echo "Generating face layer (braille + color)..."
"$AIC" "$ENHANCED" --width 24 --color --braille > "${TMP_DIR}/stitch-face.txt"

# Stitch: hat rows from dense chars, face rows from braille
{
  head -n "$HAT_END" "${TMP_DIR}/stitch-hat.txt"
  tail -n +"$((HAT_END + 1))" "${TMP_DIR}/stitch-face.txt"
} > "$OUT"

LINES=$(wc -l < "$OUT")
echo "Stitched ${HAT_END} hat rows + $((LINES - HAT_END)) face rows -> ${OUT} (${LINES} lines total)"
echo "Preview with: cat ${OUT}"
