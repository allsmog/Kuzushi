#!/usr/bin/env bash
# Stitch two ascii-image-converter outputs:
#   - v2 (dense chars + color) for the hat region (top rows)
#   - v3 (braille + color) for the face/body region (bottom rows)
#
# Both must be generated from the same source image at the same --width.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(dirname "$SCRIPT_DIR")"
AIC="${HOME}/go/bin/ascii-image-converter"
ENHANCED="/tmp/kuzushi-enhanced.png"
OUT="${ROOT}/assets/ascii/logo-color.txt"

# Where the hat ends and face begins (1-indexed)
HAT_END=4

# Generate both versions from the enhanced (contrast-boosted, cropped) image
echo "Generating hat layer (dense chars + color)..."
"$AIC" "$ENHANCED" --width 24 --color --map " .,;:!vlIJ#@" > /tmp/stitch-hat.txt

echo "Generating face layer (braille + color)..."
"$AIC" "$ENHANCED" --width 24 --color --braille > /tmp/stitch-face.txt

# Stitch: hat rows from dense chars, face rows from braille
{
  head -n "$HAT_END" /tmp/stitch-hat.txt
  tail -n +"$((HAT_END + 1))" /tmp/stitch-face.txt
} > "$OUT"

LINES=$(wc -l < "$OUT")
echo "Stitched ${HAT_END} hat rows + $((LINES - HAT_END)) face rows -> ${OUT} (${LINES} lines total)"
echo "Preview with: cat ${OUT}"
