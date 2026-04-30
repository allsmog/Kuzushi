# Pashov X-Ray Skill Attribution

This directory vendors the `x-ray` skill from:

https://github.com/pashov/skills/tree/main/x-ray

Source files are used under the MIT License. The upstream license is copied to
`skills/x-ray/LICENSE`.

Kuzushi carries one portability patch in `skills/x-ray/scripts/enumerate.sh`:
GNU-only `grep -P` expressions are rewritten to POSIX/BSD-compatible `grep -E`
patterns so the harness works on macOS without requiring GNU grep.
