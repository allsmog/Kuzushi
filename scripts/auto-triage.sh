#!/usr/bin/env bash
# Auto-triage HIGH+CRITICAL findings using deep-audit; aggregate verdicts.
# Usage: auto-triage.sh <target> [maxSteps]
set -u
TARGET="$1"
MAX_STEPS="${2:-18}"
KUZUSHI=/home/user/Kuzushi/target/release/kuzushi

# Get HIGH+CRITICAL fingerprints as JSON
"$KUZUSHI" --target "$TARGET" findings --json --severity critical,high 2>/dev/null \
  > /tmp/findings-hc.json

TOTAL=$(python3 -c "import json; print(len(json.load(open('/tmp/findings-hc.json')).get('findings',[])))")
echo "== Auto-triaging $TOTAL HIGH+CRITICAL findings in $TARGET (maxSteps=$MAX_STEPS) =="
echo ""

# Build the parallel argument list
python3 -c "
import json
d = json.load(open('/tmp/findings-hc.json'))
for f in d.get('findings', []):
    print(f\"{f['fingerprint']}|{f['severity']}|{f['file_path']}:{f['start_line']}|{f.get('title','')[:80]}\")
" > /tmp/findings-list.txt

# Triage each finding
> /tmp/triage-verdicts.txt
while IFS='|' read -r FP SEV LOC TITLE; do
  echo "-> [${SEV}] $LOC"
  echo "   $TITLE"
  RESULT=$("$KUZUSHI" --target "$TARGET" run deep-audit:run \
    --input "{\"findingFingerprint\":\"$FP\",\"maxSteps\":$MAX_STEPS,\"depositUsd\":2.0}" 2>&1)
  VERDICT=$(echo "$RESULT" | python3 -c "
import json,sys
try:
    d=json.load(sys.stdin); data=d.get('data',{})
    print(f'{data.get(\"verdict\",\"?\")}|{data.get(\"confidence\",0):.2f}|{data.get(\"rationale\",\"\")[:300].replace(chr(10), \" \")}')
except: print('parse-error|0|')
")
  echo "$FP|$SEV|$LOC|$VERDICT" >> /tmp/triage-verdicts.txt
  V=$(echo "$VERDICT" | cut -d'|' -f1)
  C=$(echo "$VERDICT" | cut -d'|' -f2)
  echo "   => verdict=$V confidence=$C"
  echo ""
done < /tmp/findings-list.txt

echo "== SUMMARY =="
python3 -c "
import collections
verdicts = collections.Counter()
true_pos = []
needs_review = []
false_pos = []
for line in open('/tmp/triage-verdicts.txt'):
    fp, sev, loc, verdict, conf, rationale = line.strip().split('|', 5)
    verdicts[verdict] += 1
    if verdict == 'true_positive':
        true_pos.append((conf, loc, rationale[:200]))
    elif verdict == 'false_positive':
        false_pos.append((conf, loc))
    elif verdict == 'needs_review':
        needs_review.append((conf, loc, rationale[:200]))

print('Verdicts:', dict(verdicts))
print()
print('--- TRUE POSITIVES ---')
for c, l, r in sorted(true_pos, reverse=True):
    print(f'  conf={c} {l}')
    print(f'    {r}')
print()
print('--- NEEDS REVIEW (top 10) ---')
for c, l, r in sorted(needs_review, key=lambda x: -float(x[0]))[:10]:
    print(f'  conf={c} {l}')
    print(f'    {r}')
print()
print('--- FALSE POSITIVES ---')
for c, l in sorted(false_pos, reverse=True):
    print(f'  conf={c} {l}')
"
