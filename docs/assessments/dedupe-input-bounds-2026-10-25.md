# Bounded duplicate proposal inputs

Status: verified implementation draft. All ten draft repository summary checks pass.
This follows the signed checkpoint `c3c699ef14` on main. It adds no live inference,
source execution, exploit development or vulnerability patching.

## Reproduced problem

The old candidate selector hydrated the complete findings ledger and rekey set
before applying `maxCandidates`. A fixture with 142 individually valid recorded
observations exceeded 8 MiB in aggregate yet still returned two candidates.
The retained pre-change executable, source hashes and failing regression are in
`scripts/devex/artifacts/dedupe-ledger-20261024/pre-change-binary.json` and
`before-fix-3.log`. The two earlier failed test attempts remain separate evidence.

Path normalization also lowercased and trimmed distinct recorded paths. Optional
confirmation read entire files and could follow symlinks. A prompt cap applied
only before a generic helper could send an automatic repair request.

J359 attempt 1 exposed an additional native producer defect before launch: the
JSONL importer trimmed literal file aliases and evidence paths. Its failed setup
and retained findings distinguish this from a model or dedupe-reader failure.
The source adapter now preserves those paths; completed historical imports stay
unchanged.

## Change

The dedicated dedupe reader uses one projection snapshot, a streaming observation
preflight, a shared raw/projected JSON byte allowance and cooperative SQL
interruption. It preserves current identity, source and suppression semantics
without hydrating irrelevant verification or gap history. It excludes rekeyed
rows through the indexed relation. Full export and identity readers are unchanged.

Five descriptor-backed advanced [limits](../operator-control-surfaces.md#duplicate-proposal-input-limits-triagededupe)
share canonical preparation, aliases and range checks. Oversized ledger or
metadata prompt input refuses before inference. Successful results report
eligible, selected and omitted candidates, retaining complete file buckets.
Case, whitespace, backslashes and `./` prefixes remain literal identity evidence.

Low-confidence confirmation reads complete, contained regular UTF-8 files under
one aggregate allowance. Each literal path is cached once per invocation and
receipted by digest. Failed reads retain conservative local reservations and
unknown byte counts. Missing citations, unavailable files and oversized prompts
drop their group before confirmation, with reasons in the result. Requests
declare no tools and one model turn. Malformed output fails without a repair
call, retaining the response's reported usage. Transport retries and durable
provider reservations remain shared runtime behavior.

Current confirmation files can differ from the source where a finding was
recorded. The prompt and receipt state this explicitly. This action proposes
relationships; it does not infer that a finding was fixed at a newer SHA.

## Validation

Current focused Rust checks pass: 23 corpus dedupe, eleven JSONL importer,
five bounded-reader, two prepared-dispatch, four SQL interruption and three
audit-matrix contracts. These are 48 distinct checks. They cover the oversized aggregate regression,
literal paths, rekeys, suppression/source parity, cancellation and callback
cleanup, no query or reservation on initial refusal, conservative source limits,
owned symlink rejection, missing citations and no repair after paid invalid output.

The changed-code risk gate and its fifteen supporting Node tests pass.
Core all-target Clippy and workspace build pass. Final native J359 has 23 machine
passes, zero failures, fifteen capture pairs and four pending formal operator
judgments. All four questions have separate agent answers; ten final ANSI cell
replays were inspected, covering six sizes, paging and no-color recovery. The
final repository summary has ten passing checks. Its draft receipt is dirty and
unsigned; publication requires clean exact-commit verification and a signed receipt. Detailed logs stay in the evidence root
above; earlier attempts are retained rather than relabeled successful.

Final native inputs remain unchanged: 6,578 source files and thirteen frozen
programs. The CLI SHA-256 is
`de9a110114156d61e79cd917ab8427584fef71913fa951a976eaff1946482289`.
Only this assessment and the two delivery ledgers are updated afterward.
A refused read makes zero requests. Explicitly correcting the limit permits two
intercepted requests, including current-source confirmation, and produces one
proposed relationship. Both reservations settle; neither has complete dollar
pricing. Four observations, zero rekeys and zero human decisions survive restart.
The source fixture is unchanged and never executed. No live request is added;
the prior sixteen-request real-model allowance remains exhausted.

Attempt 1 retains the importer defect. Attempt 2 retains sixteen machine passes
and a failed agent visual judgment for an unsettled resize and verbose failure.
Attempt 3 retains ten passes and one failed paging assertion: the correction
instruction was already on the first page. Attempt 4 corrects the assertion and
supplies final evidence. These are sequential runs, not independent detection
quality experiments. Replays are not OS screenshots or formal operator approval.

## Limits

The SQL deadline is cooperative. Lock waits and bounded decoding may finish
later. A retained-byte allowance does not bound all SQLite memory. Source reads
can probe one extra byte per file and have no hard wall-clock IO deadline.
Prompt limits count system and user UTF-8 text, excluding transport framing,
structured-output schema and output tokens. Unknown provider dollars remain
unknown. No default allowance or model is silently expanded or replaced.

This qualifies a bounded preparation path, not duplicate precision, complete
repository coverage, general large-ledger throughput or reference-level UX.
The broader delivery checklist stays open.
