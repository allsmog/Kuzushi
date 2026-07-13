# Plan 035: Make structured-output parsing and repair linear and bounded

> Executor: preserve direct JSON and last-fenced-JSON compatibility. A malformed
> model response must never trigger quadratic scans, an oversized repair call,
> or an unbounded persisted diagnostic.

## Status

- **Status**: DONE
- **Priority**: P1
- **Effort**: M
- **Risk**: MED
- **Category**: runtime performance/diagnostic safety
- **Depends on**: Plan 009
- **Planned at**: commit `775a4134f2cb`, Cycle 8

## Why this matters

The balanced-JSON fallback starts a fresh scan at every `{` and `[`, then may
parse every collected suffix in reverse. A brace-heavy malformed model response
therefore costs quadratic CPU and repeated JSON work. The repair prompt and
terminal error also embed the complete invalid response, schema, and validator
error, so one bounded-but-large bridge response can create another oversized
paid request and multi-megabyte terminal/failure artifacts.

## Steps

1. Enforce a documented byte budget on text plus structured response material
   before fallback extraction or repair. Keep direct structured values working,
   but reject over-budget material with byte count, limit, and digest rather
   than serializing it repeatedly.
2. Replace `balanced_json_slices` with a single-pass, quote-aware scanner over
   outermost complete object/array spans. Retain a finite number/total bytes of
   candidates in stable last-first precedence. Never accept a valid nested
   object from inside a malformed outer object as the final answer.
3. Bound schema, parse/validation error, and invalid-response material added to
   the repair prompt. Use a deterministic UTF-8-safe head/tail excerpt plus
   original byte count and SHA-256; one repair remains the only retry.
4. Apply the same bounded diagnostic renderer to truncation and repair-failure
   errors before they reach traces, terminal output, or run failure artifacts.
   Do not claim the excerpt is the complete response.
5. Keep parsing and excerpt helpers pure, allocation-bounded, and independently
   tested; do not solve this by increasing bridge, terminal, or artifact caps.

## Verification

- Multi-megabyte runs of opens, closes, escaped quotes, incomplete strings,
  nested invalid objects, and thousands of fences complete within linear
  inspected-byte/candidate budgets and bounded allocation.
- Direct JSON, the last valid fenced block, and a final top-level balanced JSON
  value still parse with the same reported strategy; a valid nested fragment
  inside malformed outer JSON is rejected and repaired.
- Limit and limit+1 cases are deterministic. Repair prompts and error strings
  stay under their caps, remain valid UTF-8, identify truncation, and include a
  digest matching the full source bytes.
- Structured-output, runtime, failure-artifact, formatting, Clippy, and CRAP
  gates pass with adversarial stress tests.

## Done criteria

Malformed model output has linear finite handling, and only bounded, clearly
labeled evidence can enter a second model call or durable diagnostic.

## Implementation notes

- Response material is capped before extraction, balanced candidates are found
  in one quote-aware pass with bounded retention, and repair prompts/final
  diagnostics use UTF-8-safe head/tail evidence plus byte count and digest.
- Repair requests preserve runtime options and temperature, while mismatched
  outer containers cannot leak a nested value as a successful answer.
- Focused structured-output coverage passes 33/33. The complete offline
  workspace, strict Clippy, architecture, CRAP-risk, and package gates also
  pass.
