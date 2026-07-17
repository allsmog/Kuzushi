# Plan 031: Make untrusted prompt records unambiguous and finite

> Executor: preserve the immutable built-in prompt prefix, target-owned focus
> semantics, and the public marker constants. Repository bytes must remain
> inspectable by the model, but they may not be able to manufacture framing.

## Status

- **Status**: DONE
- **Priority**: P1
- **Effort**: M
- **Risk**: MED
- **Category**: prompt integrity/resource bounds
- **Depends on**: Plan 001
- **Planned at**: commit `775a4134f2cb`, Cycle 7

## Why this matters

`render_untrusted_repo_block` and `render_untrusted_derived_block` interpolate
raw labels and content between line-oriented sentinel strings. A repository
file, finding, validator log, or path can include a fake `UNTRUSTED_*_END`
line, another label, and a new begin marker, so the rendered prompt no longer
has one mechanically unambiguous record boundary. Automatic target prompt
files may also contribute up to 1 MiB to every model call, large enough to
exhaust provider context or create disproportionate spend before useful work.

## Steps

1. Replace raw label/body interpolation with one canonical record encoding
   whose syntax cannot be extended by label or content bytes. Keep begin/end
   constants as outer compatibility markers, encode controls/newlines, and
   include explicit record kind plus byte length so tests can parse and verify
   the frame rather than count substrings.
2. Apply the encoder to raw repository blocks and transitive derived blocks.
   Remove capability-local assumptions about `--- label ---` formatting and
   update prompt builders/tests to assert decoded label/content fidelity.
3. Put a documented, provider-safe byte ceiling on target prompt files and on
   explicit inline prompt values at the canonical preparation boundary. Reject
   limit+1 input with the option name and limit; do not silently truncate or
   reinterpret it as a path.
4. Preserve preparation idempotence: an already composed prompt remains one
   immutable prefix plus one untrusted record and is neither re-framed nor
   recursively hydrated.

## Verification

- Labels and bodies containing every begin/end token, CR/LF, quotes, slashes,
  NUL/control bytes, and fake headings produce exactly one valid outer frame;
  decoding recovers the original UTF-8 text byte-for-byte.
- Target prompt input at the byte limit succeeds, limit+1 fails before runtime
  dispatch, and the same limit covers automatic files, explicit file paths,
  CLI/TUI preparation, and direct registry dispatch.
- Patch, SAST triage/verify, agentic SAST, threat-model, X-ray, Carlini,
  prompt-armor, and prompt-boundary tests pass without raw-marker assertions.
- Formatting, Clippy, model-safety, architecture, and CRAP gates pass.

## Done criteria

Repository-controlled text cannot forge prompt structure, and no target prompt
can consume an unbounded or provider-hostile share of a model request.

## Implementation notes

- Repository and derived records now use one strict `percent-v1` codec inside
  the retained compatibility markers. The frame declares its version, kind,
  encoding, label byte length, and content byte length; the decoder rejects
  invalid UTF-8, mismatched markers/kinds/lengths, lowercase or over-encoded
  escapes, unbounded length fields, trailing lines, and non-canonical bytes.
- Raw inline prompt values and workspace prompt files share a 65,536-byte
  ceiling at the registry and file-read boundaries. Limit errors retain the
  option name and limit, and oversized values are never truncated or treated
  as paths.
- The prepared-envelope exemption validates the exact descriptor default,
  decoded repository record, 65,536-byte content ceiling, 4,096-byte source
  label ceiling, and conservative encoded-envelope bound. Capability adapters
  use the same expected-default-aware resolver, so a valid prepared prompt is
  idempotent while a forged oversized envelope cannot bypass the raw limit.
- Patch, SAST, agentic SAST, registry, and TUI assertions now decode records
  and compare exact label/content fidelity instead of depending on the retired
  `--- label ---` formatting.

## Verification evidence

- `cargo test -p kuzushi-core runbooks::untrusted::tests -- --nocapture`
  passed 7 codec and adversarial-framing tests.
- `cargo test -p kuzushi-core options::prompt_override::tests -- --nocapture`
  passed 5 raw/file limit and prepared-envelope tests.
- `cargo test -p kuzushi-core prompt_input_limits::tests -- --nocapture`
  passed 3 direct/umbrella registry and forged-envelope tests.
- `cargo test -p kuzushi-core prompt_file_default_tests -- --nocapture`
  passed 12 automatic/explicit file, descriptor, and idempotence tests; the
  at-limit automatic file survives a second canonical preparation unchanged.
- Prompt-boundary (4), patch-context (3), model-safety, focused CRAP-risk, and
  `git diff --check` checks passed. Strict Clippy reached only concurrent Plan
  034 dead-code failures in `structured_json_contract.rs`; the architecture
  gate reached only concurrent findings boundary failures in
  `triage_outcome.rs` and `review_decisions.rs`. Neither failure touches this
  plan's source, and the owning agent was notified.
