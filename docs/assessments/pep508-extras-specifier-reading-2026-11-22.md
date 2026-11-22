# The Python hygiene reader treated an extras group as a version bound (2026-11-22)

## The defect

`dep-hygiene:check` reads a PEP 508 requirement in one place —
`scan/engines/dep_hygiene/analyze_pep508/pep508_manifest.rs::analyze_pep508_for_manifest`
— for both of the Python manifests it supports: `requirements.txt`
(`analyze_requirements_txt`) and the PEP 621 `[project].dependencies` array
(`analyze_pyproject_toml`).

It took the leading run of name characters as the distribution name and
**everything after it as the version specifier**. PEP 508 puts an optional
extras group between the two:

```
name [extras] [versionspec] [; marker]
```

The extras group names optional features of the *same* distribution. It bounds
no version. Reading it as part of the specifier made every requirement that
declares one look constrained:

| spec | specifier it read | verdict | correct verdict |
| --- | --- | --- | --- |
| `uvicorn[standard]` | `[standard]` | none | **High** — unconstrained |
| `celery[redis] >= 5.3` | `[redis] >= 5.3` | none | **Medium** — floor-only |
| `httpx[http2]` | `[http2]` | none | **High** — unconstrained |

The second reading in the same function has the same shape. A floor-only
specifier written with a space — `requests >= 2.0`, which PEP 508 permits —
reached `is_floor_only_nonempty_range`, whose first guard is
`value.split_whitespace().count() != 1`, and was dropped. The Gemfile reader
next door already knew that: `is_floor_only_gem_constraint` compacts its
constraint's whitespace before calling the same predicate. The Python reader
never did.

## What that cost

Both verdicts were lost silently, in the direction that reports less risk.

`uvicorn[standard]` is exactly the input the High rule exists to name — its
reason text is "accepts any installed version, including malicious", which is
the supply-chain exposure of an unpinned dependency, and the extras group does
nothing to reduce it. A manifest holding only requirements declared with
extras produced `dep-hygiene: no risky specifiers found`, and
`check_dependency_hygiene` reports that count straight into the scan's
`DepHygieneReport`, so the omission is not visible as an omission anywhere
downstream. There is no "unreadable declaration" outcome in this engine; a
specifier it cannot judge is indistinguishable from one it judged clean.

Extras are ordinary in Python packaging — `uvicorn[standard]`,
`celery[redis]`, `pydantic[email]`, `fastapi[all]` are the documented install
forms for those projects — so this is not a rare spelling.

The SBOM reader on the other side of the repo reads the same syntax correctly:
`sbom_scan/python_dependency.rs::python_dependency_name` splits on `[` among
its delimiters, so `sbom:scan` has always named `uvicorn[standard]` as
`uvicorn`. One of the two Python readings was right and the other was not.

## Why this ranked first

- It is a **false negative in a shipped engine's primary output**, not a
  cosmetic or latent problem. The rule fires at High severity for precisely
  this risk and did not fire.
- The trigger is a common, documented way to spell a Python dependency, in the
  two manifest kinds that cover almost all Python projects.
- It fails toward "clean", and the engine has no channel that would disclose
  the drop.
- The fix is confined to one function's reading of one syntax, with the correct
  reading already demonstrated twice in the same crate (the SBOM name reader
  for extras, the Gemfile constraint reader for whitespace).

The nine other candidates ranked this run are recorded in the pull request. The
closest were `sbom:scan`'s non-canonical purl names (no type-specific
normalization, so `pkg:pypi/Django@5.0` instead of `pkg:pypi/django@5.0`) and
govulncheck's per-advisory finding multiplicity; the first is export-consumer
correctness rather than a missed detection, and the second needs the upstream
JSON protocol confirmed before any claim about double counting.

## What changed

`pep508_manifest.rs` now reads the requirement as the two parts the rules
judge:

- `Pep508Requirement::read` strips the environment marker, takes the name, then
  hands the remainder to `version_specifier`.
- `version_specifier` skips a terminated extras group and returns what follows.
  An **unterminated** `[` returns `None`: it names no readable requirement, and
  that is the same no-finding outcome the prior code reached for it, so no
  input changed from a finding to silence.
- `hygiene_verdict` owns the two rules and tests the floor-only rule against a
  whitespace-compacted copy of the specifier, while the finding still reports
  the specifier **as written** (`>= 2.0`, not `>=2.0`).
- `compact_constraint` moved into `version_ranges.rs` beside the predicate it
  serves; `gemfile_manifest.rs` now calls it instead of its own identical
  private copy.

`raw_constraint` on an extras requirement is now the version specifier alone,
which is what the rule judged. No input that produced a finding before produces
a different one now, so no existing finding's identity moves.

## What is not claimed

- **A direct reference is still not judged.** `pkg @ https://host/pkg.whl` is a
  PEP 508 direct reference, not a version range; it produced no finding before
  and produces none now. Whether an unpinned direct reference (a git URL at a
  branch) deserves its own rule is a separate question, with its own severity
  decision.
- **No new outcome for unreadable declarations.** A malformed spec is still
  absent from the report rather than disclosed. Adding an "unreadable" outcome
  would change `DepHygieneFinding` and every consumer of its severity, and
  belongs in its own change.
- **Extras are not checked for well-formedness.** The group is skipped rather
  than parsed; a nested `[` inside it is not valid PEP 508 and is not
  accounted for.
- **No other ecosystem reader was changed.** The whitespace guard in
  `is_floor_only_nonempty_range` is untouched, so the readers that pass it a
  raw constraint (`composer`, `pipfile`, `dotnet`) behave exactly as before.
  Whether any of them also needs compaction was not derived from their formats
  this run.
- **No frequency measurement.** That extras are common in Python packaging is
  stated from the packaging documentation of those projects, not from a corpus
  scan.

## Verified

- The three behavioural tests fail against the prior reading with
  `left: None` — no finding at all — and pass after:
  `an_extras_group_does_not_constrain_the_version`,
  `the_reported_package_name_excludes_its_extras`,
  `a_spaced_floor_only_specifier_is_still_floor_only`.
- `cargo test -p kuzushi-core --lib --locked dep_hygiene` — 78 passed, 0 failed.
- `cargo test -p kuzushi-core --lib --locked` (whole crate) and
  `cargo clippy -p kuzushi-core --all-targets --locked -- -D warnings`.
- `pnpm quality:crap-risk` over the changed files, and
  `pnpm verify:quick:summary`.
- The owned fixtures gained the four new rows the end-to-end tests assert
  (`uvicorn[standard]`, `celery[redis] >= 5.3` in the Python fixture;
  `httpx[http2]`, `boto3 >= 1.34` in `REQUIREMENTS_TXT`), and the root-manifest
  total moved 86 → 90, which is exactly those four and nothing else.
