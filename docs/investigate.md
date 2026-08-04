# Investigate profiles

`kuzushi investigate` is the opinionated entry point for an evidence-backed
repository investigation. It does not introduce a second scanner or dispatch
path. Each profile expands into ordinary canonical `sast:scan` input, then runs
through the same source binding, findings store, lifecycle stream, phase
receipts, SARIF export, and severity gate as `kuzushi scan`.

The expanded input, not the profile name, is the durable execution truth. Use
`--plan` to inspect it before spending model budget or executing scanners.

```bash
kuzushi investigate . --profile standard --plan
kuzushi investigate . --profile deep
kuzushi investigate . --profile prove --paths src/auth,src/api
kuzushi investigate . --profile fix --fail-on high --sarif kuzushi.sarif
```

## Profiles

| Profile | Discovery | Review and proof | Remediation |
| --- | --- | --- | --- |
| `standard` | Bundled dependency, secret, license, IaC, and agentic SAST passes | Model-backed triage | None |
| `deep` | Standard engines plus Taint IRIS Next, systems hunt, and offense review | Model verification for corroborated HIGH+ findings, capped at 10 | None |
| `prove` | Deep discovery | Empirical sandbox verification for corroborated HIGH+ findings, capped at 5 | None |
| `fix` | Deep discovery | The same empirical proof requirement as `prove` | Generate a build-and-test-checked patch draft only after an empirical `exploited` result |

`deep`, `prove`, and `fix` require at least two corroborating observations before
a finding enters verification. This is deliberately conservative: the profile
prefers an explicit proof gap over spending verification effort on a
single-source claim.

## Proof and patch honesty

`prove` routes selected findings to `verify:exploit`, not to the model-only
verifier. Unsupported languages, missing sandbox support, incomplete harnesses,
and infrastructure failures remain explicit non-proof outcomes.

`fix` does not silently edit the target checkout. Patch synthesis and build/test
checks run against disposable source-pinned worktrees. A patch is attempted only
when the empirical verifier reports `exploited`; successful output is a
persisted, checked draft with its own lifecycle record. Applying the draft
remains an operator decision.

## Planning and automation

Plain plan output is line-oriented:

```text
PROFILE prove
PROOF_POLICY empirical
TARGET_MUTATION none
TASKS dep-hygiene,secret-scan,license-scan,iac-scan,agentic-sast,taint-iris-next,systems-hunt,offense-review
SCAN_INPUT {...}
```

Use JSON for automation:

```bash
kuzushi investigate . --profile prove --plan --json | jq '.scanInput'
```

Execution supports the same scan-scoped output controls used by CI:

```bash
kuzushi investigate . --profile deep --ci --fail-on high --sarif kuzushi.sarif
```

Named shards and explicit path roots compile into the canonical `paths` input:

```bash
kuzushi investigate . --profile deep --shard parsers
kuzushi investigate . --profile prove --paths crates/parser,crates/protocol
```

## Deliberate limits of the first slice

Profiles are closed and code-owned rather than arbitrary recipes. They do not
yet expose the full sampled `focus × strategy × model × runs` matrix described
in the control-room roadmap. The initial contract establishes one safe public
entry point, transparent plan expansion, empirical proof routing, and
proof-gated patch drafting without creating a parallel execution system.
