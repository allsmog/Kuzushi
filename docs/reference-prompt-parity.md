# Reference prompt parity: hunt + triage fidelity comparison

Reference prompts: the reference skills at `~/internal-skills/.claude/skills/`
(`detection` for vulnerability hunting, `triage` for adversarial review)
plus the chain-building prompt embedded in `~/orchestrate-harness/triage-run.sh`.
This document records, element by element, what kuzushi already had, what was
ported, and what was intentionally kept different — so the parity decision
trail survives the uncommitted tree.

Prompt spine version was bumped `1` → `2` when the ported blocks landed
(`crates/kuzushi-core/src/prompts/mod.rs`).

## Hunt prompts (detection vs kz finding producers)

| Element | Reference detection | kz before | kz now |
| --- | --- | --- | --- |
| Evidence bar (trace source→sink before reporting) | required | already stronger: confirmed-flow bar in `prompts/spine.rs` | unchanged (kept kz wording) |
| 12-rule exclusion list (DoS, memory-safe-lang, SSRF path-only, ReDoS carve-out, …) | numbered list, findings must survive it | absent (only the FP taxonomy's anti-dismissal traps) | ported as `EXCLUSION_RULES` in `prompts/spine.rs`; producers must cite the rule number when suppressing |
| Severity derived from preconditions (count × attacker position, lower column wins) | table | only an import-time ceiling (`findings/ingest_contract.rs::enforce_severity_ceiling`), never prompted | ported as `SEVERITY_FROM_PRECONDITIONS` using the closed `Precondition` vocabulary; "three or more preconditions ⇒ almost certainly not critical/high" |
| Exploit scenario per finding | mandatory field | absent | required by `AGENTIC_SAST_EVIDENCE_RULES`; carried on `FindingCandidate.exploit_scenario` → `Finding.exploit_scenario` |
| Preconditions per finding | mandatory field | absent | required; first entry must be the closed-vocab attacker position; parsed entries drive `apply_precondition_ceiling` at normalization (capped severities annotate the message rather than silently mutating) |
| Exhaustiveness ("one finding is a floor; cover every file") | explicit | absent | ported as `EXHAUSTIVENESS`, phrased so coverage is exhaustive while reporting stays evidence-gated ("never lowers the evidence bar") |
| Language-specific hunt hints (C/C++ double-free paths, unsigned wrap, wrong-variable bounds checks, trusted length fields, …) | per-language sections | only in deep-auditor validator catalogs / uaf-hunt | ported as `prompts/hunt_hints.rs` (C/C++, Rust, Go, TypeScript, Python, Java); `build_prompt.rs` injects `hunt_hints_for_paths(...)` from the file inventory |
| Rich output fields (title/impact/category/preconditions/exploit_scenario/recommendation) | full schema | only whitebox-static had analogs | `FindingCandidate` + `Finding` extended; ride `finding_json`; exported via `vuln-findings` renderer |
| Self-verification + adversarial pass before output | in-skill | covered by kz's separate triage phase (architecturally stronger: independent model, votes) | intentionally NOT duplicated in hunt prompts — kz separates producer and reviewer |
| Confidence as 0–1 float | float | proof bands (confirmed/likely/tentative/dismissed) | **intentionally different**: kz keeps bands internally (calibration is enforceable), converts to conventional midpoints (0.9/0.6/0.3/0.1) only at `vuln-findings` export |
| "False negatives preferable to false positives" framing | present | kz frames it as evidence-gating + FP taxonomy | **intentionally different**: kept kz framing; the campaign design (many nondeterministic hunts + adversarial triage) tolerates producer FPs better than FNs |

## Triage (reference triage skill vs kz triage)

| Element | Reference triage | kz before | kz now |
| --- | --- | --- | --- |
| Assume the scanner is wrong | core framing | already present (adversarial assume-FP stage-2 prompt) | unchanged |
| N-vote panels, disagreement → needs_review | present | already present (`votes` 1..5, strict majority) | unchanged |
| Refute-reason enum (doesnt_exist / already_handled / implausible_trigger / intentional_behavior / misread_code / duplicate / not_actionable) | required on FP verdicts | absent | `RefuteReason` on `TriageOutcome` (`findings/domain/triage_outcome.rs`); required by `TRIAGE_VERDICT_RULES` and the deep-auditor contract; persisted by folding into rationale (`[refute_reason=…; first_link=…] …`) because the TriageDecided projection rebuilds `$.triage` with fixed keys |
| First call-site citation (file:line actually read) | required | absent | `first_link` on `TriageOutcome` + deep-auditor `VulnAnalysis`; "never invent one" — null when no evidence was read |
| Code-reading during triage (open files, follow callers) | default behavior | only `strategy=deep` (single finding) | deep auditor is now the default for `scope=all` bulk triage; standard remains for latest-scope quick passes; explicit `strategy=` always wins |
| Attack-chain dedupe exemption (chains never merged by line proximity) | explicit rule | absent | `modules/triage/dedupe.rs::is_attack_chain_finding` — tool `chains` or rule prefix `exploit-chain/` become singleton clusters |
| Severity re-derivation from preconditions during review | reviewer re-derives | ceiling applied at import only | ceiling now also applied at hunt normalization; **intentionally NOT re-litigated by the triage model** — the ceiling is code (`enforce_severity_ceiling`), deterministic and auditable |
| Duplicate collapse | in-prompt | structural (±15-line tool+rule clustering before the LLM) | unchanged — structural dedupe is cheaper and deterministic; `duplicate` remains available as a refute reason for cross-tool dupes the clusterer cannot see |

## Attack chaining (orchestrate-harness triage-run.sh vs kz)

| Element | Orchestrator prompt | kz now |
| --- | --- | --- |
| Chain = 2+ findings where one enables/escalates another | required | `triage:chain-hunt` (`capabilities/chain_hunt.rs`), members `minItems: 2`, hallucinated or self-duplicate members dropped, <2 distinct real fingerprints ⇒ chain rejected |
| Schema: components / attack_path / cumulative_impact / why_this_chain_matters / detection_difficulty | strict JSON | same fields in the structured-output contract; narrative folded into the persisted finding message |
| "Do not invent chains"; zero chains is a valid answer | explicit | ported verbatim into `CHAIN_HUNT_RULES` |
| Prior chains: do not duplicate; extend/supersede | explicit | prior `tool=="chains"` findings are included in the prompt with the same instruction |
| Chains fed back into triage | appended to findings file | chains persist as open findings (rule `chains/model`, deterministic `AC-` id over ordered member fingerprints ⇒ stable identity across re-runs); the next `triage:run` picks up exactly the untriaged chain findings |
| Deterministic chain folding | n/a | `findings:chains persistFindings=true` additionally persists graph-derived candidates (rule `chains/candidate`) and archives per-run `v3/reports/chains/<runId>.json` (fixes the whole-file `chains.json` clobber) |

## Workflow capabilities closed alongside the prompt work

- `triage:run scope=all` — triages every untriaged finding across all runs and
  tools in one invocation (deep strategy by default); previously latest-run only.
- Chain findings are triageable and exempt from proximity clustering.
- `kz export --format vuln-findings` renders the external
  `VULN-FINDINGS.json` schema (title/impact/exploit_scenario/preconditions/
  category/severity HIGH-MEDIUM-LOW/confidence/recommendation + provenance
  extras fingerprint/triage_verdict/tool) for backfill into
  `~/orchestrate-harness`-style harnesses.
- Clobber resistance was already sound (append-only observations, run ids
  `{prefix}-{millis}-{uuid12}`, per-`(run_id, fingerprint)` uniqueness,
  cross-run identity carrying triage forward); the one whole-file overwrite
  (`chains.json`) now has a per-run archive.
