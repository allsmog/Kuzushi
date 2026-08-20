# Product workflow: project in, proof out

## 1. Product contract

The operator supplies a project and nothing else that is specific to “research”:

```bash
kz --target /work/target-project
```

Kuzushi reuses the current Target, Setup, Map, Scan, Review, Prove, Fix, Report, and Run Focus surfaces.

The default workflow must be useful without:

- creating a campaign;
- writing a hypothesis;
- selecting individual engines;
- importing a contest rulebook;
- creating a VM profile;
- opening Strategy Queue;
- copying results into a notebook;
- manually choosing the next proof experiment.

Advanced controls remain available, but they are not prerequisites.

## 2. First launch and Setup

Kuzushi should preserve the existing consent boundary. Pointing at a project selects the target; it does not silently authorize repository execution or model spend.

A deterministic Map plan is preselected:

```text
KUZUSHI · target-project · SETUP
READY THE MAP RUN
────────────────────────────────────────────────────────────────────

  Target         CONFIRMED       /work/target-project
> Map plan       READY           inventory · boundaries · entry points
  Model          NOT NEEDED      deterministic Map plan
  Credentials    NOT NEEDED      no selected task needs a provider
  Prompt         BUILT IN        project-first defaults
  Budget         NOT ENFORCED    applies to later model-backed research
  Start Map      READY           commit the plan and open Run Focus

────────────────────────────────────────────────────────────────────
READY · Enter Start Map
```

No row asks for research goals, contest details, target product metadata, or hypothesis seeds.

When the project has existing current-revision Map evidence, Setup should truthfully offer reuse rather than force a rebuild.

## 3. Map: explain where Kuzushi will spend effort

Map remains a projection of durable project evidence.

The Summary tab adds one research-priority section derived from the existing component, entry-point, route, dependency, threat, and authority evidence.

```text
KUZUSHI · target-project · MAP
Map   Scan×   Review×   Prove×   Fix×
────────────────────────────────────────────────────────────────────────
[Summary] · DFD · Entry points · Components

PROJECT SUMMARY                         RESEARCH PRIORITIES
Coding-agent CLI and tool runtime       1. command and tool execution
Repository data influences plans        2. project-controlled configuration
Local filesystem/process effects        3. workspace path containment
Native parser dependencies              4. parser and FFI boundaries
Multiple delegated tools                5. child-process authority

ATTACK-SURFACE FLOW
project-controlled data
    -> configuration / instructions
    -> planner or model decision
    -> tool arguments
    -> approval / policy boundary
    -> filesystem / process / network effect

TOP SURFACES
  91  tool argument normalization
  88  project configuration loading
  83  executable resolution
  79  workspace path containment
  74  native parser and FFI boundaries
  69  child-process cleanup and inheritance

COVERAGE LIMITS
  source inventory complete
  generated code partial
  native dependency internals unavailable

────────────────────────────────────────────────────────────────────────
NEXT Enter start exploitability-first research
```

### 3.1 Research priority is not a vulnerability score

The priority combines:

- boundary importance;
- attacker influence;
- exposed entry-point reachability;
- code complexity or parser sensitivity;
- historical finding density;
- existing test/harness leverage;
- available proof backend;
- estimated research cost.

The TUI should expose the reasons for a selected surface. It must not claim that a high-priority surface is vulnerable.

### 3.2 One primary action

The default Map action starts a bounded research sweep.

The operator may optionally change focus through the shared composer:

```text
focus repository trust and command execution
```

or open advanced strategy controls:

```text
strategies
```

Neither is required.

## 4. Research launch

Pressing Enter creates one governed Scan plan from the current Map.

The plan is generated in this order:

```text
current Map evidence
  -> candidate research surfaces
  -> compatible strategy templates
  -> preflight and budget
  -> automatic low-risk selection
  -> one visible plan receipt
  -> Run Focus
```

The default plan may include:

1. structural/static path analysis;
2. cross-engine corroboration;
3. dangerous-boundary review;
4. differential or metamorphic variants;
5. bounded repository mutation;
6. harness generation;
7. sandboxed reproduction;
8. deterministic evaluator checks;
9. candidate ranking.

Only strategies whose requirements are met enter the run. Missing backends become explicit skipped rows, not silent degradation.

## 5. Run Focus: one foreground execution view

The existing Run Focus screen is the only live research presentation.

```text
RUN FOCUS · SCAN · sequence 3/8 · LIVE · $1.42 · queued 5
────────────────────────────────────────────────────────────────────────
STEPS                              │ OUTPUT · path-boundary research
✓ map high-risk boundaries         │ 17 path-sensitive operations
✓ generate candidate invariants    │ 6 permission/effect invariants
> test path-resolution variants    │ variant 41/180
o inspect authority chains         │ lexical path != resolved target: 3
o build focused harnesses          │
o reproduce promising effects      │
o rank exploit candidates          │
────────────────────────────────────────────────────────────────────────
s steer       b background       Tab focus       Ctrl+C cancel
```

### 5.1 What the screen must show

- the research surface or selected finding;
- ordered semantic steps;
- current strategy;
- bounded progress;
- cost and budget;
- queue depth;
- failures or policy blocks;
- observation-boundary degradation;
- terminal receipt.

It must not stream hidden reasoning or raw model transcripts.

### 5.2 Optional steering

Steering is additive and uses the existing `run <tool> ...` contract.

Examples:

```text
run research:focus --area "repository trust and command execution"
run research:expand --finding F-0007
run research:stop-surface --surface native-parser
```

A steer command enters after the current chain and plan work. It does not rewrite already committed history.

### 5.3 Background by default for long work

A research sweep may take minutes or hours. `b` backgrounds it without cancellation. Completion produces a durable notice and Scan receipt; it must not steal focus.

## 6. Scan: account for the research funnel

Scan remains a resting projection of one selected attempt.

```text
VIEW SCAN · EXPLOIT RESEARCH              ATTEMPT scan-20260819-07 · COMPLETE
────────────────────────────────────────────────────────────────────────────
Attack surfaces tested      14            candidates                23
Harnesses executed          67            reproduced anomalies       5
Rejected candidates         18            proof-ready candidates     2
Duration                 1h42m            measured cost           $5.84

RESEARCH COVERAGE                         RESULT
static paths              complete         +23 candidate observations
tool execution            complete         5 runtime anomalies
path containment          complete         2 proof-ready findings
native parser surface     partial          1 crash, not reproduced
network behavior          skipped          no admitted harness

FUNNEL
proposed strategies        11
preflight admitted          8
completed                    7
partial                      1
candidate observations      23
deduplicated findings         5
proof-ready findings          2

TOP RESULT
F-0007 · project-controlled path reaches mismatched execution target
7/8 reproductions · boundary implicated · arbitrary control unproven

────────────────────────────────────────────────────────────────────────────
NEXT use & review
```

### 6.1 Required honesty

Scan must distinguish:

- not selected;
- preflight blocked;
- skipped because a backend was unavailable;
- execution failed;
- execution partial;
- completed with no observation;
- candidate generated;
- candidate deduplicated;
- candidate rejected;
- reproduced anomaly;
- proof-ready finding.

Every admitted strategy and every generated candidate receives a terminal reason.

### 6.2 Clean does not mean complete

A clean attempt says:

```text
No qualifying observation within the declared research and observation boundary.
```

It does not say:

```text
The project has no exploitable vulnerabilities.
```

## 7. Review: the exploit-candidate queue

Review remains finding-centered.

```text
REVIEW · 5 NEED ACTION                         SELECTED · F-0007
────────────────────────────────────────────────────────────────────────────
> ? CRIT [ooo..] 4 src  91%                    execution target mismatch
  ? HIGH [oo...] 3 src  84%                    pre-trust config execution
  ? HIGH [oo...] 2 src  78%                    child process escapes cleanup
  ! MED  [o....] 1 src  66%                    native parser crash
  - LOW  [o....] 1 src  rejected               expected tool behavior

SELECTED
Project-controlled input influences a path shown in a policy decision.
Runtime resolution reaches a different executable target.

PROOF SNAPSHOT
  static path                         established
  runtime effect                      reproduced 7/8
  attacker-controlled destination     partial
  boundary violation                  unproven
  arbitrary instruction execution    unproven

WHY IT MATTERS
A controlled target mismatch could turn a permitted project operation into
execution outside the intended project boundary.

NEXT v prove attacker control
```

### 7.1 Ranking

Review should order by research value, not severity alone.

A useful ranking model is:

```text
research value =
  boundary importance
  * attacker influence
  * entry-point reachability
  * current primitive strength
  * reproduction reliability
  * evidence quality
  / estimated next-proof cost
```

The underlying factors must be inspectable. The score is advisory.

### 7.2 Human decisions

Existing decisions remain authoritative:

- confirmed;
- rejected false positive;
- suppressed;
- deferred;
- accepted risk;
- needs review.

A machine rejection may reduce rank, but it does not overwrite a human decision attached to stable finding identity.

## 8. `v` is the proof contract

The operator should not design proof chains manually.

Pressing `v` on a selected finding asks the proof planner for the smallest experiment that could change the current proof state.

Examples:

```text
reproduced path mismatch
  -> establish attacker control over the resolved target

attacker-controlled crash
  -> establish controlled corruption

static source-to-sink path
  -> execute a harness that proves the sink effect

unexpected child process
  -> prove that it survives or crosses the intended authority boundary
```

If no backend can run the experiment, Prove says what is missing. It does not substitute model opinion.

## 9. Prove: one ladder, one next action

```text
PROVE · F-0007 · EXECUTION TARGET MISMATCH
STATUS high-value candidate · proof [oooo..]
NEXT v establish execution outside the authorized project root
────────────────────────────────────────────────────────────────────────
EVIDENCE                            │ EXPLOIT LADDER
src/config/load.rs:184              │ suspicious behavior       complete
policy display trace                │ runtime reproduction       complete
process tree receipt                 │ attacker control           complete
filesystem effect receipt            │ boundary crossing          partial
harness and minimized project        │ arbitrary execution        missing
                                     │ clean reproduction         missing

REPRODUCTION
  29 / 32 successful
  median 1.8 seconds
  target commit 71e3d02
  harness digest sha256:9c42…

OBSERVATION LIMITS
  process and filesystem effects observed
  kernel sandbox state not observed

────────────────────────────────────────────────────────────────────────
v run next proof step       r replay       e export current PoC
```

### 9.1 Proof and triage remain separate

A human may believe the finding is real before runtime proof exists. That decision is Review truth.

A runtime receipt may demonstrate an effect without proving security impact. That is Proof truth.

Neither should overwrite the other.

### 9.2 Staleness

A project revision, harness, dependency, backend, evaluator, policy, or relevant environment change can stale proof.

The screen must name exactly which identity changed and offer revalidation.

## 10. PoC export is contextual, not a new phase

Pressing `e` from Prove opens a focused export surface:

```text
EXPORT · F-0007 · POC BUNDLE
────────────────────────────────────────────────────────────────────
Status           READY WITH LIMITATIONS
Finding          execution target mismatch
Proof            attacker control established
Missing          direct kernel sandbox observation
Reproduction     29 / 32
Destination      ./kuzushi-poc-F-0007/

Enter export      e edit path      Esc return to Prove
```

The bundle contains only durable, attributable artifacts:

```text
kuzushi-poc-F-0007/
├── README.md
├── finding.json
├── proof-summary.json
├── reproducer/
├── minimized-project/
├── harness/
├── trigger-input/
├── traces/
├── evaluator-receipts.jsonl
├── target-identity.json
├── observation-boundary.json
└── SHA256SUMS
```

Unknown or missing proof remains explicit in `README.md` and `proof-summary.json`.

Fix remains remediation. Report remains the existing engagement export. No sixth offensive phase is added.

## 11. Advanced surfaces

Advanced operators may open:

- Strategy Queue to inspect, correct, keep, skip, or fire generated strategies;
- Runs and Replay to inspect lineage;
- Trace for bounded diagnostics;
- Capabilities to see available proof backends;
- permission and budget controls;
- prompt overrides.

The default journey must not require them.

## 12. Failure behavior

The TUI must fail honestly:

| Condition | TUI behavior |
| --- | --- |
| Model unavailable | Model-backed strategies skipped or blocked; deterministic work continues only when independently valid. |
| Sandbox unavailable | Execution strategies blocked; no runtime proof claim. |
| Harness fails to build | `HarnessIncomplete`; never `NotReproduced`. |
| Observer fails | Experiment inconclusive; no evaluator success. |
| Candidate cannot be reproduced | Reproduction state recorded; static evidence retained. |
| Budget exhausted | Current authorized work settles; queued work canceled or skipped with terminal reasons. |
| Project changes | Current-revision Map/Scan/Proof state becomes stale according to exact identity. |
| Run interrupted | Durable interrupted receipt and restart-safe recovery path. |
