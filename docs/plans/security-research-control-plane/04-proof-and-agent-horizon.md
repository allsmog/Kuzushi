# Proof planner, exploit ladders, and backend boundary

## 1. Goal

Make `v` the simplest useful command in exploit research.

When the operator selects a finding and presses `v`, Kuzushi should:

1. read the finding’s current proof snapshot;
2. identify the smallest missing proof claim that materially changes confidence or impact;
3. select a compatible backend;
4. estimate cost, time, authority, and observation requirements;
5. prepare and authorize the experiment through the shared dispatch boundary;
6. open Run Focus;
7. evaluate the result with a host-owned predicate;
8. update Prove and propose the next step.

The operator should not have to design a research tree.

## 2. Proof dimensions

Keep the existing static proof ladder.

Add orthogonal exploit-research dimensions:

```rust
enum ReproductionState {
    Unknown,
    Attempted { attempts: u32 },
    Reproduced { successes: u32, attempts: u32 },
    Flaky { successes: u32, attempts: u32 },
    NotReproduced { attempts: u32 },
    Inconclusive,
}

enum AttackerControlState {
    Unknown,
    InputInfluence,
    PartialControl,
    ControlledValue,
    ControlledTarget,
    ControlledInstruction,
}

enum BoundaryCrossingState {
    Unknown,
    WithinDeclaredBoundary,
    WorkspaceBoundaryCrossed,
    PermissionBoundaryCrossed,
    ProcessBoundaryCrossed,
    SandboxBoundaryCrossed,
}

enum PrimitiveState {
    Unknown,
    Crash,
    LogicPrimitive,
    ReadPrimitive,
    WritePrimitive,
    ControlFlowInfluence,
    CodeExecution,
}

enum ReachabilityState {
    Unknown,
    LocalHarnessOnly,
    ProjectInputReachable,
    EntrypointReachable,
    DefaultPathReachable,
}

enum ImpactState {
    Unknown,
    Availability,
    Confidentiality,
    Integrity,
    PrivilegeIncrease,
    ArbitraryCodeExecution,
}
```

The exact enum may be refined by implementation, but the dimensions must not collapse into one `confirmed` boolean.

## 3. Class-specific proof ladders

### 3.1 Source-to-sink finding

```text
signal
-> source cited
-> sink cited
-> path linked
-> sanitizer/guard evaluated
-> runtime effect observed
-> attacker-controlled input demonstrated
-> exposed entry point demonstrated
```

### 3.2 Command, tool, or permission boundary

```text
unexpected effect
-> effect reproduced
-> project-controlled influence
-> controlled target or argument
-> outside intended workspace
-> outside permission grant
-> arbitrary instruction execution
-> clean reproduction
```

### 3.3 Memory corruption

```text
crash
-> deterministic reproduction
-> controlled corruption
-> read or write primitive
-> control-flow influence
-> mitigation bypass
-> code execution
-> reachable project input
```

### 3.4 Parser or protocol logic

```text
parser divergence
-> invalid state transition
-> security-relevant state or memory effect
-> attacker-controlled message
-> exposed parser entry point
-> meaningful impact
```

### 3.5 Authentication or authorization

```text
policy discrepancy
-> unauthorized state transition
-> attacker-controlled principal/input
-> protected operation reached
-> access or privilege impact
-> default-path reproduction
```

### 3.6 Patch closure

```text
patch applied
-> original reproducer rerun
-> original primitive absent or changed
-> alternate equivalent variants tested
-> reachability retested
-> deterministic closure or inconclusive result
```

`Not rediscovered` remains weaker than `Verified`.

## 4. Proof step

```rust
struct ProofStep {
    id: ProofStepId,
    finding_identity: FindingIdentity,
    claim: ProofClaim,
    predicate: EvaluatorIdentity,
    backend_requirement: BackendRequirement,
    planned_input: PreparedProofInput,
    expected_evidence: Vec<EvidenceExpectation>,
    falsification_condition: SafeText,
    estimated_cost: Option<Money>,
    estimated_runtime: Option<DurationRange>,
    effect: ToolEffect,
    approval: ApprovalPolicy,
}
```

A proof step must be falsifiable. “Ask a stronger model whether this is exploitable” is not a runtime proof step.

## 5. Planner policy

Prioritize proof steps by:

```text
value =
  expected proof-state gain
  * decision relevance
  * backend reliability
  / cost
  / runtime
  / authority risk
```

The planner should prefer:

1. deterministic checks;
2. reuse of existing artifacts;
3. minimal changed variables;
4. narrow harnesses;
5. proof of attacker control before speculative impact;
6. direct observation before model interpretation;
7. the smallest experiment that can reject the candidate.

It should avoid expensive exploit engineering while basic reachability or control remains unknown.

## 6. TUI next-action contract

Examples:

```text
NEXT v reproduce the crash with the minimized input
NEXT v prove that project input controls the resolved executable
NEXT v test whether the write escapes the admitted workspace
NEXT v establish that the endpoint is reachable without authentication
NEXT v rerun the original primitive against the applied patch
```

Blocked examples:

```text
PROOF BLOCKED · no admitted native fuzz backend
PROOF BLOCKED · process observer unavailable
PROOF BLOCKED · target changed; refresh Map and rerun the reproducer
PROOF BLOCKED · experiment requires explicit repository execution approval
```

No generic “run verification” label when a precise claim is known.

## 7. Proof backend interface

Specialist engines plug into a host-owned contract.

```rust
trait ProofBackend {
    fn identity(&self) -> ProofBackendIdentity;

    fn supports(
        &self,
        claim: &ProofClaim,
        target: &TargetCapabilities,
    ) -> SupportDecision;

    fn plan(
        &self,
        request: &ProofRequest,
    ) -> Result<BackendExperimentPlan>;

    fn execute(
        &self,
        authorized: AuthorizedExperiment,
        observations: &mut dyn ObservationSink,
    ) -> Result<BackendTerminal>;
}
```

The core owns:

- authorization;
- target and run identity;
- lifecycle;
- cancellation;
- cost;
- artifact registration;
- observation boundary;
- evaluator receipt;
- proof transition;
- replay;
- presentation.

The backend owns domain mechanics.

## 8. Initial backend set

Do not add every possible research engine.

The first useful set is:

### 8.1 Static path backend

Uses existing AST/CPG/CodeQL capabilities to answer:

- source-to-sink path;
- reachable caller chain;
- guard/sanitizer presence;
- project-controlled configuration influence;
- structural boundary path.

### 8.2 Sandboxed process backend

Uses existing repository-execution and sandbox machinery to:

- build a focused harness;
- execute a target;
- capture exit, process, filesystem, and bounded output evidence;
- reproduce deterministic effects.

### 8.3 Fuzz or mutation backend

Build on the existing KWP fuzz direction for:

- bounded input mutation;
- crash discovery;
- reproduction;
- minimization;
- artifact capture.

Production use requires a host-owned isolation backend. A mounted command that merely promises isolation is insufficient for strong proof.

### 8.4 Differential backend

Runs controlled variants while holding target and environment constant.

Useful for:

- path normalization;
- configuration precedence;
- authorization display/effect mismatch;
- parser state differences;
- patch regression;
- invariant violations.

## 9. Later backends

These remain gated behind a working first vertical slice and benchmark evidence:

- browser/CDP;
- malicious protocol peer;
- binary symbolic/concolic solver;
- deployment/exposure observer;
- MCP/A2A authority graph;
- multi-session agent trajectory monitor;
- firmware/device/VM backends.

Adding a backend must not add a new top-level TUI workflow.

## 10. Evaluator contract

Each proof claim names a predicate.

Examples:

```text
process-executed-marker-v1
write-outside-root-v1
crash-reproduced-v1
controlled-byte-observed-v1
source-sink-path-v1
unauthenticated-operation-v1
original-primitive-absent-v1
```

A predicate defines:

- required evidence;
- valid observation boundary;
- success;
- falsification;
- inconclusive states;
- invalid experiment states;
- versioning and compatibility.

The evaluator receipt is the only source for empirical proof advancement.

## 11. Statistical proof

Some behaviors are nondeterministic.

The receipt must record:

- attempts;
- successes;
- invalid attempts;
- environment identity;
- stopping rule;
- success predicate;
- confidence interval or explicit simple ratio;
- whether the result meets policy.

Do not hide one failure inside a “mostly confirmed” badge.

The TUI may show:

```text
29 / 32 reproduced · 90.6%
```

Policy decides whether that is sufficient for a particular claim.

## 12. Negative results

Negative research has value when its boundary is clear.

Possible outcomes:

```text
falsified for tested construction
not reproduced in N valid attempts
inconclusive because observer failed
inconclusive because harness was incomplete
backend unsupported
target changed
budget exhausted
```

A falsified construction does not prove the vulnerability class impossible.

## 13. Agent use

Agents help with:

- surface ranking;
- strategy selection;
- harness drafting;
- mutation proposal;
- trace summarization;
- duplicate clustering;
- next-proof planning;
- impact explanation;
- PoC README drafting.

Agents do not own:

- effect observation;
- evaluator outcomes;
- proof transitions;
- target identity;
- authority grants;
- cost settlement;
- human decisions.

## 14. Cascade behavior

After an evaluator result, the planner may propose the next step.

Examples:

```text
path mismatch reproduced
  -> test controlled alternate target

crash reproduced
  -> minimize input

controlled write established
  -> test entry-point reachability

patch removes original input
  -> generate equivalent variants
```

The operator normally sees only the resulting `NEXT v ...`.

Advanced Replay may expose why the next step was chosen.

## 15. PoC export acceptance

A PoC bundle is `READY` only when:

- target identity is current;
- all referenced artifacts exist and authenticate;
- at least one valid reproduction receipt exists;
- a deterministic reproduction command or procedure is present;
- known proof gaps are listed;
- observation limits are included;
- secrets and unsafe raw payloads are redacted or intentionally packaged;
- bundle manifest and files are hashed.

The bundle may be `READY WITH LIMITATIONS`. It must not overstate proof.

## 16. Safety constraints

- No automatic live-target attack.
- No ambient network.
- No target writes without explicit descriptor and approval.
- No repository execution outside an admitted sandbox path.
- No autonomous persistence or privilege escalation testing on the operator host.
- No model-generated shell command bypassing prepared input.
- No proof claim from stdout text alone when a stronger observer is required.
- Cancellation terminates process groups and settles durable state.
- Resource and artifact limits are enforced, not advisory.
