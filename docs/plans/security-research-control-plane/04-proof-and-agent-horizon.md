# Proof Backends and Agent-Security Horizon — Kuzushi Security Research Control Plane

> **Status:** proposal for review
> **Date:** 2026-08-19
> **Plan index:** [security research control-plane productization](./README.md)
> **Roadmap constraint:** the current [ROADMAP](../../../ROADMAP.md) remains authoritative.

---

## 1. Generic proof backend contract

### 1.1 Why a backend contract

Kuzushi should not implement browsers, symbolic execution, protocol peers, fuzzers, and binary lifters inside one core architecture. It should give those engines a strict contract.

```rust
pub trait ProofBackend {
    fn descriptor(&self) -> ProofBackendDescriptor;

    fn plan(
        &self,
        request: &ExperimentRequest,
    ) -> Result<BackendPlan>;

    fn execute(
        &self,
        authorized: AuthorizedExperiment,
        sink: &mut dyn ObservationSink,
    ) -> Result<BackendTerminal>;
}
```

### 1.2 Descriptor

```rust
pub struct ProofBackendDescriptor {
    pub id: BackendId,
    pub version: String,
    pub artifact_identity: ArtifactIdentity,
    pub observation_kinds: Vec<ObservationKind>,
    pub required_authority: RequestedAuthority,
    pub supported_boundaries: Vec<BoundaryDimension>,
    pub evaluator_kinds: Vec<EvaluatorKind>,
    pub maturity: BackendMaturity,
}
```

### 1.3 Host responsibilities

The host:

- validates descriptor and input;
- resolves prepared tool policy;
- obtains authorization;
- creates the canonical run and experiment attempt;
- binds target and authority;
- captures observation boundary;
- enforces budgets/cancellation;
- normalizes artifacts;
- records evaluator receipts;
- applies proof transitions;
- commits through the writer actor.

### 1.4 Backend responsibilities

The backend:

- declares prerequisites;
- emits bounded progress;
- writes only approved artifacts;
- reports every terminal reason;
- never claims more visibility than it had;
- returns observations, not canonical truth;
- does not persist directly;
- does not silently use an undeclared fallback engine;
- provides exact engine/version/config identity.

### 1.5 Initial backend classes

Use existing capabilities first:

1. static source/AST/CPG query;
2. existing scanner import/execution;
3. existing runtime exploit/harness verification;
4. existing fuzz/reproduction path.

Later, after roadmap gates:

5. browser/CDP;
6. malicious protocol peer;
7. symbolic/binary solver import;
8. deployment/exposure observation;
9. trajectory runtime;
10. external authority-graph importer.

### 1.6 KWP and plugin relationship

A proof backend may be a first-party Rust built-in or a capability-scoped KWP/plugin adapter.

The backend contract must not weaken existing policy:

- no ambient filesystem;
- no ambient environment;
- no arbitrary subprocess;
- no direct finding/proof/research writes;
- strict output schema;
- bounded artifact and observation counts;
- host-computed identity;
- host-owned authorization and settlement.

---

## 2. Proof model refinement

### 2.1 Preserve static proof state

The existing `StaticProofState` remains valuable:

```text
signal_only
code_cited
source_sink_linked
sanitizer_checked
statically_confirmed
statically_rejected
needs_runtime_evidence
```

Do not replace it with one universal confidence score.

### 2.2 Add orthogonal dimensions

Proposed future dimensions:

```rust
pub enum ExecutionWitness {
    None,
    Attempted,
    CrashObserved,
    SanitizerViolation,
    InvariantViolation,
    SymbolicWitness,
    BrowserEffectObserved,
    ProtocolEffectObserved,
    FormalCounterexample,
    ExecutionRejected,
}

pub enum ReachabilityState {
    Unknown,
    LocalHarnessOnly,
    InputControlled,
    EntrypointReachable,
    DeploymentReachable,
}

pub enum ExploitabilityMilestone {
    Unknown,
    UncontrolledFailure,
    ControlledCorruption,
    ReadPrimitive,
    WritePrimitive,
    ControlFlowInfluence,
    MitigationBypassed,
    ImpactDemonstrated,
}

pub enum ExposureState {
    Unknown,
    LocalOnly,
    AuthenticatedSurface,
    UnauthenticatedSurface,
    CrossServicePath,
    InternetObserved,
}
```

These are examples; names require code-level reconciliation with existing verification types.

### 2.3 Transition ownership

Each transition names:

- previous state;
- next state;
- evaluator receipt;
- witness artifacts;
- backend identity;
- observation boundary;
- policy;
- actor;
- timestamp.

A model explanation may accompany the transition but cannot own it.

### 2.4 No false total order

Do not sort all proof states into one numeric ladder.

For example:

- a formal witness may establish a bug while deployment exposure remains unknown;
- a remote endpoint may be exposed while exploitability remains uncontrolled;
- a crash may be reproducible without attacker input equivalence;
- a static path may be strong while runtime instrumentation is unavailable.

The UI may summarize, but storage must preserve dimensions.

### 2.5 Patch closure

Patch verification should distinguish:

```text
signal absent
static path absent
runtime witness absent
primitive removed
entrypoint no longer reaches primitive
exposure path removed
impact no longer achievable
```

A closure claim states which predicates were rerun and which remain untested.

---

## 3. Authority graph and trajectory policy — later product horizon

### 3.1 Authority graph

The graph models principals, credentials, tools, agents, services, and effects.

Nodes:

```text
principal
agent
subagent
credential
model
tool
module
MCP server
A2A agent
gateway
service
deployment
config source
instruction source
memory/RAG store
artifact
process
data sink
```

Edges:

```text
can_read
can_write
can_call
can_execute
authenticates_as
delegates_to
loads_config_from
consumes_output_from
can_reach
can_egress_to
resolves_credential_through
```

Every edge records:

- inferred, observed, or actively verified;
- evidence references;
- environment identity;
- first/last observed;
- expiry/retest;
- source backend.

The graph does not replace the CPG. It answers authority and cross-system questions, not code data-flow questions.

### 3.2 Attack-path observation

Keep intrinsic defect separate from environment exposure.

```rust
pub struct AttackPathObservation {
    pub finding: FindingIdentityId,
    pub environment: EnvironmentIdentity,
    pub path: Vec<AuthorityEdgeRef>,
    pub state: PathObservationState,
    pub evidence: Vec<EvidenceRef>,
    pub observed_at: Timestamp,
    pub expires_at: Option<Timestamp>,
}
```

A changed deployment path should not mutate the root finding identity.

### 3.3 Normalized action events

Later trajectory policy requires:

```rust
pub struct ActionEvent {
    pub run_id: RunId,
    pub session_id: SessionId,
    pub subagent_id: Option<SubagentId>,
    pub principal: AuthorityPrincipal,
    pub tool: ArtifactIdentity,
    pub operation: NormalizedOperation,
    pub resources_read: Vec<ResourceRef>,
    pub resources_written: Vec<ResourceRef>,
    pub processes: Vec<ProcessEffect>,
    pub network: Vec<NetworkEffect>,
    pub data_labels_in: Vec<DataLabel>,
    pub data_labels_out: Vec<DataLabel>,
    pub decision: ActionDecision,
    pub effect_receipt: Option<EvidenceRef>,
}
```

### 3.4 Initial stateful policies

When this horizon begins, start inside Kuzushi's own execution boundary:

```text
secret read → encode/transform → outbound network
target instruction → privileged tool argument
untrusted tool output → repository execution
delegation → broader authority
credential source controlled separately from destination
memory/RAG write → later-session privileged action
several low-risk effects → cumulative budget/scope violation
```

Do not begin with endpoint-wide monitoring. Prove the semantic contract on Kuzushi-owned events first.

---
