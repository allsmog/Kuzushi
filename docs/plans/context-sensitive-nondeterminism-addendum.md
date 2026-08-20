# Normative addendum — managed nondeterministic security research

> **Status:** normative companion to `mdash-codemender-architecture-plan.md`
> **Scope:** architecture, product behavior, TUI semantics, and implementation sequencing only; this documentation PR does not change runtime behavior
> **Decision:** Kuzushi must preserve, expose, steer, and learn from nondeterminism. It must not treat agreement, convergence, or repeatability as the primary objective of security research.

## Supersession and correction

This document supersedes any earlier wording in this PR that sounds as though Kuzushi should make agentic scans deterministic, normalize away context sensitivity, or keep sampling until models converge on one answer.

The corrected thesis is:

> **Kuzushi is a control room for nondeterministic security research. It deliberately varies context, models, roles, tools, decomposition, and hypotheses; preserves the union of discoveries; measures where findings appear and disappear; adaptively allocates budget; and converts the strongest uncertain hypotheses into empirical evidence.**

Stable source identities, immutable receipts, explicit cache policy, content-addressed context manifests, and replayable projections remain necessary. They are the governance envelope around stochastic research. They are not an attempt to force stochastic reasoning into deterministic output.

A reproducible exploit, regression test, or contest runner may eventually be a goal-specific deliverable. That is a downstream property of one selected result, not the operating principle of the research system.

---

# 1. Product model

The product should separate three layers.

## 1.1 Stable governance layer

This layer defines what the research process may vary and what it may never silently change:

- target and source identity;
- operator-selected model/provider policy;
- allowed tools and execution capabilities;
- network, filesystem, process, and mutation authority;
- context-authority rules;
- budget ceilings and allocation constraints;
- proof vocabulary and evidence thresholds;
- approval policy;
- artifact schemas and retention;
- no-silent-fallback semantics.

This is the role of `InvestigationPlanV1`: it is an immutable **research constitution**, not a fully enumerated list of every model call that will happen.

## 1.2 Nondeterministic research layer

This layer is deliberately variable:

- source decomposition;
- frontier scope;
- threat lens;
- context composition;
- retrieval strategy;
- context and evidence ordering;
- model;
- agent role;
- prompt framing;
- tool profile;
- number and timing of samples;
- hypothesis-follow-up strategy;
- proof-harness and patch candidate generation.

This is the role of `ResearchCampaignV1`: it owns a live portfolio of research arms, hypotheses, experiments, scheduler decisions, and budget allocations.

## 1.3 Empirical adjudication layer

This layer asks mechanical, evidence-bearing questions about selected hypotheses:

- can attacker-controlled input reach the claimed effect;
- does the vulnerable condition reproduce;
- does a benign control remain safe;
- do variants reproduce;
- does a proposed patch block the original and variant cases;
- does the originating detector still rediscover the issue;
- did normal behavior regress.

Models may propose experiments, harnesses, and interpretations. Runtime evidence determines empirical proof state.

## 1.4 End-to-end loop

```text
Capture source and policy
  -> build an initial research frontier
  -> create a diverse portfolio of research arms
  -> execute fresh stochastic samples
  -> union observations into the hypothesis ledger
  -> measure context/model/role/tool sensitivity
  -> adaptively allocate more budget
  -> generate adversarial challenges and discriminating experiments
  -> empirically adjudicate selected hypotheses
  -> explore a bounded patch portfolio
  -> approve one exact patch
  -> apply, reattack, and replay the originating detector
  -> publish evidence, context, variance, and decision receipts
```

The loop may branch, pause, retire low-yield arms, reopen old hypotheses, or create successor campaigns. It is not a one-way funnel requiring consensus at every stage.

---

# 2. Core domain model

## 2.1 `InvestigationPlanV1` remains, but its responsibility narrows

The main architecture plan proposes `InvestigationPlanV1`. Keep it, but define it as the stable governance envelope:

```rust
pub struct InvestigationPlanV1 {
    pub schema_version: u32,
    pub investigation_id: InvestigationId,
    pub target_identity: TargetContentIdentity,
    pub objective: ResearchObjective,
    pub allowed_variability: AllowedVariabilityPolicy,
    pub roles: BTreeMap<SecurityRole, RoleBoundary>,
    pub tools: InvestigationToolPolicy,
    pub context_authority: ContextAuthorityPolicy,
    pub proof: InvestigationProofPolicy,
    pub patch: InvestigationPatchPolicy,
    pub budgets: InvestigationBudgetPolicy,
    pub mutation: MutationPolicy,
}
```

The plan does **not** have to enumerate every context arm, sample, or follow-up before research begins. It defines the legal and budgetary space in which the campaign may evolve.

Material operator-policy changes create a successor plan. Scheduler choices inside the existing policy produce append-only campaign events, not successor plans.

## 2.2 Add `ResearchCampaignV1`

```rust
pub struct ResearchCampaignV1 {
    pub campaign_id: ResearchCampaignId,
    pub investigation_plan_digest: Blake3Hash,
    pub source_identity: TargetContentIdentity,
    pub policy: ResearchPolicyV1,
    pub arms: BTreeMap<ResearchArmId, ResearchArmState>,
    pub hypotheses: HypothesisLedgerRef,
    pub experiment_queue: ExperimentQueueRef,
    pub allocation_state: AllocationStateV1,
    pub scheduler_state: SchedulerStateV1,
    pub created_at: Timestamp,
}
```

The campaign is projected from events such as:

```text
campaign_started
arm_proposed
arm_activated
arm_sample_completed
arm_allocation_changed
arm_paused
arm_retired
hypothesis_observed
hypothesis_linked
hypothesis_challenged
experiment_proposed
experiment_completed
operator_corrected
budget_reserved
budget_released
campaign_paused
campaign_resumed
campaign_branched
campaign_closed
```

No scheduler decision should rewrite past runs, observations, or operator decisions.

## 2.3 Add `ResearchPolicyV1`

```rust
pub struct ResearchPolicyV1 {
    pub allocation: ResearchBudgetAllocationV1,
    pub minimum_context_diversity: u32,
    pub minimum_role_diversity: u32,
    pub minimum_model_diversity: u32,
    pub per_arm_max_share: Decimal,
    pub rare_signal_policy: RareSignalPolicyV1,
    pub novelty_policy: NoveltyPolicyV1,
    pub challenge_policy: ChallengePolicyV1,
    pub stop_policy: CampaignStopPolicyV1,
}
```

A recommended default allocation is illustrative, not hardcoded product truth:

```text
broad exploration             40%
hypothesis follow-up          30%
adversarial challenge         20%
wildcard / surprise reserve   10%
```

The operator may adjust these shares. The scheduler may move budget within declared ranges, but it must preserve any configured exploration reserve and diversity floors.

## 2.4 Add `ResearchArmV1`

A research arm is the unit of managed variability:

```rust
pub struct ResearchArmV1 {
    pub arm_id: ResearchArmId,
    pub objective: ArmObjective,
    pub parent_hypothesis: Option<HypothesisId>,
    pub frontier_scope: Vec<FrontierUnitId>,
    pub threat_lens: ThreatLensRef,
    pub context_recipe: ContextRecipeRef,
    pub decomposition: DecompositionStrategy,
    pub role: SecurityRole,
    pub model: ModelSpec,
    pub tool_profile: ToolProfileRef,
    pub prompt_variant: PromptVariantRef,
    pub allocation: ArmAllocationV1,
    pub authority: ArmAuthority,
}
```

Example arms for an AI coding-agent repository:

```text
permission boundaries × function-level decomposition × minimal source context
permission boundaries × end-to-end call path × threat model included
plugin trust × lifecycle decomposition × repository guidance excluded
MCP confused deputy × tool-schema-first framing × dynamic resources included
provider credentials × data-flow framing × structural tools only
wildcard × randomly selected high-risk frontier slice × alternate model
```

The objective is not to make these arms agree. It is to explore different regions and representations of the vulnerability space.

## 2.5 Add `ResearchRunReceiptV1`

Every run records enough information to interpret differences:

```rust
pub struct ResearchRunReceiptV1 {
    pub run_id: ResearchRunId,
    pub campaign_id: ResearchCampaignId,
    pub arm_id: ResearchArmId,
    pub sample_id: SampleId,
    pub parent_run_ids: Vec<ResearchRunId>,
    pub source_identity: TargetContentIdentity,
    pub context_envelope: ContextEnvelopeRef,
    pub resolved_model: ResolvedModelReceiptV1,
    pub tool_contracts: Vec<ToolContractRefV1>,
    pub model_call_receipts: Vec<ModelCallReceiptRefV1>,
    pub cost: RuntimeCostReport,
    pub duration: Duration,
    pub outcome: ResearchRunOutcome,
}
```

A run can be fresh and independent, intentionally seeded by prior output, structurally deterministic, or dynamically tool-influenced. The receipt names that relationship rather than reducing all runs to one support count.

---

# 3. Nondeterminism is research material

## 3.1 Types of useful variation

Kuzushi should distinguish at least:

1. **Model stochasticity** — fresh calls using equivalent admitted context.
2. **Context sensitivity** — different context recipes, retrievals, ordering, or evidence availability.
3. **Decomposition sensitivity** — function, file, package, call-path, lifecycle, or invariant-oriented framing.
4. **Role sensitivity** — hunter, systems auditor, adversarial verifier, threat modeler, exploit designer, or patch critic.
5. **Model diversity** — explicitly selected models or providers.
6. **Tool diversity** — structural analyzers, CPG, CodeQL, tree-sitter, dynamic probes, imported scanners, or no-tools arms.
7. **Environment/tool variance** — changed tool output, dynamic external data, tool versions, or execution environment.
8. **Lineage effects** — a follow-up intentionally seeded by one or more prior hypotheses.

These are not all interchangeable forms of independence. They are dimensions of the research topology.

## 3.2 Context sensitivity is a finding about the research process

Examples:

```text
A hypothesis appears only with full call-path context.
  -> likely long-range reasoning requirement.

A hypothesis disappears when repository documentation is included.
  -> possible anchoring or context dilution.

A hypothesis appears only when a permission invariant is supplied.
  -> generic review may lack the necessary abstraction.

A hypothesis appears across different contexts and models.
  -> higher research priority, but still not empirical proof.

A hypothesis appears only after another model proposes a specific sub-question.
  -> useful lineage-dependent discovery; not independent rediscovery.
```

The TUI should expose these patterns instead of hiding them behind one confidence number.

## 3.3 Same-context replication is optional instrumentation

Fresh equivalent-context calls can help estimate model stochasticity, but they are not the campaign’s default objective and do not need to converge.

Use them when they answer a research question such as:

- is this context recipe producing diverse useful hypotheses;
- is an observation exceptionally rare;
- is a verifier unstable under the same evidence;
- does a prompt or tool change increase useful yield.

Do not run repeated calls merely to create the appearance of consensus.

---

# 4. Fresh-call and semantic-cache integrity remains PR 0

Managing nondeterminism requires knowing whether a supposed sample was actually sampled.

The current verifier panel loops through `run_one_verify_pass`, while that helper uses `query_cached_structured_json_with_cost`. Until cache-key behavior is proven, `VERIFY_PASSES=N` must not be assumed to mean N fresh model invocations.

Add explicit purpose and cache policy:

```rust
pub enum ModelCallPurpose {
    ReusableAnalysis,
    DiscoverySample {
        campaign_id: ResearchCampaignId,
        arm_id: ResearchArmId,
        sample_id: SampleId,
    },
    HypothesisFollowUp {
        hypothesis_id: HypothesisId,
        experiment_id: ExperimentId,
    },
    AdversarialChallenge {
        challenge_set_id: ChallengeSetId,
        challenge_id: ChallengeId,
    },
    VerificationVote {
        panel_id: VerificationPanelId,
        vote_id: VerificationVoteId,
    },
    PatchCandidate {
        patch_portfolio_id: PatchPortfolioId,
        candidate_id: PatchCandidateId,
    },
}

pub enum ModelCachePolicy {
    ReadWrite,
    ReadOnly,
    WriteOnly,
    Bypass,
}
```

Required semantics:

- a cached model response is a replayed artifact, not a new research sample;
- discovery samples, challenges, votes, and patch candidates have unique invocation identities;
- independent samples cannot read another sample’s model response from semantic cache;
- intentionally lineage-seeded arms may read prior model outputs only when the context envelope names them;
- replay of persisted receipts makes zero model calls;
- rerunning an arm creates a new sample ID and a fresh call;
- identical outputs are valid, but receipts must prove distinct invocations;
- provider seed/version opacity is recorded as a limitation.

This remains the first implementation slice because every downstream novelty, diversity, support, and independence metric depends on it.

---

# 5. Context management, not context normalization

## 5.1 `ContextEnvelopeV1` is an observability artifact

Every model-produced observation, challenge, proof proposal, or patch candidate references a context envelope:

```rust
pub struct ContextEnvelopeV1 {
    pub source_identity: TargetContentIdentity,
    pub investigation_plan_digest: Blake3Hash,
    pub campaign_id: ResearchCampaignId,
    pub arm_id: ResearchArmId,
    pub role: SecurityRole,
    pub context_recipe: ContextRecipeRef,
    pub items: Vec<ContextItemRefV1>,
    pub retrieval: RetrievalManifestV1,
    pub tools: Vec<ToolContractRefV1>,
    pub truncation: ContextTruncationReceiptV1,
    pub prior_model_lineage: Vec<ModelOutputRefV1>,
    pub model: ResolvedModelReceiptV1,
    pub generation: GenerationParametersV1,
    pub cache_policy: ModelCachePolicy,
    pub completeness: ContextCompleteness,
}
```

The purpose is to explain what influenced a result and enable meaningful branching or comparison. Kuzushi should not designate one context envelope as the universally correct context.

## 5.2 Context authority classes

```rust
pub enum ContextClass {
    OperatorPolicy,
    RepositoryGuidance,
    SourceEvidence,
    DeterministicToolOutput,
    DynamicToolOutput,
    ExternalIntel,
    PriorModelOutput,
    HumanDecision,
}
```

Authority rules:

- `OperatorPolicy` may define models, permissions, budgets, proof rules, and mutation authority.
- `RepositoryGuidance` may inform build/test commands, generated-file conventions, and architecture terminology.
- `RepositoryGuidance`, `SourceEvidence`, and `PriorModelOutput` cannot silently change operator policy.
- Source comments, fixtures, Markdown, issue templates, and prompt-like strings are untrusted data.
- Prior model output is allowed to seed a declared follow-up arm; it is not treated as independent evidence.
- Human decisions affect the declared workflow decision, not empirical truth.

## 5.3 Context recipes are first-class research strategies

```rust
pub struct ContextRecipeV1 {
    pub recipe_id: ContextRecipeId,
    pub source_selection: SourceSelectionPolicy,
    pub retrieval_strategy: RetrievalStrategy,
    pub include_repository_guidance: bool,
    pub include_threat_model: bool,
    pub include_prior_findings: PriorFindingPolicy,
    pub include_prior_model_outputs: PriorModelOutputPolicy,
    pub evidence_ordering: EvidenceOrderingPolicy,
    pub context_budget: ContextBudget,
    pub truncation_policy: TruncationPolicy,
}
```

The scheduler may compare or branch context recipes when doing so is legal under the plan. Every branch is explicit and attributable.

---

# 6. Adaptive research allocation

## 6.1 Explore versus exploit

Kuzushi should manage a portfolio rather than greedily choose one best arm.

A default policy might reserve:

```text
40% broad exploration
30% hypothesis-specific follow-up
20% adversarial challenge
10% wildcard exploration
```

As results arrive:

- high novelty, low support -> preserve and allocate bounded follow-up;
- high support across diverse arms -> escalate to adversarial challenge;
- support isolated to one context family -> branch context experiments;
- repeated low-yield arm -> reduce allocation, not necessarily delete history;
- mature hypothesis with testable predicates -> propose empirical experiments;
- rare high-impact signal -> bypass ordinary support thresholds;
- productive arm becoming repetitive -> redirect some budget to adjacent unexplored space.

## 6.2 Scheduler value model

The scheduler should use an explainable value model, not one opaque LLM priority:

```text
research_value =
    severity_potential
  + novelty
  + expected_information_gain
  + unresolved_uncertainty
  + cross_boundary_relevance
  + operator_priority
  + rare_signal_bonus
  - expected_cost
  - redundancy_penalty
  - saturation_penalty
```

The exact formula may evolve, but every allocation change must disclose its reasons.

## 6.3 Anti-collapse safeguards

Security research cannot be managed as a purely greedy multi-armed bandit. Required safeguards:

- nonzero wildcard reserve;
- minimum context, role, and model diversity when configured;
- per-arm maximum budget share;
- bounded follow-up for rare high-impact signals;
- no automatic dismissal based only on low frequency;
- no majority filter on discovery observations;
- operator pinning of hypotheses or arms;
- append-only operator corrections;
- visibility into omitted or starved frontier areas.

## 6.4 Stop conditions

A campaign may stop or pause because:

- the hard budget is reached;
- the operator stops it;
- marginal novelty and information gain fall below policy thresholds across the portfolio;
- all pinned/high-priority hypotheses reach a defensible handoff state;
- required tools, models, or proof backends are unavailable;
- the source identity changes and policy requires a successor campaign.

Agreement or convergence is **not** a universal stop condition.

---

# 7. Hypothesis ledger and support topology

## 7.1 Discovery is union-oriented

```text
all valid observations from all legal research arms
  -> observation identity/deduplication
  -> semantic clustering
  -> hypothesis ledger
  -> support and sensitivity projection
```

A finding seen once is retained. Frequency affects prioritization and interpretation, not existence.

## 7.2 Add `HypothesisV1`

```rust
pub struct HypothesisV1 {
    pub hypothesis_id: HypothesisId,
    pub target_identity: TargetContentIdentity,
    pub normalized_claim: NormalizedSecurityClaim,
    pub observation_ids: Vec<FindingIdentity>,
    pub cluster_id: Option<VulnerabilityClusterId>,
    pub support: HypothesisSupportV1,
    pub maturity: HypothesisMaturity,
    pub open_questions: Vec<ResearchQuestion>,
    pub experiment_ids: Vec<ExperimentId>,
}
```

Suggested maturity states:

```rust
pub enum HypothesisMaturity {
    Seed,
    Corroborated,
    ContextSensitive,
    AdversariallySurviving,
    ExperimentReady,
    EmpiricallyReproduced,
    Rejected,
    Inconclusive,
    RemediationReady,
}
```

These states describe research workflow. Only empirical proof types describe runtime reproduction.

## 7.3 Add `HypothesisSupportV1`

```rust
pub struct HypothesisSupportV1 {
    pub fresh_run_ids: Vec<ResearchRunId>,
    pub supporting_arms: Vec<ResearchArmId>,
    pub missing_arms: Vec<ResearchArmId>,
    pub context_families: BTreeSet<ContextFamilyId>,
    pub models: BTreeSet<ModelSpec>,
    pub roles: BTreeSet<SecurityRole>,
    pub deterministic_sources: BTreeSet<ToolIdentity>,
    pub lineage_sources: Vec<ModelOutputRefV1>,
    pub challenge_receipts: Vec<ChallengeReceiptRefV1>,
    pub empirical_status: RuntimeProofStatus,
    pub independence: IndependenceGrade,
}
```

## 7.4 Independence is descriptive, not a score multiplier pretending to be proof

Suggested labels:

```text
none
cached_replay
lineage_seeded
fresh_same_context_same_model
fresh_context_diverse_same_model
fresh_same_context_model_diverse
fresh_context_and_model_diverse
deterministic_and_agentic_cross_source
```

Kuzushi may use these labels in prioritization, but none upgrades a hypothesis to empirical proof.

## 7.5 Support topology presentation

The TUI should answer:

```text
Where was this found?
Where was it missed?
Which context changes made it appear or disappear?
Which models and roles found it?
Which tools independently corroborated source facts?
Was it rediscovered or merely copied through lineage?
Which objections remain unresolved?
Has any empirical experiment adjudicated it?
```

Do not reduce this to `confidence = 83%`.

---

# 8. Adversarial validation is experiment generation, not a vote ceremony

## 8.1 Clean-room context firewall remains essential

An adversarial challenger receives:

- normalized claim;
- exact source identity;
- validated source/evidence references;
- explicit invariant or security question;
- role-specific allowed tools.

It does not receive, unless a declared appeal workflow requires it:

- discovery-agent confidence;
- persuasive discovery prose;
- raw support frequency;
- previous challenge conclusions;
- human verdict;
- proposed patch;
- exploit storytelling.

This limits correlated confirmation while preserving rich discovery context in the research layer.

## 8.2 Diversify challenge objectives

Instead of three identical “is this exploitable?” passes, assign distinct falsification jobs:

```text
attacker-control challenger
reachability challenger
mitigation/guard challenger
environment/precondition challenger
alternate-explanation challenger
exploit-oracle designer
```

Each produces structured output:

```rust
pub struct ChallengeReceiptV1 {
    pub challenge_id: ChallengeId,
    pub hypothesis_id: HypothesisId,
    pub objective: ChallengeObjective,
    pub context_envelope: ContextEnvelopeRef,
    pub supporting_evidence: Vec<EvidenceRef>,
    pub counterevidence: Vec<EvidenceRef>,
    pub unresolved_assumptions: Vec<Assumption>,
    pub proposed_discriminating_experiments: Vec<ExperimentProposalV1>,
    pub routing_recommendation: ChallengeRoutingRecommendation,
}
```

## 8.3 Existing gate/panel/tie-break behavior should be reinterpreted

- A cheap gate may reject obvious noise, but cannot confirm a vulnerability.
- Multiple verifier calls should produce diverse objections and experiments, not merely a majority Boolean.
- Majority may remain useful workflow metadata, but it is not the central product output.
- A tie-break model may recommend routing or synthesize unresolved questions; it does not create empirical truth.

The most valuable verifier result is often:

```text
These two objections are resolved by source evidence.
This remaining assumption can be tested by instrumenting the authorization and execution identities.
```

---

# 9. Empirical experiments are a managed portfolio too

## 9.1 Add `ExperimentQueueV1`

```rust
pub struct ExperimentProposalV1 {
    pub experiment_id: ExperimentId,
    pub hypothesis_id: HypothesisId,
    pub question: ResearchQuestion,
    pub expected_information_gain: Decimal,
    pub estimated_cost: EstimatedCost,
    pub safety_policy: ExperimentSafetyPolicy,
    pub required_backend: ProofBackendRequirement,
    pub proposer: ExperimentProposer,
}
```

The operator or scheduler may approve bounded safe experiments according to policy.

## 9.2 Proof-harness generation may itself branch

For a serious hypothesis, Kuzushi may explore several harness candidates:

```text
candidate A  direct unit-level reproducer
candidate B  end-to-end integration reproducer
candidate C  protocol-level reproducer
candidate D  dynamic instrumentation probe
```

Compare them by:

- whether the vulnerable source calibrates;
- whether a benign control remains clean;
- sink reachability;
- isolation quality;
- portability;
- cost and duration;
- variant-generation potential.

The selected empirical receipt must state which harness won and why.

## 9.3 Empirical proof remains mechanically typed

Model support, context robustness, and challenge survival cannot mint `RuntimeProofVerdict::Reproduced`.

Only an admissible empirical receipt can do that.

---

# 10. Patch generation is a portfolio, not one canonical model answer

## 10.1 Add `PatchPortfolioV1`

```rust
pub struct PatchPortfolioV1 {
    pub portfolio_id: PatchPortfolioId,
    pub hypothesis_id: HypothesisId,
    pub empirical_proof: RuntimeProofRef,
    pub candidates: Vec<PatchCandidateRef>,
    pub comparison: PatchComparisonMatrixV1,
}
```

Potential strategies:

```text
minimal local guard
normalize before authorization
bind approved identity through dispatch
final authorization at sink
architectural state-machine repair
defense-in-depth variant
```

## 10.2 Compare with evidence

```text
                         A      B      C
build/test               pass   pass   pass
original exploit         block  block  block
variant set              3/4    4/4    4/4
benign controls          pass   fail   pass
detector replay          clean  clean  clean
diff size                24     17     31
maintenance risk         low    high   medium
```

The operator approves one exact source-bound diff. No majority vote chooses the patch, and the model does not regenerate after approval.

---

# 11. TUI product contract

Keep the existing top-level journey:

```text
Setup -> Map -> Scan -> Review -> Prove -> Fix -> Report
```

Do not add a separate “nondeterminism page.” Each existing page should expose the relevant part of the live research campaign.

## 11.1 Setup — research constitution and portfolio policy

```text
┌─ SETUP · RESEARCH POLICY ─────────────────────────────────────────────┐
│ Target             anomalyco/opencode                                │
│ Goal               coding-agent trust-boundary research              │
│ Source             exact commit / tree identity                      │
│                                                                    │
│ Budget allocation                                                   │
│   broad exploration          40%                                    │
│   hypothesis follow-up       30%                                    │
│   adversarial challenge      20%                                    │
│   wildcard reserve           10%                                    │
│                                                                    │
│ Diversity floors                                                   │
│   context families           4                                      │
│   security roles             3                                      │
│   models                     2                                      │
│                                                                    │
│ Rare signals        preserve valid high-impact seeds                │
│ Cache policy        cache replay is never a fresh sample            │
│ Stop policy         budget / declining novelty / operator decision  │
│ Mutation            forbidden until exact-diff approval             │
│                                                                    │
│ [Preview constitution] [Edit policy] [Start campaign]               │
└──────────────────────────────────────────────────────────────────────┘
```

The plan preview shows allowed variability and stable boundaries, not a false promise that every future sample is known in advance.

## 11.2 Map — research frontier and unexplored space

```text
┌─ MAP · RESEARCH FRONTIER ─────────────────────────────────────────────┐
│ Component              Coverage     Novelty      Uncertainty         │
│ permission             72%          high         high                │
│ session tools          63%          medium       high                │
│ plugin loading         48%          high         high                │
│ MCP resources          31%          high         very high           │
│ provider auth          54%          low          medium              │
│ desktop IPC            19%          unknown      very high           │
│                                                                    │
│ Context coverage                                                   │
│ minimal source         8 runs                                       │
│ full call path         6 runs                                       │
│ threat-model seeded    4 runs                                       │
│ repository-guided      3 runs                                       │
│ guidance excluded      2 runs                                       │
│                                                                    │
│ Recommended allocation                                             │
│   +3 MCP boundary arms                                             │
│   +2 plugin lifecycle arms                                         │
│   retain 1 wildcard desktop IPC arm                                │
└──────────────────────────────────────────────────────────────────────┘
```

Stable structural tooling may contribute to this frontier, but the frontier is a research allocation surface—not a deterministic verdict.

## 11.3 Scan — live research portfolio

```text
┌─ SCAN · NONDETERMINISTIC RESEARCH CAMPAIGN ───────────────────────────┐
│ Samples executed            27                                      │
│ Active arms                  8                                      │
│ Context families             5                                      │
│ Unique observations         31                                      │
│ Vulnerability clusters       7                                      │
│ Novel clusters last 5 runs   2                                      │
│ Cost / novel cluster        $6.80                                   │
│                                                                    │
│ Arm yield                                                          │
│   permission-call-path       ████████  5 clusters                   │
│   plugin-lifecycle           █████     3 clusters                   │
│   MCP-resource-boundary      ████      2 clusters                   │
│   docs-heavy-generic         █         0 clusters                   │
│                                                                    │
│ Scheduler decisions                                                │
│   reduce docs-heavy-generic                                        │
│   expand MCP-resource-boundary                                     │
│   preserve wildcard reserve                                        │
│                                                                    │
│ [Portfolio] [Novelty curve] [Contexts] [Hypotheses] [Pause]         │
└──────────────────────────────────────────────────────────────────────┘
```

Every scheduler decision is inspectable and reversible through a new append-only correction.

## 11.4 Review — hypothesis portfolio and support topology

```text
┌─ REVIEW · VC-0042 ────────────────────────────────────────────────────┐
│ Permission subject/object drift                                     │
│                                                                    │
│ Discovered in                                                      │
│   1 of 3 minimal-context hunts                                     │
│   3 of 4 call-path-context hunts                                   │
│   0 of 2 documentation-heavy hunts                                 │
│   2 explicitly selected models                                     │
│   1 deterministic structural source                                │
│                                                                    │
│ Sensitivity                                                        │
│   appears with end-to-end call-path context                         │
│   disappears in documentation-heavy context                        │
│                                                                    │
│ Maturity            context-sensitive seed                          │
│ Adversarial status  not challenged                                 │
│ Runtime proof       absent                                         │
│                                                                    │
│ Recommended next work                                              │
│   attacker-control challenge                                       │
│   reachability challenge                                           │
│   target-identity instrumentation experiment                       │
│                                                                    │
│ [Pin] [Challenge] [Experiment] [Defer] [Reject]                    │
└──────────────────────────────────────────────────────────────────────┘
```

## 11.5 Prove — challenge board and experiment queue

```text
┌─ PROVE · HYPOTHESIS CHALLENGES ───────────────────────────────────────┐
│ Attacker control        unresolved                                  │
│ Reachability            source evidence supports path               │
│ Existing guard          one adapter still unknown                   │
│ Environment             supported in default configuration           │
│ Alternate explanation   not yet excluded                            │
│                                                                    │
│ Proposed discriminating experiments                                │
│   E-17 instrument authorization identity vs execution identity      │
│   E-18 safe external-resource sentinel                              │
│   E-19 alternate adapter path                                       │
│                                                                    │
│ Reserved proof budget      $18.00                                   │
│ [Approve E-17] [Bundle experiments] [Request new challenge]         │
└──────────────────────────────────────────────────────────────────────┘
```

The primary output is the next evidence-producing experiment, not a vote total.

## 11.6 Fix — patch portfolio

```text
┌─ FIX · PATCH PORTFOLIO ───────────────────────────────────────────────┐
│ Candidate              A          B          C                       │
│ Strategy               local      pre-auth   sink auth               │
│ Build/test             pass       pass       pass                    │
│ Original exploit       blocked    blocked    blocked                 │
│ Variants               3/4        4/4        4/4                     │
│ Benign controls        pass       fail       pass                    │
│ Detector replay        clean      clean      clean                   │
│ Maintenance risk       low        high       medium                  │
│                                                                    │
│ Recommendation         C · strongest evidence without regression     │
│ [View candidates] [Request another] [Approve exact C diff]          │
└──────────────────────────────────────────────────────────────────────┘
```

## 11.7 Report — research graph, not just final findings

The report includes:

- research constitution and source identity;
- active/retired arms and allocation history;
- context families and manifests;
- scheduler decisions and operator corrections;
- novelty and yield curves;
- observation and semantic-cluster union;
- support topology and lineage;
- challenge receipts and unresolved assumptions;
- empirical experiment receipts;
- patch portfolio and approval;
- reattack and detector replay;
- cost and duration by arm, hypothesis, and stage;
- incomplete, unavailable, or degraded capabilities.

---

# 12. Resume, replay, rerun, continue, and branch

These operations must have distinct meanings.

## 12.1 Replay

```text
kuzushi investigate replay <campaign-id>
```

- reads persisted receipts;
- verifies hashes and relationships;
- projects the same historical campaign state;
- makes zero model or dynamic network calls.

## 12.2 Continue

```text
kuzushi investigate continue <campaign-id>
```

- resumes the live adaptive campaign;
- uses the current persisted scheduler and allocation state;
- dispatches new work only when policy and source identity permit it.

## 12.3 Rerun an arm

```text
kuzushi investigate rerun-arm <campaign-id> <arm-id>
```

- creates a new sample ID;
- performs a fresh call;
- records new context and provider receipts;
- does not promise identical output.

## 12.4 Branch a campaign

```text
kuzushi investigate branch <campaign-id> --change <context/model/policy>
```

Use a branch when:

- an operator wants a materially different context family;
- a different model portfolio is selected;
- the source identity changes;
- budget or authority changes exceed the existing plan;
- a promising hypothesis deserves a focused subcampaign.

The branch retains explicit lineage without contaminating support counts.

---

# 13. Product metrics

## 13.1 Research-management metrics

```text
novel observations per dollar
novel semantic clusters per dollar
marginal clusters by sample count
marginal information gain by arm
context-exclusive observation rate
cross-context rediscovery rate
rare-signal follow-up rate
rare-signal proof conversion rate
hypotheses surviving adversarial challenge
cost per resolved research question
frontier coverage by uncertainty
budget concentration by arm
wildcard reserve utilization
```

## 13.2 Evidence-conversion metrics

```text
static-plausible to experiment-ready conversion
experiment-ready to empirical-reproduction conversion
cost per empirically reproduced vulnerability
patch candidates per reproduced vulnerability
build/test-valid patch rate
benign-control preservation rate
variant bypass rate
detector replay clean rate
verified remediation rate
reopened/regression rate
```

## 13.3 Metrics to avoid as north stars

Do not optimize primarily for:

```text
raw findings generated
highest cross-run agreement
lowest variance
one aggregate confidence score
number of agents
number of model calls
percentage of arms that converged
```

The proposed north star is:

> **cost and operator effort required to explore the vulnerability space, preserve important rare hypotheses, and convert the strongest uncertain claims into defensible empirical evidence or a clear handoff state.**

---

# 14. Revised implementation sequence

## PR 0 — fresh-call identity and semantic-cache integrity

**Goal:** make sample, challenge, vote, and patch-candidate counts truthful.

Exit criteria:

- unique invocation identities;
- independent work cannot be satisfied by cached model responses;
- lineage-seeded work is explicit;
- replay makes zero calls;
- tests prove fresh-call semantics.

## PR 1 — proof vocabulary and typed patch eligibility

**Goal:** separate model assessment from runtime proof and remove generic Boolean remediation gates.

## PR 2 — context authority and `ContextEnvelopeV1`

**Goal:** record context influence while preventing repository/model context from changing operator policy.

## PR 3 — `InvestigationPlanV1` as research constitution

**Goal:** persist stable governance, allowed variability, budgets, proof policy, and mutation authority.

## PR 4 — `ResearchCampaignV1`, research arms, and run receipts

**Goal:** add the live evolving portfolio that the plan governs.

## PR 5 — hypothesis ledger and support topology

**Goal:** preserve union-oriented observations, lineage, context sensitivity, and independence without one confidence score.

## PR 6 — adaptive scheduler and research-budget allocator

**Goal:** allocate exploration/follow-up/challenge/wildcard budget with anti-collapse safeguards and visible reasons.

## PR 7 — campaign persistence, continue/replay/rerun/branch

**Goal:** make nondeterministic research durable and steerable across sessions.

## PR 8 — TUI managed-nondeterminism projections

**Goal:** surface policy, frontier, portfolio, novelty, support topology, challenge queue, and scheduler decisions in existing pages.

## PR 9 — Prepare frontier and campaign integration

**Goal:** seed the research portfolio with explainable high-value and high-uncertainty regions while retaining wildcard exploration.

## PR 10 — adversarial challenge roles and clean-room DTOs

**Goal:** turn verifier passes into distinct falsification and experiment-generation roles.

## PR 11 — semantic vulnerability clustering

**Goal:** distinguish observations from shared root causes and preserve affected sinks.

## PR 12 — empirical experiment queue and proof-harness portfolio

**Goal:** manage multiple safe discriminating experiments and mint runtime proof only from admissible receipts.

## PR 13 — closed-loop remediation and patch portfolio

**Goal:** generate and compare bounded patch strategies before exact-diff approval.

## PR 14 — exact apply, automatic reattack, and detector replay

**Goal:** produce an evidence-backed remediation lifecycle without automatic commit/push/PR behavior.

## PR 15 — proof-backend capabilities, SARIF interoperability, regression memory, and evaluation

This may split into narrower PRs during implementation. Exit criteria across the remaining work:

- proof strength derived from backend capabilities;
- external scanner results imported as signals;
- exposure context affects priority, not proof;
- reopened fixes retain history;
- discovery, challenge, proof, remediation, reattack, and research-management metrics remain separate.

---

# 15. Testing strategy

## 15.1 Freshness and cache tests

- N requested fresh samples invoke the runtime N times.
- Cached replay cannot increment fresh-sample support.
- Lineage-seeded follow-up records the parent output.
- persisted replay invokes no model.

## 15.2 Scheduler tests

- wildcard reserve cannot be starved;
- per-arm cap is enforced;
- rare high-impact signal receives bounded follow-up;
- low-yield arm allocation falls without deleting history;
- operator pin/correction overrides scheduler routing;
- budget accounting remains complete under pause/interruption.

## 15.3 Context tests

- repository guidance cannot change model/tool/budget/mutation policy;
- context envelope ordering and truncation are recorded;
- prior output inclusion is explicit;
- clean-room challenger DTO excludes discovery persuasion and support counts.

## 15.4 Hypothesis tests

- a single-sample observation is retained;
- majority misses do not delete a rare signal;
- support topology distinguishes rediscovery from lineage copying;
- context-sensitive states are projected honestly;
- empirical proof remains independent of model-support frequency.

## 15.5 TUI tests

- Setup shows stable policy and adaptive allocation separately;
- Scan shows scheduler decisions and arm yields;
- Review shows support topology and context sensitivity;
- Prove shows challenges and experiments rather than only votes;
- Fix compares patch candidates without implying model consensus is correctness;
- Report round-trips the campaign graph.

---

# 16. Explicit non-goals

- Do not eliminate model or context variance.
- Do not optimize for agreement or convergence.
- Do not majority-filter rare discovery signals.
- Do not treat repeated output as independent evidence without fresh-call receipts.
- Do not treat context robustness as exploitability.
- Do not make one canonical context mandatory for discovery.
- Do not prohibit prior model output from research; classify and trace its lineage instead.
- Do not allow repository content or prior model output to change operator policy.
- Do not turn verifier count into a substitute for empirical proof.
- Do not use an LLM vote to select or approve a patch.
- Do not build a mandatory cloud control plane.
- Do not automatically commit, push, open a PR, or merge after patch application.
- Do not chase MDASH’s agent count as a product metric.

---

# 17. Final product statement

The intended end state is:

> **Kuzushi is a local-first control room for nondeterministic security research. A stable governance envelope defines authority, budget, and proof semantics; an adaptive campaign deliberately explores diverse contexts, models, roles, tools, and decompositions; the hypothesis ledger preserves rare and context-sensitive discoveries; adversarial roles generate discriminating experiments; and empirical execution converts selected uncertainty into defensible proof and verified remediation.**

The product does not promise that the same scan returns the same findings.

It promises that the operator can understand, steer, budget, preserve, challenge, and learn from the differences.