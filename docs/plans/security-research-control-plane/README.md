# RFC — Productizing Kuzushi as a Replayable Security Research Control Plane

> **Status:** proposal for architectural and product review
> **Date:** 2026-08-19
> **Scope of this RFC:** product direction, domain contracts, sequencing, and acceptance criteria
> **Implementation status:** no behavior is implemented by this document
> **Primary relationship:** extends the existing repository-security workbench and the [control-room PRD](../product-flow-prd.md); it does not replace either
> **Roadmap constraint:** the current [ROADMAP](../../../ROADMAP.md) remains authoritative. New proof backends and broader target classes stay gated behind the existing evidence, verification, and benchmark exits.

---

## 0. Decision requested

Approve the following product direction:

> **Kuzushi becomes the local-first system of record and operator workbench for security research: specialist engines may discover or execute, but Kuzushi owns the research question, hypothesis, declared observation boundary, authority, experiment plan, evaluator receipt, proof transition, human decision, remediation, replay, cost, and benchmark truth.**

Approval of this RFC should authorize only a narrow first implementation program:

1. add an honest `ObservationBoundary` contract to runs and proof claims;
2. add a host-owned `EvaluatorReceipt` contract;
3. add a small, replayable research ledger for questions, hypotheses, experiments, observations, and dispositions;
4. prove the design through one vertical slice that reuses existing repository analysis and runtime verification;
5. defer new browser, binary, protocol, MCP-estate, and endpoint-monitoring product surfaces until Kuzushi's current P0-P3 roadmap gates are met.

The decision is **not** whether Kuzushi should become a generic autonomous pentesting platform. It should not. The decision is whether Kuzushi should productize the governance and evidence layer that serious security research needs.

---

## 1. Executive summary

Kuzushi already has unusually strong foundations for a security-research product:

- durable target-scoped finding identity;
- append-only evidence and human decisions;
- replayable, hash-linked run lifecycles;
- explicit static versus runtime proof;
- host-owned persistence boundaries;
- no silent model/provider fallback;
- bounded budgets, failures, cancellation, and degraded states;
- a coherent `Map → Scan → Review → Prove → Fix` operator path;
- capability-scoped modules and plugins whose output remains untrusted until the host commits it.

The important gap is not another scanner. It is that Kuzushi cannot yet represent the **scientific process** that surrounds a finding.

A serious researcher needs to answer:

- What question were we trying to resolve?
- What evidence inspired the hypothesis?
- What result would falsify it?
- What could the experiment actually observe?
- What authority existed when the experiment ran?
- Which exact backend, version, target snapshot, and evaluator produced the result?
- Did the result prove a crash, reachability, a primitive, exposure, or impact?
- Why was a candidate rejected or left inconclusive?
- Which observation inspired the next branch of research?
- Can another person replay the claim without reconstructing a chat transcript?
- Did a patch remove the primitive, merely hide the signal, or only change the environment?

Today, some of those answers can be inferred from findings, run metadata, proof artifacts, and model traces. They are not first-class, queryable, replayable domain state.

The product opportunity is to make Kuzushi the **control plane for evidence-producing security research**:

```text
Question
  → Hypothesis
  → Authorized experiment
  → Bounded observation
  → Deterministic evaluator receipt
  → Disposition
  → Finding/proof update
  → Remediation
  → Re-experiment
  → Next hypothesis
```

This strengthens the existing repository-security wedge before it broadens the target surface. It gives Kuzushi a defensible role even when detection engines commoditize: engines can be swapped; the durable truth, operator decisions, reproducibility, and proof progression remain in Kuzushi.

---

## 2. Product thesis

### 2.1 The category

Kuzushi should define and own a category narrower than “AI security agent” and more valuable than “scanner orchestration”:

> **Security research control plane:** a local-first workbench that turns stochastic discovery and heterogeneous tools into replayable, evaluator-backed, human-governed security knowledge.

The product is not valuable because it can call many models or scanners. It is valuable because it can tell the truth about what those systems did and did not establish.

### 2.2 The wedge

The initial wedge remains exactly where Kuzushi is strongest:

> **Repository-centered vulnerability investigation for AppSec and product-security operators who need defensible evidence, not AI prose.**

The research-control-plane work first productizes the difficult cases inside that wedge:

- a high-severity finding that needs multiple proof attempts;
- a scanner disagreement that needs adjudication;
- a crash that needs reachability and impact analysis;
- a patch that needs a stronger closure claim than “the scanner stopped reporting it”;
- a security campaign whose candidates, failures, cost, and terminal reasons must be accounted for;
- a novel hypothesis derived from an earlier observation;
- an AI-generated claim that must be constrained by a deterministic evaluator.

Broader domains—browser security, binaries, firmware, agent infrastructure, protocol peers, deployment paths—become backend integrations later. They do not become separate top-level products.

### 2.3 The durable moat

The moat is the combination of:

1. **host-owned truth** — untrusted engines cannot promote their own claims;
2. **research lineage** — question, hypothesis, experiment, observation, and cascade are durable;
3. **declared visibility** — every verdict says what the system could and could not observe;
4. **declared authority** — every effect is attributable to an approved principal and capability;
5. **orthogonal proof** — static evidence, execution witness, reachability, exploitability, exposure, and impact are not collapsed;
6. **replay** — another operator can reproduce the projection and inspect the exact artifacts;
7. **human governance** — acceptance, rejection, suppression, risk, and remediation remain explicit decisions;
8. **benchmark truth** — quality, failure, latency, and cost are measured from executed work.

A scanner can copy a prompt. It is much harder to copy a trustworthy, migration-safe evidence system with a mature operator workflow.

---

## 3. Relationship to existing Kuzushi direction

### 3.1 This RFC extends the control-room PRD

The existing [product-flow PRD](../product-flow-prd.md) defines Kuzushi as a control room for non-deterministic security scans. Its load-bearing mechanisms are sampled sweeps, corroboration, a governed findings ledger, strategies, budgets, and a two-plane operator experience.

This RFC adds the missing research semantics around that control room:

| Existing concept | Research-control-plane extension |
| --- | --- |
| strategy proposal | hypothesis and experiment plan with a falsification predicate |
| sweep | one or more experiment attempts under a declared observation boundary |
| run | execution record linked to a research experiment |
| result | observation plus evaluator receipt, not merely model output |
| finding | durable vulnerability identity linked to one or more research claims |
| proof state | orthogonal proof dimensions with witness-owning transitions |
| prompt mutation | one possible experiment input, never hidden reasoning state |
| cost ledger | cost per experiment, proof upgrade, confirmed finding, and closed finding |
| replay | reconstruction of both run lifecycle and research lineage |
| strategy correction | human amendment to a hypothesis, plan, or interpretation |
| report | defensible statement of evidence, visibility, authority, and remaining uncertainty |

The control-room PRD answers **how the operator steers non-determinism**. This RFC answers **how the product turns that work into durable research knowledge**.

### 3.2 This RFC does not bypass the current roadmap

The current roadmap is deliberately focused on:

- shipping the product that exists;
- making evidence validation universal;
- preserving honest verification;
- producing public benchmark numbers;
- strengthening the local-first operator wedge.

The first slices in this RFC must advance those goals, not compete with them.

Allowed before the current P3 benchmark exit:

- observation-boundary disclosure;
- evaluator receipts;
- research lifecycle and replay;
- terminal funnel accounting;
- startup authority manifests;
- one repository-security vertical slice using existing engines.

Gated until the current evidence and benchmark exits are real:

- a browser automation product surface;
- binary exploitation as a primary workflow;
- broad MCP/A2A estate discovery;
- endpoint-wide trajectory monitoring;
- malicious protocol-peer labs;
- a marketplace of third-party proof backends;
- cloud collaboration infrastructure.

### 3.3 Findings remain findings

A `ResearchHypothesis` must not replace `Finding`.

A finding is the durable identity of a suspected or established security defect. A hypothesis is a falsifiable claim investigated during a research process. The relationship is many-to-many:

- one hypothesis may produce several findings;
- several hypotheses may investigate one finding;
- a hypothesis may be rejected without creating a finding;
- a finding may predate the research ledger and later receive research lineage;
- a negative experiment may strengthen confidence in a rejection without deleting history.

The existing finding identity, evidence, decision, suppression, verification, and patch contracts remain authoritative for vulnerability state.

---

## 4. Research basis

This direction is grounded in the highest-signal DEF CON 34 research and released systems reviewed for Kuzushi. A complete public transcript set was not assumed; the analysis distinguished released implementations, detailed research text, advisories, official slides/abstracts, and title-level evidence.

| Research system or talk | Product lesson | Kuzushi primitive |
| --- | --- | --- |
| PortSwigger HTTP Terminator | autonomous research requires a falsifiable hypothesis, staged execution, a deterministic evaluator, and cascades from confirmed observations | research ledger, evaluator receipt, cascade edge |
| Project Reference / Wiring the Harness | multi-stage model orchestration is only credible when the full candidate funnel, attrition, cost, and verification are measured | terminal funnel projection, campaign metrics |
| Witchcraft Solver | a symbolic crash, external reachability, exploit primitive, and impact are different claims owned by different mechanisms | orthogonal proof dimensions |
| pre-task Gemini CLI RCE research | dangerous authority can arise from configuration, environment, startup, or headless policy before a model answers | startup authority manifest |
| AgentsLeak | individually allowed file/process/network actions can compose into a prohibited trajectory | normalized action events and stateful policy |
| SADF | benchmarks must exercise effects and disclose unimplemented metrics rather than fabricate proxies | scenario benchmark contract and undefined-metric discipline |
| AgentHound | credentials, agents, tools, MCP, A2A, gateways, vector stores, and services form one authority graph | authority graph and path observations |
| Taming the Swarm | browser claims require DOM/network/storage/console/effect evidence, not model narration | browser proof backend, later |
| LGTM | a clean verdict is meaningless when dangerous behavior sits outside the observed context | observation-boundary contract |
| malicious OCI-registry research | protocol clients need adversarial peers, reproducible traces, and host-observed side effects | malicious-peer backend, later |

The product should absorb the **general research contracts**, not create one command per talk.

---

## Plan packet

This review packet is split by decision boundary so product direction can be
accepted without implicitly approving every future backend:

1. [Product workflow](./01-product-workflow.md) — users, non-goals, lifecycle, CLI/TUI projection, and authorization UX.
2. [Domain model](./02-domain-model.md) — bounded context, research entities, and invariants.
3. [Persistence, observation boundary, and startup authority](./03-persistence-boundary-authority.md).
4. [Proof backends and later agent-security horizon](./04-proof-and-agent-horizon.md).
5. [Delivery, benchmarks, packaging, and implementation phases](./05-delivery-and-benchmarks.md).
6. [First twelve PRs, acceptance program, risks, and immediate next action](./06-pr-sequence-and-acceptance.md).

The narrow first release is repository-centered: observation boundaries,
evaluator receipts, terminal funnel accounting, a replayable research ledger,
and one static-to-runtime vertical slice. Browser, binary, protocol-peer,
agent-estate, and endpoint-wide capabilities remain separately gated.
