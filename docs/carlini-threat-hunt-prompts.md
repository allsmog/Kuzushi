# Carlini Threat Hunt Prompts, Data Flow, and TUI Mockups

This note documents the operator-facing prompt surface for the built-in
`carlini-threat-hunt` module. The real override is `CARLINI_THREAT_HUNT_PROMPT` on
`carlini-threat-hunt:run`; in the per-module prompts editor it is shown as `run`
because the tool name is `carlini-threat-hunt:run`.

The module is inspired by Nicholas Carlini's [un]prompted talk on parallel
scoped agents. It is not affiliated with or endorsed by Nicholas Carlini.

## Actor Hunt Prompt

The runtime builds one scoped prompt per selected DFD external entity:

```text
IMPORTANT: Only examine files under {scanScope}. Do not read, grep, or navigate outside this directory.

{optional untrusted_attachment block from shared .kuzushi/v2/attachments.json offense-review records}

You are competing in a CTF. You are simulating: {actor.name}
Description: {actor.description}
Trust zone: {actor.trustZone}
Use the linked flows, entrypoints, source/sink hints, guards, sanitizers, and evidence anchors to reason about actor reachability before reporting.

Linked data flows from the graph v2 threat model:
- {flow.id}: {flow.sourceId} -> {flow.targetId} - {flow.description} (protocol={flow.protocol} | classification={flow.dataClassification} | crosses={boundaryIds})

The threat model identified these specific threats from your attack surface:
1. [{IMPACT}/{STRIDE_CATEGORY}] {threat.title}
   Attack vector: {threat.attackVector}
   Actor ids: {threat.actorIds}
   Entrypoints: {threat.entrypointIds}
   Target elements: {threat.targetElementIds}
   Flow ids: {threat.flowIds}
   Source hints: {threat.sources}
   Sink hints: {threat.sinks}
   Guard hints: {threat.guards}
   Sanitizer hints: {threat.sanitizers}
   Required capabilities: {threat.requiredCapabilities}
   Affected code: {filePath}:{startLine}, ...
   Evidence: {filePath}:{startLine}-{endLine} {symbol} - {description}; ...

Your mission: find additional evidence for these threats, discover new attack vectors in the same surface, or identify variants the threat model missed.
Do NOT re-confirm what is already documented above - find something new or deeper.

Find exploitable security vulnerabilities in this codebase from this actor's perspective.
Explore the codebase using the tools available to you.
Only report findings with concrete evidence of exploitability.

## Anti-hallucination constraints
- Only report concrete issues you can verify in code. Do not report secure patterns.
- Do NOT infer or speculate about code you haven't read.
- If a library is used correctly per its documentation, do not flag it.
- Confidence must reflect your actual certainty: HIGH only if the issue is unambiguous.
```

`CARLINI_THREAT_HUNT_PROMPT` replaces only the base actor mission prompt. The
scan-scope guard and attached carlini-threat-hunt knowledge base material still wrap the
override.

## Triage Prompt

Carlini carlini-threat-hunt findings use a triage prompt that explicitly asks for source-to-sink
verification:

```text
You are triaging a finding from the threat-driven hunt in "{repoName}".
This finding was discovered by an agent simulating a specific threat actor.

Rule: {finding.ruleId}
File: {finding.filePath}:{finding.startLine}
Severity: {finding.severity}
Message: {finding.message}
Evidence: {finding.evidence}

Verify the vulnerability is genuine and exploitable:
- Trace the complete data flow from source to sink
- Check for sanitization or framework protections
- Confirm the code is reachable from the stated actor's trust zone
```

## Runtime Data Flow

```text
operator
  |
  |  /use carlini-threat-hunt
  |  prompts / show run / edit run / run .
  v
shell router
  |
  +--> prompt audit/editor
  |      reads tools exposing *_PROMPT
  |      resolves CARLINI_THREAT_HUNT_PROMPT source: default | file | inline | missing
  |
  +--> CopilotCore.executeTool("carlini-threat-hunt:run")
          |
          v
      resolveConfig
        model, effort, maxActors, runsPerActor, maxConcurrentHunts
        CARLINI_THREAT_HUNT_PROMPT override
        .kuzushi/v2/attachments.json
          |
          v
      DAG upstream output
        threat-model-randori.document
          |
          v
      extractActorsWithThreats
        graph v2 external-entity nodes
        HIGH/CRITICAL STRIDE threats linked by actorIds
        infer actors from flowIds when direct actorIds are absent
        fallback to all external actors only when no threat-to-actor links exist
          |
          v
      bounded actor hunts
        buildScopedPrompt
        linked flows, entrypoints, source/sink hints, guards/sanitizers
        runtime.query with read-only tools
        structured FINDING_SCHEMA output
        live agent activity events
          |
          v
      merge + selectFindings
        dedupe
        cap maxFindings
        stamp actorFingerprint
        attach cost metadata
          |
          v
      downstream triage
        source-to-sink data flow verification
        sanitization checks
        trust-zone reachability
          |
          v
      TUI + persistence
        module-run
        actor-detail
        /findings
        /open F-NNNN
```

## ASCII TUI Mockups

Module home:

```text
kuzushi/carlini-threat-hunt

readiness
  context         target ./repo
  attack surface  31 nodes | 44 flows | 6 boundaries
  s4 quality      18 actor-linked threats | generated
  actors          4 ready | 2 deferred

scope
  target    ./repo
  mode      reference
  model     anthropic:claude-opus-4-7
  effort    xhigh
  evidence  .kuzushi/findings.sqlite3
  output    scrollback | /findings | /open <F-NNNN>

attachments
  incident.md       incident       parsed
  prod-auth.log     runtime-log    parsed

actions
  run .             spawn one agent per ready actor
  run --changed     scope to git-changed files only
  prompts           edit the actor system prompt
  /threats dfd      review the attack surface
```

Prompts editor:

```text
kuzushi/carlini-threat-hunt/prompts                         1 prompt | 0 local edits

Prompts                         layered: builtin -> local -> inline

NAME    SOURCE     PATH OR BUILTIN
run     default    (compiled default)

actions
  edit <name>       open the override in $EDITOR
  show <name>       print the effective prompt + source
  diff <name>       unified diff vs the builtin
  reset <name>      delete the override file
  set <name> ...    inline override (text or path)

kuzushi/carlini-threat-hunt/prompts> show run
Prompt for carlini-threat-hunt:run (carlini-threat-hunt)
  `CARLINI_THREAT_HUNT_PROMPT` source=default (no override set)
```

Live run:

```text
kuzushi/carlini-threat-hunt/run                         2m 14s | running

[active] Carlini Threat Hunt(./repo)

steps
  [x] load threat model
  [x] enumerate actors                         4 actors
  [>] spawn actor agents                       2/4
  [ ] merge findings

actors                                      1-4 drill into actor
  ANON-01  Anonymous Visitor                active
    [x] Read src/routes/auth.ts
    [>] Grep "resetPassword"
  AUTH-02  Authenticated User               active
    [x] Read src/api/admin.ts
    [>] Grep "tenantId"
  PART-03  Partner API Consumer             queued

run facts
  cost     $0.42    model anthropic:claude-opus-4-7    prompts kuzushi/<module>/prompts
```

Actor drill-in:

```text
kuzushi/carlini-threat-hunt/run/ANON-01              turn 8/8 | $0.42 | 1 findings

[active] Carlini Threat Hunt(. as <Anonymous Visitor>)

* Read(src/routes/auth.ts)
  `-> 138 lines, 4.2KB
* Grep(resetPassword)
  `-> 6 matches
* Thinking - checking token expiry and tenant scoping
* Finding - Password reset token accepted across tenants
  high | src/routes/auth.ts:88

Other actors    AUTH-02 queued | PART-03 queued
```
