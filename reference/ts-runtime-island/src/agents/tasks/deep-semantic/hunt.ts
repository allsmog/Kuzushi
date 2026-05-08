/**
 * deep-semantic-hunt — LLM-driven deep semantic vulnerability analysis.
 *
 * For each CWE from deep-semantic-cwe-select, spawns a dedicated LLM agent
 * that uses CodeQL (range analysis, loop analysis, type queries — NOT
 * TaintTracking) and autonomous code reasoning to find latent memory-safety
 * bugs: integer overflows, sentinel collisions, buffer overflows,
 * use-after-free, missing mitigations, unsafe block violations.
 *
 * Architecture mirrors carlini-threat-hunt.ts (bounded concurrency, one agent per CWE)
 * with IRIS-style tool grants (Bash + Write for CodeQL query authoring).
 */
import { createHash } from "node:crypto";
import { existsSync } from "node:fs";
import path from "node:path";
import { createLogger } from "../../../logger.js";
import { coerceRepoContext } from "../../../repo-context.js";
import { scoreFindingMetadata } from "../../../scanners/scoring.js";
import type { Finding, TaintPathStep, TriageAgentConfig } from "../../../scanners/types.js";
import { attachTaskOutputMeta } from "../../../task-output-meta.js";
import type { ScanOpts } from "../../../types.js";
import { isRecord, toErrorMessage } from "../../../utils.js";
import type { DagNodeImpl, DagRunContext } from "../../types.js";
import {
  resolveTaskAllowedTools,
  resolveTaskModel,
  resolveTaskPositiveInt,
  resolveTaskRuntime,
} from "../runtime-overrides.js";
import type { CweSelection, CweSelectOutput } from "../taint-iris/cwe-select.js";

const log = createLogger({ stage: "deep-semantic-hunt" });

/* ---------- finding schema (reuses IRIS shape) ---------- */

const FINDING_SCHEMA = {
  type: "object",
  additionalProperties: false,
  required: ["findings"],
  properties: {
    findings: {
      type: "array",
      items: {
        type: "object",
        additionalProperties: false,
        required: [
          "title",
          "cwe",
          "severity",
          "filePath",
          "startLine",
          "message",
          "reasoningChain",
        ],
        properties: {
          title: { type: "string" },
          cwe: { type: "string" },
          severity: { type: "string", enum: ["critical", "high", "medium", "low"] },
          filePath: { type: "string" },
          startLine: { type: "integer" },
          message: { type: "string" },
          reasoningChain: { type: "string" },
          analysisPath: {
            type: "array",
            items: {
              type: "object",
              additionalProperties: false,
              required: ["filePath", "line"],
              properties: {
                filePath: { type: "string" },
                line: { type: "integer" },
                message: { type: "string" },
                snippet: { type: "string" },
              },
            },
          },
          confidence: { type: "string", enum: ["high", "medium", "low"] },
          exploitPreconditions: { type: "string" },
        },
      },
    },
  },
} as const;

/* ---------- config ---------- */

interface DeepSemanticHuntConfig {
  model: string;
  maxFindings: number;
  maxConcurrentHunts: number;
  maxCweClasses: number;
}

function resolveConfig(ctx: DagRunContext): DeepSemanticHuntConfig {
  return {
    model: resolveTaskModel(ctx, "deep-semantic-hunt"),
    maxFindings: resolveTaskPositiveInt(ctx, "deep-semantic-hunt", "maxFindings", 30),
    maxConcurrentHunts: resolveTaskPositiveInt(ctx, "deep-semantic-hunt", "maxConcurrentHunts", 3),
    maxCweClasses: resolveTaskPositiveInt(ctx, "deep-semantic-hunt", "maxCweClasses", 6),
  };
}

/* ---------- CodeQL database resolution ---------- */

function resolveCodeqlDbPath(context: DagRunContext): string | null {
  const candidates = [
    path.join(context.repoRoot, ".kuzushi", "codeql-db"),
    path.join(context.repoRoot, ".codeql", "db"),
  ];
  for (const p of candidates) {
    if (existsSync(p)) return p;
  }
  return null;
}

/* ---------- prompt builder ---------- */

function buildHuntPrompt(
  cwe: CweSelection,
  codeqlDbPath: string | null,
  repoContext: ReturnType<typeof coerceRepoContext>,
): string {
  const repoInfo = repoContext
    ? [
        `Languages: ${repoContext.languages.join(", ")}`,
        `Frameworks: ${repoContext.frameworks.join(", ")}`,
        `Entry points: ${repoContext.entryPoints.join(", ")}`,
      ].join("\n")
    : "No context available.";

  const codeqlSection = codeqlDbPath
    ? [
        "## CodeQL Database",
        `A CodeQL database is available at: ${codeqlDbPath}`,
        `Run queries with: codeql query run -d ${codeqlDbPath} /tmp/deep-semantic.ql`,
        `Analyze with: codeql database analyze ${codeqlDbPath} /tmp/deep-semantic.ql --format=sarif-latest --output=/tmp/results.sarif`,
        "",
        "IMPORTANT: Do NOT use TaintTracking::Configuration for this analysis.",
        "The bugs you are looking for are NOT source-to-sink taint flows.",
        "Use CodeQL's value analysis, type predicates, and control flow libraries instead.",
      ].join("\n")
    : [
        "## No CodeQL Database",
        "No pre-built CodeQL database is available.",
        "Use Grep and Read to manually analyze the code. Focus on reading the actual",
        "source files and reasoning about value ranges, type interactions, and control flow.",
      ].join("\n");

  const strategySection = buildStrategySection(cwe.id);

  return [
    "You are a deep semantic vulnerability researcher analyzing native code.",
    "Your specialty: finding bugs that static analyzers and fuzzers miss because",
    "they require reasoning about VALUE RANGES, SENTINEL COLLISIONS, TYPE",
    "INTERACTIONS, and MISSING MITIGATIONS.",
    "",
    "## Project",
    repoInfo,
    "",
    codeqlSection,
    "",
    `## Target: ${cwe.id} — ${cwe.name}`,
    `Reason selected: ${cwe.reason}`,
    "",
    strategySection,
    "",
    "## Iteration Protocol",
    "For each CodeQL query you write:",
    "1. Write the query to /tmp/deep-semantic.ql",
    "2. Run: codeql query run -d <db_path> /tmp/deep-semantic.ql",
    "3. If compile error: read the error, fix the query, retry (max 3 iterations)",
    "4. If 0 results: widen the query (relax predicates), retry once",
    "5. For each result: Read the actual source code and determine exploitability",
    "",
    "## Critical Instructions",
    "These are LATENT bugs — they have survived for years because they look correct",
    "to casual review. Do NOT dismiss a finding because 'the code looks fine.'",
    "Reason carefully about:",
    "- What happens at type boundary values (INT_MAX, UINT16_MAX, 0, -1)?",
    "- What happens after 65535 iterations of a loop with a uint16_t counter?",
    "- What happens when a signed comparison is used with an unsigned operand?",
    "- What happens when a buffer size calculation wraps around?",
    "- What happens when an 'unsafe' block assumes invariants that callers don't enforce?",
    "",
    "## Anti-hallucination Constraints",
    "- Only report findings you can point to in actual code with a specific file and line.",
    "- Do NOT report hypothetical or speculative findings.",
    "- If you cannot verify the issue in source code, do not report it.",
    "- Confidence must reflect your actual certainty: HIGH only if unambiguous.",
    "",
    "## Output",
    "Return your findings as structured JSON. Each finding needs:",
    "- title, cwe, severity, filePath, startLine, message",
    "- reasoningChain: explain the semantic reasoning (e.g., 'counter type is uint16_t → after",
    "  65535 iterations wraps to 0 → sentinel check at 0 triggers early termination → next",
    "  iteration writes OOB')",
    "- analysisPath: array of steps with filePath, line, message (role like 'type-boundary',",
    "  'overflow-point', 'dereference-site', 'missing-check'), and code snippet",
  ].join("\n");
}

function buildStrategySection(cweId: string): string {
  const normalized = cweId.replace(/^CWE-/i, "");

  switch (normalized) {
    case "190":
    case "191":
    case "681":
      return [
        "## Analysis Strategy: Range & Type Analysis",
        "Write CodeQL queries using:",
        "- `import semmle.code.cpp.rangeanalysis.SimpleRangeAnalysis`",
        "- `SignAnalysis` for signed/unsigned reasoning",
        "- Type predicates: `isSignedIntegralType()`, `isUnsignedIntegralType()`",
        "- Find signed/unsigned comparisons where the signed value could be negative",
        "- Find arithmetic operations (add, subtract, multiply) near allocation sizes or array indices",
        "- Find integer truncation: assignments from wider to narrower types",
        "- Check for missing overflow guards before security-critical operations",
        "",
        "Example CodeQL pattern:",
        "```",
        "import cpp",
        "from ComparisonOperation cmp, Variable v1, Variable v2",
        "where v1 = cmp.getAnOperand().(VariableAccess).getTarget()",
        "  and v2 = cmp.getAnOperand().(VariableAccess).getTarget()",
        "  and v1 != v2",
        "  and v1.getType().(IntegralType).isSigned()",
        "  and v2.getType().(IntegralType).isUnsigned()",
        'select cmp, "Signed/unsigned comparison between " + v1.getName() + " and " + v2.getName()',
        "```",
      ].join("\n");

    case "787":
    case "125":
      return [
        "## Analysis Strategy: Loop Induction & Sentinel Analysis",
        "Write CodeQL queries that:",
        "- Find loop induction variables with no explicit upper bound check",
        "- Find sentinel values (magic constants like 0xFFFF, -1, 0) used as loop terminators",
        "- Check if the induction variable's type range can exceed the sentinel value",
        "- Find buffer accesses indexed by loop counters without independent bounds checking",
        "- Look for `for`/`while` loops where the counter is incremented unconditionally",
        "",
        "Example CodeQL pattern:",
        "```",
        "import cpp",
        "from ForStmt loop, Variable counter, ArrayExpr access",
        "where counter = loop.getAnIterationVariable()",
        "  and access.getArrayOffset() = counter.getAnAccess()",
        "  and not exists(GuardCondition guard |",
        "    guard.controls(access.getBasicBlock(), _) and",
        "    guard.getAChild*() = counter.getAnAccess())",
        'select access, "Array access indexed by unbounded loop counter " + counter.getName()',
        "```",
      ].join("\n");

    case "119":
    case "693":
      return [
        "## Analysis Strategy: Missing Mitigation Analysis",
        "Write CodeQL queries that:",
        "- Find functions with stack-allocated arrays larger than 64 bytes",
        "- Check for stack canary protection (references to `__stack_chk_fail`)",
        "- Find `memcpy`/`memmove`/`strcpy`/`sprintf` where the size argument derives",
        "  from external input without prior bounds validation",
        "- Find `alloca()` calls with unchecked size arguments",
        "- Look for functions handling network/file input with large local buffers",
        "",
        "Example CodeQL pattern:",
        "```",
        "import cpp",
        "from Function f, LocalVariable buf",
        "where buf.getFunction() = f",
        "  and buf.getType().(ArrayType).getByteSize() > 64",
        "  and not exists(FunctionCall chk |",
        '    chk.getTarget().hasName("__stack_chk_fail") and',
        "    chk.getEnclosingFunction() = f)",
        'select f, "Function with " + buf.getType().(ArrayType).getByteSize().toString()',
        '  + "-byte stack buffer and no stack canary"',
        "```",
      ].join("\n");

    case "416":
    case "672":
      return [
        "## Analysis Strategy: Protocol State Machine Reasoning",
        "This CWE class often cannot be found via CodeQL alone.",
        "Use a combination of Grep + Read to:",
        "1. Find state machine patterns: enum-based states, transition functions, FSM tables",
        "2. Find resource allocation/deallocation tied to state transitions",
        "3. Reason about whether:",
        "   - A state transition can leave a resource handle dangling",
        "   - A message/packet can arrive in an unexpected state",
        "   - Error paths skip cleanup that success paths perform",
        "   - Re-entrant callbacks can observe partially-torn-down state",
        "4. For use-after-free specifically: find `free()` calls and check if the",
        "   pointer is still reachable after the free (via aliased pointers, struct fields, globals)",
        "",
        "If CodeQL is available, try:",
        "```",
        "import cpp",
        "from FunctionCall freeCall, VariableAccess useAfter",
        'where freeCall.getTarget().hasName("free")',
        "  and useAfter.getTarget() = freeCall.getArgument(0).(VariableAccess).getTarget()",
        "  and freeCall.getASuccessor+() = useAfter",
        'select useAfter, "Potential use-after-free: " + useAfter.getTarget().getName()',
        '  + " freed at " + freeCall.getLocation()',
        "```",
      ].join("\n");

    case "704":
      return [
        "## Analysis Strategy: Unsafe Block / Type Confusion Analysis",
        "For Rust codebases:",
        "- Use Grep to find all `unsafe {` blocks and `unsafe fn` declarations",
        "- Read each unsafe block and analyze:",
        "  - Raw pointer arithmetic (`*mut`, `*const`, `ptr::write`, `ptr::read`)",
        "  - `std::mem::transmute` — what types are being transmuted?",
        '  - FFI boundary crossings (`extern "C"`) — are Rust types safely mapped?',
        "  - Slice creation from raw pointers (`std::slice::from_raw_parts`) — are length invariants enforced?",
        "- Check if callers of unsafe functions uphold the documented safety invariants",
        "",
        "For C/C++ codebases:",
        "- Find casts between incompatible pointer types (e.g., `(struct foo *)bar`)",
        "- Find `union` types used for type punning",
        "- Find `void *` passed through multiple layers and cast to different concrete types",
      ].join("\n");

    case "476":
      return [
        "## Analysis Strategy: NULL Dereference via Integer Edge Cases",
        "Write CodeQL queries that:",
        "- Find pointer dereferences after arithmetic that could produce NULL",
        "- Find allocation functions (malloc, calloc) whose return value is checked",
        "  with a comparison that can be bypassed via integer overflow in the size argument",
        "- Find NULL checks that are unreachable due to compiler optimizations",
        "  (e.g., the pointer was already dereferenced earlier, so the compiler removes the check)",
        "",
        "If CodeQL is available:",
        "```",
        "import cpp",
        "import semmle.code.cpp.dataflow.DataFlow",
        "from FunctionCall alloc, Expr sizeArg, PointerDereferenceExpr deref",
        'where alloc.getTarget().hasName(["malloc", "calloc", "realloc"])',
        "  and sizeArg = alloc.getArgument(0)",
        "  and deref.getOperand().(VariableAccess).getTarget() =",
        "      alloc.getEnclosingFunction().getAParameter()",
        'select alloc, "Allocation with potentially overflowable size"',
        "```",
      ].join("\n");

    default:
      return [
        "## Analysis Strategy: General Deep Semantic Analysis",
        "Use CodeQL (if available) or Grep/Read to find instances of this CWE class.",
        "Focus on value-level semantic reasoning — not source-to-sink taint flows.",
        "Look for invariants that are assumed but never enforced in code.",
      ].join("\n");
  }
}

/* ---------- per-CWE agent runner ---------- */

interface HuntResult {
  findings: Finding[];
  costUsd: number;
}

async function runCweHunt(
  cwe: CweSelection,
  context: DagRunContext,
  config: DeepSemanticHuntConfig,
  codeqlDbPath: string | null,
): Promise<HuntResult> {
  const repoContext = coerceRepoContext(context.upstreamOutputs.get("context-gatherer"));
  const prompt = buildHuntPrompt(cwe, codeqlDbPath, repoContext);
  const runtime = resolveTaskRuntime(context);
  const tag = `[deep-semantic-hunt/${cwe.id}]`;

  log.info(`${tag} Starting hunt (model=${config.model})`);

  let structuredOutput: unknown;
  let resultText = "";
  let costUsd = 0;

  try {
    for await (const message of runtime.query({
      prompt,
      options: {
        cwd: context.repoRoot,
        model: config.model,
        allowedTools: [...resolveTaskAllowedTools(context), "Bash", "Write"],
        permissionMode: "dontAsk",
        outputFormat: {
          type: "json_schema",
          schema: FINDING_SCHEMA,
          strict: true,
          retryInvalidStructuredOutput: 2,
        },
      },
    })) {
      if (message.type !== "result") continue;
      if (typeof message.totalCostUsd === "number") costUsd = message.totalCostUsd;
      if ("result" in message) {
        resultText = message.result;
        structuredOutput = message.structuredOutput;
        const durationSec = message.durationMs ? (message.durationMs / 1000).toFixed(1) : "?";
        log.info(
          `${tag} Complete in ${durationSec}s — ${message.numTurns} turns, $${costUsd.toFixed(4)}`,
        );
        break;
      }
    }
  } catch (error) {
    log.error(`${tag} Error: ${toErrorMessage(error)}`);
    return { findings: [], costUsd };
  }

  const findings = parseFindings(
    structuredOutput ?? tryParseJson(resultText),
    context.repoRoot,
    context.repoName,
  );

  return { findings, costUsd };
}

/* ---------- finding parser ---------- */

function parseFindings(raw: unknown, repoRoot: string, repoName: string): Finding[] {
  if (!isRecord(raw)) return [];
  const items = Array.isArray(raw["findings"]) ? raw["findings"] : [];
  const out: Finding[] = [];

  for (const item of items) {
    if (!isRecord(item)) continue;
    const title = str(item["title"]);
    const cwe = str(item["cwe"]);
    const filePath = str(item["filePath"]);
    const startLine = Math.max(1, Math.floor(Number(item["startLine"]) || 1));
    const message = str(item["message"]);
    const chain = str(item["reasoningChain"]);
    const confidence = str(item["confidence"]) || "medium";

    if (!title || !filePath || !message) continue;

    const rawPath = Array.isArray(item["analysisPath"]) ? item["analysisPath"] : [];
    const taintPath: TaintPathStep[] = [];
    for (const step of rawPath) {
      if (!isRecord(step)) continue;
      const fp = str(step["filePath"]);
      const ln = Math.max(1, Math.floor(Number(step["line"]) || 1));
      if (!fp) continue;
      taintPath.push({
        filePath: normalizePath(repoRoot, fp),
        line: ln,
        message: str(step["message"]) || undefined,
        snippet: str(step["snippet"]) || undefined,
      });
    }

    const severity = mapSeverity(str(item["severity"]));
    const fingerprint = createHash("sha256")
      .update([repoName, "deep-semantic-hunt", cwe, filePath, String(startLine), title].join("|"))
      .digest("hex");

    out.push({
      taskId: "deep-semantic-hunt",
      fingerprint,
      ruleId: `deep-semantic/${cwe || "unknown"}`,
      filePath: normalizePath(repoRoot, filePath),
      startLine,
      severity,
      message: `[${cwe}] ${title}: ${message}`,
      evidence: chain || null,
      scannerConfidence: confidence.toUpperCase() as "HIGH" | "MEDIUM" | "LOW",
      subcategory: ["vuln"],
      likelihood: confidence.toUpperCase(),
      impact: severity === "ERROR" ? "HIGH" : "MEDIUM",
      cwe: cwe ? [cwe] : [],
      score: scoreFindingMetadata({
        severity,
        likelihood: confidence.toUpperCase(),
        impact: severity === "ERROR" ? "HIGH" : "MEDIUM",
        subcategory: ["vuln"],
        cwe: cwe ? [cwe] : [],
      }),
      taintPath: taintPath.length > 0 ? taintPath : undefined,
      proofState: "symbolic_only",
      engineProvenance: [{ kind: "agentic", detail: "LLM-driven deep semantic CodeQL analysis" }],
    });
  }

  return out;
}

/* ---------- main task ---------- */

async function run(_input: ScanOpts, context: DagRunContext): Promise<Finding[]> {
  const config = resolveConfig(context);
  const cweOutput = context.upstreamOutputs.get("deep-semantic-cwe-select") as
    | CweSelectOutput
    | undefined;
  const cwes = (cweOutput?.cwes ?? []).slice(0, config.maxCweClasses);

  if (cwes.length === 0) {
    log.info("No deep-semantic CWE classes selected — skipping");
    return attachTaskOutputMeta([], { costUsd: 0 });
  }

  const codeqlDbPath = resolveCodeqlDbPath(context);
  log.info(
    `Starting deep semantic hunt for ${cwes.length} CWE classes (model=${config.model}, codeql=${!!codeqlDbPath})`,
  );

  // Build hunt tasks, execute with bounded concurrency
  const huntTasks: Array<() => Promise<HuntResult>> = cwes.map(
    (cwe) => () =>
      runCweHunt(cwe, context, config, codeqlDbPath).catch((err) => {
        log.error(`[deep-semantic-hunt/${cwe.id}] Fatal: ${toErrorMessage(err)}`);
        return { findings: [], costUsd: 0 } as HuntResult;
      }),
  );

  const results: HuntResult[] = [];
  for (let i = 0; i < huntTasks.length; i += config.maxConcurrentHunts) {
    const batch = huntTasks.slice(i, i + config.maxConcurrentHunts);
    const batchResults = await Promise.all(batch.map((fn) => fn()));
    results.push(...batchResults);
  }

  // Merge and dedup by fingerprint (keep highest score)
  const seen = new Map<string, Finding>();
  for (const result of results) {
    for (const f of result.findings) {
      const existing = seen.get(f.fingerprint);
      if (!existing || f.score > existing.score) {
        seen.set(f.fingerprint, f);
      }
    }
  }

  const totalCost = results.reduce((sum, r) => sum + r.costUsd, 0);
  const findings = [...seen.values()]
    .sort((a, b) => b.score - a.score)
    .slice(0, config.maxFindings);

  log.info(`Deep semantic hunt complete: ${findings.length} findings, $${totalCost.toFixed(2)}`);

  return attachTaskOutputMeta(findings, { costUsd: totalCost });
}

export const deepSemanticHuntTask: DagNodeImpl<ScanOpts, Finding[]> = {
  id: "deep-semantic-hunt",
  displayName: "Deep Semantic Vulnerability Hunt",
  outputKind: "findings",
  dependsOn: ["deep-semantic-cwe-select", "context-gatherer"],

  condition(upstreamOutputs) {
    const cweOutput = upstreamOutputs.get("deep-semantic-cwe-select") as
      | CweSelectOutput
      | undefined;
    return !!cweOutput?.cwes?.length;
  },

  run,

  triageAgentConfig(finding: Finding, repoName: string): TriageAgentConfig {
    return {
      prompt: [
        `You are triaging a deep semantic vulnerability finding in "${repoName}".`,
        "This finding was discovered by analyzing value ranges, type interactions,",
        "and semantic properties — NOT a traditional source-to-sink taint flow.",
        "",
        `Rule: ${finding.ruleId}`,
        `File: ${finding.filePath}:${finding.startLine}`,
        `Severity: ${finding.severity}`,
        `Message: ${finding.message}`,
        finding.evidence ? `Reasoning chain: ${finding.evidence}` : "",
        "",
        "Verify the vulnerability is genuine and exploitable:",
        "- Check the actual type widths and value ranges at the flagged location",
        "- Verify the integer/buffer/state reasoning in the evidence chain",
        "- Confirm the code path is reachable with attacker-controlled input",
        "- Check for guards, assertions, or compiler flags that may prevent exploitation",
      ]
        .filter(Boolean)
        .join("\n"),
    };
  },
};

/* ---------- helpers ---------- */

function mapSeverity(s: string): string {
  switch (s.toLowerCase()) {
    case "critical":
    case "high":
      return "ERROR";
    case "medium":
      return "WARNING";
    default:
      return "INFO";
  }
}

function normalizePath(repoRoot: string, filePath: string): string {
  if (!path.isAbsolute(filePath)) return filePath;
  const rel = path.relative(repoRoot, filePath);
  return rel.startsWith("..") ? filePath : rel || filePath;
}

function str(v: unknown): string {
  return typeof v === "string" ? v.trim() : "";
}

function tryParseJson(text: string): unknown {
  try {
    return JSON.parse(text);
  } catch {
    return null;
  }
}

// Exported for testing
export const __deepSemanticHuntInternals = {
  buildHuntPrompt,
  buildStrategySection,
  parseFindings,
  resolveConfig,
};
