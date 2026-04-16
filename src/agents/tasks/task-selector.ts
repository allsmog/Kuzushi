import { normalizeTaskCapabilityIds } from "../../capabilities.js";
import { coerceFileIndex, coerceRepoContext } from "../../repo-context.js";
import type { FileIndex, RepoContext, ScanOpts } from "../../types.js";
import type { AgentTask } from "../types.js";

/**
 * Result of dynamic task selection based on repo context.
 */
export interface TaskSelectionResult {
  /** Task IDs recommended for this repository. */
  recommendedTasks: string[];
  /** Reasoning for each recommended task. */
  reasoning: Record<string, string>;
  /** Tasks that were considered but skipped. */
  skippedTasks?: Array<{ id: string; reason: string }>;
}

/** Language/framework to task mapping rules. */
interface SelectionRule {
  /** If any of these languages match, recommend these tasks. */
  languages?: string[];
  /** If any of these frameworks match, recommend these tasks. */
  frameworks?: string[];
  /** Pattern check functions on RepoContext. */
  condition?: (ctx: RepoContext, fileIndex?: FileIndex) => boolean;
  /** Tasks to recommend. */
  tasks: string[];
  /** Reasoning for the recommendation. */
  reason: string;
}

const SELECTION_RULES: SelectionRule[] = [
  {
    languages: ["TypeScript", "JavaScript", "tsx", "jsx"],
    tasks: [
      "dangerous-api",
      "ssrf",
      "crypto-misuse",
      "secrets",
      "prototype-pollution",
      "template-injection",
      "supply-chain",
      "command-injection",
      "deserialization",
    ],
    reason:
      "JS/TS ecosystem: prioritize dangerous APIs, SSRF, prototype pollution, templating, and package supply-chain risk",
  },
  {
    languages: ["Go", "golang"],
    tasks: [
      "race-condition",
      "crypto-misuse",
      "supply-chain",
      "command-injection",
      "deserialization",
    ],
    reason:
      "Go: goroutine races, crypto misuse, dependency risk, and command/deserialization checks",
  },
  {
    languages: ["Python"],
    tasks: [
      "dangerous-api",
      "secrets",
      "security-misconfig",
      "template-injection",
      "supply-chain",
      "command-injection",
      "deserialization",
      "xxe",
    ],
    reason:
      "Python: check for dangerous APIs, secrets, misconfiguration, templating, command injection, deserialization, and XXE risk",
  },
  {
    languages: ["Java", "Kotlin"],
    tasks: [
      "dangerous-api",
      "crypto-misuse",
      "secrets",
      "supply-chain",
      "command-injection",
      "deserialization",
      "xxe",
    ],
    reason:
      "JVM: check for dangerous APIs, crypto misuse, secrets, command injection, deserialization, and XXE",
  },
  {
    languages: ["Ruby"],
    tasks: [
      "dangerous-api",
      "secrets",
      "security-misconfig",
      "template-injection",
      "supply-chain",
      "command-injection",
      "deserialization",
      "xxe",
    ],
    reason:
      "Ruby: check for dangerous APIs, secrets, misconfiguration, templating, command injection, deserialization, and XXE",
  },
  {
    languages: ["PHP"],
    tasks: [
      "dangerous-api",
      "ssrf",
      "secrets",
      "template-injection",
      "supply-chain",
      "command-injection",
      "deserialization",
      "xxe",
    ],
    reason:
      "PHP: high risk for injection, SSRF, templating, command injection, deserialization, and XXE",
  },
  {
    languages: ["C", "C++", "Rust"],
    tasks: ["systems-hunt"],
    reason:
      "Native code: systems hunt for protocol parsing, numeric boundary bugs, and unsafe memory edges",
  },
  {
    condition: (_ctx, fileIndex) => hasSystemsPatternSignals(fileIndex),
    tasks: ["systems-hunt"],
    reason:
      "Packet/parser/unsafe/hardening signals detected — run the systems hunt even without explicit language metadata",
  },
  // Note: auth-access and dangerous-api both resolve to code-config-detect,
  // which is already in ALWAYS_RECOMMENDED via security-misconfig. Dedicated
  // rules for auth patterns and ORM/DB are unnecessary until those capabilities
  // map to distinct task IDs.
  {
    condition: (ctx) => ctx.ormOrDb.some((item) => /mongo|mongoose|dynamo|cosmos/i.test(item)),
    tasks: ["nosql-injection"],
    reason: "Document or key-value database usage detected — check for NoSQL injection patterns",
  },
  {
    condition: (ctx) =>
      ctx.frameworks.some((item) => /graphql|apollo|graphene|ariadne|mercurius/i.test(item)) ||
      ctx.entryPoints.some((item) => /graphql/i.test(item)),
    tasks: ["graphql-security"],
    reason: "GraphQL stack detected — run GraphQL-specific security checks",
  },
  {
    condition: (ctx) => ctx.languages.length > 1,
    tasks: ["threat-model", "threat-hunt"],
    reason: "Multi-language repo — STRIDE + PASTA threat models and threat-actor-driven hunting",
  },
  {
    condition: (ctx) =>
      ctx.frameworks.some((f) =>
        /express|fastapi|django|flask|spring|gin|echo|nest|next|rails|laravel/i.test(f),
      ) || ctx.authPatterns.length > 0,
    tasks: ["auth-logic", "threat-hunt"],
    reason:
      "Web framework or auth patterns detected — probe authorization logic and run threat-actor-driven hunting",
  },
  {
    condition: (ctx) => ctx.frameworks.length > 0 || ctx.authPatterns.length > 0,
    tasks: ["sharp-edges"],
    reason:
      "Framework or auth patterns detected — probe for API design footguns and dangerous defaults",
  },
];

/** Tasks always recommended regardless of context. */
const ALWAYS_RECOMMENDED = [
  "secrets",
  "security-misconfig",
  "sharp-edges",
  "threat-model",
  "threat-hunt",
  "taint-analysis",
];

/**
 * The set of resolved task IDs that task-selector manages.
 * When dynamic task selection is active, these tasks are excluded from the
 * initial candidate set — task-selector adds the relevant subset after it runs.
 */
export const SELECTABLE_TASK_IDS: ReadonlySet<string> = new Set([
  "secrets-crypto-detect",
  "code-config-detect",
  "ssrf-detect",
  "race-condition-detect",
  "nosql-injection-detect",
  "prototype-pollution-detect",
  "template-injection-detect",
  "graphql-security-detect",
  "supply-chain-detect",
  "command-injection-detect",
  "xxe-detect",
  "deserialization-detect",
  "auth-logic-detect",
  "threat-model-randori",
  "threat-hunt",
  "sharp-edges-detect",
  "taint-cwe-select",
  "taint-iris",
  "systems-context-gatherer",
  "systems-invariant-extract",
  "systems-trigger-synth",
  "systems-hunt",
]);

/**
 * Deterministic task selector — no LLM, pure rule-based mapping
 * from repository context to recommended tasks.
 */
function selectTasks(
  repoContext: RepoContext | undefined,
  fileIndex?: FileIndex,
): TaskSelectionResult {
  const recommended = new Set<string>(ALWAYS_RECOMMENDED);
  const reasoning: Record<string, string> = {};

  if (!repoContext) {
    const recommendedTasks = normalizeTaskCapabilityIds([...recommended]);
    applyDefaultReasoning(recommendedTasks, reasoning);
    return {
      recommendedTasks,
      reasoning,
      skippedTasks: [{ id: "*", reason: "No repo context available — using defaults only" }],
    };
  }

  const repoLanguages = new Set(repoContext.languages.map((l) => l.toLowerCase()));

  for (const rule of SELECTION_RULES) {
    let matches = false;

    if (rule.languages) {
      matches = rule.languages.some((l) => repoLanguages.has(l.toLowerCase()));
    }

    if (!matches && rule.frameworks) {
      const repoFrameworks = new Set(repoContext.frameworks.map((f) => f.toLowerCase()));
      matches = rule.frameworks.some((f) => repoFrameworks.has(f.toLowerCase()));
    }

    if (!matches && rule.condition) {
      matches = rule.condition(repoContext, fileIndex);
    }

    if (matches) {
      for (const taskId of rule.tasks) {
        if (!recommended.has(taskId)) {
          recommended.add(taskId);
        }
      }
    }
  }

  const normalizedRecommendedTasks = normalizeTaskCapabilityIds([...recommended]);

  // Apply rule-specific reasoning first (first matching rule wins per task ID).
  // Always-recommended tasks are skipped — they get their defaults below.
  const alwaysRecommendedIds = new Set(normalizeTaskCapabilityIds([...ALWAYS_RECOMMENDED]));
  for (const rule of SELECTION_RULES) {
    const normalizedTasks = normalizeTaskCapabilityIds(rule.tasks);
    for (const taskId of normalizedTasks) {
      if (
        normalizedRecommendedTasks.includes(taskId) &&
        !alwaysRecommendedIds.has(taskId) &&
        !reasoning[taskId]
      ) {
        reasoning[taskId] = rule.reason;
      }
    }
  }

  // Fill defaults for always-recommended tasks and any unmatched tasks
  applyDefaultReasoning(normalizedRecommendedTasks, reasoning);

  return {
    recommendedTasks: normalizedRecommendedTasks,
    reasoning,
  };
}

function applyDefaultReasoning(
  recommendedTasks: string[],
  reasoning: Record<string, string>,
): void {
  for (const taskId of recommendedTasks) {
    if (!reasoning[taskId]) {
      reasoning[taskId] =
        taskId === "secrets-crypto-detect"
          ? "Always recommended: secrets and crypto detection"
          : taskId === "code-config-detect"
            ? "Always recommended: code and config security checks"
            : "Recommended from repository context";
    }
  }
}

export const taskSelectorTask: AgentTask<ScanOpts, TaskSelectionResult> = {
  id: "task-selector",
  displayName: "Dynamic Task Selector",
  outputKind: "custom",
  dependsOn: ["context-gatherer"],

  async run(_input, context): Promise<TaskSelectionResult> {
    const contextGathererOutput = context.upstreamOutputs.get("context-gatherer");
    const repoContext = coerceRepoContext(contextGathererOutput);
    const fileIndex = coerceFileIndex(contextGathererOutput);
    const result = selectTasks(repoContext, fileIndex);
    console.error(
      `[task-selector] Recommended ${result.recommendedTasks.length} tasks: ${result.recommendedTasks.join(", ")}`,
    );
    return result;
  },
};

export const __taskSelectorInternals = {
  selectTasks,
};

function hasSystemsPatternSignals(fileIndex: FileIndex | undefined): boolean {
  if (!fileIndex) return false;
  return ["protocol-parser", "integer-boundary", "unsafe-memory", "hardening"].some(
    (domain) => (fileIndex.patternMatches[domain]?.length ?? 0) > 0,
  );
}
