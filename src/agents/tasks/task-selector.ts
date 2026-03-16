import { coerceRepoContext } from "../../repo-context.js";
import { normalizeTaskCapabilityIds } from "../../capabilities.js";
import type { RepoContext, ScanOpts } from "../../types.js";
import type { AgentTask, TaskContext } from "../types.js";

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
  condition?: (ctx: RepoContext) => boolean;
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
    ],
    reason: "JS/TS ecosystem: prioritize dangerous APIs, SSRF, prototype pollution, templating, and package supply-chain risk",
  },
  {
    languages: ["Go", "golang"],
    tasks: ["race-condition", "crypto-misuse", "supply-chain"],
    reason: "Go: goroutine races, crypto misuse, and dependency risk are common review targets",
  },
  {
    languages: ["Python"],
    tasks: ["dangerous-api", "secrets", "security-misconfig", "template-injection", "supply-chain"],
    reason: "Python: check for dangerous APIs, secrets, misconfiguration, templating risk, and dependency exposure",
  },
  {
    languages: ["Java", "Kotlin"],
    tasks: ["dangerous-api", "crypto-misuse", "secrets", "supply-chain"],
    reason: "JVM: check for dangerous APIs, crypto misuse, secrets, and dependency exposure",
  },
  {
    languages: ["Ruby"],
    tasks: ["dangerous-api", "secrets", "security-misconfig", "template-injection", "supply-chain"],
    reason: "Ruby: check for dangerous APIs, secrets, misconfiguration, ERB-like templating issues, and gem risk",
  },
  {
    languages: ["PHP"],
    tasks: ["dangerous-api", "ssrf", "secrets", "template-injection", "supply-chain"],
    reason: "PHP: high risk for injection, SSRF, templating issues, and hardcoded secrets",
  },
  {
    condition: (ctx) => ctx.authPatterns.length > 0,
    tasks: ["auth-access"],
    reason: "Auth patterns detected — check for authentication and authorization issues",
  },
  {
    condition: (ctx) => ctx.ormOrDb.length > 0,
    tasks: ["dangerous-api"],
    reason: "ORM/DB detected — check for dangerous database API usage",
  },
  {
    condition: (ctx) =>
      ctx.ormOrDb.some((item) => /mongo|mongoose|dynamo|cosmos/i.test(item)),
    tasks: ["nosql-injection"],
    reason: "Document or key-value database usage detected — check for NoSQL injection patterns",
  },
  {
    condition: (ctx) =>
      ctx.frameworks.some((item) => /graphql|apollo|graphene|ariadne|mercurius/i.test(item))
      || ctx.entryPoints.some((item) => /graphql/i.test(item)),
    tasks: ["graphql-security"],
    reason: "GraphQL stack detected — run GraphQL-specific security checks",
  },
  {
    condition: (ctx) => ctx.languages.length > 1,
    tasks: ["threat-model-stride"],
    reason: "Multi-language repo — STRIDE threat model for cross-boundary analysis",
  },
];

/** Tasks always recommended regardless of context. */
const ALWAYS_RECOMMENDED = ["secrets", "security-misconfig"];

/**
 * Deterministic task selector — no LLM, pure rule-based mapping
 * from repository context to recommended tasks.
 */
function selectTasks(repoContext: RepoContext | undefined): TaskSelectionResult {
  const recommended = new Set<string>(ALWAYS_RECOMMENDED);
  const reasoning: Record<string, string> = {};
  const skipped: Array<{ id: string; reason: string }> = [];
  const recommendedTasks = normalizeTaskCapabilityIds([...recommended]);

  if (!repoContext) {
    applyDefaultReasoning(recommendedTasks, reasoning);
    return {
      recommendedTasks,
      reasoning,
      skippedTasks: [{ id: "*", reason: "No repo context available — using defaults only" }],
    };
  }

  const repoLanguages = new Set(
    repoContext.languages.map((l) => l.toLowerCase()),
  );

  for (const rule of SELECTION_RULES) {
    let matches = false;

    if (rule.languages) {
      matches = rule.languages.some((l) => repoLanguages.has(l.toLowerCase()));
    }

    if (!matches && rule.frameworks) {
      const repoFrameworks = new Set(
        repoContext.frameworks.map((f) => f.toLowerCase()),
      );
      matches = rule.frameworks.some((f) => repoFrameworks.has(f.toLowerCase()));
    }

    if (!matches && rule.condition) {
      matches = rule.condition(repoContext);
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
  applyDefaultReasoning(normalizedRecommendedTasks, reasoning);

  for (const rule of SELECTION_RULES) {
    const normalizedTasks = normalizeTaskCapabilityIds(rule.tasks);
    for (const taskId of normalizedTasks) {
      if (normalizedRecommendedTasks.includes(taskId)) {
        reasoning[taskId] = reasoning[taskId] === "Always recommended: secrets detection"
          || reasoning[taskId] === "Always recommended: security misconfiguration checks"
          ? reasoning[taskId]
          : rule.reason;
      }
    }
  }

  return {
    recommendedTasks: normalizedRecommendedTasks,
    reasoning,
    skippedTasks: skipped.length > 0 ? skipped : undefined,
  };
}

function applyDefaultReasoning(
  recommendedTasks: string[],
  reasoning: Record<string, string>,
): void {
  for (const taskId of recommendedTasks) {
    if (!reasoning[taskId]) {
      reasoning[taskId] = taskId === "secrets-detect"
        ? "Always recommended: secrets detection"
        : taskId === "security-misconfig-detect"
          ? "Always recommended: security misconfiguration checks"
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
    const repoContext = coerceRepoContext(context.upstreamOutputs.get("context-gatherer"));
    const result = selectTasks(repoContext);
    console.error(
      `[task-selector] Recommended ${result.recommendedTasks.length} tasks: ${result.recommendedTasks.join(", ")}`,
    );
    return result;
  },
};

export const __taskSelectorInternals = {
  selectTasks,
};
