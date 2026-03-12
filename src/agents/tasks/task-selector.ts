import { coerceRepoContext } from "../../repo-context.js";
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
    tasks: ["dangerous-api", "ssrf-detect", "crypto-misuse-detect", "secrets-detection"],
    reason: "JS/TS ecosystem: check for dangerous APIs, SSRF, crypto misuse, and hardcoded secrets",
  },
  {
    languages: ["Go", "golang"],
    tasks: ["race-condition-detect", "crypto-misuse-detect"],
    reason: "Go: goroutine race conditions and crypto misuse are common",
  },
  {
    languages: ["Python"],
    tasks: ["dangerous-api", "secrets-detection", "security-misconfig"],
    reason: "Python: check for dangerous APIs, secrets, and security misconfiguration",
  },
  {
    languages: ["Java", "Kotlin"],
    tasks: ["dangerous-api", "crypto-misuse-detect", "secrets-detection"],
    reason: "JVM: check for dangerous APIs, crypto misuse, and hardcoded secrets",
  },
  {
    languages: ["Ruby"],
    tasks: ["dangerous-api", "secrets-detection", "security-misconfig"],
    reason: "Ruby: check for dangerous APIs, secrets, and misconfiguration",
  },
  {
    languages: ["PHP"],
    tasks: ["dangerous-api", "ssrf-detect", "secrets-detection"],
    reason: "PHP: high risk for injection, SSRF, and hardcoded secrets",
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
    condition: (ctx) => ctx.languages.length > 1,
    tasks: ["threat-model-stride"],
    reason: "Multi-language repo — STRIDE threat model for cross-boundary analysis",
  },
];

/** Tasks always recommended regardless of context. */
const ALWAYS_RECOMMENDED = ["secrets-detection", "security-misconfig"];

/**
 * Deterministic task selector — no LLM, pure rule-based mapping
 * from repository context to recommended tasks.
 */
function selectTasks(repoContext: RepoContext | undefined): TaskSelectionResult {
  const recommended = new Set<string>(ALWAYS_RECOMMENDED);
  const reasoning: Record<string, string> = {
    "secrets-detection": "Always recommended: secrets detection",
    "security-misconfig": "Always recommended: security misconfiguration checks",
  };
  const skipped: Array<{ id: string; reason: string }> = [];

  if (!repoContext) {
    return {
      recommendedTasks: [...recommended],
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
          reasoning[taskId] = rule.reason;
        }
      }
    }
  }

  return {
    recommendedTasks: [...recommended],
    reasoning,
    skippedTasks: skipped.length > 0 ? skipped : undefined,
  };
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
