/**
 * Multi-strategy analysis framework for vulnerability detection tasks.
 *
 * Each detection task can be associated with multiple analysis strategies.
 * A strategy is a system prompt variation that emphasizes a different analysis
 * perspective, enabling broader coverage when the same vuln class is examined
 * from complementary viewpoints.
 *
 * The registry is a pure lookup table — actual execution is handled by
 * the existing ensemble infrastructure in scan-worker.
 */

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/** A single analysis perspective for a vulnerability detection task. */
export interface AnalysisStrategy {
  /** Unique identifier for this strategy (e.g. "taint-analysis-perspective"). */
  id: string;
  /** Human-readable name shown in logs / diagnostics. */
  name: string;
  /**
   * Short prompt fragment prepended to the task's system prompt to frame the
   * analysis from this strategy's perspective (2-3 sentences).
   */
  systemPromptPrepend: string;
}

/** Maps a detection task to a set of analysis strategies. */
export interface StrategySet {
  /** The task ID this strategy set applies to. */
  taskId: string;
  /** Ordered list of strategies to run for this task. */
  strategies: AnalysisStrategy[];
}

// ---------------------------------------------------------------------------
// Strategy definitions
// ---------------------------------------------------------------------------

const NOSQL_INJECTION_STRATEGIES: AnalysisStrategy[] = [
  {
    id: "taint-analysis-perspective",
    name: "Taint Analysis",
    systemPromptPrepend:
      "Focus on tracing user-controlled input from request parameters through the application to database query construction. Pay special attention to string concatenation, template literals, and dynamic query builders that pass unsanitized input to MongoDB/NoSQL query methods.",
  },
  {
    id: "orm-config-perspective",
    name: "ORM/ODM Configuration",
    systemPromptPrepend:
      "Focus on ORM and ODM configuration weaknesses — Mongoose strict mode disabled, missing schema validation, lean() queries bypassing middleware, and driver-level options that weaken query sanitization. Check whether the application relies on framework defaults that may be insecure.",
  },
  {
    id: "api-misuse-perspective",
    name: "API Misuse",
    systemPromptPrepend:
      "Focus on incorrect or dangerous usage of NoSQL database APIs — passing user objects directly to find/update/delete methods, using $where with string concatenation, constructing aggregation pipelines from user input, and misusing $regex without escaping. Identify patterns where the developer misunderstands the API's security model.",
  },
];

const SSRF_STRATEGIES: AnalysisStrategy[] = [
  {
    id: "url-validation-perspective",
    name: "URL Validation",
    systemPromptPrepend:
      "Focus on URL validation and parsing logic — examine how the application validates URLs before making server-side requests. Look for incomplete validation (checking only scheme, ignoring host), URL parser inconsistencies between validator and HTTP client, and encoded bypass techniques (decimal IP, IPv6-mapped, octal notation).",
  },
  {
    id: "redirect-chain-perspective",
    name: "Redirect Chain",
    systemPromptPrepend:
      "Focus on HTTP redirect following behavior — identify HTTP clients configured to follow redirects where the initial URL passes validation but a redirect target points to internal services. Check for open redirect endpoints that could be chained with SSRF, and DNS rebinding scenarios where a domain resolves to an internal IP after validation.",
  },
  {
    id: "cloud-metadata-perspective",
    name: "Cloud Metadata",
    systemPromptPrepend:
      "Focus on cloud metadata endpoint exposure — determine whether server-side HTTP requests can reach cloud provider metadata services (AWS IMDSv1/v2 at 169.254.169.254, GCP metadata.google.internal, Azure instance metadata). Check for missing IMDSv2 enforcement, and identify code paths where user-controlled URLs could target these endpoints.",
  },
];

const PROTOTYPE_POLLUTION_STRATEGIES: AnalysisStrategy[] = [
  {
    id: "property-assignment-perspective",
    name: "Property Assignment",
    systemPromptPrepend:
      "Focus on dynamic property assignment patterns where attacker-controlled keys can be '__proto__', 'constructor', or 'prototype'. Examine bracket notation chains (obj[a][b] = c), lodash _.set, dot-prop, and flat utilities where user-supplied paths are not filtered for prototype-polluting keys.",
  },
  {
    id: "deep-merge-perspective",
    name: "Deep Merge",
    systemPromptPrepend:
      "Focus on deep merge and extend operations — identify recursive object merging functions (_.merge, _.defaultsDeep, deepmerge, custom recursive merge) that accept user-controlled source objects. Determine whether __proto__ and constructor.prototype keys are stripped before or during the merge process.",
  },
  {
    id: "deserialization-perspective",
    name: "Deserialization",
    systemPromptPrepend:
      "Focus on deserialization and data ingestion paths — examine JSON.parse, query string parsing, multipart form handling, and GraphQL input processing where incoming data structures could contain __proto__ or constructor properties. Check whether the application uses Object.create(null) or frozen prototypes to prevent pollution after deserialization.",
  },
];

const TEMPLATE_INJECTION_STRATEGIES: AnalysisStrategy[] = [
  {
    id: "template-syntax-perspective",
    name: "Template Syntax",
    systemPromptPrepend:
      "Focus on template engine syntax injection — identify where user input is interpolated into template strings before compilation (e.g., Jinja2, EJS, Pug, Handlebars, Nunjucks, Twig). Look for patterns where user data is embedded in the template source rather than passed as a safe context variable.",
  },
  {
    id: "sandbox-escape-perspective",
    name: "Sandbox Escape",
    systemPromptPrepend:
      "Focus on template sandbox escape techniques — examine whether template engines are configured with sandboxing, and identify known bypass chains (e.g., accessing __class__.__mro__ in Jinja2, constructor.constructor in JavaScript engines). Check for template engines running in non-sandboxed modes or with dangerous filters/extensions enabled.",
  },
];

const SUPPLY_CHAIN_STRATEGIES: AnalysisStrategy[] = [
  {
    id: "dependency-version-perspective",
    name: "Dependency Version",
    systemPromptPrepend:
      "Focus on dependency version risks — examine package manifests (package.json, requirements.txt, Gemfile, pom.xml) for pinning practices, known vulnerable version ranges, use of pre-release or deprecated packages, and overly broad version specifiers that could pull in compromised releases.",
  },
  {
    id: "typosquat-perspective",
    name: "Typosquat Detection",
    systemPromptPrepend:
      "Focus on typosquatting and dependency confusion risks — examine package names for close misspellings of popular packages, internal package names that could be claimed on public registries, and registry configuration (e.g., .npmrc, pip.conf) that does not properly scope private packages to prevent dependency confusion attacks.",
  },
];

// ---------------------------------------------------------------------------
// Registry
// ---------------------------------------------------------------------------

const STRATEGY_REGISTRY = new Map<string, StrategySet>([
  ["nosql-injection-detect", { taskId: "nosql-injection-detect", strategies: NOSQL_INJECTION_STRATEGIES }],
  ["ssrf-detect", { taskId: "ssrf-detect", strategies: SSRF_STRATEGIES }],
  ["prototype-pollution-detect", { taskId: "prototype-pollution-detect", strategies: PROTOTYPE_POLLUTION_STRATEGIES }],
  ["template-injection-detect", { taskId: "template-injection-detect", strategies: TEMPLATE_INJECTION_STRATEGIES }],
  ["supply-chain-detect", { taskId: "supply-chain-detect", strategies: SUPPLY_CHAIN_STRATEGIES }],
]);

/**
 * Return the analysis strategies registered for a given detection task.
 * Returns an empty array when no strategies are defined for the task.
 */
export function getStrategiesForTask(taskId: string): AnalysisStrategy[] {
  return STRATEGY_REGISTRY.get(taskId)?.strategies ?? [];
}

/**
 * Return the full strategy set for a given detection task, or undefined when
 * the task has no registered strategies.
 */
export function getStrategySetForTask(taskId: string): StrategySet | undefined {
  return STRATEGY_REGISTRY.get(taskId);
}

/**
 * Return all task IDs that have registered strategies.
 */
export function getTasksWithStrategies(): string[] {
  return [...STRATEGY_REGISTRY.keys()];
}
