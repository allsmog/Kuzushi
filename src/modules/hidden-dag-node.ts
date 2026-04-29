import type { DagNodeImpl, DagRunContext } from "../agents/types.js";
import {
  createPopulatedRegistry,
  getProfileForTask,
  withMultiStrategy,
} from "../strategies/index.js";
import { canonicalDagId } from "./dag-registry.js";
import { defineDagTool } from "./define.js";
import type { DagTool, ExecutionContext } from "./types.js";

export function defineHiddenDagNodeTool<Id extends string>(
  node: DagNodeImpl,
  options: {
    moduleId: Id;
    description?: string;
    multiStrategy?: boolean;
  },
): DagTool<Id> {
  const runnable = options.multiStrategy ? applyMultiStrategyWrap(node) : node;
  return defineDagTool<Id>({
    name: `${options.moduleId}:${node.id}` as `${Id}:${string}`,
    displayName: node.displayName,
    description: options.description ?? `Internal DAG node: ${node.displayName}.`,
    headless: true,
    hidden: true,
    inputSchema: {
      type: "object",
      additionalProperties: true,
    },
    dag: {
      outputKind: node.outputKind,
      dependsOn: node.dependsOn.map(canonicalDagId),
      ...(node.condition ? { condition: node.condition } : {}),
      ...(node.promptMode ? { promptMode: node.promptMode } : {}),
      ...(node.toolPolicy ? { toolPolicy: node.toolPolicy } : {}),
      ...(node.triageAgentConfig ? { triageAgentConfig: node.triageAgentConfig } : {}),
    },
    ...(node.init
      ? {
          async init(config) {
            await node.init?.(config);
          },
        }
      : {}),
    async run(input, ctx: ExecutionContext) {
      return runnable.run(input, buildDagRunContextFromExecutionContext(ctx));
    },
  });
}

export function buildDagRunContextFromExecutionContext(ctx: ExecutionContext): DagRunContext {
  if (!ctx.dag) {
    throw new Error("DagTool.run requires ExecutionContext.dag from the scan orchestrator.");
  }
  const dag = ctx.dag;
  return {
    runId: dag.runId,
    projectRoot: dag.repoRoot,
    repoRoot: dag.scanPath ?? dag.workRoot ?? dag.repoRoot,
    ...(dag.workRoot !== undefined ? { workRoot: dag.workRoot } : {}),
    ...(dag.scanPath !== undefined ? { scanPath: dag.scanPath } : {}),
    ...(dag.gitRoot !== undefined ? { gitRoot: dag.gitRoot } : {}),
    repoName: dag.repoName,
    ...(dag.db !== undefined ? { db: dag.db } : {}),
    config: ctx.config,
    runtime: ctx.runtime,
    bus: ctx.bus,
    upstreamOutputs: withBareOutputKeys(dag.upstreamOutputs),
    ...(ctx.securityProfiles ? { securityProfiles: ctx.securityProfiles } : {}),
    ...(ctx.knowledgeRegistry ? { knowledgeRegistry: ctx.knowledgeRegistry } : {}),
    ...(ctx.modelOverride ? { modelOverride: ctx.modelOverride } : {}),
    ...(ctx.signal ? { signal: ctx.signal } : {}),
  };
}

function withBareOutputKeys(upstream: ReadonlyMap<string, unknown>): Map<string, unknown> {
  const out = new Map(upstream);
  for (const key of [...upstream.keys()]) {
    const bare = bareDagId(key);
    if (bare && !out.has(bare)) {
      out.set(bare, upstream.get(key));
    }
  }
  return out;
}

function bareDagId(id: string): string | undefined {
  const found = Object.entries(BARE_TO_CANONICAL).find(([, canonical]) => canonical === id);
  return found?.[0];
}

const BARE_TO_CANONICAL: Record<string, string> = {
  semgrep: "semgrep:scan",
  codeql: "codeql:scan",
  agentic: "agentic-sast:scan",
  "carlini-threat-hunt": "carlini-threat-hunt:run",
  "taint-cwe-select": "pipeline:taint-cwe-select",
  "taint-iris": "taint-iris:hunt",
  "task-selector": "pipeline:task-selector",
  "approval-gate": "pipeline:approval-gate",
  "context-gatherer": "context:context-gatherer",
  "context-enricher": "context:context-enricher",
  "app-model-build": "context:app-model-build",
  "code-config-detect": "context:code-config-detect",
  "call-graph-assist": "context:call-graph-assist",
  "code-graph-build": "context:code-graph-build",
  "code-graph-enrich": "context:code-graph-enrich",
  "invariant-extract": "context:invariant-extract",
  "invariant-check": "context:invariant-check",
  "threat-model-randori": "threat-model:threat-model-randori",
  "threat-scenario-build": "threat-model:threat-scenario-build",
  "ssrf-detect": "agentic-sast:ssrf-detect",
  "nosql-injection-detect": "agentic-sast:nosql-injection-detect",
  "command-injection-detect": "agentic-sast:command-injection-detect",
  "template-injection-detect": "agentic-sast:template-injection-detect",
  "deserialization-detect": "agentic-sast:deserialization-detect",
  "xxe-detect": "agentic-sast:xxe-detect",
  "prototype-pollution-detect": "agentic-sast:prototype-pollution-detect",
  "graphql-security-detect": "agentic-sast:graphql-security-detect",
  "secrets-crypto-detect": "agentic-sast:secrets-crypto-detect",
  "race-condition-detect": "agentic-sast:race-condition-detect",
  "sharp-edges-detect": "agentic-sast:sharp-edges-detect",
  "supply-chain-detect": "agentic-sast:supply-chain-detect",
  "auth-logic-detect": "agentic-sast:auth-logic-detect",
  "crypto-behavioral-test": "agentic-sast:crypto-behavioral-test",
  "reachability-check": "agentic-sast:reachability-check",
  "diff-review": "agentic-sast:diff-review",
  "systems-context-gatherer": "systems-hunt:systems-context-gatherer",
  "systems-invariant-extract": "systems-hunt:systems-invariant-extract",
  "systems-trigger-synth": "systems-hunt:systems-trigger-synth",
  "systems-hunt": "systems-hunt:systems-hunt",
  "deep-semantic-cwe-select": "systems-hunt:deep-semantic-cwe-select",
  "deep-semantic-hunt": "systems-hunt:deep-semantic-hunt",
  "tob-audit": "tob:tob-audit",
  "vuln-scout": "vuln-scout:vuln-scout",
};

let cachedStrategyRegistry: ReturnType<typeof createPopulatedRegistry> | undefined;

function applyMultiStrategyWrap(node: DagNodeImpl): DagNodeImpl {
  const profile = getProfileForTask(node.id);
  if (!profile) return node;
  if (!cachedStrategyRegistry) cachedStrategyRegistry = createPopulatedRegistry();
  const registryRef = cachedStrategyRegistry;
  return withMultiStrategy(
    node as DagNodeImpl<unknown, unknown>,
    profile,
    () => registryRef,
  ) as DagNodeImpl;
}
