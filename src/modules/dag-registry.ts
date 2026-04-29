import type { DagNodeImpl } from "../agents/types.js";
import { normalizeTaskCapabilityIds } from "../capabilities.js";
import type { CopilotModule, DagTool, ExecutionContext, ModuleTool, OutputKind } from "./types.js";
import { isDagTool } from "./types.js";

/** Summary info returned by DagRegistry.list(). */
export interface DagInfo {
  id: string;
  name: string;
  displayName: string;
  outputKind: OutputKind;
  dependsOn: string[];
}

/**
 * Orchestrator-facing view of a DagTool.
 *
 * Bus events still use taskId terminology, but registry ids are qualified
 * DagTool names and execution is the native DagTool.run(input, ctx) contract.
 */
export interface DagRegistryEntry<TInput = unknown, TOutput = unknown>
  extends DagTool<string, TInput, TOutput> {
  readonly id: string;
  readonly outputKind: OutputKind;
  readonly dependsOn: string[];
  readonly condition?: NonNullable<DagTool["dag"]["condition"]>;
  readonly promptMode?: DagTool["dag"]["promptMode"];
  readonly toolPolicy?: DagTool["dag"]["toolPolicy"];
  readonly triageAgentConfig?: DagTool["dag"]["triageAgentConfig"];
}

/** Registry and DAG resolver for module-owned DAG tools. */
export class DagRegistry {
  private readonly tools = new Map<string, DagTool>();

  register(tool: DagTool | DagNodeImpl): void {
    const dagTool = isDagToolShape(tool) ? tool : dagToolFromNode(tool);
    this.tools.set(dagTool.name, dagTool);
  }

  get(id: string): DagRegistryEntry {
    const name = this.resolveName(id);
    const tool = this.tools.get(name);
    if (!tool) {
      throw new Error(`Unknown DAG tool: ${id}`);
    }
    return this.entryFor(tool);
  }

  has(id: string): boolean {
    return this.tools.has(this.resolveName(id));
  }

  ids(): string[] {
    return [...this.tools.keys()];
  }

  list(): DagInfo[] {
    return [...this.tools.values()].map((tool) => {
      const entry = this.entryFor(tool);
      return {
        id: entry.id,
        name: entry.name,
        displayName: entry.displayName ?? entry.name,
        outputKind: entry.outputKind,
        dependsOn: [...entry.dependsOn],
      };
    });
  }

  validate(): void {
    for (const tool of this.tools.values()) {
      const entry = this.entryFor(tool);
      for (const dep of entry.dependsOn) {
        if (!this.has(dep)) {
          throw new Error(`DAG tool "${entry.name}" depends on unknown DAG tool "${dep}"`);
        }
      }
    }
  }

  resolveOrder(enabledIds: string[]): string[][] {
    const enabled = normalizeDagIds(enabledIds, this);
    if (enabled.length === 0) return [];

    for (const id of enabled) {
      if (!this.has(id)) {
        throw new Error(`Unknown enabled DAG tool: ${id}`);
      }
    }

    const enabledSet = new Set(enabled);
    const priority = new Map<string, number>(enabled.map((id, idx) => [id, idx]));
    const indegree = new Map<string, number>();
    const edges = new Map<string, string[]>();

    for (const id of enabled) {
      indegree.set(id, 0);
      edges.set(id, []);
    }

    for (const id of enabled) {
      const tool = this.get(id);
      for (const dep of tool.dependsOn) {
        if (!this.has(dep)) {
          throw new Error(`DAG tool "${id}" depends on unknown DAG tool "${dep}"`);
        }
        if (!enabledSet.has(dep)) {
          throw new Error(`DAG tool "${id}" depends on "${dep}" but it is not enabled`);
        }
        indegree.set(id, (indegree.get(id) ?? 0) + 1);
        edges.get(dep)?.push(id);
      }
    }

    const groups: string[][] = [];
    const processed = new Set<string>();

    while (processed.size < enabled.length) {
      const group = enabled
        .filter((id) => !processed.has(id) && (indegree.get(id) ?? 0) === 0)
        .sort((a, b) => (priority.get(a) ?? 0) - (priority.get(b) ?? 0));

      if (group.length === 0) {
        const stuck = enabled.filter((id) => !processed.has(id));
        throw new Error(`DAG dependency cycle detected among: ${stuck.join(", ")}`);
      }

      groups.push(group);

      for (const id of group) {
        processed.add(id);
        for (const dependent of edges.get(id) ?? []) {
          indegree.set(dependent, (indegree.get(dependent) ?? 0) - 1);
        }
      }
    }

    return groups;
  }

  resolveName(id: string): string {
    return canonicalDagId(id.trim());
  }

  private entryFor<TInput, TOutput>(
    tool: DagTool<string, TInput, TOutput>,
  ): DagRegistryEntry<TInput, TOutput> {
    return {
      ...tool,
      id: tool.name,
      outputKind: tool.dag.outputKind,
      dependsOn: tool.dag.dependsOn.map((dep) => this.resolveName(dep)),
      ...(tool.dag.condition ? { condition: tool.dag.condition } : {}),
      ...(tool.dag.promptMode ? { promptMode: tool.dag.promptMode } : {}),
      ...(tool.dag.toolPolicy ? { toolPolicy: tool.dag.toolPolicy } : {}),
      ...(tool.dag.triageAgentConfig ? { triageAgentConfig: tool.dag.triageAgentConfig } : {}),
      async run(input: TInput, ctx: ExecutionContext): Promise<TOutput> {
        return tool.run(input, ctx);
      },
    };
  }
}

function isDagToolShape(value: DagTool | DagNodeImpl): value is DagTool {
  return "dag" in value && typeof (value as Partial<DagTool>).run === "function";
}

function dagToolFromNode(node: DagNodeImpl): DagTool {
  const name = canonicalDagId(node.id) as `${string}:${string}`;
  return {
    name,
    displayName: node.displayName,
    description: `Internal DAG node: ${node.displayName}.`,
    inputSchema: { type: "object", additionalProperties: true },
    headless: true,
    hidden: true,
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
    async execute() {
      throw new Error(`DAG node "${name}" cannot be invoked through execute().`);
    },
    async run(input, ctx) {
      const { buildDagRunContextFromExecutionContext } = await import("./hidden-dag-node.js");
      return node.run(input, buildDagRunContextFromExecutionContext(ctx));
    },
  };
}

export function registerDagToolsInDagRegistry(registry: DagRegistry, mod: CopilotModule): void {
  for (const tool of mod.tools as ReadonlyArray<ModuleTool>) {
    if (!isDagTool(tool)) continue;
    if (registry.has(tool.name)) continue;
    registry.register(tool);
  }
}

export function normalizeDagIds(ids: string[], registry?: DagRegistry): string[] {
  const seen = new Set<string>();
  const out: string[] = [];
  for (const raw of normalizeTaskCapabilityIds(ids)) {
    const id = registry?.resolveName(raw) ?? canonicalDagId(raw.trim());
    if (!id || seen.has(id)) continue;
    seen.add(id);
    out.push(id);
  }
  return out;
}

export function canonicalDagId(id: string): string {
  return CANONICAL_DAG_IDS[id] ?? id;
}

const CANONICAL_DAG_IDS: Record<string, string> = {
  semgrep: "semgrep:scan",
  codeql: "codeql:scan",
  agentic: "agentic-sast:scan",
  "agentic-sast": "agentic-sast:scan",
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
