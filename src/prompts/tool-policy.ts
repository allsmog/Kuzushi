/**
 * Layered tool policy pipeline.
 *
 * Resolves the effective set of allowed tools by applying policy layers
 * in order. Each layer can allow or deny specific tools. Deny always wins.
 *
 * Layer ordering (lowest to highest priority):
 * 1. Global defaults
 * 2. Task-specific policy (from DagNodeImpl.toolPolicy)
 * 3. Config-level overrides (from KuzushiConfig.toolPolicies)
 */

/** A tool policy specifying allow and/or deny lists. */
export interface ToolPolicy {
  /** If set, only these tools (or groups) are allowed. */
  allow?: string[];
  /** These tools (or groups) are always blocked. Deny wins over allow. */
  deny?: string[];
}

/** A named policy layer in the resolution pipeline. */
export interface ToolPolicyLayer {
  name: string;
  policy: ToolPolicy;
}

/** Predefined tool groups for convenience. */
export const TOOL_GROUPS: Record<string, string[]> = {
  "group:readonly": ["Read", "Glob", "Grep"],
  "group:analysis": [
    "GetCallers",
    "GetCallees",
    "GetFunctionBody",
    "GoToDefinition",
    "FindReferences",
    "TypeAtPosition",
  ],
  "group:readwrite": ["Read", "Glob", "Grep", "Write"],
  "group:all": [
    "Read",
    "Glob",
    "Grep",
    "Bash",
    "Write",
    "GetCallers",
    "GetCallees",
    "GetFunctionBody",
    "GoToDefinition",
    "FindReferences",
    "TypeAtPosition",
  ],
};

/** All known tool names in the system. */
export const ALL_TOOLS = [
  "Read",
  "Glob",
  "Grep",
  "Bash",
  "Write",
  "GetCallers",
  "GetCallees",
  "GetFunctionBody",
  "GoToDefinition",
  "FindReferences",
  "TypeAtPosition",
];

/**
 * Expand tool group references in a list of tool names.
 *
 * If a name starts with "group:", it is expanded to the corresponding
 * tool group. Unknown groups are silently ignored.
 */
export function expandToolGroups(tools: string[]): string[] {
  const expanded = new Set<string>();
  for (const tool of tools) {
    if (tool.startsWith("group:")) {
      const group = TOOL_GROUPS[tool];
      if (group) {
        for (const t of group) expanded.add(t);
      }
    } else {
      expanded.add(tool);
    }
  }
  return [...expanded];
}

/**
 * Resolve the effective tool set through policy layers.
 *
 * Processing:
 * 1. Start with the full set of available tools.
 * 2. For each layer (in order), apply allow filter then deny filter.
 * 3. Deny always wins — a tool denied in any layer is removed.
 *
 * @param availableTools - The full set of tools the runtime supports
 * @param layers - Policy layers in priority order (lowest first)
 * @returns The resolved set of allowed tool names
 */
export function resolveToolPolicy(availableTools: string[], layers: ToolPolicyLayer[]): string[] {
  let allowed = new Set(availableTools);
  const globalDeny = new Set<string>();

  for (const layer of layers) {
    // Collect all denied tools across all layers (deny always wins)
    if (layer.policy.deny) {
      for (const tool of expandToolGroups(layer.policy.deny)) {
        globalDeny.add(tool);
      }
    }

    // Apply allow filter: if a layer specifies allow, intersect
    if (layer.policy.allow) {
      const expandedAllow = new Set(expandToolGroups(layer.policy.allow));
      allowed = new Set([...allowed].filter((t) => expandedAllow.has(t)));
    }
  }

  // Remove all globally denied tools
  for (const denied of globalDeny) {
    allowed.delete(denied);
  }

  return [...allowed];
}

/**
 * Build policy layers from task and config settings.
 *
 * @param taskPolicy - Optional policy from DagNodeImpl.toolPolicy
 * @param configPolicies - Optional policies from KuzushiConfig.toolPolicies
 * @returns Ordered array of policy layers
 */
export function buildPolicyLayers(
  taskPolicy?: ToolPolicy,
  configPolicies?: Record<string, ToolPolicy>,
): ToolPolicyLayer[] {
  const layers: ToolPolicyLayer[] = [];

  // Layer 1: Global defaults (readonly tools always allowed)
  layers.push({
    name: "global-defaults",
    policy: {
      allow: [...ALL_TOOLS],
    },
  });

  // Layer 2: Task-specific policy
  if (taskPolicy) {
    layers.push({
      name: "task",
      policy: taskPolicy,
    });
  }

  // Layer 3: Config-level overrides
  if (configPolicies) {
    for (const [name, policy] of Object.entries(configPolicies)) {
      layers.push({
        name: `config:${name}`,
        policy,
      });
    }
  }

  return layers;
}
