/**
 * Typed authoring helpers for CopilotModules and ModuleTools.
 *
 * These are thin identity functions (`(spec) => spec`) that give TypeScript
 * the inference it needs to keep literal types tight, plus a lightweight
 * runtime guard that tool names match the module id. They exist so module
 * authors can write
 *
 *   export default defineModule({ id: "my-mod", tools: [defineTool({...})] });
 *
 * instead of annotating every expression with the bare interface types.
 *
 * The template-literal typing on `ModuleTool.name` enforces the `id:` prefix
 * at compile time — a typo like `name: "foo:scan"` under `id: "bar"` fails
 * typecheck before the runtime guard gets a chance to catch it.
 */

import { ModuleLoadError } from "./errors.js";
import type { CopilotModule, ModuleTool } from "./types.js";

/**
 * Specification for a single tool, parameterised by the owning module id.
 * Writing the name as `` `${Id}:${string}` `` fails compilation when the
 * prefix doesn't match.
 */
export type DefineToolSpec<Id extends string = string> = Omit<ModuleTool, "name"> & {
  name: `${Id}:${string}`;
};

/**
 * Author-facing tool builder. Returns the input unchanged so the callsite
 * can continue to export it. The template-literal type on `name` enforces
 * the `moduleId:` prefix; pass the module id as the generic parameter:
 *
 *   defineTool<"my-mod">({ name: "my-mod:scan", ... })
 *
 * Preserves the Id in the returned type so `defineModule` can re-verify
 * the prefix when assembling the tool array.
 */
export function defineTool<Id extends string>(
  spec: DefineToolSpec<Id>,
): DefineToolSpec<Id> & ModuleTool {
  return spec as DefineToolSpec<Id> & ModuleTool;
}

/** Specification for a module. `tools` are validated at runtime against `id`. */
export interface DefineModuleSpec<Id extends string = string>
  extends Omit<CopilotModule, "id" | "tools"> {
  id: Id;
  tools: ReadonlyArray<DefineToolSpec<Id> & ModuleTool>;
}

/**
 * Author-facing module builder. Performs a runtime check that every tool
 * name starts with `<id>:` — the same guard the loader enforces, fail-fast
 * at construction time so authors catch mistakes immediately.
 */
export function defineModule<Id extends string>(spec: DefineModuleSpec<Id>): CopilotModule {
  for (let i = 0; i < spec.tools.length; i++) {
    const tool = spec.tools[i]!;
    if (typeof tool.name !== "string" || !tool.name.startsWith(`${spec.id}:`)) {
      throw new ModuleLoadError(
        "SHAPE_INVALID",
        `Module "${spec.id}" tools[${i}].name "${String(tool.name)}" does not start with "${spec.id}:".`,
        { moduleId: spec.id, toolIndex: i, toolName: tool.name },
      );
    }
  }
  return spec as unknown as CopilotModule;
}
