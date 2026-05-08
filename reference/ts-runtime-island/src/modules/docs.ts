/**
 * Module docs generator — reads a loaded CopilotModule's metadata +
 * tools and emits a markdown reference file.
 *
 * Output layout:
 *   # <displayName> (<id>)
 *   Category / Version / Rank / Disclosure / Authors
 *   ## Description
 *   ## Tools
 *     ### <tool:action>
 *       options table (from inputSchema)
 *   ## References
 *   ## Events
 *   ## Requires (preflight)
 *   ## Examples (verbatim)
 *
 * Intentionally deterministic — no timestamps, no env-dependent output — so
 * running `kuzushi docs generate` twice produces identical files.
 */

import type { CopilotModule, JSONSchema, ModuleReference, ModuleTool } from "./types.js";

export interface DocOptions {
  /** Optional "Last generated" date string injected into the footer. */
  footerNote?: string;
}

export function generateModuleDoc(mod: CopilotModule, opts: DocOptions = {}): string {
  const lines: string[] = [];
  lines.push(`# ${mod.displayName} — \`${mod.id}\``);
  lines.push("");
  lines.push(renderHeaderTable(mod));
  lines.push("");
  lines.push("## Description");
  lines.push("");
  for (const p of mod.description.split("\n")) lines.push(p);
  lines.push("");

  if (mod.notes) {
    const parts: string[] = [];
    if (mod.notes.stability) parts.push(`**Stability:** ${mod.notes.stability.join(", ")}`);
    if (mod.notes.reliability) parts.push(`**Reliability:** ${mod.notes.reliability.join(", ")}`);
    if (mod.notes.sideEffects) parts.push(`**Side effects:** ${mod.notes.sideEffects.join(", ")}`);
    if (parts.length > 0) {
      lines.push("## Notes");
      lines.push("");
      for (const p of parts) lines.push(`- ${p}`);
      lines.push("");
    }
  }

  if (mod.requires && mod.requires.length > 0) {
    lines.push("## Requires (preflight)");
    lines.push("");
    for (const req of mod.requires) lines.push(`- ${renderRequire(req)}`);
    lines.push("");
  }

  if (mod.tools.length > 0) {
    lines.push("## Tools");
    lines.push("");
    for (const tool of mod.tools) {
      lines.push(renderToolSection(tool, mod.id));
    }
  }

  if (mod.references && mod.references.length > 0) {
    lines.push("## References");
    lines.push("");
    for (const r of mod.references) lines.push(`- ${r.type}: ${r.value}`);
    lines.push("");
  }

  if (mod.events) {
    const produces = mod.events.produces ?? [];
    const consumes = mod.events.consumes ?? [];
    if (produces.length > 0 || consumes.length > 0) {
      lines.push("## Events");
      lines.push("");
      if (produces.length > 0) lines.push(`- **Produces:** ${produces.join(", ")}`);
      if (consumes.length > 0) lines.push(`- **Consumes:** ${consumes.join(", ")}`);
      lines.push("");
    }
  }

  if (mod.examples && mod.examples.length > 0) {
    lines.push("## Examples");
    lines.push("");
    for (const ex of mod.examples) {
      lines.push("```");
      lines.push(ex);
      lines.push("```");
      lines.push("");
    }
  }

  if (opts.footerNote) {
    lines.push("---");
    lines.push(`_${opts.footerNote}_`);
    lines.push("");
  }
  return lines.join("\n");
}

function renderHeaderTable(mod: CopilotModule): string {
  const rows: Array<[string, string]> = [
    ["Category", mod.category],
    ["Version", mod.version],
    ["Rank", mod.rank ?? "normal"],
  ];
  if (mod.disclosureDate) rows.push(["Disclosed", mod.disclosureDate]);
  if (mod.authors && mod.authors.length > 0) rows.push(["Authors", mod.authors.join(", ")]);
  const header = "| Field | Value |";
  const sep = "| ----- | ----- |";
  const body = rows.map(([k, v]) => `| ${k} | ${v} |`).join("\n");
  return [header, sep, body].join("\n");
}

function renderRequire(req: NonNullable<CopilotModule["requires"]>[number]): string {
  switch (req.kind) {
    case "snapshot":
      return `snapshot.\`${req.field}\` (produced by \`${req.moduleId}\`)`;
    case "findings":
      return `${req.minCount ?? 1}+ findings in the active workspace`;
    case "hosts":
      return `${req.minCount ?? 1}+ hosts in the active workspace`;
    case "session":
      return req.sessionKind ? `live session of kind \`${req.sessionKind}\`` : "any live session";
    case "env":
      return `environment variable \`${req.name}\``;
  }
}

function renderToolSection(tool: ModuleTool, moduleId: string): string {
  const lines: string[] = [];
  lines.push(`### \`${tool.name}\``);
  lines.push("");
  lines.push(tool.description);
  lines.push("");
  const attrs: string[] = [];
  attrs.push(`headless: ${tool.headless ? "yes" : "no"}`);
  if (tool.rank) attrs.push(`rank: ${tool.rank}`);
  lines.push(`_(${attrs.join(" · ")})_`);
  lines.push("");

  const optionRows = extractOptionRows(tool.inputSchema);
  if (optionRows.length > 0) {
    lines.push("| Option | Type | Required | Default | Description |");
    lines.push("| ------ | ---- | -------- | ------- | ----------- |");
    for (const row of optionRows) {
      lines.push(
        `| ${row.name} | ${row.type} | ${row.required ? "yes" : ""} | ${row.default ?? ""} | ${row.description} |`,
      );
    }
    lines.push("");
  }

  const refs = mergeRefs(tool.references);
  if (refs.length > 0) {
    lines.push("**Tool references:**");
    lines.push("");
    for (const r of refs) lines.push(`- ${r.type}: ${r.value}`);
    lines.push("");
  }
  void moduleId; // reserved for future cross-links
  return lines.join("\n");
}

interface OptionRow {
  name: string;
  type: string;
  required: boolean;
  default: string | null;
  description: string;
}

function extractOptionRows(schema: JSONSchema): OptionRow[] {
  const props = (schema as { properties?: Record<string, JSONSchema> }).properties;
  const required = new Set(
    Array.isArray((schema as { required?: unknown }).required)
      ? ((schema as { required: unknown[] }).required.filter(
          (x): x is string => typeof x === "string",
        ) as string[])
      : [],
  );
  if (!props) return [];
  const rows: OptionRow[] = [];
  for (const [name, s] of Object.entries(props)) {
    const t = (s as { type?: string }).type ?? "any";
    const def = (s as { default?: unknown }).default;
    const description = String((s as { description?: string }).description ?? "");
    rows.push({
      name,
      type: t,
      required: required.has(name),
      default: def === undefined ? null : JSON.stringify(def),
      description: description.replace(/\|/g, "\\|"),
    });
  }
  return rows;
}

function mergeRefs(refs?: ReadonlyArray<ModuleReference>): ModuleReference[] {
  return refs ? [...refs] : [];
}
