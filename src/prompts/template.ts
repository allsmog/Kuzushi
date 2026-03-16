/**
 * Lightweight {{ variable }} template engine for prompt construction.
 *
 * Supports:
 * - {{ var }} — simple substitution
 * - {{ obj.nested.path }} — dotted path access
 * - {{ env.VAR_NAME }} — environment variable access
 * - {{ arr | join(", ") }} — join filter for arrays
 * - {{ var | upper }} — uppercase filter
 * - {{ var | lower }} — lowercase filter
 * - {{ var | default("fallback") }} — default value filter
 */

export interface TemplateContext {
  [key: string]: unknown;
  env?: Record<string, string | undefined>;
}

/**
 * Render a template string by substituting `{{ expr }}` placeholders
 * with values resolved from the supplied context.
 *
 * Environment variables are automatically available under `env.*`
 * unless the caller provides an explicit `env` key in the context.
 */
export function renderTemplate(template: string, context: TemplateContext): string {
  // Merge env into context (caller-supplied env wins over process.env)
  const fullContext: TemplateContext = {
    env: process.env as Record<string, string | undefined>,
    ...context,
  };

  return template.replace(/\{\{\s*(.+?)\s*\}\}/g, (match, expr: string) => {
    // Split on pipe to separate path from filters
    const [pathPart, ...filterParts] = expr.split("|").map((s: string) => s.trim());

    // Resolve the value from dotted path
    let value = resolvePath(fullContext, pathPart);

    // Apply filters in order
    for (const filterExpr of filterParts) {
      value = applyFilter(value, filterExpr);
    }

    if (value === undefined || value === null) {
      return "";
    }

    return String(value);
  });
}

function resolvePath(context: TemplateContext, path: string): unknown {
  const parts = path.split(".");
  let current: unknown = context;
  for (const part of parts) {
    if (current === null || current === undefined) return undefined;
    if (typeof current !== "object") return undefined;
    current = (current as Record<string, unknown>)[part];
  }
  return current;
}

function applyFilter(value: unknown, filterExpr: string): unknown {
  // Parse filter name and optional arguments: name(args)
  const match = filterExpr.match(/^(\w+)(?:\((.+)\))?$/);
  if (!match) return value;

  const [, filterName, argsStr] = match;

  switch (filterName) {
    case "join": {
      if (!Array.isArray(value)) return value;
      const separator = argsStr ? argsStr.replace(/^["']|["']$/g, "") : ", ";
      return value.join(separator);
    }
    case "upper":
      return typeof value === "string" ? value.toUpperCase() : value;
    case "lower":
      return typeof value === "string" ? value.toLowerCase() : value;
    case "default": {
      if (value === undefined || value === null || value === "") {
        return argsStr ? argsStr.replace(/^["']|["']$/g, "") : "";
      }
      return value;
    }
    default:
      console.warn(`[prompt-template] Unknown template filter: ${filterName}`);
      return value;
  }
}

/**
 * Validate that all template variables in a template string are present
 * in the context. Returns list of missing variable paths.
 */
export function validateTemplate(template: string, context: TemplateContext): string[] {
  const missing: string[] = [];
  const fullContext: TemplateContext = {
    env: process.env as Record<string, string | undefined>,
    ...context,
  };

  template.replace(/\{\{\s*(.+?)\s*\}\}/g, (_match, expr: string) => {
    const pathPart = expr.split("|")[0].trim();
    const value = resolvePath(fullContext, pathPart);
    if (value === undefined) missing.push(pathPart);
    return "";
  });

  return missing;
}
