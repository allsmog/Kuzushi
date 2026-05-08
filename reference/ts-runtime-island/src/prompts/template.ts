/**
 * Lightweight template engine for prompt construction.
 *
 * Supports:
 * - {{ var }} — simple substitution
 * - {{ obj.nested.path }} — dotted path access
 * - {{ env.VAR_NAME }} — environment variable access
 * - {{ arr | join(", ") }} — join filter for arrays
 * - {{ var | upper }} — uppercase filter
 * - {{ var | lower }} — lowercase filter
 * - {{ var | default("fallback") }} — default value filter
 * - {{ var | sanitize }} — sanitize untrusted content for prompt injection defense
 * - {% if condition %}...{% elif condition %}...{% else %}...{% endif %}
 * - {% if not condition %} — negation
 * - {% if var == "value" %} — equality
 * - {% if var != "value" %} — inequality
 * - {% for item in list %}...{% endfor %} with {{ loop.index }} (1-based)
 */

import { sanitizeForPrompt } from "./sanitize.js";

export interface TemplateContext {
  [key: string]: unknown;
  env?: Record<string, string | undefined>;
}

const MAX_BLOCK_DEPTH = 10;

/**
 * Render a template string by first processing block constructs ({% if %}, {% for %}),
 * then substituting `{{ expr }}` placeholders with values resolved from the supplied context.
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

  const processed = processBlocks(template, fullContext);

  return substituteVars(processed, fullContext);
}

/**
 * Perform {{ expr }} substitution on a string using the given context.
 * Extracted so it can be reused inside processBlocks for loop bodies.
 */
function substituteVars(template: string, context: TemplateContext): string {
  return template.replace(/\{\{\s*(.+?)\s*\}\}/g, (_match, expr: string) => {
    const [pathPart, ...filterParts] = expr.split("|").map((s: string) => s.trim());
    let value = resolvePath(context, pathPart);
    for (const filterExpr of filterParts) {
      value = applyFilter(value, filterExpr);
    }
    if (value === undefined || value === null) {
      return "";
    }
    return String(value);
  });
}

/**
 * Resolve a dotted path against a context object.
 */
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
    case "sanitize":
      return typeof value === "string" ? sanitizeForPrompt(value) : value;
    default:
      console.warn(`[prompt-template] Unknown template filter: ${filterName}`);
      return value;
  }
}

/**
 * Evaluate a condition expression against a context.
 *
 * Supports:
 * - Simple truthy check: `varPath`
 * - Negation: `not varPath`
 * - Equality: `varPath == "value"` or `varPath == value`
 * - Inequality: `varPath != "value"` or `varPath != value`
 */
function evaluateCondition(conditionStr: string, context: TemplateContext): boolean {
  const condition = conditionStr.trim();

  // Equality: var == "value" or var == value
  const eqMatch = condition.match(/^(.+?)\s*==\s*(.+)$/);
  if (eqMatch) {
    const lhs = resolvePath(context, eqMatch[1].trim());
    const rhs = parseConditionValue(eqMatch[2].trim(), context);
    return lhs === rhs;
  }

  // Inequality: var != "value" or var != value
  const neqMatch = condition.match(/^(.+?)\s*!=\s*(.+)$/);
  if (neqMatch) {
    const lhs = resolvePath(context, neqMatch[1].trim());
    const rhs = parseConditionValue(neqMatch[2].trim(), context);
    return lhs !== rhs;
  }

  // Negation: not var
  const notMatch = condition.match(/^not\s+(.+)$/);
  if (notMatch) {
    const value = resolvePath(context, notMatch[1].trim());
    return !isTruthy(value);
  }

  // Simple truthy check
  const value = resolvePath(context, condition);
  return isTruthy(value);
}

/**
 * Parse the right-hand side of a condition comparison.
 * Supports quoted strings and variable paths.
 */
function parseConditionValue(raw: string, context: TemplateContext): unknown {
  // Quoted string literal
  const strMatch = raw.match(/^["'](.*)["']$/);
  if (strMatch) {
    return strMatch[1];
  }
  // Otherwise treat as a variable path
  return resolvePath(context, raw);
}

/**
 * Determine if a value is truthy in template terms.
 * Falsy: null, undefined, empty string, empty array, 0, false
 */
function isTruthy(value: unknown): boolean {
  if (value === null || value === undefined) return false;
  if (value === "") return false;
  if (value === 0) return false;
  if (value === false) return false;
  if (Array.isArray(value) && value.length === 0) return false;
  return true;
}

/**
 * Find the matching closing tag for a block, accounting for nesting.
 * Returns the index in the source string right after the closing tag,
 * or -1 if no matching tag is found.
 */
function findMatchingEndTag(
  template: string,
  openTagName: "if" | "for",
  startSearchFrom: number,
): number {
  const endTag = `end${openTagName}`;
  const openPattern = new RegExp(`\\{%[-\\s]\\s*${openTagName}\\b`, "g");
  const closePattern = new RegExp(`\\{%[-\\s]\\s*${endTag}\\s*[-\\s]?%\\}`, "g");

  let depth = 1;
  let pos = startSearchFrom;

  while (depth > 0) {
    openPattern.lastIndex = pos;
    closePattern.lastIndex = pos;

    const nextOpen = openPattern.exec(template);
    const nextClose = closePattern.exec(template);

    if (!nextClose) {
      return -1;
    }

    if (nextOpen && nextOpen.index < nextClose.index) {
      depth++;
      pos = nextOpen.index + nextOpen[0].length;
    } else {
      depth--;
      if (depth === 0) {
        return nextClose.index + nextClose[0].length;
      }
      pos = nextClose.index + nextClose[0].length;
    }
  }

  return -1;
}

/**
 * Given the position right after an end tag, find where the end tag starts.
 */
function findEndTagStart(template: string, endAfterTag: number): number {
  let pos = endAfterTag - 1;
  while (pos >= 0) {
    if (template[pos] === "%" && pos > 0 && template[pos - 1] === "{") {
      return pos - 1;
    }
    pos--;
  }
  return endAfterTag;
}

/**
 * Process block constructs ({% if %} and {% for %}) in a template string.
 * Runs BEFORE {{ }} substitution. Uses recursive descent with a depth cap.
 *
 * Exported for testing.
 */
export function processBlocks(
  template: string,
  context: TemplateContext,
  depth: number = 0,
): string {
  if (depth > MAX_BLOCK_DEPTH) {
    throw new Error(`Template block nesting depth exceeded maximum of ${MAX_BLOCK_DEPTH}`);
  }

  let result = template;

  // Process {% for %} blocks
  result = processForBlocks(result, context, depth);

  // Process {% if %} blocks
  result = processIfBlocks(result, context, depth);

  return result;
}

/**
 * Process all top-level {% for item in list %}...{% endfor %} blocks.
 */
function processForBlocks(template: string, context: TemplateContext, depth: number): string {
  const forOpenPattern = /\{%[-\s]\s*for\s+(\w+)\s+in\s+(.+?)\s*[-\s]?%\}/g;

  let result = "";
  let lastIndex = 0;

  forOpenPattern.lastIndex = 0;
  let match = forOpenPattern.exec(template);

  while (match) {
    result += template.slice(lastIndex, match.index);

    const itemName = match[1];
    const listPath = match[2].trim();
    const bodyStart = match.index + match[0].length;

    const blockEnd = findMatchingEndTag(template, "for", bodyStart);
    if (blockEnd === -1) {
      result += match[0];
      lastIndex = bodyStart;
      forOpenPattern.lastIndex = bodyStart;
      match = forOpenPattern.exec(template);
      continue;
    }

    const bodyContent = template.slice(bodyStart, findEndTagStart(template, blockEnd));
    const listValue = resolvePath(context, listPath);

    if (Array.isArray(listValue) && listValue.length > 0) {
      const parts: string[] = [];
      for (let i = 0; i < listValue.length; i++) {
        const childContext: TemplateContext = {
          ...context,
          [itemName]: listValue[i],
          loop: { index: i + 1 },
        };
        // Recursively process nested blocks, then substitute {{ }} vars
        // using the child context (which has the loop variable and loop.index).
        const processed = processBlocks(bodyContent, childContext, depth + 1);
        parts.push(substituteVars(processed, childContext));
      }
      result += parts.join("");
    }

    lastIndex = blockEnd;
    forOpenPattern.lastIndex = blockEnd;
    match = forOpenPattern.exec(template);
  }

  result += template.slice(lastIndex);
  return result;
}

/**
 * Process all top-level {% if %}...{% elif %}...{% else %}...{% endif %} blocks.
 */
function processIfBlocks(template: string, context: TemplateContext, depth: number): string {
  const ifOpenPattern = /\{%[-\s]\s*if\s+(.+?)\s*[-\s]?%\}/g;

  let result = "";
  let lastIndex = 0;

  ifOpenPattern.lastIndex = 0;
  let match = ifOpenPattern.exec(template);

  while (match) {
    result += template.slice(lastIndex, match.index);

    const condition = match[1];
    const bodyStart = match.index + match[0].length;

    const blockEnd = findMatchingEndTag(template, "if", bodyStart);
    if (blockEnd === -1) {
      result += match[0];
      lastIndex = bodyStart;
      ifOpenPattern.lastIndex = bodyStart;
      match = ifOpenPattern.exec(template);
      continue;
    }

    const fullBlock = template.slice(bodyStart, findEndTagStart(template, blockEnd));
    const branches = splitIfBranches(fullBlock);

    if (evaluateCondition(condition, context)) {
      result += processBlocks(branches[0].body, context, depth + 1);
    } else {
      for (let i = 1; i < branches.length; i++) {
        const branch = branches[i];
        if (branch.type === "elif") {
          if (evaluateCondition(branch.condition!, context)) {
            result += processBlocks(branch.body, context, depth + 1);
            break;
          }
        } else if (branch.type === "else") {
          result += processBlocks(branch.body, context, depth + 1);
          break;
        }
      }
    }

    lastIndex = blockEnd;
    ifOpenPattern.lastIndex = blockEnd;
    match = ifOpenPattern.exec(template);
  }

  result += template.slice(lastIndex);
  return result;
}

interface IfBranch {
  type: "if" | "elif" | "else";
  condition?: string;
  body: string;
}

/**
 * Split the inner content of an if block into branches.
 * Handles nested if blocks correctly by only splitting on top-level elif/else tags.
 */
function splitIfBranches(content: string): IfBranch[] {
  const branches: IfBranch[] = [];

  const tagPattern = /\{%[-\s]\s*(if|elif|else|endif)\b(.*?)\s*[-\s]?%\}/g;

  let depth = 0;
  let currentStart = 0;
  let currentType: "if" | "elif" | "else" = "if";
  let currentCondition: string | undefined;

  tagPattern.lastIndex = 0;
  let tagMatch: RegExpExecArray | null;

  while ((tagMatch = tagPattern.exec(content)) !== null) {
    const tagType = tagMatch[1];
    const tagArgs = tagMatch[2]?.trim();

    if (tagType === "if") {
      depth++;
    } else if (tagType === "endif") {
      depth--;
    } else if (depth === 0 && (tagType === "elif" || tagType === "else")) {
      branches.push({
        type: currentType,
        condition: currentCondition,
        body: content.slice(currentStart, tagMatch.index),
      });

      currentStart = tagMatch.index + tagMatch[0].length;
      currentType = tagType as "elif" | "else";
      currentCondition = tagType === "elif" ? tagArgs : undefined;
    }
  }

  branches.push({
    type: currentType,
    condition: currentCondition,
    body: content.slice(currentStart),
  });

  return branches;
}

/**
 * Validate that all template variables in a template string are present
 * in the context. Returns list of missing variable paths.
 *
 * Block tags are stripped before checking so that variables inside conditional
 * branches that may not be active are not flagged as missing.
 */
export function validateTemplate(template: string, context: TemplateContext): string[] {
  const missing: string[] = [];
  const fullContext: TemplateContext = {
    env: process.env as Record<string, string | undefined>,
    ...context,
  };

  // Strip block tags before checking for missing variables
  const stripped = template.replace(/\{%[-\s].*?[-\s]?%\}/g, "");

  stripped.replace(/\{\{\s*(.+?)\s*\}\}/g, (_match, expr: string) => {
    const pathPart = expr.split("|")[0].trim();
    const value = resolvePath(fullContext, pathPart);
    if (value === undefined) missing.push(pathPart);
    return "";
  });

  return missing;
}
