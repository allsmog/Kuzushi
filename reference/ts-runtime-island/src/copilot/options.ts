/**
 * Typed option primitives + layered datastore — the msfconsole Opt* / Datastore
 * model, adapted for Kuzushi.
 *
 * Design notes
 *  - Option specs are declarative (`{ type, required, description, default, ... }`)
 *    and render into a `show options` table via `formatOptionsTable()`.
 *  - `Datastore` layers three scopes: global (setg) → workspace → module-local,
 *    with `get()` resolving lowest-to-highest specificity.
 *  - Validation coerces strings to typed values so tools can trust `get()`.
 *  - Every option spec round-trips to a JSONSchema fragment so existing
 *    `inputSchema` declarations stay the source of truth.
 *
 * See lib/msf/core/option_container.rb and lib/msf/core/opt_*.rb for prior art.
 */

import type { JSONSchema } from "../modules/schema.js";
import { wrapToWidth } from "../ui/format.js";

// Option spec

export type OptionType = "string" | "bool" | "int" | "float" | "port" | "address" | "path" | "enum";

export interface OptionSpec<T = unknown> {
  name: string;
  type: OptionType;
  description: string;
  required?: boolean;
  /** Advanced options are hidden by `show options` unless `show advanced` is used. */
  advanced?: boolean;
  /** Evasion options live in `show evasion`. */
  evasion?: boolean;
  default?: T;
  /** Allowed values for `type: "enum"`. */
  choices?: ReadonlyArray<T>;
  /** Optional additional validator returning an error message, or null if ok. */
  validate?(value: T): string | null;
}

/** Factory helpers — sugar for declaring options. */
export const Opt = {
  string(name: string, init: Omit<OptionSpec<string>, "name" | "type">): OptionSpec<string> {
    return { name, type: "string", ...init };
  },
  bool(name: string, init: Omit<OptionSpec<boolean>, "name" | "type">): OptionSpec<boolean> {
    return { name, type: "bool", ...init };
  },
  int(name: string, init: Omit<OptionSpec<number>, "name" | "type">): OptionSpec<number> {
    return { name, type: "int", ...init };
  },
  float(name: string, init: Omit<OptionSpec<number>, "name" | "type">): OptionSpec<number> {
    return { name, type: "float", ...init };
  },
  port(name: string, init: Omit<OptionSpec<number>, "name" | "type">): OptionSpec<number> {
    return { name, type: "port", ...init };
  },
  address(name: string, init: Omit<OptionSpec<string>, "name" | "type">): OptionSpec<string> {
    return { name, type: "address", ...init };
  },
  path(name: string, init: Omit<OptionSpec<string>, "name" | "type">): OptionSpec<string> {
    return { name, type: "path", ...init };
  },
  enum<T extends string>(
    name: string,
    init: Omit<OptionSpec<T>, "name" | "type"> & { choices: ReadonlyArray<T> },
  ): OptionSpec<T> {
    return { name, type: "enum", ...init };
  },
};

// Coercion + validation

export interface CoerceResult<T = unknown> {
  ok: boolean;
  value?: T;
  error?: string;
}

const TRUE_STRINGS = new Set(["true", "t", "yes", "y", "1", "on"]);
const FALSE_STRINGS = new Set(["false", "f", "no", "n", "0", "off"]);

/** Coerce a raw string (from CLI/`set`) into the option's typed value. */
export function coerceOption<T>(spec: OptionSpec<T>, raw: string): CoerceResult<T> {
  const err = (m: string): CoerceResult<T> => ({ ok: false, error: m });

  switch (spec.type) {
    case "string":
    case "path":
    case "address":
      return { ok: true, value: raw as unknown as T };
    case "bool": {
      const lower = raw.trim().toLowerCase();
      if (TRUE_STRINGS.has(lower)) return { ok: true, value: true as unknown as T };
      if (FALSE_STRINGS.has(lower)) return { ok: true, value: false as unknown as T };
      return err(`expected boolean (true/false/yes/no/1/0), got "${raw}"`);
    }
    case "int": {
      if (!/^-?\d+$/.test(raw.trim())) return err(`expected integer, got "${raw}"`);
      return { ok: true, value: Number.parseInt(raw, 10) as unknown as T };
    }
    case "float": {
      const n = Number.parseFloat(raw);
      if (Number.isNaN(n)) return err(`expected number, got "${raw}"`);
      return { ok: true, value: n as unknown as T };
    }
    case "port": {
      if (!/^\d+$/.test(raw.trim())) return err(`expected port 1-65535, got "${raw}"`);
      const n = Number.parseInt(raw, 10);
      if (n < 1 || n > 65535) return err(`port out of range (1-65535): ${n}`);
      return { ok: true, value: n as unknown as T };
    }
    case "enum": {
      if (!spec.choices?.includes(raw as unknown as T)) {
        return err(`expected one of ${spec.choices?.join("|")}, got "${raw}"`);
      }
      return { ok: true, value: raw as unknown as T };
    }
    default:
      return err(`unsupported option type: ${spec.type}`);
  }
}

/** Validate an already-typed value against a spec (custom validator + choices). */
export function validateOption<T>(spec: OptionSpec<T>, value: T): string | null {
  if (spec.type === "enum" && !spec.choices?.includes(value)) {
    return `expected one of ${spec.choices?.join("|")}, got "${String(value)}"`;
  }
  return spec.validate?.(value) ?? null;
}

// JSONSchema bridge

/** Convert an OptionSpec list into a JSONSchema `object` (for ModuleTool.inputSchema). */
export function optionsToJsonSchema(opts: ReadonlyArray<OptionSpec>): JSONSchema {
  const properties: Record<string, JSONSchema> = {};
  const required: string[] = [];

  for (const opt of opts) {
    const prop: Record<string, unknown> = { description: opt.description };
    switch (opt.type) {
      case "string":
      case "path":
      case "address":
        prop["type"] = "string";
        break;
      case "bool":
        prop["type"] = "boolean";
        break;
      case "int":
        prop["type"] = "integer";
        break;
      case "float":
        prop["type"] = "number";
        break;
      case "port":
        prop["type"] = "integer";
        prop["minimum"] = 1;
        prop["maximum"] = 65535;
        break;
      case "enum":
        prop["type"] = "string";
        if (opt.choices) prop["enum"] = [...opt.choices];
        break;
    }
    if (opt.default !== undefined) prop["default"] = opt.default;
    properties[opt.name] = prop as JSONSchema;
    if (opt.required) required.push(opt.name);
  }

  const schema: Record<string, unknown> = { type: "object", properties };
  if (required.length > 0) schema["required"] = required;
  return schema as JSONSchema;
}

// Layered datastore

export type DatastoreScope = "module" | "workspace" | "global";

/**
 * Three-layer key/value store. Resolution order (highest precedence first):
 *   module → workspace → global → spec.default.
 *
 * `set(scope="module")` is the shell's `set` command; `set(scope="global")`
 * is `setg`. Keys are case-insensitive (normalized to UPPER).
 */
export class Datastore {
  private readonly layers: Record<DatastoreScope, Map<string, unknown>> = {
    module: new Map(),
    workspace: new Map(),
    global: new Map(),
  };

  private readonly specs = new Map<string, OptionSpec>();

  constructor(specs: ReadonlyArray<OptionSpec> = []) {
    for (const spec of specs) this.registerOption(spec);
  }

  /** Register (or replace) an option spec. */
  registerOption(spec: OptionSpec): void {
    this.specs.set(spec.name.toUpperCase(), spec as OptionSpec);
  }

  /** Replace all specs (used when `use`-ing a new module). */
  replaceSpecs(specs: ReadonlyArray<OptionSpec>): void {
    this.specs.clear();
    this.layers.module.clear();
    for (const spec of specs) this.registerOption(spec);
  }

  /** Known spec for a name (case-insensitive). */
  spec(name: string): OptionSpec | undefined {
    return this.specs.get(name.toUpperCase());
  }

  /** All registered specs. */
  allSpecs(): OptionSpec[] {
    return [...this.specs.values()].sort((a, b) => a.name.localeCompare(b.name));
  }

  /**
   * Get the resolved value for a key. Returns undefined if unset at every layer
   * and the spec has no `default`.
   */
  get<T = unknown>(name: string): T | undefined {
    const key = name.toUpperCase();
    for (const scope of ["module", "workspace", "global"] as const) {
      const v = this.layers[scope].get(key);
      if (v !== undefined) return v as T;
    }
    const spec = this.specs.get(key);
    return spec?.default as T | undefined;
  }

  /**
   * Whether any layer has an explicit value for the key (i.e. `whence` is
   * not "default" or "unset"). Doesn't consult `OptionSpec.default`, so this
   * is a true "was it set by set/setg" check. Satisfies `ToolOptionStore.has`
   * (see src/modules/host-handles.ts).
   */
  has(name: string): boolean {
    const key = name.toUpperCase();
    for (const scope of ["module", "workspace", "global"] as const) {
      if (this.layers[scope].has(key)) return true;
    }
    return false;
  }

  /** Which scope currently holds the resolved value (or "default" / "unset"). */
  whence(name: string): DatastoreScope | "default" | "unset" {
    const key = name.toUpperCase();
    for (const scope of ["module", "workspace", "global"] as const) {
      if (this.layers[scope].has(key)) return scope;
    }
    const spec = this.specs.get(key);
    return spec?.default !== undefined ? "default" : "unset";
  }

  /**
   * Parse + coerce + validate a raw string, then store at the given scope.
   * Returns null on success or an error message on failure.
   */
  set(name: string, raw: string, scope: DatastoreScope = "module"): string | null {
    const key = name.toUpperCase();
    const spec = this.specs.get(key);
    if (!spec) {
      // No spec — accept as opaque string; most users expect `set FOO bar` to work.
      this.layers[scope].set(key, raw);
      return null;
    }
    const coerced = coerceOption(spec, raw);
    if (!coerced.ok) return coerced.error ?? "invalid value";
    const err = validateOption(spec, coerced.value as never);
    if (err) return err;
    this.layers[scope].set(key, coerced.value);
    return null;
  }

  /** Remove a key from a specific scope (or all scopes when "all"). */
  unset(name: string, scope: DatastoreScope | "all" = "module"): void {
    const key = name.toUpperCase();
    if (scope === "all") {
      for (const s of ["module", "workspace", "global"] as const) this.layers[s].delete(key);
    } else {
      this.layers[scope].delete(key);
    }
  }

  /** Missing-but-required option names. */
  missingRequired(): string[] {
    return this.allSpecs()
      .filter((s) => s.required && this.get(s.name) === undefined)
      .map((s) => s.name);
  }

  /** Snapshot of all current values (post-resolution). */
  snapshot(): Record<string, unknown> {
    const out: Record<string, unknown> = {};
    const knownSpecKeys = new Set(this.allSpecs().map((spec) => spec.name.toUpperCase()));
    for (const spec of this.allSpecs()) {
      const v = this.get(spec.name);
      if (v !== undefined) out[spec.name] = v;
    }
    // Include unknown-but-set keys from any layer
    for (const scope of ["module", "workspace", "global"] as const) {
      for (const [k, v] of this.layers[scope]) {
        if (knownSpecKeys.has(k)) continue;
        if (!(k in out)) out[k] = v;
      }
    }
    return out;
  }
}

// `show options` renderer

export interface FormatOptionsOpts {
  advanced?: boolean;
  evasion?: boolean;
  /** If true, mark missing-required rows with a leading "*". */
  highlightMissing?: boolean;
  /**
   * Target width in columns for the rendered table. Descriptions that would
   * overflow this width are word-wrapped into continuation lines aligned
   * under the Description column. Defaults to `process.stdout.columns` or
   * 100 if the terminal width is unavailable.
   */
  availableWidth?: number;
}

/** Render a `show options`-style table. Returns a string (multi-line). */
export function formatOptionsTable(store: Datastore, opts: FormatOptionsOpts = {}): string {
  const include = (s: OptionSpec): boolean => {
    if (opts.advanced) return Boolean(s.advanced);
    if (opts.evasion) return Boolean(s.evasion);
    return !s.advanced && !s.evasion;
  };

  const rows = store
    .allSpecs()
    .filter(include)
    .map((spec) => {
      const value = store.get(spec.name);
      const required = spec.required ? "yes" : "no";
      const missing = spec.required && value === undefined;
      const current =
        value === undefined ? "" : typeof value === "string" ? value : JSON.stringify(value);
      return {
        name: spec.name + (opts.highlightMissing && missing ? " *" : ""),
        current,
        required,
        description: spec.description,
      };
    });

  if (rows.length === 0) return "  (no options)";

  const pad = (s: string, w: number): string => s + " ".repeat(Math.max(0, w - s.length));
  const widths = {
    name: Math.max(4, ...rows.map((r) => r.name.length)),
    current: Math.max(15, ...rows.map((r) => r.current.length)),
    required: Math.max(8, ...rows.map((r) => r.required.length)),
  };

  // Column start offset for the Description cell (in total visible columns).
  // Leading 2-space indent + 3 cells each followed by 2-space gap.
  const descStart = 2 + widths.name + 2 + widths.current + 2 + widths.required + 2;
  const availableWidth = opts.availableWidth ?? process.stdout?.columns ?? 100;
  // Reserve a 1-column safety margin so terminal output does not wrap on its own.
  // Enforce a 20-column minimum so descriptions stay readable on narrow shells
  // (a shorter column produces extreme single-word stacks that look worse than
  // a mild right-overflow).
  const descWidth = Math.max(20, availableWidth - descStart - 1);

  const header = `  ${pad("Name", widths.name)}  ${pad("Current Setting", widths.current)}  ${pad("Required", widths.required)}  Description`;
  const sep = `  ${"-".repeat(widths.name)}  ${"-".repeat(widths.current)}  ${"-".repeat(widths.required)}  -----------`;
  const contPad = " ".repeat(descStart);
  const body = rows
    .map((r) => {
      const descLines = wrapToWidth(r.description, descWidth);
      const first = descLines[0] ?? "";
      const rest = descLines.slice(1);
      const leader = `  ${pad(r.name, widths.name)}  ${pad(r.current, widths.current)}  ${pad(r.required, widths.required)}  ${first}`;
      return [leader, ...rest.map((l) => `${contPad}${l}`)].join("\n");
    })
    .join("\n");

  return [header, sep, body].join("\n");
}
