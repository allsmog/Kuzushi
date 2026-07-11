/**
 * Zod-backed schemas for module manifests + JSON Schema fragments.
 *
 * `JSONSchema` stays a structural alias (`Record<string, unknown>`) because
 * we intentionally accept any object-shaped JSON Schema — tools hand-author
 * these. `zModuleManifest` backs the loader's `validateManifest()` so third
 * parties get structured error reports (issues with paths + messages) they
 * can surface in their tooling.
 */

import { z } from "zod";

/** Shared JSON Schema alias used by option/tool metadata. */
export type JSONSchema = Record<string, unknown>;

/**
 * Loose Zod runtime guard for an object-shaped JSON Schema. We don't try to
 * validate the full JSON Schema dialect — just that it's a non-null object.
 * Tools decide how strictly to parse with their own schemas.
 */
export const zJsonSchema: z.ZodType<JSONSchema> = z
  .record(z.string(), z.unknown())
  .refine((v) => v !== null && typeof v === "object" && !Array.isArray(v), {
    message: "expected a JSON Schema object",
  });

/** Category values accepted in `module.manifest.json`. */
export const zModuleCategory = z.enum(["offense", "defense", "governance", "intel"]);

/** Semver-ish string check — permissive to accept pre-release/build suffixes. */
const zSemverLike = z.string().regex(/^\d+\.\d+\.\d+([-+].+)?$/, {
  message: "expected a semver string (e.g. '0.17.2' or '1.0.0-beta.1')",
});

/** Constraint expression accepted by `kuzushiSdkVersion` — semver or range. */
const zVersionConstraint = z
  .string()
  .min(1)
  .refine((v) => /^([\^~>=<]*\s*)?\d+(\.\d+){0,2}([-+].+)?(\s*\|\|\s*.+)?$/.test(v), {
    message: "expected a semver constraint (e.g. '0.19.0', '>=0.19', '^1.0.0')",
  });

/** Requirements subschema for `module.manifest.json`. */
export const zModuleRequirements = z
  .object({
    env: z.array(z.string()).optional(),
    bins: z.array(z.string()).optional(),
    nodeVersion: z.string().optional(),
  })
  .strict();

/**
 * Zod schema describing a valid `module.manifest.json`. Kept `passthrough`
 * so third parties can add fields the host doesn't parse (they'll survive
 * round-trips through `validateManifest`).
 */
export const zModuleManifest = z
  .object({
    id: z
      .string()
      .min(1)
      .regex(/^[a-z][a-z0-9-]*$/, {
        message: "id must be kebab-case (lowercase letters, digits, and hyphens)",
      }),
    displayName: z.string().min(1),
    version: zSemverLike,
    description: z.string().default(""),
    category: zModuleCategory,
    entry: z.string().min(1),
    requires: zModuleRequirements.optional(),
    configSchema: zJsonSchema.optional(),
    author: z.string().optional(),
    license: z.string().optional(),
    /**
     * Host/SDK version the module was built against. Validated as a
     * semver-constraint-ish string; the loader compares it against the host
     * `kuzushi` package `version` and warns on major-version drift.
     */
    kuzushiSdkVersion: zVersionConstraint.optional(),
  })
  .passthrough();
