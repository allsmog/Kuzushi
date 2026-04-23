/**
 * `kuzushi create-module <id>` scaffolder.
 *
 * Generates a minimal but runnable CopilotModule project directory:
 *
 *   <id>/
 *     module.manifest.json     — Kuzushi manifest with kuzushiSdkVersion + $schema
 *     package.json             — npm manifest pinning kuzushi as a peer-dep
 *     tsconfig.json            — strict TS config targeting ES2022
 *     src/index.ts             — defineModule + defineTool starter
 *     src/index.test.ts        — vitest using kuzushi/testing helpers
 *     README.md                — usage instructions
 *
 * The emitted manifest references the published JSON schema so editors get
 * autocomplete and inline validation. The emitted module uses `defineModule`
 * and `defineTool<"id">` so the tool-name prefix is enforced at compile time,
 * mirroring core-sast.ts as the canonical reference.
 */

import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

export type ModuleTemplate = "offense" | "defense" | "intel";
export type ScaffoldRank = "manual" | "low" | "normal" | "good" | "great" | "excellent";

const VALID_TEMPLATES: ReadonlySet<ModuleTemplate> = new Set(["offense", "defense", "intel"]);
const VALID_RANKS: ReadonlySet<ScaffoldRank> = new Set([
  "manual",
  "low",
  "normal",
  "good",
  "great",
  "excellent",
]);

const DEFAULT_SCHEMA_URL =
  "https://raw.githubusercontent.com/allsmog/Kuzushi/main/schemas/module.manifest.schema.json";

export function isValidTemplate(value: string): value is ModuleTemplate {
  return VALID_TEMPLATES.has(value as ModuleTemplate);
}

export function isValidRank(value: string): value is ScaffoldRank {
  return VALID_RANKS.has(value as ScaffoldRank);
}

export interface CreateModuleOptions {
  id: string;
  template: ModuleTemplate;
  targetDir: string;
  force?: boolean;
  /** Optional rank for the generated module. Defaults to `"normal"`. */
  rank?: ScaffoldRank;
  /** Override `$schema` URL in the generated manifest. */
  schemaUrl?: string;
  /** Omit `peerDependencies.kuzushi` in the generated package.json. */
  skipPeerDeps?: boolean;
  /**
   * Pin of the host `kuzushi` package. When omitted, the scaffolder reads the
   * installed `kuzushi/package.json` at runtime. Exposed for tests.
   */
  hostVersion?: string;
}

export interface CreateModuleResult {
  /** Absolute path to the created module directory. */
  moduleDir: string;
  /** Relative-to-cwd files written. */
  files: string[];
}

export function createModule(options: CreateModuleOptions): CreateModuleResult {
  const { id, template, targetDir, force, rank, schemaUrl, skipPeerDeps } = options;
  if (!/^[a-z][a-z0-9-]*$/.test(id)) {
    throw new Error(
      `Invalid module id "${id}". Use lowercase letters, digits, and hyphens; start with a letter.`,
    );
  }
  if (!isValidTemplate(template)) {
    throw new Error(`Invalid template "${template}". Valid options: offense, defense, intel.`);
  }
  if (rank !== undefined && !isValidRank(rank)) {
    throw new Error(
      `Invalid rank "${rank}". Valid options: manual, low, normal, good, great, excellent.`,
    );
  }

  const moduleDir = path.resolve(targetDir, id);
  if (existsSync(moduleDir) && !force) {
    throw new Error(`Target directory already exists: ${moduleDir}. Use --force to overwrite.`);
  }
  mkdirSync(path.join(moduleDir, "src"), { recursive: true });

  const hostVersion = options.hostVersion ?? readHostVersion();
  const resolvedRank: ScaffoldRank = rank ?? "normal";
  const resolvedSchema = schemaUrl ?? DEFAULT_SCHEMA_URL;

  const files: string[] = [];
  const write = (relPath: string, content: string): void => {
    const abs = path.join(moduleDir, relPath);
    mkdirSync(path.dirname(abs), { recursive: true });
    writeFileSync(abs, content, "utf-8");
    files.push(path.relative(process.cwd(), abs));
  };

  write("module.manifest.json", manifestFor(id, template, hostVersion, resolvedSchema));
  write("package.json", packageJsonFor(id, hostVersion, { skipPeerDeps: skipPeerDeps === true }));
  write("tsconfig.json", tsconfigFor());
  write("src/index.ts", starterTsFor(id, template, resolvedRank));
  write("src/index.test.ts", starterTestFor(id, template));
  write("README.md", readmeFor(id, template));

  return { moduleDir, files };
}

function manifestFor(
  id: string,
  template: ModuleTemplate,
  hostVersion: string,
  schemaUrl: string,
): string {
  const category = template;
  return `${JSON.stringify(
    {
      $schema: schemaUrl,
      id,
      displayName: toTitle(id),
      version: "0.1.0",
      description: `${toTitle(id)} — ${categoryBlurb(template)} module`,
      category,
      entry: "./dist/index.js",
      kuzushiSdkVersion: hostVersion,
      requires: { nodeVersion: ">=22" },
    },
    null,
    2,
  )}\n`;
}

function packageJsonFor(id: string, hostVersion: string, opts: { skipPeerDeps: boolean }): string {
  const caretPin = `^${hostVersion}`;
  const pkg: Record<string, unknown> = {
    name: id,
    version: "0.1.0",
    type: "module",
    main: "./dist/index.js",
    types: "./dist/index.d.ts",
    scripts: {
      build: "tsc",
      test: "vitest run",
    },
    devDependencies: {
      "@types/node": "^22",
      kuzushi: hostVersion,
      typescript: "^5.7.0",
      vitest: "^3.0.0",
    },
  };
  if (!opts.skipPeerDeps) {
    pkg.peerDependencies = { kuzushi: caretPin };
    pkg.peerDependenciesMeta = { kuzushi: { optional: false } };
  }
  return `${JSON.stringify(pkg, null, 2)}\n`;
}

function tsconfigFor(): string {
  return `${JSON.stringify(
    {
      compilerOptions: {
        target: "ES2022",
        module: "ES2022",
        moduleResolution: "bundler",
        strict: true,
        declaration: true,
        outDir: "./dist",
        rootDir: "./src",
        esModuleInterop: true,
        resolveJsonModule: true,
        skipLibCheck: true,
      },
      include: ["src/**/*.ts"],
      exclude: ["dist", "node_modules", "src/**/*.test.ts"],
    },
    null,
    2,
  )}\n`;
}

function starterTsFor(id: string, template: ModuleTemplate, rank: ScaffoldRank): string {
  const { toolSuffix, description, defaultTarget } = templateData(template);
  const toolName = `${id}:${toolSuffix}`;
  const toolVar = `${camel(toolSuffix)}Tool`;
  return `import { defineModule, defineTool } from "kuzushi/modules";
import type { ExecutionContext, ToolResult } from "kuzushi/modules";

/**
 * ${description}
 *
 * \`headless: true\` means this tool is safe to dispatch from \`kuzushi run\`
 * and pipeline mode — no TTY, no stdin prompts, no interactive subprocess
 * attach. If you add user-interaction to this tool, flip the flag.
 */
const ${toolVar} = defineTool<"${id}">({
  name: "${toolName}",
  description: "${description}",
  inputSchema: {
    type: "object",
    properties: {
      target: {
        type: "string",
        description: "${defaultTarget}",
      },
    },
    required: ["target"],
  },
  headless: true,
  async execute(input: unknown, ctx: ExecutionContext): Promise<ToolResult> {
    const params = (input ?? {}) as Record<string, unknown>;
    const target = (params.target as string) ?? ctx.target ?? ctx.cwd;

    ctx.reportActivity?.(\`${toolName}: starting on \${target}\`);
    ctx.logger?.info?.("${toolName} invoked", { target, sdk: ctx.host?.sdkVersion });

    // Capability probe — adapt behavior when the host provides a workspace.
    if (ctx.host?.capabilities.has("workspace")) {
      ctx.logger?.debug?.("workspace capability available", {
        workspaceId: ctx.workspaceId,
      });
    }

    return {
      ok: true,
      output: \`${toolName}: hello from \${target}\`,
      data: { target },
    };
  },
});

export default defineModule({
  id: "${id}",
  displayName: "${toTitle(id)}",
  category: "${template}",
  version: "0.1.0",
  rank: "${rank}",
  description:
    "${toTitle(id)} — ${categoryBlurb(template)} module (generated by kuzushi create-module).",
  tools: [${toolVar}],
});
`;
}

function starterTestFor(id: string, template: ModuleTemplate): string {
  const { toolSuffix } = templateData(template);
  const toolName = `${id}:${toolSuffix}`;
  return `import { describe, expect, it } from "vitest";
import {
  assertToolResult,
  createMockToolContext,
  expectModuleShape,
} from "kuzushi/testing";
import mod from "./index.js";

describe("${id} module", () => {
  it("validates against the CopilotModule contract", () => {
    expectModuleShape(mod);
  });

  it("exposes the expected metadata", () => {
    expect(mod.id).toBe("${id}");
    expect(mod.tools.map((t) => t.name)).toContain("${toolName}");
  });

  it("runs the starter tool end-to-end with a mocked context", async () => {
    const tool = mod.tools.find((t) => t.name === "${toolName}")!;
    const ctx = createMockToolContext({ target: "/tmp/fixture" });
    const result = await tool.execute({ target: "/tmp/fixture" }, ctx);
    assertToolResult(result, {
      ok: true,
      outputContains: "/tmp/fixture",
    });
  });
});
`;
}

function readmeFor(id: string, template: ModuleTemplate): string {
  const { toolSuffix } = templateData(template);
  return `# ${toTitle(id)}

${categoryBlurb(template)} module for Kuzushi. Generated by \`kuzushi create-module\`.

## Develop

\`\`\`bash
pnpm install
pnpm build
pnpm test
\`\`\`

## Try it

\`\`\`bash
# Interactive shell with this module loaded
kuzushi shell --load file://$(pwd)

# Headless single-tool dispatch
kuzushi run ${id}:${toolSuffix} --input '{"target":"./"}' --load file://$(pwd)
\`\`\`

## Customize me

1. Rename the module id if you haven't already (\`module.manifest.json\` + \`src/index.ts\`).
2. Expand \`tool.inputSchema\` to match your real arguments.
3. Implement \`tool.execute(input, ctx)\` — the context gives you a
   \`runtime\`, \`bus\`, \`workspace\`, \`datastore\`, \`logger\`, and capability
   probe via \`ctx.host.capabilities.has(...)\`.
4. Add more tools by calling \`defineTool<"${id}">({...})\` and pushing into
   the \`tools\` array.
5. Implement \`init()\` / \`dispose()\` if you need to validate credentials or
   hold long-lived connections.

See the full authoring guide at
https://github.com/allsmog/Kuzushi/blob/main/docs/modules.md.
`;
}

interface TemplateData {
  toolSuffix: string;
  description: string;
  defaultTarget: string;
}

function templateData(template: ModuleTemplate): TemplateData {
  switch (template) {
    case "offense":
      return {
        toolSuffix: "recon",
        description:
          "Run reconnaissance against the target. Returns a structured finding list with severity + evidence.",
        defaultTarget: "Host or repo path to recon (defaults to ctx.target/ctx.cwd).",
      };
    case "defense":
      return {
        toolSuffix: "monitor",
        description:
          "Deploy/refresh a detection or monitor against the target. Returns a status report.",
        defaultTarget: "Environment or resource to monitor (defaults to ctx.target/ctx.cwd).",
      };
    case "intel":
      return {
        toolSuffix: "lookup",
        description:
          "Query the intel store for context about the target. Returns matched documents and score.",
        defaultTarget: "Entity to look up (defaults to ctx.target/ctx.cwd).",
      };
  }
}

function categoryBlurb(template: ModuleTemplate): string {
  switch (template) {
    case "offense":
      return "offensive security";
    case "defense":
      return "defensive / detection";
    case "intel":
      return "intel / knowledge";
  }
}

function toTitle(id: string): string {
  return id
    .split("-")
    .map((part) => (part ? part[0].toUpperCase() + part.slice(1) : part))
    .join(" ");
}

function camel(slug: string): string {
  return slug
    .split("-")
    .map((p, i) => (i === 0 ? p : p[0].toUpperCase() + p.slice(1)))
    .join("");
}

/**
 * Read the host `kuzushi` package version. Walks upward from this file's
 * location to find a `package.json` with `name === "kuzushi"`. Falls back
 * to `"0.0.0"` only if the walk fails (e.g. in a pathological bundle).
 */
function readHostVersion(): string {
  const here = fileURLToPath(import.meta.url);
  let dir = path.dirname(here);
  for (let depth = 0; depth < 8; depth++) {
    const candidate = path.join(dir, "package.json");
    if (existsSync(candidate)) {
      try {
        const pkg = JSON.parse(readFileSync(candidate, "utf-8")) as {
          name?: string;
          version?: string;
        };
        if (pkg.name === "kuzushi" && typeof pkg.version === "string") {
          return pkg.version;
        }
      } catch {
        // ignore parse errors and keep walking
      }
    }
    const parent = path.dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  return "0.0.0";
}
