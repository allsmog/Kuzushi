/**
 * `kuzushi create-module <id>` scaffolder.
 *
 * Generates a minimal but runnable CopilotModule project directory:
 *
 *   <id>/
 *     module.manifest.json     — Kuzushi module manifest (entry + requires)
 *     package.json             — npm manifest with vitest + tsc scripts
 *     tsconfig.json            — strict TS config targeting ES2022
 *     src/index.ts             — CopilotModule export with one starter tool
 *     src/index.test.ts        — vitest test invoking the starter tool
 *     README.md                — usage instructions
 *
 * Three category templates:
 *   - offense: starter tool framed as a recon/scanner action
 *   - defense: starter tool framed as a honeypot/monitor action
 *   - intel:   starter tool framed as an intel/lookup action
 */

import { existsSync, mkdirSync, writeFileSync } from "node:fs";
import path from "node:path";

export type ModuleTemplate = "offense" | "defense" | "intel";

const VALID_TEMPLATES: ReadonlySet<ModuleTemplate> = new Set(["offense", "defense", "intel"]);

export function isValidTemplate(value: string): value is ModuleTemplate {
  return VALID_TEMPLATES.has(value as ModuleTemplate);
}

export interface CreateModuleOptions {
  id: string;
  template: ModuleTemplate;
  targetDir: string;
  force?: boolean;
}

export interface CreateModuleResult {
  /** Absolute path to the created module directory. */
  moduleDir: string;
  /** Relative-to-cwd files written. */
  files: string[];
}

export function createModule(options: CreateModuleOptions): CreateModuleResult {
  const { id, template, targetDir, force } = options;
  if (!/^[a-z][a-z0-9-]*$/.test(id)) {
    throw new Error(
      `Invalid module id "${id}". Use lowercase letters, digits, and hyphens; start with a letter.`,
    );
  }
  if (!isValidTemplate(template)) {
    throw new Error(`Invalid template "${template}". Valid options: offense, defense, intel.`);
  }

  const moduleDir = path.resolve(targetDir, id);
  if (existsSync(moduleDir) && !force) {
    throw new Error(`Target directory already exists: ${moduleDir}. Use --force to overwrite.`);
  }
  mkdirSync(path.join(moduleDir, "src"), { recursive: true });

  const files: string[] = [];
  const write = (relPath: string, content: string): void => {
    const abs = path.join(moduleDir, relPath);
    mkdirSync(path.dirname(abs), { recursive: true });
    writeFileSync(abs, content, "utf-8");
    files.push(path.relative(process.cwd(), abs));
  };

  write("module.manifest.json", manifestFor(id, template));
  write("package.json", packageJsonFor(id));
  write("tsconfig.json", tsconfigFor());
  write("src/index.ts", starterTsFor(id, template));
  write("src/index.test.ts", starterTestFor(id, template));
  write("README.md", readmeFor(id, template));

  return { moduleDir, files };
}

function manifestFor(id: string, template: ModuleTemplate): string {
  const category = template;
  return (
    JSON.stringify(
      {
        id,
        displayName: toTitle(id),
        version: "0.1.0",
        description: `${toTitle(id)} — ${categoryBlurb(template)} module`,
        category,
        entry: "./dist/index.js",
        requires: { nodeVersion: ">=22" },
      },
      null,
      2,
    ) + "\n"
  );
}

function packageJsonFor(id: string): string {
  return (
    JSON.stringify(
      {
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
          kuzushi: "latest",
          typescript: "^5.7.0",
          vitest: "^3.0.0",
        },
        peerDependencies: {
          kuzushi: ">=0.17.0",
        },
      },
      null,
      2,
    ) + "\n"
  );
}

function tsconfigFor(): string {
  return (
    JSON.stringify(
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
    ) + "\n"
  );
}

function starterTsFor(id: string, template: ModuleTemplate): string {
  const { toolSuffix, description, defaultTarget } = templateData(template);
  const toolName = `${id}:${toolSuffix}`;
  return `import type {
  CopilotModule,
  ModuleTool,
  ToolExecutionContext,
  ToolResult,
} from "kuzushi/modules";

const ${camel(toolSuffix)}Tool: ModuleTool = {
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
  },
  headless: true,
  async execute(input: unknown, ctx: ToolExecutionContext): Promise<ToolResult> {
    const params = (input ?? {}) as Record<string, unknown>;
    const target = (params.target as string) ?? ctx.target ?? ctx.cwd;

    // TODO: implement the real action. This starter returns a synthetic result
    // so the tool is callable end-to-end from \`kuzushi run ${toolName} target=...\`
    // the moment you build and link the module.
    return {
      ok: true,
      output: \`${toolName}: hello from \${target}\`,
      data: { target },
    };
  },
};

const mod: CopilotModule = {
  id: "${id}",
  displayName: "${toTitle(id)}",
  category: "${template}",
  version: "0.1.0",
  description: "${toTitle(id)} — ${categoryBlurb(template)} module (generated by kuzushi create-module).",
  tools: [${camel(toolSuffix)}Tool],
};

export default mod;
`;
}

function starterTestFor(id: string, template: ModuleTemplate): string {
  const { toolSuffix } = templateData(template);
  const toolName = `${id}:${toolSuffix}`;
  return `import { describe, expect, it } from "vitest";
import { createMockToolContext } from "kuzushi/testing";
import mod from "./index.js";

describe("${id} module", () => {
  it("exposes the expected metadata", () => {
    expect(mod.id).toBe("${id}");
    expect(mod.tools.map((t) => t.name)).toContain("${toolName}");
  });

  it("runs the starter tool end-to-end with a mocked context", async () => {
    const tool = mod.tools.find((t) => t.name === "${toolName}")!;
    const ctx = createMockToolContext({ target: "/tmp/fixture" });
    const result = await tool.execute({ target: "/tmp/fixture" }, ctx);
    expect(result.ok).toBe(true);
    expect(result.output).toContain("/tmp/fixture");
  });
});
`;
}

function readmeFor(id: string, template: ModuleTemplate): string {
  const { toolSuffix } = templateData(template);
  return `# ${toTitle(id)}

${categoryBlurb(template)} module for Kuzushi.

## Develop

\`\`\`bash
pnpm install
pnpm build
pnpm test
\`\`\`

## Try it

\`\`\`bash
kuzushi run ${id}:${toolSuffix} target=./ --load file://$(pwd)
\`\`\`

Edit \`src/index.ts\` to implement the real tool body. Add more tools by
appending to the \`tools\` array in the default export.
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
