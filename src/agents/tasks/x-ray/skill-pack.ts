import { existsSync, readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { toErrorMessage } from "../../../utils.js";
export type XRayRuntimeMode = "claude" | "pi-ai" | "codex";

export interface XRaySkillPack {
  pluginRoot: string;
  skillDir: string;
  skillPath: string;
  version: string;
  skillMarkdown: string;
  templatesMarkdown: string;
  threatsMarkdown: string;
  attributionPath: string;
}

export interface XRayPromptParts {
  runtimeMode: XRayRuntimeMode;
  prompt: string;
  systemPromptPrefix?: string;
  plugins?: Array<{ type: "local"; path: string }>;
}

export interface BuildXRayPromptParams {
  runtimeMode: XRayRuntimeMode;
  targetRoot: string;
  repoName: string;
  skillPack?: XRaySkillPack;
}

export function loadXRaySkillPack(): XRaySkillPack {
  const pluginRoot = resolveXRayPluginRoot();
  const skillDir = path.join(pluginRoot, "skills", "x-ray");
  const skillPath = path.join(skillDir, "SKILL.md");
  const templatesPath = path.join(skillDir, "references", "templates.md");
  const threatsPath = path.join(skillDir, "references", "threats.md");
  const versionPath = path.join(skillDir, "VERSION");
  const attributionPath = path.join(pluginRoot, "ATTRIBUTION.md");

  return {
    pluginRoot,
    skillDir,
    skillPath,
    version: readText(versionPath).trim(),
    skillMarkdown: readText(skillPath),
    templatesMarkdown: readText(templatesPath),
    threatsMarkdown: readText(threatsPath),
    attributionPath,
  };
}

export function buildXRayPrompt(params: BuildXRayPromptParams): XRayPromptParts {
  const skillPack = params.skillPack ?? loadXRaySkillPack();
  const targetRoot = path.resolve(params.targetRoot);
  const artifactDir = path.join(targetRoot, "x-ray");

  if (params.runtimeMode === "claude") {
    return {
      runtimeMode: "claude",
      plugins: [{ type: "local", path: skillPack.pluginRoot }],
      prompt: [
        `Use the loaded /pashov-xray:x-ray plugin skill to generate an X-Ray report for ${params.repoName}.`,
        "",
        `Target repository: ${targetRoot}`,
        `Vendored skill directory: ${skillPack.skillDir}`,
        `Write artifacts only under: ${artifactDir}`,
        "",
        "Required artifacts:",
        "- x-ray/x-ray.md",
        "- x-ray/entry-points.md",
        "- x-ray/invariants.md",
        "- x-ray/architecture.svg",
        "",
        "After the skill finishes, respond with a short completion summary and the artifact paths.",
      ].join("\n"),
    };
  }

  const systemPromptPrefix = buildPortableXRaySystemPrompt(params.runtimeMode, skillPack);
  return {
    runtimeMode: params.runtimeMode,
    systemPromptPrefix,
    prompt: [
      `Run the vendored Pashov X-Ray skill pack against ${params.repoName}.`,
      "",
      `Target repository: ${targetRoot}`,
      `Project root to analyze: ${targetRoot}`,
      `Artifact directory: ${artifactDir}`,
      `Resolved $SKILL_DIR: ${skillPack.skillDir}`,
      "",
      "Create the artifact directory if missing and produce these required files:",
      "- x-ray/x-ray.md",
      "- x-ray/entry-points.md",
      "- x-ray/invariants.md",
      "- x-ray/architecture.svg",
      "",
      "Do not write outside the x-ray artifact directory. Keep final output short; the harness validates the files.",
    ].join("\n"),
  };
}

export function buildPortableXRaySystemPrompt(
  runtimeMode: Exclude<XRayRuntimeMode, "claude">,
  skillPack: XRaySkillPack,
): string {
  return [
    "# Vendored Pashov X-Ray Skill Pack",
    "",
    `Source: https://github.com/pashov/skills/tree/main/x-ray`,
    `Local $SKILL_DIR: ${skillPack.skillDir}`,
    `Vendored VERSION: ${skillPack.version}`,
    "",
    "## Runtime Adapter",
    "",
    buildRuntimeAdapterText(runtimeMode),
    "",
    "## SKILL.md",
    "",
    "```markdown",
    skillPack.skillMarkdown.trim(),
    "```",
    "",
    "## references/templates.md",
    "",
    "```markdown",
    skillPack.templatesMarkdown.trim(),
    "```",
    "",
    "## references/threats.md",
    "",
    "```markdown",
    skillPack.threatsMarkdown.trim(),
    "```",
  ].join("\n");
}

export function buildRuntimeAdapterText(runtimeMode: Exclude<XRayRuntimeMode, "claude">): string {
  if (runtimeMode === "pi-ai") {
    return [
      "You are not Claude Code, so the X-Ray skill is provided inline instead of by a native plugin.",
      "Compatibility tools named TodoWrite and Task are available.",
      "Use TodoWrite exactly where SKILL.md asks for it.",
      "Use Task only for bounded read-only sub-analysis; the harness may reject writes from Task.",
      "Use only the deterministic filesystem, grep, git, coverage, and local script commands needed by the skill.",
    ].join("\n");
  }

  return [
    "You are running through the Kuzushi Codex adapter, which currently does not load native skill/plugin paths.",
    "Treat every SKILL.md TodoWrite instruction as inline progress tracking in your own response stream; do not call a TodoWrite tool.",
    "Treat every SKILL.md Task or subagent instruction as sequential sub-analysis in this same agent; do not call a Task tool.",
    "Where SKILL.md asks for parallel calls or same-message launches, perform the steps sequentially while preserving the output contract.",
    "Use command/file capabilities only to read the target repo, run deterministic local enumeration, and write final x-ray artifacts.",
  ].join("\n");
}

export function detectXRayRuntimeMode(runtimeId: string): XRayRuntimeMode {
  const normalized = runtimeId.trim().toLowerCase();
  if (normalized.includes("claude") || normalized.includes("anthropic")) return "claude";
  if (normalized === "pi-ai" || normalized.includes("pi-ai")) return "pi-ai";
  return "codex";
}

function resolveXRayPluginRoot(): string {
  const here = path.dirname(fileURLToPath(import.meta.url));
  const candidates = [
    path.resolve(here, "../../../../assets/pashov-xray"),
    path.resolve(process.cwd(), "assets/pashov-xray"),
  ];

  for (const candidate of candidates) {
    if (existsSync(path.join(candidate, ".claude-plugin", "plugin.json"))) {
      return candidate;
    }
  }

  throw new Error(
    `Unable to locate vendored Pashov X-Ray skill pack. Checked: ${candidates.join(", ")}`,
  );
}

function readText(filePath: string): string {
  try {
    return readFileSync(filePath, "utf8");
  } catch (err) {
    const message = toErrorMessage(err);
    throw new Error(`Unable to read X-Ray skill asset ${filePath}: ${message}`);
  }
}
