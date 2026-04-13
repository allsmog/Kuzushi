import { existsSync } from "node:fs";
import { readdir } from "node:fs/promises";
import path from "node:path";
import { DEFAULT_IGNORED_DIRS } from "../../repo-walk.js";
import type { DiscoveryAdapter, RawDiscoveryNode } from "./types.js";
import { normalizePromptPath, readFirstSnippet, readText } from "../helpers.js";

export class MsvsAdapter implements DiscoveryAdapter {
  readonly id = "msvs";

  async discover(repoRoot: string, _maxDepth: number): Promise<RawDiscoveryNode[]> {
    const nodes: RawDiscoveryNode[] = [];

    // Walk depth <=2 for .sln files
    const slnFiles = await findSlnFiles(repoRoot, 2);

    for (const slnRelPath of slnFiles) {
      const slnDir = path.dirname(slnRelPath);
      const slnAbsDir = path.resolve(repoRoot, slnDir);
      const slnAbsPath = path.resolve(repoRoot, slnRelPath);
      const slnContent = await readText(slnAbsPath);
      if (!slnContent) continue;

      const projectRefs = parseSlnProjectReferences(slnContent);
      const childPaths: string[] = [];

      for (const ref of projectRefs) {
        // Resolve project path relative to the .sln directory
        const projectRelToSln = ref.path.replace(/\\/g, "/");
        const projectAbsPath = path.resolve(slnAbsDir, projectRelToSln);
        if (!existsSync(projectAbsPath)) continue;

        const projectDir = path.dirname(projectAbsPath);
        const projectDirRel = normalizePromptPath(path.relative(repoRoot, projectDir));
        const ext = path.extname(ref.path).toLowerCase();
        const language = ext === ".vcxproj" ? "C++" : "C#";

        childPaths.push(projectDirRel);
        const readme = await readFirstSnippet(projectDir);

        nodes.push({
          path: projectDirRel,
          name: ref.name,
          language,
          buildSystem: ext === ".vcxproj" ? ".vcxproj" : ".csproj",
          description: readme?.snippet ?? "",
          evidence: [`${path.basename(ref.path)} referenced by ${path.basename(slnRelPath)}`],
          isContainer: false,
          childPaths: [],
        });
      }

      if (childPaths.length > 0) {
        const containerPath = normalizePromptPath(slnDir);
        nodes.push({
          path: containerPath,
          name: path.basename(slnRelPath, ".sln"),
          language: "C#",
          buildSystem: ".sln",
          description: "",
          evidence: [path.basename(slnRelPath)],
          isContainer: true,
          containerKind: "solution",
          childPaths,
        });
      }
    }

    return nodes;
  }
}

interface SlnProjectRef {
  name: string;
  path: string;
}

function parseSlnProjectReferences(slnContent: string): SlnProjectRef[] {
  const refs: SlnProjectRef[] = [];
  // Match: Project("{GUID}") = "Name", "path\to\project.csproj", "{GUID}"
  const projectRegex = /Project\("[^"]*"\)\s*=\s*"([^"]+)"\s*,\s*"([^"]+\.(?:csproj|vcxproj|fsproj))"/gi;
  let match: RegExpExecArray | null;
  while ((match = projectRegex.exec(slnContent)) !== null) {
    refs.push({ name: match[1], path: match[2] });
  }
  return refs;
}

async function findSlnFiles(repoRoot: string, maxDepth: number): Promise<string[]> {
  const results: string[] = [];
  await walkForSln(repoRoot, repoRoot, 0, maxDepth, results);
  return results.sort();
}

async function walkForSln(
  repoRoot: string,
  currentDir: string,
  depth: number,
  maxDepth: number,
  results: string[],
): Promise<void> {
  let entries;
  try {
    entries = await readdir(currentDir, { withFileTypes: true });
  } catch {
    return;
  }

  for (const entry of entries) {
    if (entry.isFile() && entry.name.endsWith(".sln")) {
      results.push(normalizePromptPath(path.relative(repoRoot, path.join(currentDir, entry.name))));
    }
    if (entry.isDirectory() && depth < maxDepth) {
      if (entry.name.startsWith(".") || DEFAULT_IGNORED_DIRS.has(entry.name)) continue;
      await walkForSln(repoRoot, path.join(currentDir, entry.name), depth + 1, maxDepth, results);
    }
  }
}
