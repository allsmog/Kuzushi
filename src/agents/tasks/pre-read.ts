import { readFile, stat } from "node:fs/promises";
import path from "node:path";
import type { FileIndex } from "../../types.js";

const MAX_PRE_READ_BYTES = 50_000;
const MAX_FILES = 20;

export interface TaskFileSpec {
  namePatterns?: RegExp[];
  patternDomains?: string[];
  pathFilter?: (p: string) => boolean;
}

const TASK_FILE_SPECS: Record<string, TaskFileSpec> = {
  "secrets-crypto-detect": {
    namePatterns: [/\.env/, /config\./, /\.key$/, /\.pem$/, /docker-compose/],
    patternDomains: ["secret-pattern", "crypto-import"],
  },
  "code-config-detect": {
    namePatterns: [/\.yml$/, /\.yaml$/, /Dockerfile/, /\.conf$/],
    patternDomains: ["eval-exec", "auth-session", "config-security"],
    pathFilter: (p) => /middleware|auth|guard|session|config|docker/i.test(p),
  },
  "ssrf-detect": {
    patternDomains: ["eval-exec"],
    pathFilter: (p) => /fetch|http|request|client|api/i.test(p),
  },
  "race-condition-detect": {
    pathFilter: (p) => /lock|mutex|semaphore|queue|transaction|atomic/i.test(p),
  },
  "nosql-injection-detect": {
    pathFilter: (p) => /mongo|model|schema|query|repository/i.test(p),
  },
  "prototype-pollution-detect": {
    pathFilter: (p) => /merge|extend|assign|deep|clone|util/i.test(p),
    namePatterns: [/package\.json$/],
  },
  "template-injection-detect": {
    pathFilter: (p) => /template|render|view|layout/i.test(p),
  },
  "graphql-security-detect": {
    pathFilter: (p) => /graphql|schema|resolver|mutation|query/i.test(p),
    namePatterns: [/\.graphql$/, /\.gql$/],
  },
  "supply-chain-detect": {
    namePatterns: [/package\.json$/, /package-lock\.json$/, /go\.mod$/, /go\.sum$/, /requirements\.txt$/, /Cargo\.toml$/, /Cargo\.lock$/, /pom\.xml$/, /build\.gradle/],
  },
  "sharp-edges-detect": {
    namePatterns: [/config\./, /\.env/, /default/, /options\./],
    patternDomains: ["config-security", "crypto-import"],
    pathFilter: (p) => /config|option|setting|default|init|setup|crypto|auth|session/i.test(p),
  },
};

export function getTaskFileSpec(taskId: string): TaskFileSpec | undefined {
  return TASK_FILE_SPECS[taskId];
}

export interface PreReadFile {
  path: string;
  content: string;
}

export interface PreReadResult {
  files: PreReadFile[];
  totalBytes: number;
  truncated: boolean;
}

export async function preReadFilesForTask(
  taskId: string,
  fileIndex: FileIndex | undefined,
  repoRoot: string,
): Promise<PreReadResult> {
  if (!fileIndex) return { files: [], totalBytes: 0, truncated: false };

  const spec = TASK_FILE_SPECS[taskId];
  if (!spec) return { files: [], totalBytes: 0, truncated: false };

  const candidates = new Set<string>();

  // Collect from pattern match file paths
  if (spec.patternDomains) {
    for (const domain of spec.patternDomains) {
      const matches = fileIndex.patternMatches[domain];
      if (matches) {
        for (const m of matches) {
          candidates.add(m.filePath);
        }
      }
    }
  }

  // Collect from name patterns against tree
  if (spec.namePatterns) {
    for (const entry of fileIndex.tree) {
      for (const pattern of spec.namePatterns) {
        if (pattern.test(entry.path)) {
          candidates.add(entry.path);
          break;
        }
      }
    }
  }

  // Collect from path filter against tree
  if (spec.pathFilter) {
    for (const entry of fileIndex.tree) {
      if (spec.pathFilter(entry.path)) {
        candidates.add(entry.path);
      }
    }
  }

  const files: PreReadFile[] = [];
  let totalBytes = 0;

  for (const relPath of candidates) {
    if (files.length >= MAX_FILES) break;
    if (totalBytes >= MAX_PRE_READ_BYTES) break;

    const absPath = path.join(repoRoot, relPath);
    try {
      const s = await stat(absPath);
      if (!s.isFile()) continue;
      const remaining = MAX_PRE_READ_BYTES - totalBytes;
      if (s.size > remaining) continue;

      const content = await readFile(absPath, "utf-8");
      files.push({ path: relPath, content });
      totalBytes += Buffer.byteLength(content, "utf-8");
    } catch {
      continue;
    }
  }

  return {
    files,
    totalBytes,
    truncated: candidates.size > files.length,
  };
}
