import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { promisify } from "node:util";
import { getCodeIntelligenceProvider } from "../../../analysis-support/index.js";
import { createLogger } from "../../../logger.js";
import { coerceFileIndex, coerceRepoContext } from "../../../repo-context.js";
import { attachTaskOutputMeta } from "../../../task-output-meta.js";
import type { FileIndex, RepoContext, ScanOpts, SecurityPatternMatch } from "../../../types.js";
import type { AgentTask, TaskContext } from "../../types.js";
import { buildSystemsSurfacePack } from "./helpers.js";
import {
  hasSystemsSignals,
  isSystemsLanguage,
  type RankedSystemsSurface,
  resolveSystemsCodeqlDbPath,
  resolveSystemsHuntConfig,
  type SystemsContextOutput,
  type SystemsPatternDomain,
  type SystemsSurfaceKind,
} from "./types.js";

const execFileAsync = promisify(execFile);
const log = createLogger({ stage: "systems-context-gatherer" });

const DOMAIN_WEIGHTS: Record<SystemsPatternDomain, number> = {
  "protocol-parser": 7,
  "integer-boundary": 5,
  "unsafe-memory": 6,
  hardening: 2,
};

const PATH_HINTS: Array<{
  pattern: RegExp;
  kind: SystemsSurfaceKind;
  score: number;
  reason: string;
}> = [
  {
    pattern: /(tcp|udp|packet|segment|socket|skb|net|sack)/i,
    kind: "protocol-parser",
    score: 5,
    reason: "network or packet-processing path",
  },
  {
    pattern: /(rpc|nfs|gss|xdr)/i,
    kind: "rpc-handler",
    score: 6,
    reason: "RPC or NFS parsing path",
  },
  {
    pattern: /(codec|decode|parser|h264|slice|frame|ffmpeg|avcodec)/i,
    kind: "codec-parser",
    score: 6,
    reason: "codec or parser path",
  },
  {
    pattern: /(vmm|hypervisor|guest|virt|vmexit|virtio)/i,
    kind: "hypervisor-boundary",
    score: 7,
    reason: "hypervisor or guest/host boundary path",
  },
  {
    pattern: /(unsafe|ptr|ffi|memory|buffer|copy)/i,
    kind: "unsafe-region",
    score: 4,
    reason: "unsafe or memory-manipulation path",
  },
];

type SurfaceAccumulator = RankedSystemsSurface & {
  domainSet: Set<SystemsPatternDomain>;
  attackerFieldSet: Set<string>;
  hardeningSet: Set<string>;
};

export const systemsContextGathererTask: AgentTask<ScanOpts, SystemsContextOutput> = {
  id: "systems-context-gatherer",
  displayName: "Systems Context Gatherer",
  outputKind: "custom",
  dependsOn: ["context-gatherer"],

  condition(upstreamOutputs) {
    const repoContext = coerceRepoContext(upstreamOutputs.get("context-gatherer"));
    const fileIndex = coerceFileIndex(upstreamOutputs.get("context-gatherer"));
    return (
      repoContext?.languages.some((language) => isSystemsLanguage(language)) === true ||
      hasSystemsSignals(fileIndex)
    );
  },

  async run(_input, context): Promise<SystemsContextOutput> {
    const fileIndex = coerceFileIndex(context.upstreamOutputs.get("context-gatherer"));
    const repoContext = coerceRepoContext(context.upstreamOutputs.get("context-gatherer"));
    const config = resolveSystemsHuntConfig(context);
    const codeqlDbPath = config.enableCodeqlAssist
      ? resolveSystemsCodeqlDbPath(context.repoRoot)
      : undefined;
    const bashMatches = config.enableBashProbing ? await runBashSurfaceProbe(context.repoRoot) : [];
    const surfaces = await rankSystemsSurfaces(
      fileIndex,
      repoContext,
      context.repoRoot,
      config.maxSurfaces,
      bashMatches,
    );
    const provider = await getCodeIntelligenceProvider(context.repoRoot);
    const surfacePacks = await Promise.all(
      surfaces.map((surface) =>
        buildSystemsSurfacePack({
          repoRoot: context.repoRoot,
          fileIndex,
          surface,
          provider,
          surfacePackDepth: config.surfacePackDepth,
          enableCodeqlTemplates: config.enableCodeqlTemplates,
          codeqlDbPath,
        }),
      ),
    );

    return attachTaskOutputMeta(
      {
        surfaces,
        surfacePacks,
        metadata: {
          codeqlAvailable: Boolean(codeqlDbPath),
          codeqlDbPath,
          bashProbingUsed: bashMatches.length > 0,
        },
      },
      { costUsd: 0 },
    );
  },
};

export async function rankSystemsSurfaces(
  fileIndex: FileIndex | undefined,
  repoContext: RepoContext | undefined,
  repoRoot: string,
  maxSurfaces: number,
  extraMatches: SecurityPatternMatch[] = [],
): Promise<RankedSystemsSurface[]> {
  if (!fileIndex) return [];

  const accumulators = new Map<string, SurfaceAccumulator>();
  const hardeningByFile = new Map<string, string[]>();
  const targetDomains: SystemsPatternDomain[] = [
    "protocol-parser",
    "integer-boundary",
    "unsafe-memory",
    "hardening",
  ];

  for (const match of extraMatches) {
    fileIndex.patternMatches["protocol-parser"] = dedupeMatches([
      ...(fileIndex.patternMatches["protocol-parser"] ?? []),
      match,
    ]);
  }

  for (const domain of targetDomains) {
    for (const match of fileIndex.patternMatches[domain] ?? []) {
      if (domain === "hardening") {
        const existing = hardeningByFile.get(match.filePath) ?? [];
        existing.push(trimLine(match.lineContent));
        hardeningByFile.set(match.filePath, existing);
        continue;
      }

      const kind = inferSurfaceKind(match.filePath, match.lineContent, domain);
      const key = `${kind}:${match.filePath}`;
      const accumulator =
        accumulators.get(key) ??
        createAccumulator(kind, match.filePath, match.lineNumber, repoRoot);
      accumulator.startLine = Math.min(accumulator.startLine, match.lineNumber);
      accumulator.score += DOMAIN_WEIGHTS[domain];
      accumulator.domainSet.add(domain);
      accumulator.reasons.push(describeSignal(domain, match));
      accumulator.evidence.push({
        domain,
        lineNumber: match.lineNumber,
        lineContent: trimLine(match.lineContent),
        reason: describeSignal(domain, match),
      });
      for (const field of extractAttackerFields(match.lineContent)) {
        accumulator.attackerFieldSet.add(field);
      }
      accumulators.set(key, accumulator);
    }
  }

  for (const accumulator of accumulators.values()) {
    const pathHint = PATH_HINTS.find(
      (hint) => hint.kind === accumulator.kind && hint.pattern.test(accumulator.filePath),
    );
    if (pathHint) {
      accumulator.score += pathHint.score;
      accumulator.reasons.push(`Path hint: ${pathHint.reason}`);
    } else {
      const genericHint = PATH_HINTS.find((hint) => hint.pattern.test(accumulator.filePath));
      if (genericHint) {
        accumulator.score += Math.max(2, genericHint.score - 2);
        accumulator.reasons.push(`Path hint: ${genericHint.reason}`);
      }
    }

    if (accumulator.domainSet.size > 1) {
      accumulator.score += accumulator.domainSet.size;
      accumulator.reasons.push(`Multi-domain signal overlap (${accumulator.domainSet.size})`);
    }

    for (const hardening of hardeningByFile.get(accumulator.filePath) ?? []) {
      accumulator.hardeningSet.add(hardening);
    }

    if (repoContext?.languages.some((language) => isSystemsLanguage(language))) {
      accumulator.score += 1;
    }
  }

  const surfaces = [...accumulators.values()]
    .map((accumulator) =>
      finalizeSurface(accumulator, hardeningByFile.get(accumulator.filePath) ?? []),
    )
    .sort((left, right) => {
      if (right.score !== left.score) return right.score - left.score;
      if (left.filePath !== right.filePath) return left.filePath.localeCompare(right.filePath);
      return left.startLine - right.startLine;
    })
    .slice(0, maxSurfaces);

  for (const surface of surfaces) {
    if (surface.evidence.length === 0) continue;
    const snippet = await readSnippet(repoRoot, surface.filePath, surface.startLine);
    if (snippet) {
      surface.evidence[0] = {
        ...surface.evidence[0],
        lineContent: snippet,
      };
    }
  }

  return surfaces;
}

function createAccumulator(
  kind: SystemsSurfaceKind,
  filePath: string,
  startLine: number,
  repoRoot: string,
): SurfaceAccumulator {
  const normalizedPath = normalizePath(repoRoot, filePath);
  return {
    id: createHash("sha256").update(`${kind}|${normalizedPath}`).digest("hex"),
    filePath: normalizedPath,
    startLine,
    displayName: `${kind} in ${normalizedPath}`,
    kind,
    score: 0,
    domains: [],
    reasons: [],
    attackerControlledFields: [],
    hardeningSignals: [],
    evidence: [],
    domainSet: new Set<SystemsPatternDomain>(),
    attackerFieldSet: new Set<string>(),
    hardeningSet: new Set<string>(),
  };
}

function finalizeSurface(
  accumulator: SurfaceAccumulator,
  hardeningSignals: string[],
): RankedSystemsSurface {
  return {
    id: accumulator.id,
    filePath: accumulator.filePath,
    startLine: accumulator.startLine,
    displayName: accumulator.displayName,
    kind: accumulator.kind,
    score: accumulator.score,
    domains: [...accumulator.domainSet],
    reasons: dedupeStrings(accumulator.reasons).slice(0, 8),
    attackerControlledFields: [...accumulator.attackerFieldSet].slice(0, 8),
    hardeningSignals: dedupeStrings([...accumulator.hardeningSet, ...hardeningSignals]).slice(0, 6),
    evidence: accumulator.evidence.slice(0, 8),
  };
}

export function inferSurfaceKind(
  filePath: string,
  lineContent: string,
  domain: SystemsPatternDomain,
): SystemsSurfaceKind {
  const haystack = `${filePath} ${lineContent}`;
  if (/rpc|nfs|gss|xdr/i.test(haystack)) return "rpc-handler";
  if (/codec|decode|parser|h264|slice|frame|ffmpeg|avcodec/i.test(haystack)) return "codec-parser";
  if (/vmm|hypervisor|guest|virt|vmexit|virtio/i.test(haystack)) return "hypervisor-boundary";
  if (domain === "protocol-parser" || /tcp|udp|packet|segment|socket|skb|sack/i.test(haystack)) {
    return "protocol-parser";
  }
  if (
    domain === "unsafe-memory" ||
    /\.rs$/i.test(filePath) ||
    /\bunsafe\b|memcpy|ptr::|transmute/i.test(lineContent)
  ) {
    return "unsafe-region";
  }
  if (/memcpy|memmove|strcpy|copy|alloca|malloc|realloc/i.test(lineContent)) {
    return "buffer-operation";
  }
  return "boundary-heavy-routine";
}

function describeSignal(domain: SystemsPatternDomain, match: SecurityPatternMatch): string {
  switch (domain) {
    case "protocol-parser":
      return `Protocol or parser signal at ${match.filePath}:${match.lineNumber}`;
    case "integer-boundary":
      return `Integer boundary or sentinel logic at ${match.filePath}:${match.lineNumber}`;
    case "unsafe-memory":
      return `Unsafe memory primitive at ${match.filePath}:${match.lineNumber}`;
    case "hardening":
      return `Hardening signal at ${match.filePath}:${match.lineNumber}`;
  }
}

function extractAttackerFields(lineContent: string): string[] {
  const fields = new Set<string>();
  const patterns = [
    /\b(len|length|size|count|offset|index|seq|ack|slice_count|packet_len|frame_size|guest_len|iov_len)\b/gi,
    /\b(opt|option|segment|packet|request|header|payload|rpc|gss|state)\b/gi,
  ];
  for (const pattern of patterns) {
    for (const match of lineContent.matchAll(pattern)) {
      const value = match[1] ?? match[0];
      if (value) fields.add(value.toLowerCase());
    }
  }
  return [...fields];
}

async function readSnippet(
  repoRoot: string,
  filePath: string,
  lineNumber: number,
): Promise<string | undefined> {
  try {
    const content = await readFile(path.join(repoRoot, filePath), "utf-8");
    const lines = content.split(/\r?\n/u);
    return trimLine(lines[Math.max(0, lineNumber - 1)] ?? "");
  } catch {
    return undefined;
  }
}

async function runBashSurfaceProbe(repoRoot: string): Promise<SecurityPatternMatch[]> {
  try {
    const { stdout } = await execFileAsync(
      "rg",
      [
        "-n",
        "--no-heading",
        "--with-filename",
        "--glob",
        "*.{c,cc,cpp,cxx,h,hpp,hxx,rs}",
        String.raw`\b(tcp|udp|packet|rpc|nfs|gss|codec|h264|slice|unsafe|memcpy|memmove|stack_chk_fail|fortify|from_raw_parts|get_unchecked|set_len)\b`,
        repoRoot,
      ],
      { cwd: repoRoot, maxBuffer: 1024 * 1024 },
    );

    const matches: SecurityPatternMatch[] = [];
    for (const line of stdout.split(/\r?\n/u)) {
      const match = line.match(/^(.+?):(\d+):(.*)$/u);
      if (!match) continue;
      const filePath = normalizePath(repoRoot, match[1]);
      if (filePath.startsWith("..")) continue;
      matches.push({
        pattern: "bash-probe",
        filePath,
        lineNumber: Number(match[2]),
        lineContent: trimLine(match[3]),
      });
      if (matches.length >= 50) break;
    }
    return matches;
  } catch (error) {
    log.debug(`systems context bash probe skipped: ${String(error)}`);
    return [];
  }
}

function normalizePath(repoRoot: string, filePath: string): string {
  if (!path.isAbsolute(filePath)) return filePath.replace(/\\/g, "/");
  const relative = path.relative(repoRoot, filePath).replace(/\\/g, "/");
  return relative.startsWith("..") ? filePath : relative || filePath;
}

function dedupeStrings(values: string[]): string[] {
  return [...new Set(values.filter(Boolean))];
}

function dedupeMatches(values: SecurityPatternMatch[]): SecurityPatternMatch[] {
  const deduped = new Map<string, SecurityPatternMatch>();
  for (const value of values) {
    deduped.set(`${value.filePath}:${value.lineNumber}:${value.pattern}`, value);
  }
  return [...deduped.values()];
}

function trimLine(value: string): string {
  return value.replace(/\s+/g, " ").trim().slice(0, 220);
}

export const __systemsContextGathererInternals = {
  rankSystemsSurfaces,
  inferSurfaceKind,
  runBashSurfaceProbe,
};
