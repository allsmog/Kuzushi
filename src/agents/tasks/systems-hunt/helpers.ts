import { readFile } from "node:fs/promises";
import path from "node:path";
import type { CodeIntelligenceProvider } from "../../../analysis-support/types.js";
import { formatProfilesForPrompt, getProfilesForTask } from "../../../security-profiles.js";
import type { FileIndex, SecurityProfile } from "../../../types.js";
import type {
  RankedSystemsSurface,
  SystemsCodeLocation,
  SystemsHelperTemplate,
  SystemsHelperTemplateId,
  SystemsSurfacePack,
} from "./types.js";

const PACK_SCAN_LIMIT = 250;

const COMPARE_CAST_PATTERNS = [
  /\b(?:if|while)\s*\([^)]*(?:<|>|<=|>=|==|!=)[^)]*\)/,
  /\bstatic_cast<[^>]+>/,
  /\breinterpret_cast<[^>]+>/,
  /\bconst_cast<[^>]+>/,
  /\b(?:u?int(?:8|16|32|64)_t|size_t|ssize_t)\s*\)/,
  /\(\s*(?:unsigned|signed|int|long|short|size_t|ssize_t|u(?:8|16|32|64)|i(?:8|16|32|64))\s*\)/,
  /\bas\s+(?:u(?:8|16|32|64|size)|i(?:8|16|32|64|size)|usize|isize)\b/,
] as const;

const COUNTER_PATTERNS = [
  /\b(?:count|cnt|len|length|size|index|offset|seq|ack|window|slice|frame|packet)\b/i,
  /\+\+|--|\+=|-=|\bwrapping_(?:add|sub)\b|\bsaturating_(?:add|sub)\b/,
] as const;

const SENTINEL_PATTERNS = [
  /\b(?:UINT_MAX|INT_MAX|INT_MIN|SIZE_MAX|SSIZE_MAX|UINT16_MAX|UINT32_MAX|U?INT64_MAX)\b/,
  /\b0x(?:ffff|ffffffff|ffffffffffffffff)\b/i,
  /\b-1\b/,
  /\b(?:INVALID|SENTINEL|EOF|NONE|UNKNOWN)\b/,
] as const;

const ALLOC_COPY_PATTERNS = [
  /\b(?:memcpy|memmove|strcpy|strncpy|snprintf|sprintf)\s*\(/,
  /\b(?:malloc|calloc|realloc|alloca)\s*\(/,
  /\b(?:copy_from|copy_to|copy_nonoverlapping|Vec::with_capacity|reserve|resize)\b/,
] as const;

const UNSAFE_PATTERNS = [
  /\bunsafe\s*\{/,
  /\bunsafe\s+fn\b/,
  /\b(?:from_raw_parts|get_unchecked|set_len|ptr::|transmute|slice::from_raw_parts)\b/,
  /\bFFI\b|\bextern\s+"C"/,
] as const;

const RESOURCE_PROVENANCE_PATTERNS = [
  /\b(?:splice|vmsplice|sendfile|mmap)\s*\(/,
  /\bAF_ALG\b|\balgif\b/i,
  /\b(?:scatterlist|sg_chain|sg_page|page[_-]?cache|pipe_buffer|iov_iter)\b/i,
  /\b(?:kmap_local_page|scatterwalk_map_and_copy|aead_request_set_crypt)\s*\(/,
] as const;

const ALIASING_PATTERNS = [
  /\bsrc\s*==\s*dst\b/,
  /\breq->src\s*=\s*req->dst\b/,
  /\breq->dst\s*=\s*req->src\b/,
  /\b(?:in-place|inplace)\b/i,
  /\bsg_chain\s*\(/,
  /\baead_request_set_crypt\s*\([^;]*(\bsrc\b|\bdst\b|\brsgl_src\b)[^;]*(\bsrc\b|\bdst\b|\brsgl_src\b)/,
] as const;

const SCRATCH_WRITE_PATTERNS = [
  /\bscatterwalk_map_and_copy\s*\(/,
  /\b(?:scratch|temporary|tmp)\b/i,
  /\b(?:assoclen|cryptlen|authsize)\b.*\+/,
  /\b(?:dst|out|output)\s*\[[^\]]+\]\s*=/,
  /\b(?:write|overwrite|copy).*?(?:tag|tail|after|past|beyond)/i,
] as const;

const FAILURE_SIDE_EFFECT_PATTERNS = [
  /\b(?:EBADMSG|EINVAL|EFAULT|EIO|EPERM)\b/,
  /\b(?:auth|verify|validate|check).*?(?:fail|error|reject)/i,
  /\breturn\s+-[A-Z0-9_]+/,
  /\bgoto\s+(?:err|error|fail|free|out)\b/i,
] as const;

const INPUT_PATTERNS = [
  /\b(?:recv|recvmsg|read|socket|accept|packet|segment|rpc|xdr|guest|virtio|descriptor|iov|iov_len|splice|vmsplice|sendfile)\b/i,
  /\b(?:tcp|udp|nfs|gss|h264|frame|slice|opcode|header|AF_ALG|algif|pipe|page)\b/i,
] as const;

const HARDENING_PATTERNS = [
  /\b(?:__stack_chk_fail|stack[_ -]?canary|FORTIFY_SOURCE)\b/i,
  /\b(?:panic!|debug_assert!|assert)\s*\(/,
  /\b(?:harden|mitigat|guard)\w*\b/i,
] as const;

interface TemplateSpec {
  id: SystemsHelperTemplateId;
  title: string;
  rationale: string;
  queryText: string;
}

const TEMPLATE_SPECS: readonly TemplateSpec[] = [
  {
    id: "signed-wraparound",
    title: "Signed/unsigned compare and wraparound",
    rationale:
      "Find mixed-width comparisons, casts, and arithmetic that can wrap before bounds or state checks.",
    queryText: [
      "/* CodeQL template: signed-wraparound */",
      "import cpp",
      "from Expr a, Expr b",
      'where a.getType().toString().matches("%int%") and b.getType().toString().matches("%unsigned%")',
      'select a, "Inspect mixed signed/unsigned compare or cast near control/data boundary."',
    ].join("\n"),
  },
  {
    id: "counter-allocation-flow",
    title: "Counter to index/allocation flow",
    rationale:
      "Trace counters and lengths that drive allocation sizes, indexing, loop exits, or sentinel checks.",
    queryText: [
      "/* CodeQL template: counter-allocation-flow */",
      "import cpp",
      "from FunctionCall alloc, Expr sizeArg",
      'where alloc.getTarget().hasName(["malloc", "calloc", "realloc"]) and sizeArg = alloc.getArgument(0)',
      'select sizeArg, "Inspect counter-derived allocation or index sizing."',
    ].join("\n"),
  },
  {
    id: "stack-length-copy",
    title: "Stack/heap copy length from input",
    rationale:
      "Look for copy operations where attacker-controlled length can exceed local buffer or object capacity.",
    queryText: [
      "/* CodeQL template: stack-length-copy */",
      "import cpp",
      "from FunctionCall copy",
      'where copy.getTarget().hasName(["memcpy", "memmove", "strcpy", "strncpy"])',
      'select copy, "Inspect copy length against stack/heap destination bounds."',
    ].join("\n"),
  },
  {
    id: "rpc-xdr-length",
    title: "RPC/XDR framing lengths",
    rationale:
      "Inspect RPC or XDR handlers where sequential message state and framing lengths control parsing or copies.",
    queryText: [
      "/* CodeQL template: rpc-xdr-length */",
      "import cpp",
      "from Function f",
      'where f.getName().regexpMatch(".*(rpc|xdr|gss|nfs).*")',
      'select f, "Inspect framing length and auth state transitions."',
    ].join("\n"),
  },
  {
    id: "rust-unsafe-len",
    title: "Rust unsafe len/pointer misuse",
    rationale:
      "Inspect unsafe blocks that use raw pointers, slice constructors, unchecked indexing, or set_len without guards.",
    queryText: [
      "/* CodeQL template: rust-unsafe-len */",
      "import rust",
      "from Expr e",
      'where e.toString().regexpMatch(".*(from_raw_parts|get_unchecked|set_len|ptr::).*" )',
      'select e, "Inspect unsafe length or pointer assumptions."',
    ].join("\n"),
  },
  {
    id: "hardening-presence",
    title: "Hardening and mitigation presence",
    rationale:
      "Check whether canaries, fortify, panic/assert guards, or isolation assumptions materially change exploitability.",
    queryText: [
      "/* CodeQL template: hardening-presence */",
      "import cpp",
      "from MacroInvocation m",
      'where m.getMacroName().regexpMatch(".*(FORTIFY|STACK_CHK|ASSERT).*" )',
      'select m, "Inspect whether hardening is present or missing near the sink."',
    ].join("\n"),
  },
  {
    id: "shared-backing-resource",
    title: "Shared backing resource into writable sink",
    rationale:
      "Trace file/page/pipe/shared-buffer provenance into later APIs that may treat the object as writable.",
    queryText: [
      "/* CodeQL template: shared-backing-resource */",
      "import cpp",
      "from FunctionCall c",
      'where c.getTarget().getName().regexpMatch(".*(splice|vmsplice|sendfile|mmap|sg_chain|sg_page).*")',
      'select c, "Inspect whether shared backing resources cross into writable scatterlists or buffers."',
    ].join("\n"),
  },
  {
    id: "in-place-writable-alias",
    title: "In-place source/destination alias",
    rationale:
      "Inspect operations where source and destination are intentionally aliased across different provenance domains.",
    queryText: [
      "/* CodeQL template: in-place-writable-alias */",
      "import cpp",
      "from Assignment a",
      'where a.toString().regexpMatch(".*(src.*=.*dst|dst.*=.*src|in.?place).*")',
      'select a, "Inspect source/destination aliasing and ownership boundary assumptions."',
    ].join("\n"),
  },
  {
    id: "scratch-write-boundary",
    title: "Scratch write outside output contract",
    rationale:
      "Look for temporary writes into caller-owned output buffers, especially offsets after tags, headers, or authenticated data.",
    queryText: [
      "/* CodeQL template: scratch-write-boundary */",
      "import cpp",
      "from FunctionCall c",
      'where c.getTarget().getName().regexpMatch(".*(scatterwalk_map_and_copy|memcpy|memmove).*")',
      'select c, "Inspect scratch writes and offsets relative to the API output contract."',
    ].join("\n"),
  },
  {
    id: "failure-side-effect",
    title: "Side effect before auth/validation failure",
    rationale:
      "Check whether mutations occur before authentication, validation, or tag checks return an error.",
    queryText: [
      "/* CodeQL template: failure-side-effect */",
      "import cpp",
      "from ReturnStmt r",
      'where r.toString().regexpMatch(".*-(EBADMSG|EINVAL|EFAULT|EPERM).*")',
      'select r, "Inspect side effects before this failure return."',
    ].join("\n"),
  },
] as const;

export async function buildSystemsSurfacePack(args: {
  repoRoot: string;
  fileIndex: FileIndex | undefined;
  surface: RankedSystemsSurface;
  provider: CodeIntelligenceProvider;
  surfacePackDepth: number;
  enableCodeqlTemplates: boolean;
  codeqlDbPath?: string;
}): Promise<SystemsSurfacePack> {
  const {
    repoRoot,
    fileIndex,
    surface,
    provider,
    surfacePackDepth,
    enableCodeqlTemplates,
    codeqlDbPath,
  } = args;
  const anchorSymbol = await inferAnchorSymbol(repoRoot, surface.filePath, surface.startLine);
  const callers = anchorSymbol
    ? (await collectCallerLocations(provider, anchorSymbol, surfacePackDepth)).slice(
        0,
        surfacePackDepth,
      )
    : [];
  const callees = anchorSymbol
    ? (
        await collectCalleeLocations(provider, anchorSymbol, surface.filePath, surfacePackDepth)
      ).slice(0, surfacePackDepth)
    : [];
  const relatedFiles = dedupeStrings([
    surface.filePath,
    ...callers.map((entry) => entry.filePath),
    ...callees.map((entry) => entry.filePath),
  ]).slice(0, Math.max(1, surfacePackDepth * 2));

  const compareCastSites = await collectPatternLocations(
    repoRoot,
    relatedFiles,
    COMPARE_CAST_PATTERNS,
    surfacePackDepth,
    "compare/cast boundary logic",
  );
  const counterSites = await collectPatternLocations(
    repoRoot,
    relatedFiles,
    COUNTER_PATTERNS,
    surfacePackDepth,
    "counter or boundary variable",
  );
  const sentinelConstants = await collectPatternLocations(
    repoRoot,
    relatedFiles,
    SENTINEL_PATTERNS,
    surfacePackDepth,
    "sentinel or reserved boundary value",
  );
  const allocationCopySites = await collectPatternLocations(
    repoRoot,
    relatedFiles,
    ALLOC_COPY_PATTERNS,
    surfacePackDepth,
    "allocation/copy primitive",
  );
  const unsafeSites = await collectPatternLocations(
    repoRoot,
    relatedFiles,
    UNSAFE_PATTERNS,
    surfacePackDepth,
    "unsafe memory primitive",
  );
  const resourceProvenanceSites = await collectPatternLocations(
    repoRoot,
    relatedFiles,
    RESOURCE_PROVENANCE_PATTERNS,
    surfacePackDepth,
    "shared-resource provenance transfer",
  );
  const aliasingSites = await collectPatternLocations(
    repoRoot,
    relatedFiles,
    ALIASING_PATTERNS,
    surfacePackDepth,
    "source/destination alias or in-place operation",
  );
  const scratchWriteSites = await collectPatternLocations(
    repoRoot,
    relatedFiles,
    SCRATCH_WRITE_PATTERNS,
    surfacePackDepth,
    "scratch write or output-boundary write",
  );
  const failureSideEffectSites = await collectPatternLocations(
    repoRoot,
    relatedFiles,
    FAILURE_SIDE_EFFECT_PATTERNS,
    surfacePackDepth,
    "failure path that may preserve earlier side effects",
  );
  const inputSites = dedupeLocations([
    ...(await collectPatternLocations(
      repoRoot,
      relatedFiles,
      INPUT_PATTERNS,
      surfacePackDepth,
      "network/guest-controlled input",
    )),
    ...collectDomainLocations(
      fileIndex,
      relatedFiles,
      ["protocol-parser"],
      "file-index input signal",
      surfacePackDepth,
    ),
  ]).slice(0, surfacePackDepth);
  const hardeningSites = dedupeLocations([
    ...(await collectPatternLocations(
      repoRoot,
      relatedFiles,
      HARDENING_PATTERNS,
      surfacePackDepth,
      "hardening or guard",
    )),
    ...collectDomainLocations(
      fileIndex,
      relatedFiles,
      ["hardening"],
      "file-index hardening signal",
      surfacePackDepth,
    ),
  ]).slice(0, surfacePackDepth);

  return {
    surfaceId: surface.id,
    anchorFilePath: surface.filePath,
    anchorStartLine: surface.startLine,
    anchorSymbol,
    relatedFiles,
    callers,
    callees,
    compareCastSites,
    counterSites,
    sentinelConstants,
    allocationCopySites,
    unsafeSites,
    resourceProvenanceSites,
    aliasingSites,
    scratchWriteSites,
    failureSideEffectSites,
    inputSites,
    hardeningSites,
    helperTemplates: selectHelperTemplates(surface, enableCodeqlTemplates && Boolean(codeqlDbPath)),
  };
}

export function formatSystemsSurfacePack(pack: SystemsSurfacePack): string[] {
  const lines: string[] = [
    "## Surface pack",
    `Anchor: ${pack.anchorFilePath}:${pack.anchorStartLine}${pack.anchorSymbol ? ` (${pack.anchorSymbol})` : ""}`,
    `Related files: ${pack.relatedFiles.join(", ") || "none"}`,
    `Callers: ${formatLocations(pack.callers)}`,
    `Callees: ${formatLocations(pack.callees)}`,
    `Compare/cast sites: ${formatLocations(pack.compareCastSites)}`,
    `Counter sites: ${formatLocations(pack.counterSites)}`,
    `Sentinel constants: ${formatLocations(pack.sentinelConstants)}`,
    `Allocation/copy sites: ${formatLocations(pack.allocationCopySites)}`,
    `Unsafe sites: ${formatLocations(pack.unsafeSites)}`,
    `Resource provenance sites: ${formatLocations(pack.resourceProvenanceSites)}`,
    `Aliasing sites: ${formatLocations(pack.aliasingSites)}`,
    `Scratch write sites: ${formatLocations(pack.scratchWriteSites)}`,
    `Failure side-effect sites: ${formatLocations(pack.failureSideEffectSites)}`,
    `Input sites: ${formatLocations(pack.inputSites)}`,
    `Hardening sites: ${formatLocations(pack.hardeningSites)}`,
    `Built-in helpers: ${formatTemplates(pack.helperTemplates)}`,
  ];
  return lines;
}

export function matchTriggerHypothesisToFinding(args: {
  triggerHypothesisIds: string[];
  triggerSequence: string[];
  expectedPrimitive: string;
  hypotheses: readonly {
    id: string;
    orderedSteps: string[];
    boundaryAssignments: Record<string, string>;
    statePreconditions: string[];
    expectedPrimitive: string;
    cheapVerifiable: boolean;
  }[];
}): {
  matchedIds: string[];
  boundaryAssignments: Record<string, string>;
  stateMachine: string[];
  cheapVerifiable: boolean;
} {
  const matched = args.hypotheses.filter(
    (hypothesis) =>
      args.triggerHypothesisIds.includes(hypothesis.id) ||
      (args.triggerSequence.length > 0 &&
        hypothesis.orderedSteps.some((step) => args.triggerSequence.includes(step)) &&
        (args.expectedPrimitive === "unknown" ||
          hypothesis.expectedPrimitive === args.expectedPrimitive)),
  );

  const boundaryAssignments: Record<string, string> = {};
  const stateMachine: string[] = [];
  let cheapVerifiable = false;

  for (const hypothesis of matched) {
    for (const [key, value] of Object.entries(hypothesis.boundaryAssignments)) {
      boundaryAssignments[key] = value;
    }
    for (const step of hypothesis.statePreconditions) {
      stateMachine.push(`Precondition: ${step}`);
    }
    for (const step of hypothesis.orderedSteps) {
      stateMachine.push(step);
    }
    cheapVerifiable ||= hypothesis.cheapVerifiable;
  }

  return {
    matchedIds: matched.map((hypothesis) => hypothesis.id),
    boundaryAssignments,
    stateMachine: dedupeStrings(stateMachine),
    cheapVerifiable,
  };
}

export function formatSystemsHuntProfileLines(
  securityProfiles: SecurityProfile[] | undefined,
): string[] {
  if (!securityProfiles || securityProfiles.length === 0) return [];
  return formatProfilesForPrompt(getProfilesForTask(securityProfiles, "systems-hunt"));
}

function selectHelperTemplates(
  surface: RankedSystemsSurface,
  includeQueryText: boolean,
): SystemsHelperTemplate[] {
  const selectedIds = new Set<SystemsHelperTemplateId>(["hardening-presence"]);

  if (surface.kind === "protocol-parser" || surface.kind === "rpc-handler") {
    selectedIds.add("signed-wraparound");
    selectedIds.add("rpc-xdr-length");
  }
  if (surface.kind === "codec-parser" || surface.domains.includes("integer-boundary")) {
    selectedIds.add("counter-allocation-flow");
  }
  if (surface.kind === "buffer-operation" || surface.kind === "rpc-handler") {
    selectedIds.add("stack-length-copy");
  }
  if (
    surface.kind === "unsafe-region" ||
    surface.kind === "hypervisor-boundary" ||
    surface.domains.includes("unsafe-memory")
  ) {
    selectedIds.add("rust-unsafe-len");
  }
  if (surface.kind === "resource-provenance" || surface.domains.includes("resource-provenance")) {
    selectedIds.add("shared-backing-resource");
    selectedIds.add("in-place-writable-alias");
    selectedIds.add("scratch-write-boundary");
    selectedIds.add("failure-side-effect");
  }

  return TEMPLATE_SPECS.filter((template) => selectedIds.has(template.id)).map((template) => ({
    id: template.id,
    title: template.title,
    rationale: template.rationale,
    queryText: includeQueryText ? template.queryText : undefined,
  }));
}

async function collectCallerLocations(
  provider: CodeIntelligenceProvider,
  functionName: string,
  limit: number,
): Promise<SystemsCodeLocation[]> {
  try {
    const raw = await provider.getCallers({
      functionName,
      maxResults: Math.max(limit * 2, limit),
    });
    return dedupeLocations(
      raw
        .map(parseCallSite)
        .filter((entry): entry is SystemsCodeLocation => Boolean(entry))
        .map((entry) => ({ ...entry, reason: "caller of anchor symbol", symbol: functionName })),
    ).slice(0, limit);
  } catch {
    return [];
  }
}

async function collectCalleeLocations(
  provider: CodeIntelligenceProvider,
  functionName: string,
  filePath: string,
  limit: number,
): Promise<SystemsCodeLocation[]> {
  try {
    const rawNames = await provider.getCallees({ functionName, filePath });
    const resolved: SystemsCodeLocation[] = [];
    for (const name of rawNames.slice(0, limit * 2)) {
      const [match] = await provider.findSymbol({ symbol: name, maxResults: 1 });
      if (!match) continue;
      resolved.push({
        filePath: match.filePath,
        line: match.line,
        snippet: match.snippet,
        reason: "callee of anchor symbol",
        symbol: name,
      });
    }
    return dedupeLocations(resolved).slice(0, limit);
  } catch {
    return [];
  }
}

async function collectPatternLocations(
  repoRoot: string,
  filePaths: string[],
  patterns: readonly RegExp[],
  limit: number,
  reason: string,
): Promise<SystemsCodeLocation[]> {
  const matches: SystemsCodeLocation[] = [];
  for (const filePath of filePaths) {
    if (matches.length >= limit) break;
    const lines = await readLines(repoRoot, filePath);
    if (!lines) continue;

    for (let index = 0; index < lines.length && matches.length < limit; index += 1) {
      const line = lines[index];
      if (line.length > PACK_SCAN_LIMIT) continue;
      if (!patterns.some((pattern) => pattern.test(line))) continue;
      matches.push({
        filePath,
        line: index + 1,
        snippet: line.trim(),
        reason,
      });
    }
  }
  return dedupeLocations(matches).slice(0, limit);
}

function collectDomainLocations(
  fileIndex: FileIndex | undefined,
  filePaths: string[],
  domains: string[],
  reason: string,
  limit: number,
): SystemsCodeLocation[] {
  if (!fileIndex) return [];
  const allowed = new Set(filePaths);
  const matches: SystemsCodeLocation[] = [];
  for (const domain of domains) {
    for (const match of fileIndex.patternMatches[domain] ?? []) {
      if (!allowed.has(match.filePath)) continue;
      matches.push({
        filePath: match.filePath,
        line: match.lineNumber,
        snippet: match.lineContent.trim(),
        reason,
      });
      if (matches.length >= limit) {
        return dedupeLocations(matches).slice(0, limit);
      }
    }
  }
  return dedupeLocations(matches).slice(0, limit);
}

async function inferAnchorSymbol(
  repoRoot: string,
  filePath: string,
  startLine: number,
): Promise<string | undefined> {
  const lines = await readLines(repoRoot, filePath);
  if (!lines) return undefined;
  const startIndex = Math.max(0, Math.min(lines.length - 1, startLine - 1));
  const windowStart = Math.max(0, startIndex - 25);

  for (let index = startIndex; index >= windowStart; index -= 1) {
    const line = lines[index]?.trim() ?? "";
    if (!line || /^(if|for|while|switch|return)\b/.test(line)) continue;
    const match =
      line.match(/(?:^|[\s:*&])([A-Za-z_]\w*)\s*\([^;]*\)\s*(?:const)?\s*(?:\{|$)/) ??
      line.match(/^\s*(?:pub\s+)?(?:async\s+)?fn\s+([A-Za-z_]\w*)\s*[<(]/) ??
      line.match(
        /^\s*(?:static\s+)?(?:inline\s+)?(?:[\w:<>~*&]+\s+)+([A-Za-z_]\w*)\s*\([^;]*\)\s*(?:\{|$)/,
      );
    const symbol = match?.[1]?.trim();
    if (symbol && !["if", "for", "while", "switch"].includes(symbol)) {
      return symbol;
    }
  }
  return undefined;
}

async function readLines(repoRoot: string, filePath: string): Promise<string[] | undefined> {
  try {
    const content = await readFile(path.join(repoRoot, filePath), "utf-8");
    return content.split(/\r?\n/u);
  } catch {
    return undefined;
  }
}

function parseCallSite(value: string): SystemsCodeLocation | undefined {
  const match = value.match(/^(.*?):(\d+):(.*)$/);
  if (!match) return undefined;
  return {
    filePath: match[1].trim(),
    line: Math.max(1, Math.floor(Number(match[2]) || 1)),
    snippet: match[3].trim(),
  };
}

function formatLocations(locations: SystemsCodeLocation[]): string {
  if (locations.length === 0) return "none";
  return locations
    .map((location) => `${location.filePath}:${location.line} ${location.snippet}`)
    .join(" | ");
}

function formatTemplates(templates: SystemsHelperTemplate[]): string {
  if (templates.length === 0) return "none";
  return templates.map((template) => `${template.id}: ${template.title}`).join(" | ");
}

function dedupeLocations(locations: SystemsCodeLocation[]): SystemsCodeLocation[] {
  const seen = new Set<string>();
  const deduped: SystemsCodeLocation[] = [];
  for (const location of locations) {
    const key = `${location.filePath}:${location.line}:${location.snippet}`;
    if (seen.has(key)) continue;
    seen.add(key);
    deduped.push(location);
  }
  return deduped;
}

function dedupeStrings(values: string[]): string[] {
  return [...new Set(values.filter(Boolean))];
}

export const __systemsHelperInternals = {
  inferAnchorSymbol,
  matchTriggerHypothesisToFinding,
};
