import { readFile } from "node:fs/promises";
import path from "node:path";
import type { CodeIntelligenceProvider } from "../../../analysis-support/types.js";
import { formatProfilesForPrompt, getProfilesForTask } from "../../../security-profiles.js";
import type { FileIndex, SecurityProfile } from "../../../types.js";
import { buildProvenanceChains } from "./provenance-chain.js";
import { buildProvenanceSummaries } from "./provenance-summary.js";
import type {
  RankedSystemsSurface,
  SystemsCodeLocation,
  SystemsHelperTemplate,
  SystemsHelperTemplateId,
  SystemsProvenanceChain,
  SystemsProvenanceFact,
  SystemsProvenanceFactKind,
  SystemsProvenanceFactStrength,
  SystemsProvenanceState,
  SystemsProvenanceSummary,
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
  /\b(?:splice_to_pipe|splice_direct_to_actor|filemap_splice_read|copy_page_to_iter_pipe|push_pipe)\b/,
  /\bAF_ALG\b|\balgif\b/i,
  /\b(?:scatterlist|sg_set_page|sg_chain|sg_page|page[_-]?cache|pipe_buffer|iov_iter)\b/i,
  /\b(?:ITER_PIPE|ITER_XARRAY|ITER_FOLIOQ|ITER_BVEC)\b/,
  /\b(?:kmap_local_page|scatterwalk_map_and_copy|memcpy_to_sglist|aead_request_set_crypt)\s*\(/,
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

interface ProvenanceRule {
  state: SystemsProvenanceState;
  kind: SystemsProvenanceFactKind;
  strength: SystemsProvenanceFactStrength;
  resourceFamily: string;
  reason: string;
  patterns: readonly RegExp[];
}

const PROVENANCE_RULES: readonly ProvenanceRule[] = [
  {
    state: "FILE_BACKED_SHARED",
    kind: "shared-origin",
    strength: "signal",
    resourceFamily: "file/page-cache",
    reason: "file mapping or page-cache backing can preserve shared storage identity",
    patterns: [
      /\bpage[_-]?cache\b/i,
      /\bpage->mapping\b/,
      /\bmmap\s*\(/,
      /\bfilemap_[A-Za-z0-9_]*\b/,
      /\bread[_-]?only\b/i,
    ],
  },
  {
    state: "PIPE_PAGE_SHARED",
    kind: "alias-preserving-transport",
    strength: "strong",
    resourceFamily: "pipe/page",
    reason: "zero-copy pipe/splice transport can move page references without copying",
    patterns: [
      /\b(?:splice|vmsplice|sendfile|splice_to_pipe|splice_direct_to_actor|filemap_splice_read|copy_page_to_iter_pipe|push_pipe)\b/,
      /\bpipe_buffer\b/,
      /\bMSG_SPLICE_PAGES\b/,
    ],
  },
  {
    state: "ITER_SHARED",
    kind: "iterator-propagation",
    strength: "signal",
    resourceFamily: "iov_iter",
    reason: "iterator-backed segments may carry shared xarray, folio, pipe, or bvec storage",
    patterns: [
      /\biov_iter\b/,
      /\bITER_(?:PIPE|XARRAY|FOLIOQ|BVEC)\b/,
      /\bcopy_(?:page_)?to_iter\b/,
      /\bcopy_from_iter\b/,
    ],
  },
  {
    state: "SG_SHARED",
    kind: "scatterlist-alias",
    strength: "strong",
    resourceFamily: "scatterlist/page",
    reason: "scatterlist APIs preserve page references across crypto and scatterwalk calls",
    patterns: [
      /\bscatterlist\b/,
      /\bsg_set_page\s*\(/,
      /\bsg_page\s*\(/,
      /\bsg_chain\s*\(/,
      /\bscatterwalk_[A-Za-z0-9_]*\b/,
    ],
  },
  {
    state: "REQ_ALIAS_MUST",
    kind: "request-alias",
    strength: "strong",
    resourceFamily: "request src/dst",
    reason: "source and destination are explicitly the same request object or branch-refined alias",
    patterns: [
      /\breq->src\s*=\s*req->dst\b/,
      /\breq->dst\s*=\s*req->src\b/,
      /\bareq->aead_req\.src\s*=\s*areq->aead_req\.dst\b/,
      /\bsrc\s*==\s*dst\b/,
      /\breq->src\s*==\s*req->dst\b/,
      /\baead_req\.src\s*==\s*aead_req\.dst\b/,
    ],
  },
  {
    state: "REQ_ALIAS_MAY",
    kind: "request-alias",
    strength: "signal",
    resourceFamily: "request src/dst",
    reason: "request setup may bind caller source and destination into an in-place operation",
    patterns: [/\baead_request_set_crypt\s*\(/, /\b(?:in-place|inplace)\b/i],
  },
  {
    state: "MUTATED_SHARED",
    kind: "write-through-shared",
    strength: "strong",
    resourceFamily: "scatterlist/page",
    reason: "write primitive can mutate through a scatterlist or page-backed alias",
    patterns: [
      /\bscatterwalk_map_and_copy\s*\([^;\n]*,\s*1\s*\)/,
      /\bmemcpy_to_sglist\s*\(/,
      /\bmemcpy_to_page\s*\(/,
      /\b(?:cursor|dst|sg)->page->/i,
      /\bpage->dirty\s*=/,
    ],
  },
  {
    state: "VALIDATION_PENDING",
    kind: "validation-before-trust",
    strength: "signal",
    resourceFamily: "auth/tag/checksum",
    reason:
      "authentication, tag, checksum, or validation result still gates whether output is trusted",
    patterns: [
      /\b(?:auth|verify|validate|checksum|integrity|tag).*?(?:check|ok|fail|error|reject)/i,
      /\btag_ok\b/,
      /\bauthsize\b/,
      /\bcrypto_aead_decrypt\b/,
    ],
  },
  {
    state: "FAILED_AFTER_MUTATION",
    kind: "failure-after-mutation",
    strength: "strong",
    resourceFamily: "failure path",
    reason: "error return may preserve earlier writes unless a rollback or discard is proven",
    patterns: [
      /\bEBADMSG\b/,
      /\breturn\s+-E[A-Z0-9_]+\b/,
      /\breturn\s+-74\b/,
      /\bgoto\s+(?:err|error|fail|out)\b/i,
    ],
  },
  {
    state: "PRIVATE_OWNED",
    kind: "private-copy-guard",
    strength: "hard-guard",
    resourceFamily: "private copy",
    reason: "fresh private allocation or private copy can break shared-resource provenance",
    patterns: [
      /\b(?:kmalloc|kzalloc|malloc|calloc|alloc_page|__get_free_page|alloca)\s*\(/,
      /\bprivate_(?:dst|src|buf|page|copy)\b/i,
      /\bcopy_(?:page|from_iter_full|to_iter_full)\b/,
      /\b(?:clone|duplicate|dup)\b/i,
    ],
  },
  {
    state: "SAFE_COUNTEREXAMPLE",
    kind: "nonalias-guard",
    strength: "hard-guard",
    resourceFamily: "nonalias/shared guard",
    reason: "explicit non-alias or not-shared check can kill the provenance bug path",
    patterns: [
      /\bsrc\s*!=\s*dst\b/,
      /\breq->src\s*!=\s*req->dst\b/,
      /\bif\s*\([^)]*src\s*==\s*dst[^)]*\)\s*\{\s*return\b/,
      /\bif\s*\([^)]*req->src\s*==\s*req->dst[^)]*\)\s*\{\s*return\b/,
      /\bpage->mapping\s*==\s*NULL\b/,
      /\b!page->mapping\b/,
      /\bnot[_-]?shared\b/i,
    ],
  },
  {
    state: "SAFE_COUNTEREXAMPLE",
    kind: "rollback-guard",
    strength: "hard-guard",
    resourceFamily: "rollback/discard",
    reason: "failure path appears to restore, discard, wipe, or overwrite the mutated region",
    patterns: [
      /\b(?:rollback|restore|discard|revert|undo)\b/i,
      /\b(?:memzero_explicit|memset|wipe)\s*\(/,
      /\b(?:drop|release|put)_page\b/,
    ],
  },
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
  const provenanceFacts = await collectProvenanceFacts(
    repoRoot,
    relatedFiles,
    Math.max(surfacePackDepth * 6, surfacePackDepth),
  );
  const provenanceSummaries = await buildProvenanceSummaries({
    repoRoot,
    filePaths: relatedFiles,
    facts: provenanceFacts,
    limit: Math.max(surfacePackDepth * 2, surfacePackDepth),
  });
  const provenanceChains = buildProvenanceChains({
    surfaceId: surface.id,
    facts: provenanceFacts,
    summaries: provenanceSummaries,
    limit: Math.max(1, Math.min(3, surfacePackDepth)),
  });
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
    provenanceFacts,
    provenanceSummaries,
    provenanceChains,
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
    `Provenance facts: ${formatProvenanceFacts(pack.provenanceFacts)}`,
    `Function provenance summaries: ${formatProvenanceSummaries(pack.provenanceSummaries)}`,
    `Provenance chains: ${formatProvenanceChains(pack.provenanceChains)}`,
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

async function collectProvenanceFacts(
  repoRoot: string,
  filePaths: string[],
  limit: number,
): Promise<SystemsProvenanceFact[]> {
  const facts: SystemsProvenanceFact[] = [];
  const candidateLimit = Math.max(limit * 8, limit);
  for (const filePath of filePaths) {
    if (facts.length >= candidateLimit) break;
    const lines = await readLines(repoRoot, filePath);
    if (!lines) continue;

    for (let index = 0; index < lines.length && facts.length < candidateLimit; index += 1) {
      const line = lines[index];
      if (line.length > PACK_SCAN_LIMIT) continue;
      const snippet = line.trim();
      if (!snippet) continue;

      for (const rule of PROVENANCE_RULES) {
        if (!rule.patterns.some((pattern) => pattern.test(snippet))) continue;
        facts.push({
          filePath,
          line: index + 1,
          snippet,
          reason: rule.reason,
          state: rule.state,
          kind: rule.kind,
          strength: rule.strength,
          resourceFamily: rule.resourceFamily,
        });
        if (facts.length >= candidateLimit) break;
      }
      const contextualGuard = inferContextualProvenanceGuard(filePath, index, lines);
      if (contextualGuard && facts.length < candidateLimit) {
        facts.push(contextualGuard);
      }
    }
  }
  return prioritizeProvenanceFacts(dedupeProvenanceFacts(facts)).slice(0, limit);
}

function inferContextualProvenanceGuard(
  filePath: string,
  index: number,
  lines: string[],
): SystemsProvenanceFact | undefined {
  const snippet = lines[index]?.trim() ?? "";
  if (
    !/\b(?:src|req->src|(?:\w+->)?aead_req\.src)\s*==\s*(?:dst|req->dst|(?:\w+->)?aead_req\.dst)\b/.test(
      snippet,
    )
  ) {
    return undefined;
  }
  const lookahead = lines
    .slice(index, Math.min(lines.length, index + 4))
    .map((line) => line.trim())
    .join(" ");
  if (!/\breturn\s+-E[A-Z0-9_]+\b/.test(lookahead) && !/\breturn\s+-\d+\b/.test(lookahead)) {
    return undefined;
  }
  return {
    filePath,
    line: index + 1,
    snippet,
    reason: "alias equality is rejected before the downstream write path",
    state: "SAFE_COUNTEREXAMPLE",
    kind: "nonalias-guard",
    strength: "hard-guard",
    resourceFamily: "nonalias/shared guard",
  };
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

function formatProvenanceFacts(facts: SystemsProvenanceFact[]): string {
  if (facts.length === 0) return "none";
  return facts
    .map(
      (fact) =>
        `[${fact.state}/${fact.kind}/${fact.strength}] ${fact.filePath}:${fact.line} ${fact.snippet} (${fact.reason})`,
    )
    .join(" | ");
}

function formatProvenanceSummaries(summaries: SystemsProvenanceSummary[]): string {
  if (summaries.length === 0) return "none";
  return summaries
    .map(
      (summary) =>
        `[score=${summary.score}] ${summary.filePath}:${summary.startLine}-${summary.endLine} ${summary.summary}`,
    )
    .join(" | ");
}

function formatProvenanceChains(chains: SystemsProvenanceChain[]): string {
  if (chains.length === 0) return "none";
  return chains
    .map(
      (chain) =>
        `[${chain.status} score=${chain.score}] ${chain.narrative}${
          chain.guardSummary ? ` guard=${chain.guardSummary}` : ""
        }`,
    )
    .join(" | ");
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

function dedupeProvenanceFacts(facts: SystemsProvenanceFact[]): SystemsProvenanceFact[] {
  const seen = new Set<string>();
  const deduped: SystemsProvenanceFact[] = [];
  for (const fact of facts) {
    const key = `${fact.filePath}:${fact.line}:${fact.state}:${fact.kind}:${fact.snippet}`;
    if (seen.has(key)) continue;
    seen.add(key);
    deduped.push(fact);
  }
  return deduped;
}

function prioritizeProvenanceFacts(facts: SystemsProvenanceFact[]): SystemsProvenanceFact[] {
  const weight: Record<SystemsProvenanceFactStrength, number> = {
    "hard-guard": 3,
    strong: 2,
    signal: 1,
  };
  const stateWeight: Record<SystemsProvenanceState, number> = {
    SAFE_COUNTEREXAMPLE: 7,
    PRIVATE_OWNED: 6,
    FAILED_AFTER_MUTATION: 5,
    MUTATED_SHARED: 5,
    REQ_ALIAS_MUST: 4,
    PIPE_PAGE_SHARED: 4,
    FILE_BACKED_SHARED: 3,
    SG_SHARED: 3,
    REQ_ALIAS_MAY: 2,
    ITER_SHARED: 2,
    VALIDATION_PENDING: 1,
  };
  return [...facts].sort((left, right) => {
    if (weight[right.strength] !== weight[left.strength]) {
      return weight[right.strength] - weight[left.strength];
    }
    if (stateWeight[right.state] !== stateWeight[left.state]) {
      return stateWeight[right.state] - stateWeight[left.state];
    }
    if (left.filePath !== right.filePath) return left.filePath.localeCompare(right.filePath);
    return left.line - right.line;
  });
}

function dedupeStrings(values: string[]): string[] {
  return [...new Set(values.filter(Boolean))];
}

export const __systemsHelperInternals = {
  collectProvenanceFacts,
  inferAnchorSymbol,
  matchTriggerHypothesisToFinding,
};
