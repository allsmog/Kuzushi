import { readFile, stat } from "node:fs/promises";
import path from "node:path";
import { getCodeIntelligenceProvider, type ImportGraphEdge } from "../../analysis-support/index.js";
import { createLogger } from "../../logger.js";
import { coerceContextEnrichment, coerceFileIndex, coerceRepoContext } from "../../repo-context.js";
import { attachTaskOutputMeta } from "../../task-output-meta.js";
import type {
  ApplicationBackgroundJob,
  ApplicationDataStore,
  ApplicationModel,
  ApplicationOutboundClient,
  ApplicationRoute,
  ApplicationServiceBoundary,
  EnrichedRepoContext,
  FileIndex,
  ModelEvidenceAnchor,
  RepoContext,
  ScanOpts,
} from "../../types.js";
import type { DagNodeImpl } from "../types.js";

const log = createLogger({ stage: "app-model-build" });

const MAX_CANDIDATE_FILES = 120;
const MAX_FILE_BYTES = 200_000;
const MAX_BOUNDARIES = 30;

interface CandidateFile {
  filePath: string;
  content: string;
}

interface GoFunctionContext {
  name: string;
  startLine: number;
}

interface SyntheticEntryRoute {
  method: string;
  path: string;
  startLine: number;
  framework?: string;
  handlerSymbol?: string;
}

export const appModelBuildTask: DagNodeImpl<ScanOpts, ApplicationModel> = {
  id: "app-model-build",
  displayName: "Application Model Builder",
  outputKind: "custom",
  dependsOn: ["context-gatherer", "context-enricher"],

  async run(_input, context): Promise<ApplicationModel> {
    context.signal?.throwIfAborted();
    const repoContext = coerceRepoContext(context.upstreamOutputs.get("context-gatherer"));
    const enrichment = coerceContextEnrichment(context.upstreamOutputs.get("context-enricher"));
    const fileIndex = coerceFileIndex(context.upstreamOutputs.get("context-gatherer"));
    const intelligence = await getCodeIntelligenceProvider(context.repoRoot);
    context.signal?.throwIfAborted();
    const importGraph = await intelligence.getImportGraph();
    context.signal?.throwIfAborted();
    const candidateFiles = await loadCandidateFiles(
      context.repoRoot,
      repoContext,
      enrichment,
      fileIndex,
    );
    context.signal?.throwIfAborted();

    const routes = collectRoutes(candidateFiles, repoContext, enrichment);
    const outboundClients = collectOutboundClients(candidateFiles);
    const dataStores = collectDataStores(candidateFiles, repoContext);
    const backgroundJobs = collectBackgroundJobs(candidateFiles);
    const serviceBoundaries = collectServiceBoundaries(
      routes,
      outboundClients,
      dataStores,
      enrichment,
    );
    const relevantFiles = [
      ...new Set([
        ...routes.map((route) => route.filePath),
        ...outboundClients.map((client) => client.filePath),
        ...dataStores.map((store) => store.filePath),
        ...backgroundJobs.map((job) => job.filePath),
        ...serviceBoundaries.flatMap((boundary) =>
          boundary.evidenceAnchors.map((anchor) => anchor.filePath),
        ),
      ]),
    ].slice(0, 60);
    const notes = collectNotes(repoContext, enrichment, importGraph, candidateFiles);

    const model: ApplicationModel = {
      version: "1",
      routes,
      outboundClients,
      dataStores,
      backgroundJobs,
      serviceBoundaries,
      relevantFiles,
      notes,
    };

    log.info(
      `Built model routes=${routes.length} outbound=${outboundClients.length} stores=${dataStores.length} jobs=${backgroundJobs.length} boundaries=${serviceBoundaries.length}`,
    );

    return attachTaskOutputMeta(model, { costUsd: 0 });
  },
};

async function loadCandidateFiles(
  repoRoot: string,
  repoContext: RepoContext | undefined,
  enrichment: EnrichedRepoContext["enrichment"] | undefined,
  fileIndex: FileIndex | undefined,
): Promise<CandidateFile[]> {
  const candidates = new Set<string>();

  for (const entryPoint of repoContext?.entryPoints ?? []) {
    candidates.add(entryPoint);
  }

  for (const middleware of enrichment?.customMiddleware ?? []) {
    candidates.add(middleware.filePath);
  }

  for (const sanitizer of enrichment?.customSanitizers ?? []) {
    candidates.add(sanitizer.filePath);
  }

  for (const entry of fileIndex?.tree ?? []) {
    if (candidates.size >= MAX_CANDIDATE_FILES) {
      break;
    }
    if (isApplicationModelCandidate(entry.path)) {
      candidates.add(entry.path);
    }
  }

  const loaded: CandidateFile[] = [];
  for (const filePath of candidates) {
    if (loaded.length >= MAX_CANDIDATE_FILES) {
      break;
    }
    const absolutePath = path.join(repoRoot, filePath);
    try {
      const metadata = await stat(absolutePath);
      if (!metadata.isFile() || metadata.size > MAX_FILE_BYTES) {
        continue;
      }
      const content = await readFile(absolutePath, "utf-8");
      loaded.push({ filePath, content });
    } catch (err) {
      const code = (err as NodeJS.ErrnoException)?.code;
      if (code !== "ENOENT" && code !== "EACCES" && code !== "EISDIR") {
        log.warn(`app-model-build: skipping ${filePath} due to read error: ${String(err)}`);
      }
    }
  }

  return loaded;
}

function isApplicationModelCandidate(filePath: string): boolean {
  return (
    /(^|\/)(api|routes?|route|controllers?|handlers?|middleware|auth|guards?|resolvers?|graphql|clients?|services?|jobs?|workers?|queues?|models?|schemas?|repositories?|consumers?|producers?)(\/|\.|$)/i.test(
      filePath,
    ) ||
    /route\.(ts|tsx|js|jsx)$/i.test(filePath) ||
    /\.(graphql|gql)$/i.test(filePath)
  );
}

function collectRoutes(
  files: CandidateFile[],
  repoContext: RepoContext | undefined,
  enrichment: EnrichedRepoContext["enrichment"] | undefined,
): ApplicationRoute[] {
  const routes: ApplicationRoute[] = [];
  const seen = new Set<string>();

  for (const file of files) {
    const lines = file.content.split(/\r?\n/u);
    const controllerBasePath = extractControllerBasePath(file.content);
    let currentGoFunction: GoFunctionContext | undefined;

    for (let index = 0; index < lines.length; index += 1) {
      const line = lines[index] ?? "";
      const goFunction = extractGoFunctionContext(line, index + 1);
      if (goFunction) {
        currentGoFunction = goFunction;
      }
      const match =
        line.match(/\b(?:app|router)\.(get|post|put|patch|delete|all)\(\s*["'`]([^"'`]+)["'`]/i) ??
        line.match(/@(Get|Post|Put|Patch|Delete)\(\s*["'`]?(.*?)["'`]?\s*\)/) ??
        line.match(/@(app|router)\.(get|post|put|patch|delete)\(\s*["'`]([^"'`]+)["'`]/i) ??
        line.match(/\b\w+\.(GET|POST|PUT|PATCH|DELETE)\(\s*"([^"]+)"/) ??
        line.match(/export\s+(?:async\s+)?function\s+(GET|POST|PUT|PATCH|DELETE)\s*\(/);
      if (match) {
        const method = String(match[1] ?? "GET").toUpperCase();
        const rawPath =
          match[2] &&
          method !== "GET" &&
          method !== "POST" &&
          method !== "PUT" &&
          method !== "PATCH" &&
          method !== "DELETE"
            ? String(match[3] ?? "/")
            : String(match[2] ?? routePathFromFilePath(file.filePath));
        const routePath = normalizeRoutePath(
          controllerBasePath,
          rawPath || routePathFromFilePath(file.filePath),
        );
        const handlerSymbol =
          extractHandlerSymbol(line) ??
          routeHandlerFromExport(lines, index) ??
          currentGoFunction?.name ??
          path.basename(file.filePath);
        const middleware = extractMiddlewareHints(file.content, line, enrichment);
        const authMechanisms = extractAuthMechanisms(file.content, middleware, repoContext);
        const framework = detectRouteFramework(file.filePath, file.content);
        const id = [method, routePath, file.filePath, String(index + 1)].join("|");
        if (seen.has(id)) {
          continue;
        }
        seen.add(id);
        routes.push({
          id,
          method,
          path: routePath,
          filePath: file.filePath,
          startLine: index + 1,
          framework,
          handlerSymbol,
          middleware,
          authMechanisms,
        });
        continue;
      }

      const synthetic = detectSyntheticEntryRoute(line, index + 1, currentGoFunction);
      if (!synthetic) {
        continue;
      }

      const id = [
        synthetic.method,
        synthetic.path,
        file.filePath,
        String(synthetic.startLine),
      ].join("|");
      if (seen.has(id)) {
        continue;
      }
      seen.add(id);
      routes.push({
        id,
        method: synthetic.method,
        path: synthetic.path,
        filePath: file.filePath,
        startLine: synthetic.startLine,
        framework: synthetic.framework ?? detectRouteFramework(file.filePath, file.content),
        handlerSymbol:
          synthetic.handlerSymbol ?? currentGoFunction?.name ?? path.basename(file.filePath),
        middleware: [],
        authMechanisms: extractAuthMechanisms(file.content, [], repoContext),
      });
    }
  }

  return routes.slice(0, 80);
}

function collectOutboundClients(files: CandidateFile[]): ApplicationOutboundClient[] {
  const results: ApplicationOutboundClient[] = [];
  const patterns: Array<{ kind: string; regex: RegExp }> = [
    { kind: "fetch", regex: /\bfetch\(/g },
    { kind: "axios", regex: /\baxios\.(?:get|post|put|patch|delete|request)\(/g },
    { kind: "http-client", regex: /\b(?:http|https)\.(?:get|request)\(/g },
    { kind: "requests", regex: /\brequests\.(?:get|post|put|delete|request)\(/g },
    { kind: "urllib", regex: /\burllib\.(?:request|urlopen)/g },
    { kind: "graphql-client", regex: /\bgraphql(?:Client)?\.(?:request|query|mutate)\(/g },
    { kind: "websocket", regex: /\b(?:new\s+WebSocket|ws\.connect)\(/g },
  ];

  for (const file of files) {
    const lines = file.content.split(/\r?\n/u);
    for (let index = 0; index < lines.length; index += 1) {
      const line = lines[index] ?? "";
      for (const pattern of patterns) {
        if (!pattern.regex.test(line)) {
          pattern.regex.lastIndex = 0;
          continue;
        }
        pattern.regex.lastIndex = 0;
        results.push({
          id: `${pattern.kind}|${file.filePath}|${index + 1}`,
          kind: pattern.kind,
          filePath: file.filePath,
          startLine: index + 1,
          symbol: extractInvocationSymbol(line),
          targetHint: extractQuotedString(line),
          protocol: detectProtocolHint(line),
        });
      }
    }
  }

  return dedupeById(results).slice(0, 80);
}

function collectDataStores(
  files: CandidateFile[],
  repoContext: RepoContext | undefined,
): ApplicationDataStore[] {
  const results: ApplicationDataStore[] = [];
  const kinds = repoContext?.ormOrDb ?? [];
  for (const file of files) {
    const lines = file.content.split(/\r?\n/u);
    for (let index = 0; index < lines.length; index += 1) {
      const line = lines[index] ?? "";
      if (
        !/\b(prisma|sequelize|typeorm|mongoose|knex|redis|mongo|sql|query|collection|repository|model)\b/i.test(
          line,
        )
      ) {
        continue;
      }
      const kind =
        kinds.find((value) =>
          new RegExp(value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "i").test(line),
        ) ?? inferDataStoreKind(file.filePath, line);
      results.push({
        id: `${kind}|${file.filePath}|${index + 1}`,
        kind,
        name: extractStoreName(line) ?? path.basename(file.filePath),
        filePath: file.filePath,
        startLine: index + 1,
      });
    }
  }

  return dedupeById(results).slice(0, 60);
}

function collectBackgroundJobs(files: CandidateFile[]): ApplicationBackgroundJob[] {
  const results: ApplicationBackgroundJob[] = [];
  for (const file of files) {
    const lines = file.content.split(/\r?\n/u);
    for (let index = 0; index < lines.length; index += 1) {
      const line = lines[index] ?? "";
      if (
        !/\b(queue|job|worker|consumer|producer|cron|schedule|bull|celery|sidekiq|agenda)\b/i.test(
          line,
        )
      ) {
        continue;
      }
      results.push({
        id: `${file.filePath}|${index + 1}`,
        name: extractInvocationSymbol(line) ?? path.basename(file.filePath),
        filePath: file.filePath,
        startLine: index + 1,
        queue: extractQuotedString(line),
        handlerSymbol: extractHandlerSymbol(line),
      });
    }
  }

  return dedupeById(results).slice(0, 40);
}

function collectServiceBoundaries(
  routes: ApplicationRoute[],
  outboundClients: ApplicationOutboundClient[],
  dataStores: ApplicationDataStore[],
  enrichment: EnrichedRepoContext["enrichment"] | undefined,
): ApplicationServiceBoundary[] {
  const boundaries: ApplicationServiceBoundary[] = [];

  for (const trustBoundary of enrichment?.trustBoundaries ?? []) {
    boundaries.push({
      id: `trust-zone|${trustBoundary.name}`,
      name: trustBoundary.name,
      kind: "trust-zone",
      description: trustBoundary.description,
      evidenceAnchors: (trustBoundary.entryPoints ?? []).slice(0, 3).map((entryPoint) => ({
        filePath: entryPoint,
        startLine: 1,
        description: trustBoundary.description,
      })),
    });
  }

  for (const route of routes.slice(0, 12)) {
    boundaries.push({
      id: `entrypoint|${route.id}`,
      name: `${route.method} ${route.path}`,
      kind: "entrypoint",
      description: `External entry point handled by ${route.handlerSymbol ?? route.filePath}`,
      evidenceAnchors: [anchor(route.filePath, route.startLine, `${route.method} ${route.path}`)],
    });
  }

  for (const client of outboundClients.slice(0, 12)) {
    boundaries.push({
      id: `outbound|${client.id}`,
      name: client.symbol ?? client.kind,
      kind: "outbound",
      description: `Outbound ${client.kind} client${client.targetHint ? ` targeting ${client.targetHint}` : ""}`,
      evidenceAnchors: [anchor(client.filePath, client.startLine, client.kind)],
    });
  }

  for (const store of dataStores.slice(0, 6)) {
    boundaries.push({
      id: `datastore|${store.id}`,
      name: store.name,
      kind: "datastore",
      description: `${store.kind} access point`,
      evidenceAnchors: [anchor(store.filePath, store.startLine, store.kind)],
    });
  }

  return dedupeById(boundaries).slice(0, MAX_BOUNDARIES);
}

function collectNotes(
  repoContext: RepoContext | undefined,
  enrichment: EnrichedRepoContext["enrichment"] | undefined,
  importGraph: ImportGraphEdge[],
  files: CandidateFile[],
): string[] {
  const notes = new Set<string>();
  for (const note of enrichment?.architecturalNotes ?? []) {
    notes.add(note);
  }
  if ((repoContext?.frameworks ?? []).length > 0) {
    notes.add(`Frameworks observed: ${repoContext?.frameworks.join(", ")}`);
  }
  if ((repoContext?.authPatterns ?? []).length > 0) {
    notes.add(`Auth mechanisms observed: ${repoContext?.authPatterns.join(", ")}`);
  }
  if (importGraph.length > 0) {
    notes.add(`Import graph edges indexed: ${importGraph.length}`);
  }
  if (files.some((file) => /graphql|resolver|schema/i.test(file.filePath))) {
    notes.add("GraphQL-like surface detected in candidate files.");
  }
  return [...notes].slice(0, 20);
}

function extractControllerBasePath(content: string): string | undefined {
  return content.match(/@Controller\(\s*["'`]([^"'`]+)["'`]\s*\)/)?.[1];
}

function normalizeRoutePath(basePath: string | undefined, routePath: string): string {
  const normalizedBase = (basePath ?? "").trim().replace(/\/+$/u, "");
  const normalizedRoute = routePath.trim() || "/";
  if (!normalizedBase) {
    return normalizedRoute;
  }
  if (normalizedRoute.startsWith("/")) {
    return `${normalizedBase}${normalizedRoute}`;
  }
  return `${normalizedBase}/${normalizedRoute}`;
}

function routePathFromFilePath(filePath: string): string {
  const normalized = filePath.replace(/\\/g, "/");
  const apiIndex = normalized.indexOf("/api/");
  if (apiIndex >= 0) {
    const raw = normalized.slice(apiIndex + 4).replace(/\.(ts|tsx|js|jsx)$/i, "");
    return `/${raw.replace(/\/route$/i, "").replace(/\[([^\]]+)\]/g, ":$1")}`;
  }
  return `/${path.basename(normalized).replace(/\.(ts|tsx|js|jsx|py|go)$/i, "")}`;
}

function routeHandlerFromExport(lines: string[], index: number): string | undefined {
  for (let offset = 0; offset <= 4 && index + offset < lines.length; offset += 1) {
    const line = lines[index + offset] ?? "";
    const match = line.match(/function\s+([A-Za-z0-9_]+)/);
    if (match?.[1]) {
      return match[1];
    }
  }
  return undefined;
}

function extractGoFunctionContext(line: string, startLine: number): GoFunctionContext | undefined {
  const match = line.match(/^\s*func\s+(?:\([^)]*\)\s*)?([A-Za-z_][A-Za-z0-9_]*)\s*\(/);
  if (!match?.[1]) {
    return undefined;
  }
  return {
    name: match[1],
    startLine,
  };
}

function extractHandlerSymbol(line: string): string | undefined {
  return (
    line.match(/,\s*([A-Za-z0-9_$.]+)\s*\)?\s*$/)?.[1] ??
    line.match(/function\s+([A-Za-z0-9_]+)/)?.[1] ??
    undefined
  );
}

function detectSyntheticEntryRoute(
  line: string,
  lineNumber: number,
  currentGoFunction: GoFunctionContext | undefined,
): SyntheticEntryRoute | undefined {
  if (/^\s*func\s+main\s*\(/.test(line)) {
    return {
      method: "CLI",
      path: "cli://main",
      startLine: lineNumber,
      framework: "CLI",
      handlerSymbol: "main",
    };
  }

  if (/^\s*func\s+init\s*\(/.test(line)) {
    return {
      method: "INIT",
      path: "go://init",
      startLine: lineNumber,
      framework: "Go",
      handlerSymbol: "init",
    };
  }

  if (/\bgrpc\.NewServer\s*\(/.test(line)) {
    return {
      method: "GRPC",
      path: `grpc://${currentGoFunction?.name ?? "server"}`,
      startLine: lineNumber,
      framework: "gRPC",
      handlerSymbol: currentGoFunction?.name,
    };
  }

  if (/\bnet\.Listen(?:TCP|UDP|Unix)?\s*\(/.test(line)) {
    const quoted = extractQuotedStrings(line);
    const protocol = quoted[0] ?? "tcp";
    const address = quoted[1] ?? currentGoFunction?.name ?? "listen";
    return {
      method: protocol.toUpperCase(),
      path: `${protocol}://${address}`,
      startLine: lineNumber,
      framework: "Go net",
      handlerSymbol: currentGoFunction?.name,
    };
  }

  if (/\bhttp\.ListenAndServe(?:TLS)?\s*\(/.test(line)) {
    const [address] = extractQuotedStrings(line);
    return {
      method: "HTTP",
      path: `http://${address ?? currentGoFunction?.name ?? "listen"}`,
      startLine: lineNumber,
      framework: "net/http",
      handlerSymbol: currentGoFunction?.name,
    };
  }

  if (
    /\bflag\.(?:String|Bool|Int|Int64|Uint|Uint64|Float64|Duration|Var|Parse)\s*\(/.test(line) ||
    /\bcobra\.Command\b/.test(line) ||
    /\b(?:cli\.App|kong\.Parse)\s*\(/.test(line) ||
    /\b[A-Za-z_][A-Za-z0-9_]*\.(?:Execute|ExecuteContext)\s*\(/.test(line)
  ) {
    return {
      method: "CLI",
      path: `cli://${currentGoFunction?.name ?? "flags"}`,
      startLine: currentGoFunction?.startLine ?? lineNumber,
      framework: "CLI",
      handlerSymbol: currentGoFunction?.name ?? "flags",
    };
  }

  return undefined;
}

function extractMiddlewareHints(
  content: string,
  routeLine: string,
  enrichment: EnrichedRepoContext["enrichment"] | undefined,
): string[] {
  const hints = new Set<string>();
  for (const token of [
    "auth",
    "session",
    "passport",
    "jwt",
    "guard",
    "acl",
    "rbac",
    "permission",
    "csrf",
    "rateLimit",
  ]) {
    if (
      new RegExp(`\\b${token}\\b`, "i").test(routeLine) ||
      new RegExp(`\\b${token}\\b`, "i").test(content)
    ) {
      hints.add(token);
    }
  }
  for (const middleware of enrichment?.customMiddleware ?? []) {
    if (content.includes(middleware.name) || routeLine.includes(middleware.name)) {
      hints.add(middleware.name);
    }
  }
  return [...hints].slice(0, 8);
}

function extractAuthMechanisms(
  content: string,
  middleware: string[],
  repoContext: RepoContext | undefined,
): string[] {
  const mechanisms = new Set<string>(repoContext?.authPatterns ?? []);
  for (const item of middleware) {
    if (/auth|jwt|session|guard|passport/i.test(item)) {
      mechanisms.add(item);
    }
  }
  if (/req\.user|context\.user|current_user|@UseGuards|Authorize/i.test(content)) {
    mechanisms.add("user-context");
  }
  return [...mechanisms].slice(0, 8);
}

function detectRouteFramework(filePath: string, content: string): string | undefined {
  if (/next\/|src\/app\/api|src\/pages\/api/i.test(filePath)) {
    return "Next.js";
  }
  if (/express|router\.(get|post|put|delete)/i.test(content)) {
    return "Express";
  }
  if (/@Controller|@Get|@Post/i.test(content)) {
    return "NestJS";
  }
  if (/@app\.(get|post|put|patch|delete)|APIRouter/i.test(content)) {
    return "FastAPI";
  }
  if (/\bgrpc\.NewServer\s*\(/.test(content)) {
    return "gRPC";
  }
  if (
    /\b(?:flag\.(?:String|Bool|Int|Int64|Uint|Uint64|Float64|Duration|Var|Parse)|cobra\.Command|cli\.App|kong\.Parse)\b/.test(
      content,
    ) ||
    /\b[A-Za-z_][A-Za-z0-9_]*\.(?:Execute|ExecuteContext)\s*\(/.test(content)
  ) {
    return "CLI";
  }
  if (
    /\b(?:http\.ListenAndServe|http\.HandleFunc|http\.ResponseWriter|http\.Request)\b/.test(content)
  ) {
    return "net/http";
  }
  if (/\b\w+\.(GET|POST|PUT|PATCH|DELETE)\(/.test(content)) {
    return "Gin/Echo";
  }
  return undefined;
}

function extractInvocationSymbol(line: string): string | undefined {
  return line.match(/\b([A-Za-z0-9_$.]+)\s*\(/)?.[1];
}

function extractQuotedString(line: string): string | undefined {
  return line.match(/["'`]([^"'`]+)["'`]/)?.[1];
}

function extractQuotedStrings(line: string): string[] {
  return [...line.matchAll(/["'`]([^"'`]+)["'`]/g)].map((match) => match[1]).filter(Boolean);
}

function detectProtocolHint(line: string): string | undefined {
  return line.match(/\b(https?|wss?|gopher|file):\/\//i)?.[1]?.toLowerCase();
}

function inferDataStoreKind(filePath: string, line: string): string {
  if (/mongo|mongoose/i.test(line) || /mongo/i.test(filePath)) {
    return "MongoDB";
  }
  if (/redis/i.test(line) || /redis/i.test(filePath)) {
    return "Redis";
  }
  if (/prisma/i.test(line) || /prisma/i.test(filePath)) {
    return "Prisma";
  }
  if (/sequelize/i.test(line) || /sequelize/i.test(filePath)) {
    return "Sequelize";
  }
  if (/sql|query|select|insert|update|delete/i.test(line)) {
    return "SQL";
  }
  return "datastore";
}

function extractStoreName(line: string): string | undefined {
  return (
    line.match(/\b(?:model|collection|table|repository|client)\s*[:=]?\s*([A-Za-z0-9_]+)/i)?.[1] ??
    line.match(/\b([A-Za-z0-9_]+)(?:Repository|Model|Client)\b/)?.[1]
  );
}

function anchor(filePath: string, startLine: number, description: string): ModelEvidenceAnchor {
  return {
    filePath,
    startLine,
    description,
  };
}

function dedupeById<T extends { id: string }>(items: T[]): T[] {
  const deduped = new Map<string, T>();
  for (const item of items) {
    if (!deduped.has(item.id)) {
      deduped.set(item.id, item);
    }
  }
  return [...deduped.values()];
}

export const __appModelBuildInternals = {
  collectRoutes,
  detectRouteFramework,
  detectSyntheticEntryRoute,
  extractGoFunctionContext,
};
