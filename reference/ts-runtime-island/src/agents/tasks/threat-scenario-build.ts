import { attachTaskOutputMeta } from "../../task-output-meta.js";
import { loadPersistentThreatModel } from "../../threat-model-renderer.js";
import type {
  ApplicationModel,
  ModelEvidenceAnchor,
  ThreatScenario,
  ThreatScenarioDetectorId,
} from "../../types.js";
import { isRecord } from "../../utils.js";
import type { DagNodeImpl } from "../types.js";
import { resolveThreatModelOutput } from "./threat-model-guidance.js";
import type { ThreatModelDocument } from "./threat-modeling/types.js";

export interface ThreatScenarioBuildOutput {
  scenarios: ThreatScenario[];
}

const DETECTOR_MATCHERS: Array<{
  detectorId: ThreatScenarioDetectorId;
  cwes?: string[];
  keywords: string[];
  expectedGuard: string;
}> = [
  {
    detectorId: "ssrf-detect",
    cwes: ["918"],
    keywords: ["ssrf", "url", "metadata", "internal service", "redirect", "fetch", "http client"],
    expectedGuard: "Destination allowlist and strict hostname/IP validation",
  },
  {
    detectorId: "auth-access-detect",
    cwes: ["639", "862", "863", "915", "384", "345"],
    keywords: [
      "auth",
      "authorization",
      "idor",
      "permission",
      "role",
      "session",
      "tenant",
      "ownership",
    ],
    expectedGuard: "Router-level authentication and object-level authorization checks",
  },
  {
    detectorId: "security-misconfig-detect",
    cwes: ["942", "614", "489", "307", "347"],
    keywords: ["cors", "cookie", "debug", "header", "admin", "metrics", "jwt", "rate limit"],
    expectedGuard: "Environment-aware production hardening and secure defaults",
  },
  {
    detectorId: "dangerous-api-detect",
    cwes: ["78", "94", "95", "22", "502", "611", "90", "1333"],
    keywords: ["eval", "exec", "deserialize", "subprocess", "file", "xxe", "ldap", "regex"],
    expectedGuard: "Validated inputs and safe API usage patterns",
  },
  {
    detectorId: "graphql-security-detect",
    keywords: ["graphql", "resolver", "schema", "introspection", "query depth", "batch"],
    expectedGuard: "Resolver authz and query complexity/depth controls",
  },
  {
    detectorId: "template-injection-detect",
    cwes: ["1336"],
    keywords: ["template", "render", "jinja", "ejs", "pug", "handlebars", "ssti"],
    expectedGuard: "Static template sources and escaped context handling",
  },
  {
    detectorId: "prototype-pollution-detect",
    cwes: ["1321"],
    keywords: ["prototype", "__proto__", "constructor", "merge"],
    expectedGuard: "Prototype key filtering and safe merge utilities",
  },
  {
    detectorId: "nosql-injection-detect",
    cwes: ["943"],
    keywords: ["mongo", "nosql", "operator", "query object", "$where", "$regex"],
    expectedGuard: "Query shape validation and operator allowlists",
  },
  {
    detectorId: "race-condition-detect",
    cwes: ["362"],
    keywords: ["race", "concurrent", "lock", "toctou", "queue"],
    expectedGuard: "Locking, transactional guards, or idempotency controls",
  },
];

export const threatScenarioBuildTask: DagNodeImpl<unknown, ThreatScenarioBuildOutput> = {
  id: "threat-scenario-build",
  displayName: "Threat Scenario Builder",
  outputKind: "custom",
  dependsOn: ["app-model-build", "threat-model-randori"],

  async run(_input, context): Promise<ThreatScenarioBuildOutput> {
    context.signal?.throwIfAborted();
    const appModel = asApplicationModel(context.upstreamOutputs.get("app-model-build"));
    const strideOutput =
      asStrideDocument(resolveThreatModelOutput(context.upstreamOutputs)) ??
      loadPersistentThreatModel(context.repoRoot);
    if (!appModel || !strideOutput) {
      return attachTaskOutputMeta({ scenarios: [] }, { costUsd: 0 });
    }

    const scenarios = buildThreatScenarios(appModel, strideOutput);
    return attachTaskOutputMeta({ scenarios }, { costUsd: 0 });
  },
};

function buildThreatScenarios(
  appModel: ApplicationModel,
  strideDocument: ThreatModelDocument,
): ThreatScenario[] {
  const scenarios: ThreatScenario[] = [];

  for (const threat of strideDocument.threats) {
    const normalizedText = normalizeThreatText(threat);
    const normalizedCwes = normalizeCwes(threat.relatedCwe);
    const relatedFiles = collectThreatFiles(threat);
    const relatedRoute = findRelatedRoute(appModel, relatedFiles);
    const relatedClient = findRelatedClient(appModel, relatedFiles);
    const relatedStore = findRelatedStore(appModel, relatedFiles);
    const evidenceAnchors = collectEvidenceAnchors(threat);
    const relatedSymbols = [
      relatedRoute?.handlerSymbol,
      relatedClient?.symbol,
      relatedStore?.name,
    ].filter((value): value is string => Boolean(value));

    for (const matcher of DETECTOR_MATCHERS) {
      if (!matchesDetector(matcher, normalizedText, normalizedCwes, relatedFiles, appModel)) {
        continue;
      }

      const id = `${matcher.detectorId}|${threat.id}`;
      scenarios.push({
        id,
        detectorId: matcher.detectorId,
        title: threat.title,
        rationale: threat.description || threat.attackVector,
        attackSurface: relatedRoute
          ? `${relatedRoute.method} ${relatedRoute.path}`
          : threat.attackVector,
        expectedGuard: matcher.expectedGuard,
        relatedFiles,
        relatedSymbols,
        sourceThreatIds: [threat.id],
        cwe: threat.relatedCwe,
        entryPoint: relatedRoute
          ? {
              kind: "route",
              filePath: relatedRoute.filePath,
              startLine: relatedRoute.startLine,
              method: relatedRoute.method,
              path: relatedRoute.path,
              handlerSymbol: relatedRoute.handlerSymbol,
            }
          : undefined,
        sink: relatedClient
          ? {
              kind: relatedClient.kind,
              filePath: relatedClient.filePath,
              startLine: relatedClient.startLine,
              symbol: relatedClient.symbol,
              detail: relatedClient.targetHint,
            }
          : relatedStore
            ? {
                kind: relatedStore.kind,
                filePath: relatedStore.filePath,
                startLine: relatedStore.startLine,
                symbol: relatedStore.name,
              }
            : undefined,
        evidenceAnchors,
      });
    }
  }

  return dedupeScenarios(scenarios).slice(0, 120);
}

function matchesDetector(
  matcher: (typeof DETECTOR_MATCHERS)[number],
  normalizedText: string,
  normalizedCwes: Set<string>,
  relatedFiles: string[],
  appModel: ApplicationModel,
): boolean {
  if ((matcher.cwes ?? []).some((cwe) => normalizedCwes.has(cwe))) {
    return true;
  }

  if (matcher.keywords.some((keyword) => normalizedText.includes(keyword))) {
    return true;
  }

  if (matcher.detectorId === "graphql-security-detect") {
    return (
      relatedFiles.some((file) => /graphql|resolver|schema/i.test(file)) ||
      appModel.routes.some((route) => /graphql/i.test(route.path))
    );
  }

  if (matcher.detectorId === "security-misconfig-detect") {
    return relatedFiles.some((file) => /(config|docker|yaml|workflow|session|auth)/i.test(file));
  }

  if (matcher.detectorId === "auth-access-detect") {
    return appModel.routes.some(
      (route) => relatedFiles.includes(route.filePath) && route.authMechanisms.length > 0,
    );
  }

  return false;
}

function collectThreatFiles(threat: ThreatModelDocument["threats"][number]): string[] {
  const files = new Set<string>();
  for (const file of threat.affectedFiles) {
    files.add(normalizePath(file.filePath));
  }
  for (const anchor of threat.evidenceAnchors ?? []) {
    files.add(normalizePath(anchor.filePath));
  }
  return [...files];
}

function collectEvidenceAnchors(
  threat: ThreatModelDocument["threats"][number],
): ModelEvidenceAnchor[] {
  const anchors = (threat.evidenceAnchors ?? []).map((anchor) => ({
    filePath: normalizePath(anchor.filePath),
    startLine: anchor.startLine,
    description: anchor.description,
  }));
  if (anchors.length > 0) {
    return anchors.slice(0, 4);
  }

  return threat.affectedFiles.slice(0, 4).map((file) => ({
    filePath: normalizePath(file.filePath),
    startLine: file.startLine,
    description: threat.title,
  }));
}

function findRelatedRoute(appModel: ApplicationModel, files: string[]) {
  return appModel.routes.find((route) => files.some((file) => pathsOverlap(file, route.filePath)));
}

function findRelatedClient(appModel: ApplicationModel, files: string[]) {
  return appModel.outboundClients.find((client) =>
    files.some((file) => pathsOverlap(file, client.filePath)),
  );
}

function findRelatedStore(appModel: ApplicationModel, files: string[]) {
  return appModel.dataStores.find((store) =>
    files.some((file) => pathsOverlap(file, store.filePath)),
  );
}

function normalizeThreatText(threat: ThreatModelDocument["threats"][number]): string {
  return [
    threat.title,
    threat.description,
    threat.attackVector,
    ...threat.preconditions,
    ...threat.existingMitigations,
    ...threat.missingMitigations,
  ]
    .join(" ")
    .toLowerCase();
}

function normalizeCwes(values: string[]): Set<string> {
  const cwes = new Set<string>();
  for (const value of values) {
    const match = value.match(/(\d+)/);
    if (match?.[1]) {
      cwes.add(match[1]);
    }
  }
  return cwes;
}

function normalizePath(filePath: string): string {
  return filePath.replace(/\\/g, "/").replace(/^\.\//u, "");
}

function pathsOverlap(left: string, right: string): boolean {
  const a = normalizePath(left).toLowerCase();
  const b = normalizePath(right).toLowerCase();
  return a === b || a.endsWith(`/${b}`) || b.endsWith(`/${a}`);
}

function asStrideDocument(value: unknown): ThreatModelDocument | undefined {
  if (!isRecord(value) || !isRecord(value["document"])) {
    return undefined;
  }
  const document = value["document"];
  if (!isRecord(document) || !Array.isArray(document["threats"])) {
    return undefined;
  }
  return document as unknown as ThreatModelDocument;
}

function asApplicationModel(value: unknown): ApplicationModel | undefined {
  if (
    !isRecord(value) ||
    !Array.isArray(value["routes"]) ||
    !Array.isArray(value["serviceBoundaries"])
  ) {
    return undefined;
  }
  return value as unknown as ApplicationModel;
}

function dedupeScenarios(scenarios: ThreatScenario[]): ThreatScenario[] {
  const deduped = new Map<string, ThreatScenario>();
  for (const scenario of scenarios) {
    if (!deduped.has(scenario.id)) {
      deduped.set(scenario.id, scenario);
    }
  }
  return [...deduped.values()];
}

export const __threatScenarioBuildInternals = {
  asApplicationModel,
  asStrideDocument,
  buildThreatScenarios,
  collectThreatFiles,
  matchesDetector,
};
