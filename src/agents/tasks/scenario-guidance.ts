import { getCodeIntelligenceProvider } from "../../analysis-support/index.js";
import { isRecord } from "../../utils.js";
import type {
  ApplicationModel,
  ApplicationOutboundClient,
  ApplicationRoute,
  ThreatScenario,
  ThreatScenarioDetectorId,
} from "../../types.js";

export type ScenarioAwareDetectorTaskId =
  | ThreatScenarioDetectorId
  | "supply-chain-detect";

interface ThreatScenarioOutputLike {
  scenarios: ThreatScenario[];
}

export function buildApplicationModelSection(
  taskId: ScenarioAwareDetectorTaskId,
  applicationModel: ApplicationModel | undefined,
): string {
  if (!applicationModel) {
    return "";
  }

  const routes = selectRoutes(taskId, applicationModel.routes).slice(0, 4);
  const outbound = selectOutboundClients(taskId, applicationModel.outboundClients).slice(0, 4);
  const lines: string[] = ["## Application model"];

  if (routes.length > 0) {
    lines.push("Routes:");
    for (const route of routes) {
      lines.push(`- ${route.method} ${route.path} -> ${route.handlerSymbol ?? route.filePath} (${route.filePath}:${route.startLine})`);
      if (route.middleware.length > 0 || route.authMechanisms.length > 0) {
        lines.push(`  Guards: ${[...route.middleware, ...route.authMechanisms].slice(0, 5).join(", ")}`);
      }
    }
  }

  if (outbound.length > 0) {
    lines.push("Outbound clients:");
    for (const client of outbound) {
      const hint = client.targetHint ? ` target=${client.targetHint}` : "";
      lines.push(`- ${client.kind}${hint} (${client.filePath}:${client.startLine})`);
    }
  }

  if (applicationModel.notes.length > 0) {
    lines.push("Model notes:");
    for (const note of applicationModel.notes.slice(0, 4)) {
      lines.push(`- ${note}`);
    }
  }

  lines.push("");
  return lines.join("\n");
}

export async function buildThreatScenarioEvidenceSection(
  taskId: ScenarioAwareDetectorTaskId,
  repoRoot: string,
  applicationModel: ApplicationModel | undefined,
  scenarioOutput: unknown,
): Promise<string> {
  const parsed = asThreatScenarioOutput(scenarioOutput);
  if (!applicationModel || !parsed || parsed.scenarios.length === 0) {
    return "";
  }

  const selected = selectScenarios(taskId, parsed.scenarios).slice(0, 5);
  if (selected.length === 0) {
    return "";
  }

  const intelligence = await getCodeIntelligenceProvider(repoRoot);
  const lines = ["## Threat scenarios to validate"];

  for (const scenario of selected) {
    lines.push(`- [${scenario.id}] ${scenario.title}`);
    lines.push(`  Why relevant: ${scenario.rationale}`);
    lines.push(`  Surface: ${scenario.attackSurface}`);
    if (scenario.expectedGuard) {
      lines.push(`  Expected guard: ${scenario.expectedGuard}`);
    }
    if (scenario.entryPoint) {
      const snippet = await intelligence.getSnippet(scenario.entryPoint.filePath, scenario.entryPoint.startLine);
      lines.push(`  Entry point: ${scenario.entryPoint.filePath}:${scenario.entryPoint.startLine}${scenario.entryPoint.method ? ` (${scenario.entryPoint.method} ${scenario.entryPoint.path ?? ""})` : ""}`);
      if (snippet) {
        lines.push(`  Entry snippet: ${snippet}`);
      }
    }
    if (scenario.sink) {
      const snippet = await intelligence.getSnippet(scenario.sink.filePath, scenario.sink.startLine);
      lines.push(`  Sink: ${scenario.sink.kind} at ${scenario.sink.filePath}:${scenario.sink.startLine}${scenario.sink.symbol ? ` [${scenario.sink.symbol}]` : ""}`);
      if (snippet) {
        lines.push(`  Sink snippet: ${snippet}`);
      }
    }
    if (scenario.relatedSymbols.length > 0) {
      const symbolEvidence = await collectSymbolEvidence(intelligence, scenario.relatedSymbols);
      if (symbolEvidence.length > 0) {
        lines.push(`  Symbol evidence: ${symbolEvidence.join("; ")}`);
      }
    }
    if (scenario.relatedFiles.length > 0) {
      lines.push(`  Files: ${scenario.relatedFiles.slice(0, 5).join(", ")}`);
    }
    if (scenario.evidenceAnchors.length > 0) {
      lines.push(
        `  Anchors: ${scenario.evidenceAnchors.slice(0, 3).map((anchor) => `${anchor.filePath}:${anchor.startLine} (${anchor.description})`).join("; ")}`,
      );
    }
  }

  lines.push("");
  return lines.join("\n");
}

function asThreatScenarioOutput(value: unknown): ThreatScenarioOutputLike | undefined {
  if (!isRecord(value) || !Array.isArray(value["scenarios"])) {
    return undefined;
  }
  return value as unknown as ThreatScenarioOutputLike;
}

function selectScenarios(
  taskId: ScenarioAwareDetectorTaskId,
  scenarios: ThreatScenario[],
): ThreatScenario[] {
  if (taskId === "code-config-detect") {
    return scenarios.filter((scenario) =>
      scenario.detectorId === "dangerous-api-detect"
      || scenario.detectorId === "auth-access-detect"
      || scenario.detectorId === "security-misconfig-detect",
    );
  }

  return scenarios.filter((scenario) => scenario.detectorId === taskId);
}

function selectRoutes(
  taskId: ScenarioAwareDetectorTaskId,
  routes: ApplicationRoute[],
): ApplicationRoute[] {
  if (taskId === "ssrf-detect") {
    return routes.filter((route) => route.method !== "GET" || route.authMechanisms.length > 0);
  }
  if (taskId === "graphql-security-detect") {
    return routes.filter((route) => /graphql/i.test(route.path) || /graphql|resolver/i.test(route.filePath));
  }
  if (taskId === "auth-access-detect" || taskId === "code-config-detect") {
    return routes.filter((route) => route.authMechanisms.length > 0 || route.middleware.length > 0);
  }
  return routes;
}

function selectOutboundClients(
  taskId: ScenarioAwareDetectorTaskId,
  clients: ApplicationOutboundClient[],
): ApplicationOutboundClient[] {
  if (taskId === "ssrf-detect") {
    return clients.filter((client) => client.kind !== "graphql-client");
  }
  if (taskId === "graphql-security-detect") {
    return clients.filter((client) => client.kind === "graphql-client");
  }
  return clients;
}

async function collectSymbolEvidence(
  intelligence: Awaited<ReturnType<typeof getCodeIntelligenceProvider>>,
  symbols: string[],
): Promise<string[]> {
  const evidence: string[] = [];
  for (const symbol of symbols.slice(0, 3)) {
    const matches = await intelligence.findSymbol({ symbol, maxResults: 1 });
    const match = matches[0];
    if (!match) {
      continue;
    }
    evidence.push(`${symbol} -> ${match.filePath}:${match.line}`);
  }
  return evidence;
}

export const __scenarioGuidanceInternals = {
  asThreatScenarioOutput,
  selectRoutes,
  selectOutboundClients,
  selectScenarios,
};
