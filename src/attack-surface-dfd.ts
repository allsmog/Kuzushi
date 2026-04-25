import type {
  DfdElement,
  StrideCategory,
  StrideThreat,
  ThreatModelDocument,
} from "./agents/tasks/threat-modeling/types.js";
import { ApplicationModelSchema, RepoContextSchema } from "./schemas.js";
import type { ApplicationModel } from "./types.js";
import type { ContextSnapshot } from "./ui/state.js";

export type AttackSurfaceSourceKind = "persistent" | "context" | "empty";

export interface AttackSurfaceNode {
  id: string;
  type: "external-entity" | "process" | "data-store";
  name: string;
  zone: string;
  description: string;
  risk: "hot" | "watch" | "normal";
  tags: string[];
  sourceElement?: DfdElement;
}

export interface AttackSurfaceFlow {
  id: string;
  source: string;
  target: string;
  protocol?: string;
  dataClassification?: string;
  description: string;
  crosses: string[];
  hot: boolean;
  sourceElement?: DfdElement;
}

export interface AttackSurfaceBoundary {
  id: string;
  name: string;
  from: string;
  to: string;
  crossingFlows: string[];
}

export interface AttackSurfaceZone {
  id: string;
  title: string;
  nodes: AttackSurfaceNode[];
}

export interface AttackSurfaceDfdModel {
  sourceKind: AttackSurfaceSourceKind;
  sourceLabel: string;
  target?: string;
  generatedAt?: number;
  zones: AttackSurfaceZone[];
  nodes: AttackSurfaceNode[];
  flows: AttackSurfaceFlow[];
  boundaries: AttackSurfaceBoundary[];
  threats: StrideThreat[];
  strideCounts: Record<StrideCategory, number>;
  stats: {
    routes: number;
    publicRoutes: number;
    authRoutes: number;
    serviceBoundaries: number;
    dataStores: number;
    threats: number;
  };
  selectedId?: string;
  nextActions: string[];
}

const STRIDE_ZERO: Record<StrideCategory, number> = {
  spoofing: 0,
  tampering: 0,
  repudiation: 0,
  "information-disclosure": 0,
  "denial-of-service": 0,
  "elevation-of-privilege": 0,
};

const ZONE_ORDER = [
  "internet / untrusted",
  "edge / entrypoints",
  "application / trusted",
  "data / high value",
  "(unzoned)",
];

export function deriveAttackSurfaceDfdModel(input: {
  threatModel?: ThreatModelDocument | null;
  contextSnapshot?: ContextSnapshot | null;
  sourceKind?: AttackSurfaceSourceKind;
  sourceLabel?: string;
  selectedId?: string;
}): AttackSurfaceDfdModel {
  const appModel = parseApplicationModel(input.contextSnapshot?.appModel);
  const repoContext = parseRepoContext(input.contextSnapshot?.repoContext);
  const threatModel = normalizeThreatModel(input.threatModel ?? input.contextSnapshot?.threatModel);
  const sourceKind =
    input.sourceKind ?? (threatModel ? "persistent" : input.contextSnapshot ? "context" : "empty");
  const sourceLabel =
    input.sourceLabel ??
    (sourceKind === "persistent"
      ? ".kuzushi/threat-model.json"
      : sourceKind === "context"
        ? ".kuzushi/context-snapshot.json"
        : "no context loaded");

  const dfdElements = threatModel?.dfd?.elements ?? [];
  const dfdBoundaries = threatModel?.dfd?.trustBoundaries ?? [];
  const fromThreatModel = dfdElements.length > 0;
  const built = fromThreatModel
    ? buildFromThreatModel(dfdElements, dfdBoundaries, appModel)
    : buildFromApplicationModel(appModel, repoContext);

  const threats = threatModel?.threats ?? [];
  const strideCounts = { ...STRIDE_ZERO };
  for (const threat of threats) {
    strideCounts[threat.category] = (strideCounts[threat.category] ?? 0) + 1;
  }

  const stats = statsFrom(appModel, threats);
  const selectedId =
    input.selectedId && built.nodes.some((n) => n.id === input.selectedId)
      ? input.selectedId
      : (built.nodes.find((n) => n.risk === "hot")?.id ??
        built.nodes.find((n) => n.risk === "watch")?.id ??
        built.nodes[0]?.id);

  return {
    sourceKind,
    sourceLabel,
    target: input.contextSnapshot?.target,
    generatedAt: input.contextSnapshot?.timestamp,
    zones: groupZones(built.nodes),
    nodes: built.nodes,
    flows: built.flows,
    boundaries: built.boundaries,
    threats,
    strideCounts,
    stats,
    selectedId,
    nextActions: nextActions(stats, threats.length),
  };
}

export function selectedAttackSurfaceNode(
  model: AttackSurfaceDfdModel,
): AttackSurfaceNode | undefined {
  return model.nodes.find((node) => node.id === model.selectedId) ?? model.nodes[0];
}

export function flowsForNode(
  model: AttackSurfaceDfdModel,
  nodeId: string,
): { inputs: AttackSurfaceFlow[]; outputs: AttackSurfaceFlow[] } {
  return {
    inputs: model.flows.filter((flow) => flow.target === nodeId),
    outputs: model.flows.filter((flow) => flow.source === nodeId),
  };
}

function buildFromThreatModel(
  elements: DfdElement[],
  boundaries: Array<{
    id: string;
    name: string;
    innerZone: string;
    outerZone: string;
    crossingFlows: string[];
  }>,
  appModel: ApplicationModel | null,
): {
  nodes: AttackSurfaceNode[];
  flows: AttackSurfaceFlow[];
  boundaries: AttackSurfaceBoundary[];
} {
  const boundaryList = boundaries.map((boundary) => ({
    id: boundary.id,
    name: boundary.name,
    from: normalizeZone(boundary.outerZone, "external-entity"),
    to: normalizeZone(boundary.innerZone, "process"),
    crossingFlows: boundary.crossingFlows ?? [],
  }));
  const boundaryByFlow = new Map<string, string[]>();
  for (const boundary of boundaryList) {
    for (const flowId of boundary.crossingFlows) {
      const current = boundaryByFlow.get(flowId) ?? [];
      current.push(boundary.id);
      boundaryByFlow.set(flowId, current);
    }
  }

  const nodes = elements
    .filter((element) => element.type !== "data-flow")
    .map((element) => {
      const zone = normalizeZone(element.trustZone, element.type);
      const tags = inferNodeTags(element, appModel);
      return {
        id: element.id,
        type: element.type as AttackSurfaceNode["type"],
        name: element.name,
        zone,
        description: element.description,
        risk: inferRisk(element, tags),
        tags,
        sourceElement: element,
      };
    });

  const flows = elements
    .filter((element) => element.type === "data-flow")
    .map((element) => {
      const crosses = boundaryByFlow.get(element.id) ?? [];
      const hot =
        crosses.length > 0 &&
        /public|identity|credential|secret|token|admin/i.test(
          [element.description, element.dataClassification, element.protocol]
            .filter(Boolean)
            .join(" "),
        );
      return {
        id: element.id,
        source: element.source ?? "?",
        target: element.target ?? "?",
        protocol: element.protocol,
        dataClassification: element.dataClassification,
        description: element.description,
        crosses,
        hot,
        sourceElement: element,
      };
    });

  return { nodes, flows, boundaries: boundaryList };
}

function buildFromApplicationModel(
  appModel: ApplicationModel | null,
  repoContext: { authPatterns?: string[]; frameworks?: string[] } | null,
): {
  nodes: AttackSurfaceNode[];
  flows: AttackSurfaceFlow[];
  boundaries: AttackSurfaceBoundary[];
} {
  if (!appModel && !repoContext) return { nodes: [], flows: [], boundaries: [] };
  const routes = appModel?.routes ?? [];
  const publicRoutes = routes.filter((route) => route.authMechanisms.length === 0);
  const authRoutes = routes.filter((route) => route.authMechanisms.length > 0);
  const dataStores = appModel?.dataStores ?? [];
  const authLabel = first(repoContext?.authPatterns) ?? "auth boundary";

  const nodes: AttackSurfaceNode[] = [
    node(
      "E1",
      "external-entity",
      "unauth user",
      "internet / untrusted",
      "External caller reaching public ingress.",
      "hot",
      ["public ingress"],
    ),
    node(
      "E2",
      "external-entity",
      "admin browser",
      "internet / untrusted",
      "Authenticated privileged browser session.",
      "watch",
      ["privileged"],
    ),
    node(
      "P1",
      "process",
      "web router",
      "edge / entrypoints",
      `${routes.length} routes · ${publicRoutes.length} public · ${authRoutes.length} auth-gated`,
      publicRoutes.length > 0 ? "hot" : "watch",
      [`routes ${routes.length}`, `public ${publicRoutes.length}`, `auth ${authRoutes.length}`],
    ),
  ];

  if (authRoutes.length > 0 || authLabel) {
    nodes.push(
      node(
        "P2",
        "process",
        authLabel,
        "edge / entrypoints",
        "Identity and session boundary inferred from route/auth signals.",
        "watch",
        ["identity", "sessions"],
      ),
    );
  }

  const boundaryNodes = (appModel?.serviceBoundaries ?? []).slice(0, 5);
  boundaryNodes.forEach((boundary, index) => {
    nodes.push(
      node(
        `P${index + 3}`,
        "process",
        boundary.name,
        "application / trusted",
        boundary.description,
        boundary.kind === "entrypoint" ? "watch" : "normal",
        [boundary.kind],
      ),
    );
  });

  dataStores.slice(0, 8).forEach((store, index) => {
    nodes.push(
      node(
        `D${index + 1}`,
        "data-store",
        store.name || store.kind,
        "data / high value",
        `${store.kind} · ${store.filePath}`,
        "hot",
        ["high-value data", store.kind],
      ),
    );
  });

  const flows: AttackSurfaceFlow[] = [];
  flows.push(flow("F1", "E1", "P1", "HTTPS", "user-input", "public route traffic", ["B1"], true));
  if (nodes.some((n) => n.id === "P2")) {
    flows.push(
      flow("F2", "E2", "P2", "HTTPS", "identity", "privileged auth traffic", ["B1"], true),
    );
    flows.push(flow("F3", "P1", "P2", "internal", "session", "route auth checks", [], false));
  }
  const firstApp = nodes.find((n) => n.zone === "application / trusted");
  if (firstApp) {
    flows.push(
      flow(
        "F4",
        "P1",
        firstApp.id,
        "internal",
        "request",
        "entrypoint to application service",
        ["B2"],
        publicRoutes.length > 0,
      ),
    );
  }
  const firstStore = nodes.find((n) => n.type === "data-store");
  if (firstApp && firstStore) {
    flows.push(
      flow(
        "F5",
        firstApp.id,
        firstStore.id,
        "db",
        "sensitive",
        "application data access",
        ["B3"],
        true,
      ),
    );
  }

  const boundaries: AttackSurfaceBoundary[] = [
    {
      id: "B1",
      name: "perimeter",
      from: "internet / untrusted",
      to: "edge / entrypoints",
      crossingFlows: flows.filter((f) => f.crosses.includes("B1")).map((f) => f.id),
    },
    {
      id: "B2",
      name: "service edge",
      from: "edge / entrypoints",
      to: "application / trusted",
      crossingFlows: flows.filter((f) => f.crosses.includes("B2")).map((f) => f.id),
    },
    {
      id: "B3",
      name: "data boundary",
      from: "application / trusted",
      to: "data / high value",
      crossingFlows: flows.filter((f) => f.crosses.includes("B3")).map((f) => f.id),
    },
  ].filter((boundary) => boundary.crossingFlows.length > 0 || boundary.id === "B1");

  return { nodes, flows, boundaries };
}

function node(
  id: string,
  type: AttackSurfaceNode["type"],
  name: string,
  zone: string,
  description: string,
  risk: AttackSurfaceNode["risk"],
  tags: string[],
): AttackSurfaceNode {
  return { id, type, name, zone, description, risk, tags };
}

function flow(
  id: string,
  source: string,
  target: string,
  protocol: string,
  dataClassification: string,
  description: string,
  crosses: string[],
  hot: boolean,
): AttackSurfaceFlow {
  return { id, source, target, protocol, dataClassification, description, crosses, hot };
}

function groupZones(nodes: AttackSurfaceNode[]): AttackSurfaceZone[] {
  const grouped = new Map<string, AttackSurfaceNode[]>();
  for (const node of nodes) {
    const bucket = grouped.get(node.zone) ?? [];
    bucket.push(node);
    grouped.set(node.zone, bucket);
  }
  return [...grouped.entries()]
    .sort(([a], [b]) => zoneRank(a) - zoneRank(b) || a.localeCompare(b))
    .map(([id, zoneNodes]) => ({ id, title: id.toUpperCase(), nodes: zoneNodes }));
}

function zoneRank(zone: string): number {
  const idx = ZONE_ORDER.indexOf(zone);
  if (idx !== -1) return idx;
  if (/internet|external|untrusted|public/.test(zone)) return 0;
  if (/edge|entry|ingress|router|gateway/.test(zone)) return 1;
  if (/app|vpc|service|trusted/.test(zone)) return 2;
  if (/data|store|db|database|secret|credential/.test(zone)) return 3;
  return ZONE_ORDER.length;
}

function normalizeZone(zone: string | undefined, type: DfdElement["type"]): string {
  const raw = (zone ?? "").trim().toLowerCase();
  if (/internet|external|untrusted|public/.test(raw)) return "internet / untrusted";
  if (/edge|entry|ingress|router|gateway/.test(raw)) return "edge / entrypoints";
  if (/data|store|db|database|queue|secret|credential/.test(raw) || type === "data-store") {
    return "data / high value";
  }
  if (raw.length > 0) return raw;
  return type === "external-entity" ? "internet / untrusted" : "application / trusted";
}

function inferNodeTags(element: DfdElement, appModel: ApplicationModel | null): string[] {
  const text = `${element.name} ${element.description} ${element.trustZone}`.toLowerCase();
  const tags: string[] = [];
  if (/auth|identity|session|token|sso|oidc/.test(text)) tags.push("identity");
  if (/admin|privilege|role|policy/.test(text)) tags.push("privileged");
  if (/public|internet|unauth|external/.test(text)) tags.push("public ingress");
  if (
    /db|database|store|secret|credential|key|token|session/.test(text) ||
    element.type === "data-store"
  ) {
    tags.push("high-value data");
  }
  if (element.type === "process" && appModel?.routes?.length)
    tags.push(`routes ${appModel.routes.length}`);
  return tags.length > 0 ? tags : [element.type];
}

function inferRisk(element: DfdElement, tags: string[]): AttackSurfaceNode["risk"] {
  if (element.type === "data-store") return "hot";
  if (tags.some((tag) => /public ingress|high-value|credential|secret/.test(tag))) return "hot";
  if (tags.some((tag) => /identity|privileged|auth/.test(tag))) return "watch";
  return "normal";
}

function statsFrom(appModel: ApplicationModel | null, threats: StrideThreat[]) {
  const routes = appModel?.routes ?? [];
  return {
    routes: routes.length,
    publicRoutes: routes.filter((route) => route.authMechanisms.length === 0).length,
    authRoutes: routes.filter((route) => route.authMechanisms.length > 0).length,
    serviceBoundaries: appModel?.serviceBoundaries.length ?? 0,
    dataStores: appModel?.dataStores.length ?? 0,
    threats: threats.length,
  };
}

function nextActions(stats: AttackSurfaceDfdModel["stats"], threatCount: number): string[] {
  const actions = [
    "threat-hunt: run actor-driven adversarial review",
    "taint-iris: trace public inputs across trust boundaries",
  ];
  if (stats.dataStores > 0) actions.push("/threats scope: inspect high-value stores");
  if (threatCount === 0) actions.push("/context regen stride: rebuild STRIDE overlay only");
  return actions;
}

function parseApplicationModel(value: unknown): ApplicationModel | null {
  const parsed = ApplicationModelSchema.safeParse(value);
  return parsed.success ? parsed.data : null;
}

function parseRepoContext(
  value: unknown,
): { authPatterns?: string[]; frameworks?: string[] } | null {
  const parsed = RepoContextSchema.safeParse(value);
  return parsed.success ? parsed.data : null;
}

function normalizeThreatModel(value: unknown): ThreatModelDocument | null {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  const record = value as Partial<ThreatModelDocument>;
  if (!record.dfd || !Array.isArray(record.dfd.elements)) return null;
  return record as ThreatModelDocument;
}

function first(values: ReadonlyArray<string> | undefined): string | undefined {
  return values?.find((value) => value.trim().length > 0);
}
