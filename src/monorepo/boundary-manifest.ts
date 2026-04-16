import path from "node:path";
import type {
  BoundaryManifest,
  BoundaryPoint,
  BoundaryProtocol,
} from "../agents/tasks/taint-analysis/cross-service/types.js";
import type { StoredFindingRecord } from "../store.js";
import type { ModuleScanPlan, ModuleSharedContext } from "./types.js";

export function buildBoundaryManifest(
  plan: ModuleScanPlan,
  sharedContext: ModuleSharedContext,
  findings: StoredFindingRecord[],
): BoundaryManifest {
  return {
    serviceId: plan.module.path,
    servicePath: plan.module.path,
    entryPoints: buildEntryPoints(plan.module.path, sharedContext),
    exitPoints: buildExitPoints(plan.module.path, sharedContext, findings),
    errors: [],
  };
}

function buildEntryPoints(modulePath: string, sharedContext: ModuleSharedContext): BoundaryPoint[] {
  const fallbackFilePath = sharedContext.fileIndex.tree[0]?.path ?? "README.md";
  const protocol = resolveEntryProtocol(sharedContext.attackSurface.entryPointTypes[0]);
  const entryStrings =
    sharedContext.repoContext.entryPoints.length > 0
      ? sharedContext.repoContext.entryPoints
      : [fallbackFilePath];

  return entryStrings.slice(0, 10).map((entryPoint, index) => ({
    id: `entry-${index + 1}`,
    direction: "entry",
    protocol,
    filePath: canonicalizeModuleFilePath(modulePath, inferFilePath(entryPoint, fallbackFilePath)),
    startLine: 1,
    callable: entryPoint,
    dataDescription: `Inbound data via ${entryPoint}`,
    taintedParameters: ["input"],
    confidence: 0.4,
    rationale: "Derived from shared module context entry points.",
  }));
}

function buildExitPoints(
  modulePath: string,
  sharedContext: ModuleSharedContext,
  findings: StoredFindingRecord[],
): BoundaryPoint[] {
  const taintLikeFindings = findings
    .filter(
      (finding) => finding.taskId === "taint-iris" || finding.ruleId.startsWith("cross-module/"),
    )
    .slice(0, 10);

  if (taintLikeFindings.length > 0) {
    return taintLikeFindings.map((finding, index) => ({
      id: `exit-${index + 1}`,
      direction: "exit",
      protocol: resolveExitProtocol(finding.taskId),
      filePath: canonicalizeModuleFilePath(modulePath, finding.filePath),
      startLine: finding.startLine,
      callable: `${finding.taskId}:${finding.ruleId}`,
      dataDescription: finding.message,
      taintedParameters: [],
      confidence: finding.confidence,
      rationale: "Derived from taint-oriented per-module findings.",
    }));
  }

  const fallbackFilePath = sharedContext.fileIndex.tree[0]?.path ?? "README.md";
  return sharedContext.dependsOn.slice(0, 5).map((targetPath, index) => ({
    id: `exit-${index + 1}`,
    direction: "exit",
    protocol: "unknown",
    filePath: canonicalizeModuleFilePath(modulePath, fallbackFilePath),
    startLine: 1,
    callable: `dependsOn:${targetPath}`,
    dataDescription: `Potential cross-module flow from ${modulePath} to ${targetPath}`,
    taintedParameters: [],
    confidence: 0.2,
    rationale: "Derived from static module dependency edges.",
  }));
}

function inferFilePath(value: string, fallback: string): string {
  if (value.includes("/")) {
    return value;
  }
  return fallback;
}

function canonicalizeModuleFilePath(modulePath: string, filePath: string): string {
  const normalizedModulePath = modulePath.replace(/\\/g, "/");
  const normalizedFilePath = filePath.replace(/\\/g, "/");
  if (
    normalizedFilePath === normalizedModulePath ||
    normalizedFilePath.startsWith(`${normalizedModulePath}/`)
  ) {
    return normalizedFilePath;
  }
  return path.posix.join(normalizedModulePath, normalizedFilePath);
}

function resolveEntryProtocol(entryPointType?: string): BoundaryProtocol {
  switch (entryPointType) {
    case "http-route":
      return "http-server";
    case "websocket":
      return "http-server";
    case "webhook":
      return "http-server";
    case "rpc-listener":
      return "grpc-server";
    case "event-listener":
      return "message-consume";
    default:
      return "unknown";
  }
}

function resolveExitProtocol(scannerId: string): BoundaryProtocol {
  if (scannerId === "ssrf-detect") {
    return "http-client";
  }
  if (scannerId === "taint-iris") {
    return "unknown";
  }
  return "unknown";
}
