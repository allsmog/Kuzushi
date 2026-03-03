import type { Finding } from "../../../../scanners/types.js";
import type { TaintAnalysisLanguage, TaintAnalysisTaskConfig } from "../types.js";

// ── Service Discovery ───────────────────────────────────────────────────

export interface ServiceDescriptor {
  id: string;
  displayName: string;
  rootPath: string;
  language: string;
  framework: string | null;
  discoveryMethod: "auto" | "manifest";
  manifestFiles: string[];
}

export interface CrossServiceDiscoverOutput {
  services: ServiceDescriptor[];
  usedManifest: boolean;
  autoDetectedPaths: string[];
}

// ── Service Manifest (`.kuzushi/services.json`) ─────────────────────────

export interface ServiceManifest {
  version: string;
  services: ServiceManifestEntry[];
}

export interface ServiceManifestEntry {
  id: string;
  displayName?: string;
  rootPath: string;
  language: string;
  framework?: string;
}

// ── Boundary Detection ──────────────────────────────────────────────────

export type BoundaryDirection = "entry" | "exit";

export type BoundaryProtocol =
  | "http-server"
  | "http-client"
  | "grpc-server"
  | "grpc-client"
  | "message-publish"
  | "message-consume"
  | "database-write"
  | "database-read"
  | "event-emit"
  | "event-listen"
  | "unknown";

export interface BoundaryPoint {
  id: string;
  direction: BoundaryDirection;
  protocol: BoundaryProtocol;
  filePath: string;
  startLine: number;
  callable: string;
  routePath?: string;
  httpMethod?: string;
  topicOrQueue?: string;
  grpcMethod?: string;
  dataEntity?: string;
  dataDescription: string;
  taintedParameters: string[];
  confidence: number;
  rationale: string;
}

export interface BoundaryManifest {
  serviceId: string;
  servicePath: string;
  entryPoints: BoundaryPoint[];
  exitPoints: BoundaryPoint[];
  errors: string[];
}

// ── Per-Service Analysis ────────────────────────────────────────────────

export interface PerServiceAnalysis {
  service: ServiceDescriptor;
  boundary: BoundaryManifest;
  intraServiceFindings: Finding[];
  taintAnalysisSkipped: boolean;
  taintAnalysisSkipReason?: string;
  durationMs: number;
}

export interface CrossServiceAnalysisOutput {
  services: PerServiceAnalysis[];
  allBoundaries: BoundaryManifest[];
}

// ── Stitching ───────────────────────────────────────────────────────────

export type StitchMatchMethod =
  | "url-path"
  | "topic-name"
  | "grpc-method"
  | "data-entity"
  | "llm-semantic";

export interface StitchedEdge {
  source: { serviceId: string; boundaryPointId: string; point: BoundaryPoint };
  target: { serviceId: string; boundaryPointId: string; point: BoundaryPoint };
  matchMethod: StitchMatchMethod;
  confidence: number;
  rationale: string;
}

export interface CrossServicePath {
  serviceChain: string[];
  edges: StitchedEdge[];
  ultimateSource: {
    serviceId: string;
    filePath: string;
    startLine: number;
    description: string;
  };
  ultimateSink: {
    serviceId: string;
    filePath: string;
    startLine: number;
    description: string;
  };
  pathConfidence: number;
}

// ── Config Helpers ──────────────────────────────────────────────────────

export interface CrossServiceConfig {
  enabled: boolean;
  boundaryModel: string;
  stitchModel: string;
  maxServices: number;
  concurrency: number;
  continueOnError: boolean;
  boundaryThreshold: number;
  stitchThreshold: number;
  maxPathDepth: number;
}

/** Resolve cross-service config from a full TaintAnalysisTaskConfig. */
export function resolveCrossServiceConfig(
  cfg: TaintAnalysisTaskConfig,
): CrossServiceConfig {
  return {
    enabled: cfg.crossService ?? false,
    boundaryModel: cfg.crossServiceBoundaryModel ?? cfg.labelingModel,
    stitchModel: cfg.crossServiceStitchModel ?? cfg.labelingModel,
    maxServices: cfg.crossServiceMaxServices ?? 20,
    concurrency: cfg.crossServiceConcurrency ?? 3,
    continueOnError: cfg.crossServiceContinueOnError ?? true,
    boundaryThreshold: cfg.crossServiceBoundaryThreshold ?? 0.5,
    stitchThreshold: cfg.crossServiceStitchThreshold ?? 0.6,
    maxPathDepth: cfg.crossServiceMaxPathDepth ?? 5,
  };
}

// ── Boundary Agent Schema ───────────────────────────────────────────────

export const BOUNDARY_RESPONSE_SCHEMA = {
  type: "object",
  additionalProperties: false,
  required: ["entryPoints", "exitPoints"],
  properties: {
    entryPoints: {
      type: "array",
      items: {
        type: "object",
        additionalProperties: false,
        required: [
          "id",
          "direction",
          "protocol",
          "filePath",
          "startLine",
          "callable",
          "dataDescription",
          "taintedParameters",
          "confidence",
          "rationale",
        ],
        properties: {
          id: { type: "string" },
          direction: { type: "string", enum: ["entry"] },
          protocol: {
            type: "string",
            enum: [
              "http-server", "http-client",
              "grpc-server", "grpc-client",
              "message-publish", "message-consume",
              "database-write", "database-read",
              "event-emit", "event-listen",
              "unknown",
            ],
          },
          filePath: { type: "string" },
          startLine: { type: "integer", minimum: 1 },
          callable: { type: "string" },
          routePath: { type: "string" },
          httpMethod: { type: "string" },
          topicOrQueue: { type: "string" },
          grpcMethod: { type: "string" },
          dataEntity: { type: "string" },
          dataDescription: { type: "string" },
          taintedParameters: { type: "array", items: { type: "string" } },
          confidence: { type: "number", minimum: 0, maximum: 1 },
          rationale: { type: "string" },
        },
      },
    },
    exitPoints: {
      type: "array",
      items: {
        type: "object",
        additionalProperties: false,
        required: [
          "id",
          "direction",
          "protocol",
          "filePath",
          "startLine",
          "callable",
          "dataDescription",
          "taintedParameters",
          "confidence",
          "rationale",
        ],
        properties: {
          id: { type: "string" },
          direction: { type: "string", enum: ["exit"] },
          protocol: {
            type: "string",
            enum: [
              "http-server", "http-client",
              "grpc-server", "grpc-client",
              "message-publish", "message-consume",
              "database-write", "database-read",
              "event-emit", "event-listen",
              "unknown",
            ],
          },
          filePath: { type: "string" },
          startLine: { type: "integer", minimum: 1 },
          callable: { type: "string" },
          routePath: { type: "string" },
          httpMethod: { type: "string" },
          topicOrQueue: { type: "string" },
          grpcMethod: { type: "string" },
          dataEntity: { type: "string" },
          dataDescription: { type: "string" },
          taintedParameters: { type: "array", items: { type: "string" } },
          confidence: { type: "number", minimum: 0, maximum: 1 },
          rationale: { type: "string" },
        },
      },
    },
  },
} as const;

// ── Stitch Agent Schema ─────────────────────────────────────────────────

export const STITCH_RESPONSE_SCHEMA = {
  type: "object",
  additionalProperties: false,
  required: ["validatedEdges", "additionalEdges", "paths"],
  properties: {
    validatedEdges: {
      type: "array",
      items: {
        type: "object",
        additionalProperties: false,
        required: ["sourcePointId", "targetPointId", "valid", "confidence", "rationale"],
        properties: {
          sourcePointId: { type: "string" },
          targetPointId: { type: "string" },
          valid: { type: "boolean" },
          confidence: { type: "number", minimum: 0, maximum: 1 },
          rationale: { type: "string" },
        },
      },
    },
    additionalEdges: {
      type: "array",
      items: {
        type: "object",
        additionalProperties: false,
        required: [
          "sourceServiceId", "sourcePointId",
          "targetServiceId", "targetPointId",
          "matchMethod", "confidence", "rationale",
        ],
        properties: {
          sourceServiceId: { type: "string" },
          sourcePointId: { type: "string" },
          targetServiceId: { type: "string" },
          targetPointId: { type: "string" },
          matchMethod: {
            type: "string",
            enum: ["url-path", "topic-name", "grpc-method", "data-entity", "llm-semantic"],
          },
          confidence: { type: "number", minimum: 0, maximum: 1 },
          rationale: { type: "string" },
        },
      },
    },
    paths: {
      type: "array",
      items: {
        type: "object",
        additionalProperties: false,
        required: ["serviceChain", "description", "cwe", "severity"],
        properties: {
          serviceChain: { type: "array", items: { type: "string" } },
          description: { type: "string" },
          cwe: { type: "string" },
          severity: { type: "string", enum: ["ERROR", "WARNING", "INFO"] },
        },
      },
    },
  },
} as const;

export interface StitchLlmResponse {
  validatedEdges: Array<{
    sourcePointId: string;
    targetPointId: string;
    valid: boolean;
    confidence: number;
    rationale: string;
  }>;
  additionalEdges: Array<{
    sourceServiceId: string;
    sourcePointId: string;
    targetServiceId: string;
    targetPointId: string;
    matchMethod: StitchMatchMethod;
    confidence: number;
    rationale: string;
  }>;
  paths: Array<{
    serviceChain: string[];
    description: string;
    cwe: string;
    severity: string;
  }>;
}

// ── Supported Taint Analysis Languages ──────────────────────────────────

const TAINT_ANALYSIS_LANGUAGES: Set<TaintAnalysisLanguage> = new Set([
  "python", "go", "java", "javascript", "csharp",
]);

export function isTaintAnalysisLanguage(lang: string): lang is TaintAnalysisLanguage {
  return TAINT_ANALYSIS_LANGUAGES.has(lang.toLowerCase() as TaintAnalysisLanguage);
}
