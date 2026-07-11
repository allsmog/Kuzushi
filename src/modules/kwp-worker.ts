import type { McpHandle } from "./kwp-mcp.js";

/** Public filesystem scope names accepted by the KWP broker. */
export type KwpFsScope = "workspace" | "module-data" | "input" | "moduleData";
export type KwpFsKind = "file" | "dir" | "other";

export interface KwpFsReadOptions {
  offset?: number;
  length?: number;
  encoding?: string;
}

export interface KwpFsWriteOptions {
  append?: boolean;
  encoding?: string;
}

export interface KwpFsHandle {
  read(scope: KwpFsScope, path: string, options?: KwpFsReadOptions): Promise<Uint8Array>;
  readText(scope: KwpFsScope, path: string, options?: KwpFsReadOptions): Promise<string>;
  write(
    scope: KwpFsScope,
    path: string,
    data: Uint8Array | string,
    options?: KwpFsWriteOptions,
  ): Promise<number>;
  writeText(
    scope: KwpFsScope,
    path: string,
    text: string,
    options?: KwpFsWriteOptions,
  ): Promise<number>;
  list(
    scope: KwpFsScope,
    path: string,
  ): Promise<Array<{ name: string; kind: KwpFsKind; size: number }>>;
  stat(
    scope: KwpFsScope,
    path: string,
  ): Promise<{
    kind: KwpFsKind;
    size: number;
    mtime: number;
  }>;
  remove(scope: KwpFsScope, path: string): Promise<void>;
}

export interface KwpArtifactRef {
  path: string;
  mediaType: string;
  sha256?: string;
}

export interface KwpNetRequestInit {
  method?: string;
  headers?: Record<string, string>;
  body?: Uint8Array | string;
  timeoutMs?: number;
  credentialName?: string;
  responseArtifactPath?: string;
  responseMediaType?: string;
}

export interface KwpNetRequest extends KwpNetRequestInit {
  url: string;
}

export interface KwpBrokeredResponse {
  status: number;
  headers: Record<string, string>;
  body(): Promise<Uint8Array>;
  artifact?: KwpArtifactRef;
}

export interface KwpNetHandle {
  fetch(request: KwpNetRequest): Promise<KwpBrokeredResponse>;
  /** Compatibility overload; normalized to the request-object form by the host. */
  fetch(url: string, init?: KwpNetRequestInit): Promise<KwpBrokeredResponse>;
}

export interface KwpStructuredOutput {
  name: string;
  schema: unknown;
  strict?: boolean;
}

/** Worker-controlled portion of a runtime request; model, cwd, and tools stay host-owned. */
export interface KwpRuntimeQuery {
  prompt: string;
  systemPrompt?: string;
  structuredOutput?: KwpStructuredOutput;
  thinkingLevel?: string;
  maxOutputTokens?: number;
  temperature?: number;
}

/** Minimal stable subset of the native runtime response returned to a worker. */
export interface KwpRuntimeCompletion {
  text: string;
  structured?: unknown;
  truncated?: boolean;
  stop_reason?: string | null;
}

export interface KwpRuntimeHandle {
  query(request: KwpRuntimeQuery): Promise<KwpRuntimeCompletion>;
}

export interface KwpBusHandle {
  publish(topic: string, payload?: unknown): Promise<void>;
}

export interface KwpArtifactsHandle {
  record(artifacts: KwpArtifactRef[]): Promise<{ artifacts: KwpArtifactRef[] }>;
}

export interface KwpFindingsHandle {
  create(findings: unknown[]): Promise<{ created: number }>;
}

export interface KwpFuzzHandle {
  run(request: KwpFuzzRunRequest): Promise<KwpFuzzRunResult>;
}

export interface KwpFuzzRunRequest {
  engine: string;
  target: { language: string; projectPath: string; harnessPath: string };
  inputs?: Record<string, string>;
  limits?: {
    deadlineMs?: number;
    cpuSeconds?: number;
    memoryBytes?: number;
    artifactBytes?: number;
    maxCrashes?: number;
  };
  sandbox?: { network?: boolean; readOnlySource?: boolean };
}

export interface KwpFuzzRunResult {
  status: string;
  artifacts?: KwpArtifactRef[];
  crashes?: unknown[];
}

/**
 * Context supplied to a plain module by the Rust-owned KWP wrapper.
 *
 * Module files export their module object; they do not start a worker loop.
 */
export interface KwpExecutionContext {
  /** KWP workers receive a virtual cwd; the host retains real workspace paths. */
  readonly cwd: string;
  readonly config: { readonly model?: string };
  readonly kwp: {
    readonly version: string;
    readonly invocationId: string;
    readonly runId: string;
    readonly epoch: number;
    readonly moduleDigest: string;
    readonly descriptorHash: string;
  };
  readonly invocationId: string;
  readonly runId: string;
  readonly signal: AbortSignal;
  readonly runtime: KwpRuntimeHandle;
  readonly bus: KwpBusHandle;
  readonly fs: KwpFsHandle;
  readonly net: KwpNetHandle;
  readonly artifacts: KwpArtifactsHandle;
  readonly findings: KwpFindingsHandle;
  readonly mcp?: McpHandle;
  readonly fuzz?: KwpFuzzHandle;
}

/** Compatibility type name for modules authored against the early KWP draft. */
export type KwpWorkerExecutionContext = KwpExecutionContext;
