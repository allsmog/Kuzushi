/**
 * KWP-hosted MCP call limits. These are requests to the host broker, not
 * guarantees: the host may lower limits or reject the call under the module's
 * immutable grant.
 */
export interface McpCallLimits {
  deadlineMs?: number;
  cpuSeconds?: number;
  artifactBytes?: number;
}

export interface McpContentBlock {
  type: "text";
  text: string;
}

export interface McpArtifactRef {
  /** Workspace-scope-relative path. The host verifies containment and hashes it. */
  path: string;
  mediaType: string;
  sha256?: string;
}

export interface McpCallResult<TStructured = unknown> {
  /** Optional raw MCP text blocks; the native broker primarily returns structured content. */
  content?: McpContentBlock[];
  structuredContent: TStructured;
  artifacts?: McpArtifactRef[];
}

export interface McpCallOptions {
  limits?: McpCallLimits;
}

/**
 * Broker-backed MCP composition handle exposed by KWP workers.
 *
 * MCP aliases are host-mounted capabilities. A module can probe whether an
 * alias is granted, but authorization is still checked host-side for every
 * alias/tool pair on every invocation.
 */
export interface McpHandle {
  /** True when the current invocation grant includes this host-mounted alias. */
  has(alias: string): boolean;

  /** Return granted aliases for diagnostics and adaptive fallbacks. */
  grantedAliases(): readonly string[];

  /**
   * Call a granted MCP tool through the host McpBroker.
   *
   * The module never connects to the MCP server directly. The host owns MCP
   * lifecycle, descriptor-hash pinning, per-invocation sessions, artifact
   * validation, quotas, and audit.
   */
  call<TStructured = unknown>(
    alias: string,
    tool: string,
    arguments_: Record<string, unknown>,
    options?: McpCallOptions,
  ): Promise<McpCallResult<TStructured>>;
}

/** Minimal context refinement for KWP-hosted modules with MCP composition. */
export interface KwpMcpExecutionContext {
  readonly mcp?: McpHandle;
}

export class McpNotGrantedError extends Error {
  constructor(alias: string) {
    super(`MCP alias ${alias} is not granted for this invocation`);
    this.name = "McpNotGrantedError";
  }
}

export function requireMcp(ctx: KwpMcpExecutionContext, alias: string): McpHandle {
  if (!ctx.mcp?.has(alias)) {
    throw new McpNotGrantedError(alias);
  }
  return ctx.mcp;
}
