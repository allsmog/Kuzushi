import { realpathSync, statSync } from "node:fs";
import { isDeepStrictEqual } from "node:util";
import { fileToolsForRequest } from "./file-tools.mjs";
import { READ_ONLY_SCOPE_POLICY_ID, readScopeForPolicy } from "./read-scope.mjs";

export const READ_ONLY_ASK_POLICY_PROTOCOL_VERSION = 1;
export const READ_ONLY_ASK_POLICY_ID = "ask.concurrent-read-only.v1";
export const READ_ONLY_ASK_TOOLS = ["Read", "LS", "Glob", "Grep"];

export function acknowledgeToolPolicy(request) {
  const authorization = request?.authorization;
  validateAuthorization(authorization);
  const policy = authorization.policy;
  const readRoots = canonicalReadRoots(policy);
  const effectiveTools = fileToolsForRequest({ toolPolicy: policy }).map((tool) => tool.name);
  const scope = readScopeForPolicy(policy, readRoots);
  requireExact(effectiveTools, READ_ONLY_ASK_TOOLS, "effective read-only tools");
  return {
    ok: true,
    acknowledgement: {
      protocolVersion: authorization.protocolVersion,
      policyId: authorization.policyId,
      effectiveTools,
      readRoots,
      writeShellToolsMounted: false,
      mcpToolsMounted: false,
      ...(scope ? { readScopeSha256: scope.sha256 } : {}),
    },
  };
}

export function authorizeExecutingQuery(request) {
  const acknowledgement = acknowledgeToolPolicy(request).acknowledgement;
  if (!isDeepStrictEqual(request?.toolPolicy, request?.authorization?.policy)) {
    throw new Error("executing Ask tool policy differs from its authorization");
  }
  requireExecutionTargetRoot(request, acknowledgement.readRoots);
  return acknowledgement;
}

function validateAuthorization(authorization) {
  if (!authorization || typeof authorization !== "object") {
    throw new Error("tool-policy authorization is required");
  }
  if (authorization.protocolVersion !== READ_ONLY_ASK_POLICY_PROTOCOL_VERSION) {
    throw new Error("unsupported Ask tool-policy protocol version");
  }
  if (![READ_ONLY_ASK_POLICY_ID, READ_ONLY_SCOPE_POLICY_ID].includes(authorization.policyId)) {
    throw new Error("unknown Ask tool-policy id");
  }
  validatePolicy(authorization.policy, authorization.policyId);
}

function validatePolicy(policy, id) {
  if (!policy || policy.profile !== id) {
    throw new Error("Ask tool policy profile does not match its authorization");
  }
  requireExact(policy.tools, READ_ONLY_ASK_TOOLS, "authorized tools");
  if (policy.mcps === true || (policy.mcpsAttached ?? []).length > 0) {
    throw new Error("concurrent Ask cannot mount MCP tools");
  }
  requireMembershipKind(policy, id);
}

function requireMembershipKind(policy, id) {
  const hasScope = policy.readScope !== undefined;
  if (hasScope !== (id === READ_ONLY_SCOPE_POLICY_ID)) {
    throw new Error("tool authorization and read membership kind differ");
  }
}

function canonicalReadRoots(policy) {
  const roots = policy.mcpReadRoots;
  if (!Array.isArray(roots) || roots.length !== 1 || typeof roots[0] !== "string") {
    throw new Error("concurrent Ask requires exactly one explicit read root");
  }
  const canonical = realpathSync(roots[0]);
  if (!statSync(canonical).isDirectory()) throw new Error("Ask read root is not a directory");
  if (canonical !== roots[0]) throw new Error("Ask read root must be canonical");
  return [canonical];
}

function requireExecutionTargetRoot(request, readRoots) {
  if (typeof request?.cwd !== "string") {
    throw new Error("concurrent Ask requires an explicit execution target");
  }
  const target = realpathSync(request.cwd);
  if (!statSync(target).isDirectory()) throw new Error("Ask execution target is not a directory");
  if (readRoots[0] !== target) {
    throw new Error("Ask read root must match the canonical execution target");
  }
}

function requireExact(actual, expected, label) {
  if (!Array.isArray(actual) || actual.length !== expected.length) {
    throw new Error(`${label} differ from the read-only Ask contract`);
  }
  if (actual.some((value, index) => value !== expected[index])) {
    throw new Error(`${label} differ from the read-only Ask contract`);
  }
}
