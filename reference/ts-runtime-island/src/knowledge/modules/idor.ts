import type { KnowledgeModule } from "../types.js";

export const idorModule: KnowledgeModule = {
  id: "idor",
  cwes: ["CWE-639", "CWE-284"],
  languages: [],
  frameworks: [],
  dangerousPatterns: [
    {
      pattern: "Resource lookup by user-supplied ID without ownership check",
      why: "Attacker can access other users' resources by guessing IDs",
      severity: "ERROR",
    },
    {
      pattern: "Sequential/predictable resource identifiers",
      why: "Auto-increment IDs are trivially enumerable",
      severity: "WARNING",
    },
    {
      pattern: "Direct database lookup from route parameter",
      why: "No authorization between authentication and data access",
      severity: "ERROR",
    },
    {
      pattern: "File download using user-supplied path or ID",
      why: "Access to arbitrary files via ID manipulation",
      severity: "ERROR",
    },
    {
      pattern: "API endpoint returning data based solely on request parameter",
      why: "Missing ownership validation",
      severity: "WARNING",
    },
  ],
  safePatterns: [
    {
      pattern: "Ownership check: WHERE user_id = currentUser.id AND id = params.id",
      why: "Scopes query to authenticated user",
    },
    { pattern: "UUID/ULID resource identifiers", why: "Non-enumerable, unpredictable identifiers" },
    {
      pattern: "Policy-based authorization (CASL, Pundit, Spring Security ACL)",
      why: "Framework enforces resource-level permissions",
    },
    {
      pattern: "Tenant isolation in multi-tenant apps",
      why: "Database-level row security prevents cross-tenant access",
    },
  ],
  bypassTechniques: [
    "Incrementing numeric IDs in API requests (/api/users/1, /api/users/2, ...)",
    "Replacing UUIDs with other users' UUIDs obtained from public endpoints",
    "Using GraphQL introspection to discover ID-based queries without authz",
    "Exploiting batch/bulk endpoints that bypass per-item authorization",
    "HTTP parameter pollution to inject additional IDs",
    "Accessing soft-deleted resources via direct ID reference",
  ],
  detectionKeywords: [
    "findById",
    "findByPk",
    "get_object_or_404",
    "params.id",
    "req.params",
    "request.args.get",
    "PathVariable",
    "route param",
    "/api/users/:id",
    "/api/orders/:id",
  ],
  fixExamples: [
    {
      language: "JavaScript",
      before: "const order = await Order.findById(req.params.id)",
      after: "const order = await Order.findOne({ _id: req.params.id, userId: req.user.id })",
      explanation: "Scope database query to the authenticated user to prevent IDOR",
    },
  ],
  tags: ["idor", "authorization", "access-control"],
};
