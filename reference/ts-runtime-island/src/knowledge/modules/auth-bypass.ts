import type { KnowledgeModule } from "../types.js";

export const authBypassModule: KnowledgeModule = {
  id: "auth-bypass",
  cwes: ["CWE-287", "CWE-862"],
  languages: [],
  frameworks: [],
  dangerousPatterns: [
    {
      pattern: "Missing auth middleware on sensitive routes",
      why: "Endpoints accessible without authentication",
      severity: "ERROR",
    },
    {
      pattern: "Client-side only auth checks",
      why: "Server must enforce auth independently",
      severity: "ERROR",
    },
    {
      pattern: "Predictable/sequential resource IDs",
      why: "IDOR enables unauthorized access to other users' data",
      severity: "ERROR",
    },
    {
      pattern: "Role check in frontend only",
      why: "API must enforce authorization server-side",
      severity: "ERROR",
    },
    {
      pattern: "JWT with no signature verification",
      why: "Tokens can be forged without secret",
      severity: "ERROR",
    },
    {
      pattern: "Session tokens in URL parameters",
      why: "Leaks via Referer header and server logs",
      severity: "WARNING",
    },
  ],
  safePatterns: [
    {
      pattern: "Middleware-based auth on all routes",
      why: "Centralized enforcement, hard to bypass",
    },
    { pattern: "UUID v4 for resource identifiers", why: "Unguessable, prevents enumeration" },
    {
      pattern: "RBAC with server-side role verification",
      why: "Authorization enforced at API layer",
    },
    {
      pattern: "JWT with RS256 and key rotation",
      why: "Asymmetric signing prevents secret extraction",
    },
  ],
  bypassTechniques: [
    "IDOR via sequential/predictable ID enumeration",
    "Step-skipping in multi-step auth flows (jump to step 3 directly)",
    "Verification code leaked in response body or headers",
    "Type juggling (sending array instead of string, null vs empty)",
    "JWT algorithm confusion (none, HS256 vs RS256)",
    "Session fixation / token reuse across privilege boundaries",
    "Forced browsing to admin/privileged endpoints",
    "Parameter tampering (role=admin, isAdmin=true)",
    "HTTP method override (X-HTTP-Method-Override, _method parameter)",
    "Mass assignment / object injection to set privileged fields",
  ],
  detectionKeywords: [
    "authenticate",
    "authorize",
    "isAdmin",
    "role",
    "permission",
    "jwt",
    "token",
    "session",
    "passport",
    "auth",
    "middleware",
    "requireAuth",
    "checkPermission",
    "isAuthenticated",
  ],
  fixExamples: [
    {
      language: "JavaScript",
      before: "app.get('/admin/users', listUsers)",
      after: "app.get('/admin/users', requireAuth, requireRole('admin'), listUsers)",
      explanation: "Add authentication and authorization middleware to sensitive routes",
    },
  ],
  tags: ["auth", "authorization", "authentication", "idor", "access-control"],
};
