/** Framework-specific guidance modules for LLM-assisted code graph tracing. */

const EXPRESS_GUIDANCE = `
Express/Koa/Fastify middleware chain resolution:
- app.use() registers middleware in order — trace the stack.
- router.use() scopes middleware to a path prefix.
- Error-handling middleware has 4 parameters (err, req, res, next).
- Express passes req/res objects through the chain — track mutations to req.body, req.params, req.query.
- Look for: body-parser, cors, helmet, express-validator, passport, multer, cookie-parser.
- Route params (:id) flow through req.params. Query strings through req.query.
`;

const DJANGO_GUIDANCE = `
Django URL dispatch resolution:
- urls.py defines urlpatterns — path()/re_path() map URLs to views.
- Middleware classes in settings.MIDDLEWARE run in order on request, reverse on response.
- Class-based views use dispatch() -> get()/post()/etc.
- Django REST Framework: ViewSet -> get_serializer() -> validate() -> perform_create().
- Look for: login_required, permission_required, @api_view, IsAuthenticated.
- Template rendering: render() passes context dict to template — track what data enters context.
`;

const SPRING_GUIDANCE = `
Spring MVC/Boot dispatch resolution:
- @RequestMapping/@GetMapping/@PostMapping on @Controller/@RestController classes.
- @Autowired/@Inject for dependency injection — follow constructor/field injection to service beans.
- Spring Security filter chain: SecurityFilterChain configures auth requirements per path.
- @Valid/@Validated triggers JSR-303 bean validation on request bodies.
- @Transactional wraps service methods — DB operations happen inside.
- Look for: @Service, @Repository, @Component, JpaRepository, JdbcTemplate.
`;

const RAILS_GUIDANCE = `
Rails routing and controller conventions:
- config/routes.rb defines resources/routes — map to controller#action.
- ApplicationController provides before_action filters (auth, params).
- Strong params: params.require(:model).permit(:field1, :field2).
- ActiveRecord models: Model.find/where/create map to SQL.
- Concerns and modules mixed into controllers/models.
- Look for: before_action, authenticate_user!, authorize, pundit, cancancan.
`;

const NESTJS_GUIDANCE = `
NestJS module-based resolution:
- @Module() declares controllers, providers, imports.
- @Controller() with @Get()/@Post() decorators define routes.
- @Injectable() services injected via constructor DI.
- Guards (@UseGuards) and Pipes (@UsePipes) for auth/validation.
- Interceptors wrap execution around handlers.
- Look for: @Body(), @Param(), @Query() parameter decorators.
`;

const FASTAPI_GUIDANCE = `
FastAPI/Starlette resolution:
- @app.get()/@app.post() decorator routes with type-annotated parameters.
- Depends() for dependency injection — follow the dependency chain.
- Pydantic models for request/response validation.
- Middleware via @app.middleware or Starlette middleware stack.
- Look for: HTTPBearer, OAuth2PasswordBearer, get_db session factories.
`;

const GIN_GUIDANCE = `
Go Gin/Echo/Chi resolution:
- r.GET()/r.POST() register handlers. r.Group() creates prefixed groups.
- Middleware via r.Use() — runs in registration order.
- c.Bind()/c.ShouldBind() deserializes request body.
- c.Param()/c.Query() accesses URL params.
- Look for: gin.Context, middleware functions, GORM/sqlx database calls.
`;

const FRAMEWORK_GUIDANCE: Record<string, string> = {
  express: EXPRESS_GUIDANCE,
  koa: EXPRESS_GUIDANCE,
  fastify: EXPRESS_GUIDANCE,
  django: DJANGO_GUIDANCE,
  flask: DJANGO_GUIDANCE,
  spring: SPRING_GUIDANCE,
  "spring-boot": SPRING_GUIDANCE,
  rails: RAILS_GUIDANCE,
  nestjs: NESTJS_GUIDANCE,
  fastapi: FASTAPI_GUIDANCE,
  starlette: FASTAPI_GUIDANCE,
  gin: GIN_GUIDANCE,
  echo: GIN_GUIDANCE,
  chi: GIN_GUIDANCE,
};

/** Get framework-specific guidance for the tracing prompt. */
export function getFrameworkGuidance(frameworks: string[]): string {
  const sections: string[] = [];
  const seen = new Set<string>();
  for (const fw of frameworks) {
    const key = fw.toLowerCase();
    const guidance = FRAMEWORK_GUIDANCE[key];
    if (guidance && !seen.has(guidance)) {
      seen.add(guidance);
      sections.push(`### ${fw} Framework Guidance\n${guidance}`);
    }
  }
  return sections.length > 0
    ? `## Framework-Specific Tracing Guidance\n\n${sections.join("\n")}`
    : "";
}

/** Build the LLM prompt for tracing a single entry point through the codebase. */
export function buildTracePrompt(params: {
  method: string;
  routePath: string;
  handlerSymbol: string;
  filePath: string;
  startLine: number;
  frameworks: string[];
  middlewareList: string[];
}): string {
  const frameworkGuidance = getFrameworkGuidance(params.frameworks);
  const middlewareStr =
    params.middlewareList.length > 0 ? params.middlewareList.join(" -> ") : "none detected";

  return [
    "You are a code path tracer. Given the entry point below, trace the complete execution path",
    "through the codebase to identify all function calls, middleware, and data transformations",
    "between the entrypoint and the final side effect (database write, network listener, HTTP response, file I/O, etc.).",
    "",
    "## Entry Point",
    `Method: ${params.method}`,
    `Path: ${params.routePath}`,
    `Handler: ${params.handlerSymbol} (${params.filePath}:${params.startLine})`,
    `Middleware chain: ${middlewareStr}`,
    "",
    "This entry point may be an HTTP handler, CLI command, startup hook, RPC bootstrap, or other server/event entry.",
    "",
    frameworkGuidance,
    "",
    "## Instructions",
    "1. Read the handler file and trace every function call it makes.",
    "2. For each call, use GetCallers/GetCallees or Read to follow the chain.",
    "3. Classify each hop as: middleware, controller, service, data-access, sanitizer, validator, transformer, or external-call.",
    "4. Record what data flows through each hop (parameter names, return values).",
    "5. Stop tracing at: database queries, external API calls, file system operations, process boundaries.",
    "",
    "## Cross-File Tracing Rules",
    "- When you encounter an import, Read the source module. Follow re-exports to their origin.",
    "- When a function takes a callback or returns a Promise, trace what the callback receives and what the Promise resolves to.",
    "- When data flows through a config object, use Grep to find where the config is populated.",
    "- When data is serialized/deserialized, track the field names across the boundary.",
    "",
    "## Output",
    "For each hop in the path, report:",
    "- filePath: relative path to the file",
    "- startLine: line number",
    "- symbol: function/method/class name",
    "- nodeKind: one of entry-http, entry-cli, entry-event, entry-cron, entry-background, middleware, controller, service, data-access, external-call, sanitizer, validator, transformer, unknown",
    "- edgeKind: how this hop connects to the previous one (calls, imports, middleware-chain, callback, promise-chain, event-emit, event-listen, di-inject, dynamic-dispatch, data-flow, config-read, serialization)",
    "- dataLabel: what data flows along this edge (e.g. 'req.body.username', 'userId param')",
    "- confidence: 0.0-1.0 how confident you are this hop exists",
  ].join("\n");
}

/**
 * Build a discovery-mode prompt for Phase B when no pre-identified entry points exist.
 * The LLM identifies entry points itself and traces security-relevant paths.
 */
export function buildDiscoveryPrompt(params: {
  fileList: string[];
  frameworks: string[];
  languages: string[];
  threatModelSummary?: string;
  repoContextSummary?: string;
}): string {
  const frameworkGuidance = getFrameworkGuidance(params.frameworks);
  const fileListStr = params.fileList.slice(0, 100).join("\n");
  const truncatedNote =
    params.fileList.length > 100
      ? `\n... and ${params.fileList.length - 100} more files (use Glob to explore)`
      : "";

  const sections: string[] = [
    "You are a code path tracer performing DISCOVERY MODE. No HTTP routes were pre-identified for this project.",
    "Your job is to (1) identify the main entry points, and (2) trace the most security-relevant execution paths from each.",
    "",
    "## Project Context",
    `Languages: ${params.languages.join(", ") || "unknown"}`,
    `Frameworks: ${params.frameworks.join(", ") || "none detected"}`,
  ];

  if (params.repoContextSummary) {
    sections.push("", params.repoContextSummary);
  }

  if (params.threatModelSummary) {
    sections.push("", "## Threat Model Context", params.threatModelSummary);
  }

  sections.push(
    "",
    "## Files in Import Graph",
    "These are the project's source files (excluding standard library and external dependencies):",
    fileListStr + truncatedNote,
    "",
    frameworkGuidance,
    "",
    "## Phase 1: Discover Entry Points",
    "Read the project's main files to identify ALL entry points. These include:",
    "- main() / init() functions (Go, C, Rust)",
    "- HTTP/gRPC/socket listeners (net.Listen, grpc.NewServer, http.ListenAndServe)",
    "- CLI command handlers (cobra, urfave/cli, flag, argparse, click)",
    "- Daemon/service loops, background workers, cron jobs",
    "- Event handlers, message queue consumers",
    "- Test harnesses that exercise security-relevant code",
    "",
    "Use Read, Grep, and Glob to find them. Don't guess — read the actual code.",
    "",
    "## Phase 2: Trace Security-Relevant Paths",
    "For each entry point you discover, trace the execution path focusing on:",
    "- Data flow from untrusted input to dangerous sinks (command execution, file I/O, network calls, deserialization)",
    "- Authentication and authorization decision points",
    "- Trust boundary crossings (network, process, privilege level)",
    "- Cryptographic operations and key management",
    "- Error handling paths that might leak information",
    "",
    "## Instructions",
    "1. Read main files (main.go, main.py, index.ts, etc.) to find entry points.",
    "2. For each entry point, use GetCallers/GetCallees and Read to trace the call chain.",
    "3. Classify each hop: middleware, controller, service, data-access, sanitizer, validator, transformer, external-call, or entry-*.",
    "4. Record what data flows through each hop.",
    "5. Stop at: database queries, external API calls, file system operations, process boundaries.",
    "",
    "## Output",
    "Return ALL traced hops across ALL entry points in a single array.",
    "For each hop, report:",
    "- filePath: relative path to the file",
    "- startLine: line number",
    "- symbol: function/method/class name",
    "- nodeKind: one of entry-http, entry-cli, entry-event, entry-cron, entry-background, middleware, controller, service, data-access, external-call, sanitizer, validator, transformer, unknown",
    "- edgeKind: how this hop connects to the previous (calls, imports, middleware-chain, callback, promise-chain, event-emit, event-listen, di-inject, dynamic-dispatch, data-flow, config-read, serialization)",
    "- dataLabel: what data flows along this edge (e.g. 'os.Args', 'net.Conn', 'tls.Config')",
    "- confidence: 0.0-1.0 how confident you are this hop exists",
  );

  return sections.join("\n");
}

/** JSON schema for the structured output of a code graph trace. */
export const TRACE_OUTPUT_SCHEMA = {
  type: "object",
  additionalProperties: false,
  required: ["hops"],
  properties: {
    hops: {
      type: "array",
      items: {
        type: "object",
        additionalProperties: false,
        required: ["filePath", "startLine", "symbol", "nodeKind", "edgeKind", "confidence"],
        properties: {
          filePath: { type: "string" },
          startLine: { type: "integer" },
          symbol: { type: "string" },
          nodeKind: {
            type: "string",
            enum: [
              "entry-http",
              "entry-cli",
              "entry-event",
              "entry-cron",
              "entry-background",
              "middleware",
              "controller",
              "service",
              "data-access",
              "external-call",
              "sanitizer",
              "validator",
              "transformer",
              "unknown",
            ],
          },
          edgeKind: {
            type: "string",
            enum: [
              "calls",
              "imports",
              "middleware-chain",
              "callback",
              "promise-chain",
              "event-emit",
              "event-listen",
              "di-inject",
              "dynamic-dispatch",
              "data-flow",
              "config-read",
              "serialization",
            ],
          },
          dataLabel: { type: "string" },
          confidence: { type: "number" },
        },
      },
    },
  },
} as const;
