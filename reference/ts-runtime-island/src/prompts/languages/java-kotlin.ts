// NOTE: This file contains DETECTION PATTERNS for a security scanner.
// The API references are DETECTION TARGETS describing what the scanner
// looks for in scanned codebases, not code this file executes.

import type { LanguageProfile } from "./types.js";

export const javaKotlinProfile: LanguageProfile = {
  languageId: "Java/Kotlin",
  aliases: ["java", "kotlin", "jvm", "kt"],
  generalHints: {
    grepPatterns: [
      "@RestController",
      "@Controller",
      "@RequestMapping",
      "@GetMapping",
      "@PostMapping",
      "@Service",
      "@Component",
      "HttpServlet",
      "doGet\\(",
      "doPost\\(",
    ],
    fileHints: [
      "pom.xml for Maven dependency versions and plugin configuration",
      "build.gradle / build.gradle.kts for Gradle dependency versions",
      "application.properties / application.yml for Spring Boot configuration",
      "web.xml for servlet mappings and filter chains",
      "SecurityConfig.java for Spring Security filter chain and auth rules",
      "persistence.xml / hibernate.cfg.xml for JPA/Hibernate settings",
    ],
    instructions: [
      "Check Spring Security configuration for permitAll on sensitive endpoints and CSRF settings",
      "Look for JNDI lookup calls — especially with user-controlled names (Log4Shell pattern)",
      "Inspect Jackson ObjectMapper configuration for enableDefaultTyping or polymorphic type handling",
      "Check for @CrossOrigin annotations with overly permissive origins",
    ],
  },
  generalAntiHallucination: [
    "Spring Data JPA repository methods with derived queries (findByName, etc.) use parameterized queries — they are SAFE against SQL injection",
    "Spring Security enables CSRF protection by default — do NOT flag CSRF unless it is explicitly disabled",
    "Hibernate parameter binding via :paramName or ?1 prevents SQL injection — do NOT flag parameterized HQL/JPQL",
  ],
  vulnClasses: {
    deserialization: {
      sinks: [
        {
          api: "ObjectInputStream.readObject()",
          risk: "Deserializes arbitrary Java objects — gadget chains enable RCE via crafted byte streams",
          cwes: ["CWE-502"],
        },
        {
          api: "XMLDecoder.readObject()",
          risk: "Deserializes Java objects from XML — allows arbitrary method invocation",
          cwes: ["CWE-502"],
        },
        {
          api: "XStream without security framework",
          risk: "Converts XML/JSON to Java objects — exploitable without allowlist via crafted type references",
          cwes: ["CWE-502"],
        },
        {
          api: "ObjectMapper.enableDefaultTyping()",
          risk: "Jackson polymorphic deserialization allows instantiation of arbitrary classes from JSON type hints",
          cwes: ["CWE-502"],
        },
        {
          api: "Kryo without class registration",
          risk: "Kryo deserializes arbitrary classes when setRegistrationRequired(false)",
          cwes: ["CWE-502"],
        },
      ],
      safePatterns: [
        {
          api: "Jackson ObjectMapper without polymorphic type handling",
          why: "Default Jackson only deserializes to the declared target type — no arbitrary class instantiation",
        },
        {
          api: "JSON-only processing (Gson, Jackson default)",
          why: "Plain JSON parsing to concrete types does not invoke gadget chains",
        },
        {
          api: "XStream with setupDefaultSecurity() and allowTypes()",
          why: "Allowlist restricts deserializable classes",
        },
        {
          api: "ObjectInputFilter (JEP 290)",
          why: "Java 9+ deserialization filter restricts classes during readObject()",
        },
      ],
      investigationHints: {
        grepPatterns: [
          "ObjectInputStream",
          "readObject\\(",
          "XMLDecoder",
          "enableDefaultTyping",
          "XStream",
          "Kryo",
          "setRegistrationRequired",
        ],
        fileHints: [
          "RMI service implementations and remote interfaces",
          "JMS message consumers and message-driven beans",
          "Custom HTTP message converters or servlet filters that read request body",
          "Cache serialization configuration (Redis, Hazelcast, EhCache)",
          "Session persistence / clustering configuration",
        ],
        instructions: [
          "Check if ObjectInputStream reads data from HTTP requests, message queues, or network sockets",
          "Look for RMI endpoints — Java RMI uses ObjectInputStream by default",
          "Inspect Jackson ObjectMapper configuration for activateDefaultTyping or enableDefaultTyping calls",
          "Check XStream instances — are they configured with allowTypes or setupDefaultSecurity?",
          "Look for Kryo instances — is setRegistrationRequired(true) called?",
        ],
      },
      fewShots: [
        {
          scenario: "RMI endpoint accepting serialized objects",
          vulnerableCode:
            "public class RemoteServiceImpl extends UnicastRemoteObject implements RemoteService {\n    public Object processData(byte[] data) throws RemoteException {\n        ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data));\n        return ois.readObject();\n    }\n}",
          explanation:
            "data is attacker-controlled byte array deserialized via ObjectInputStream. Attacker sends crafted serialized object with gadget chain (e.g., Commons Collections) to achieve RCE.",
        },
      ],
      frameworkGuidance: [
        {
          framework: "Spring Boot",
          defaults: [
            "Spring Boot uses Jackson with safe defaults (no polymorphic typing) for REST endpoints",
          ],
          pitfalls: [
            "Custom ObjectMapper beans may enable defaultTyping globally",
            "Spring Session with Redis may use Java serialization by default",
            "Spring Remoting (HttpInvoker, RMI) uses ObjectInputStream",
          ],
          configChecks: [
            "Check for ObjectMapper bean configuration in @Configuration classes",
            "Check spring.session.store-type and serializer settings",
            "Check for spring.remoting or HttpInvokerServiceExporter beans",
          ],
        },
        {
          framework: "Jakarta EE",
          defaults: ["JSON-B / JSON-P are safe for plain JSON processing"],
          pitfalls: [
            "JMS ObjectMessage uses Java serialization",
            "EJB remote interfaces use Java serialization over RMI/IIOP",
            "Custom JAX-RS MessageBodyReaders may use ObjectInputStream",
          ],
          configChecks: [
            "Check JMS consumer code for ObjectMessage usage",
            "Check remote EJB interfaces and their transport",
          ],
        },
      ],
      antiHallucinationExtra: [
        "Jackson ObjectMapper without enableDefaultTyping/activateDefaultTyping is SAFE — do NOT flag standard JSON deserialization to concrete types",
        "Gson.fromJson() to a concrete class is SAFE — Gson does not support polymorphic instantiation by default",
        "JSON parsing (Jackson, Gson, JSON-B) to concrete POJOs is NOT unsafe deserialization",
      ],
    },
    xxe: {
      sinks: [
        {
          api: "DocumentBuilderFactory without FEATURE_SECURE_PROCESSING",
          risk: "Parses XML with external entity resolution enabled — allows file read and SSRF",
          cwes: ["CWE-611"],
        },
        {
          api: "SAXParserFactory without secure features",
          risk: "SAX parsing with external entities enabled — same XXE risk as DocumentBuilder",
          cwes: ["CWE-611"],
        },
        {
          api: "XMLInputFactory without IS_SUPPORTING_EXTERNAL_ENTITIES=false",
          risk: "StAX parser resolves external entities by default on some implementations",
          cwes: ["CWE-611"],
        },
        {
          api: "TransformerFactory without secure processing",
          risk: "XSLT processing can resolve external entities and run code via xsl:script",
          cwes: ["CWE-611"],
        },
        {
          api: "SchemaFactory without secure processing",
          risk: "XML Schema validation can trigger external entity resolution",
          cwes: ["CWE-611"],
        },
      ],
      safePatterns: [
        {
          api: "DocumentBuilderFactory with FEATURE_SECURE_PROCESSING and disallowDoctype",
          why: "Secure processing feature disables external entities and DTD processing",
        },
        {
          api: "SAXParserFactory with external-general-entities and external-parameter-entities set to false",
          why: "Explicitly disables both types of external entity resolution",
        },
        {
          api: "XMLInputFactory with IS_SUPPORTING_EXTERNAL_ENTITIES=false and SUPPORT_DTD=false",
          why: "StAX parser will not resolve external entities or process DTDs",
        },
      ],
      investigationHints: {
        grepPatterns: [
          "DocumentBuilderFactory",
          "SAXParser",
          "XMLInputFactory",
          "FEATURE_SECURE",
          "TransformerFactory",
          "SchemaFactory",
          "external-general-entities",
          "IS_SUPPORTING_EXTERNAL_ENTITIES",
        ],
        fileHints: [
          "SOAP endpoint implementations and WS-* handlers",
          "XML import/upload features",
          "Configuration file parsers",
          "RSS/Atom feed parsers",
          "SAML authentication handlers",
        ],
        instructions: [
          "Check every DocumentBuilderFactory/SAXParserFactory instantiation — is FEATURE_SECURE_PROCESSING set?",
          "Look for factory.setFeature() calls — are external-general-entities and external-parameter-entities disabled?",
          "Check XMLInputFactory instances for IS_SUPPORTING_EXTERNAL_ENTITIES and SUPPORT_DTD settings",
          "SOAP endpoints are high-risk — the SOAP envelope is XML and often processed without XXE protection",
          "SAML XML parsing is a common XXE vector — check SAML library version and configuration",
        ],
      },
      fewShots: [
        {
          scenario: "SOAP endpoint parsing XML without XXE protection",
          vulnerableCode:
            '@WebServlet("/api/import")\npublic class ImportServlet extends HttpServlet {\n    protected void doPost(HttpServletRequest req, HttpServletResponse resp) {\n        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();\n        DocumentBuilder db = dbf.newDocumentBuilder();\n        Document doc = db.parse(req.getInputStream());\n        // process doc...\n    }\n}',
          explanation:
            "DocumentBuilderFactory is created with default settings — external entity resolution is enabled. Attacker sends XML with a DOCTYPE declaring an external entity to read local files or perform SSRF.",
        },
      ],
      frameworkGuidance: [
        {
          framework: "Spring Boot",
          defaults: ["Spring RestTemplate and WebClient do not parse XML by default"],
          pitfalls: [
            "Spring WS (spring-ws) endpoints parse SOAP XML — check XXE protection in Wss4jSecurityInterceptor",
            "Custom XML message converters may use unprotected parsers",
            "@RequestBody with XML content type uses JAXB which may be vulnerable depending on implementation",
          ],
          configChecks: [
            "Check for custom HttpMessageConverter beans that handle XML",
            "Check Spring WS configuration for secure XML parser settings",
          ],
        },
        {
          framework: "Jakarta EE",
          defaults: ["JAX-RS implementations vary in XML parser defaults"],
          pitfalls: [
            "JAX-WS SOAP endpoints use XML parsing internally",
            "JAXB unmarshalling may resolve external entities depending on the XML parser",
            "Servlet-based XML processing with manual DocumentBuilder creation",
          ],
          configChecks: [
            "Check web.xml for servlet-based XML endpoints",
            "Check JAX-WS handler chain configuration",
          ],
        },
      ],
      antiHallucinationExtra: [
        "DocumentBuilderFactory with setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true) and setFeature for disallow-doctype-decl is SAFE",
        "JAXB with a properly configured SAXSource is SAFE if the underlying parser disables external entities",
        "Do NOT flag XML generation (writing XML) — XXE is a parsing vulnerability only",
      ],
    },
    "command-injection": {
      sinks: [
        {
          api: "Runtime.getRuntime().exec(cmd) with single String",
          risk: "Single string form may invoke shell interpretation — metacharacter injection possible",
          shellInvoking: true,
          cwes: ["CWE-78"],
        },
        {
          api: "ProcessBuilder with shell wrapper",
          risk: "ProcessBuilder wrapping /bin/sh -c or cmd /c enables shell interpretation of user input",
          shellInvoking: true,
          cwes: ["CWE-78"],
        },
        {
          api: "Runtime.exec with cmd /c and user input",
          risk: "Windows cmd.exe shell interpretation of user-controlled arguments",
          shellInvoking: true,
          cwes: ["CWE-78"],
        },
      ],
      safePatterns: [
        {
          api: "ProcessBuilder with argument list",
          why: "ProcessBuilder(List<String>) passes arguments directly to the process — no shell interpretation",
        },
        {
          api: "Runtime.exec(String[]) array form",
          why: "Array form bypasses shell — arguments are passed directly to the target process",
        },
        {
          api: "ProcessBuilder with hardcoded commands only",
          why: "No attacker-controlled data in process arguments",
        },
      ],
      investigationHints: {
        grepPatterns: [
          "Runtime\\.getRuntime\\(\\)",
          "ProcessBuilder",
          "\\.exec\\(",
          "/bin/sh",
          "cmd\\.exe",
        ],
        fileHints: [
          "Utility classes that wrap system command invocation",
          "File processing services (PDF generation, image conversion)",
          "Build/deployment automation code",
          "Monitoring or health check endpoints that invoke system commands",
        ],
        instructions: [
          "Check if Runtime.exec() uses single String form (shell interpretation) vs String[] array form (safe)",
          "Look for ProcessBuilder calls that wrap commands in /bin/sh -c or cmd /c — this reintroduces shell interpretation",
          "Trace user input from @RequestParam, @PathVariable, or request body to process invocation arguments",
          "Check for string concatenation building command strings with user-controlled data",
        ],
      },
      fewShots: [
        {
          scenario: "File conversion endpoint with user-controlled filename in exec call",
          vulnerableCode:
            '@PostMapping("/convert")\npublic ResponseEntity<byte[]> convert(@RequestParam String filename) {\n    Process p = Runtime.getRuntime().exec("convert " + filename + " output.png");\n    // read process output...\n}',
          explanation:
            "filename is user-controlled and concatenated into a single command string passed to exec(String). Attacker injects shell metacharacters to run arbitrary commands.",
        },
      ],
      frameworkGuidance: [
        {
          framework: "Spring Boot",
          defaults: ["Spring does not provide command invocation utilities"],
          pitfalls: [
            "Controller methods that invoke system commands for file processing",
            "Scheduled tasks (@Scheduled) that run system commands with dynamic parameters",
            "Actuator custom endpoints that expose command invocation",
          ],
          configChecks: [
            "Check for custom ProcessBuilder or Runtime usage in service classes",
            "Review @Scheduled methods for command invocation with variable input",
          ],
        },
      ],
      antiHallucinationExtra: [
        "ProcessBuilder with a List<String> of separate arguments (no shell wrapper) is SAFE against metacharacter injection — do NOT flag it",
        'Runtime.exec(new String[]{"program", "arg1", "arg2"}) array form does NOT invoke shell — it is SAFE',
        "Do NOT flag Runtime.exec or ProcessBuilder calls where all arguments are hardcoded constants",
      ],
    },
    ssrf: {
      sinks: [
        {
          api: "HttpURLConnection with user-controlled URL",
          risk: "Direct HTTP connection to attacker-specified URL enables access to internal services",
          cwes: ["CWE-918"],
        },
        {
          api: "OkHttpClient with user-controlled URL",
          risk: "HTTP client follows redirects by default — can reach internal endpoints",
          cwes: ["CWE-918"],
        },
        {
          api: "RestTemplate with user-controlled URL",
          risk: "Spring RestTemplate makes HTTP request to attacker-specified URL",
          cwes: ["CWE-918"],
        },
        {
          api: "WebClient with user-controlled URL",
          risk: "Spring WebFlux reactive HTTP client with user-controlled target",
          cwes: ["CWE-918"],
        },
        {
          api: "URL(userInput).openConnection()",
          risk: "Supports file://, jar://, and other protocol handlers beyond HTTP",
          cwes: ["CWE-918"],
        },
      ],
      safePatterns: [
        {
          api: "URL validated against allowlist of domains/IPs",
          why: "Only permitted destinations are reachable",
        },
        {
          api: "Requests to hardcoded URLs with user data in body/params only",
          why: "URL is fixed — user controls only the payload, not the destination",
        },
        {
          api: "URL parsed and validated against scheme + host allowlist before request",
          why: "Proper validation prevents reaching internal endpoints",
        },
      ],
      investigationHints: {
        grepPatterns: [
          "new URL\\(",
          "HttpURLConnection",
          "RestTemplate",
          "WebClient",
          "OkHttpClient",
          "\\.openConnection\\(",
          "URI\\.create\\(",
        ],
        fileHints: [
          "Webhook registration and callback endpoints",
          "URL preview/unfurl features",
          "Proxy or redirect endpoints",
          "File download/import-from-URL features",
          "OAuth callback and token exchange handlers",
        ],
        instructions: [
          "Check if the URL parameter originates from user input (@RequestParam, @PathVariable, request body, database record)",
          'Look for URL validation that can be bypassed — checking startsWith("http") does NOT prevent http://169.254.169.254',
          "Check for redirect following — OkHttpClient and HttpURLConnection follow redirects by default, which can bypass URL checks",
          "Cloud metadata: can the URL reach 169.254.169.254 (AWS), metadata.google.internal (GCP), or 169.254.169.254 (Azure)?",
          "Check for DNS rebinding — URL validated against allowlist but DNS resolves to internal IP at request time",
        ],
      },
      fewShots: [
        {
          scenario: "Spring controller fetching user-provided URL",
          vulnerableCode:
            '@GetMapping("/preview")\npublic ResponseEntity<String> preview(@RequestParam String url) {\n    RestTemplate restTemplate = new RestTemplate();\n    String body = restTemplate.getForObject(url, String.class);\n    return ResponseEntity.ok(body);\n}',
          explanation:
            "url is directly from @RequestParam with no validation. Attacker sends http://169.254.169.254/latest/meta-data/ to read AWS instance metadata or http://internal-service:8080/admin to access internal APIs.",
        },
      ],
      frameworkGuidance: [
        {
          framework: "Spring Boot",
          defaults: ["RestTemplate and WebClient do not validate destination URLs"],
          pitfalls: [
            "Feign clients with dynamic URL construction from user input",
            "Spring Cloud Gateway routes with user-controlled forwarding targets",
            "Actuator endpoints that proxy requests",
          ],
          configChecks: [
            "Check RestTemplate and WebClient bean configurations for interceptors that validate URLs",
            "Review Feign client interfaces for dynamic @Url parameters",
          ],
        },
      ],
      antiHallucinationExtra: [
        "RestTemplate/WebClient requests to hardcoded URLs with only user-controlled query parameters or request body are NOT SSRF",
        "Internal service-to-service calls with no user-controlled URL component are NOT SSRF",
        "Feign client calls to service-discovery-resolved names (Eureka, Consul) without user-controlled URL are NOT SSRF",
      ],
    },
    "template-injection": {
      sinks: [
        {
          api: "SpelExpressionParser with user input",
          risk: "Spring Expression Language (SpEL) enables method invocation and class instantiation — RCE via type references",
          cwes: ["CWE-917"],
        },
        {
          api: "Velocity.evaluate() with user template string",
          risk: "Apache Velocity templates allow arbitrary Java method calls via reflection",
          cwes: ["CWE-1336"],
        },
        {
          api: "Freemarker Template with user-controlled source",
          risk: "FreeMarker new() builtin allows arbitrary class instantiation",
          cwes: ["CWE-1336"],
        },
        {
          api: "OGNL with user input",
          risk: "Object-Graph Navigation Language enables arbitrary method invocation — Struts2 RCE vector",
          cwes: ["CWE-917"],
        },
      ],
      safePatterns: [
        {
          api: "SpEL with SimpleEvaluationContext",
          why: "SimpleEvaluationContext restricts type references and method invocation — safe for user expressions",
        },
        {
          api: "Velocity/Freemarker with user data as template variables only",
          why: "User data passed as variables, not as template source — no code invocation",
        },
        {
          api: "Thymeleaf with th:text (escaped output)",
          why: "th:text escapes output — only th:utext or preprocessing expressions are dangerous",
        },
      ],
      investigationHints: {
        grepPatterns: [
          "SpelExpressionParser",
          "parseExpression\\(",
          "Velocity",
          "Freemarker",
          "FreeMarker",
          "OGNL",
          "OgnlUtil",
          "StandardEvaluationContext",
          "SimpleEvaluationContext",
        ],
        fileHints: [
          "Spring controllers that evaluate user-provided expressions",
          "Email template generation services",
          "Report generation with dynamic templates",
          "Rule engine or formula evaluation features",
          "Struts2 action classes (for OGNL)",
        ],
        instructions: [
          "Check if SpelExpressionParser evaluates user-supplied strings — is StandardEvaluationContext or SimpleEvaluationContext used?",
          "StandardEvaluationContext allows type references for RCE — SimpleEvaluationContext does NOT",
          "Look for Velocity.evaluate() where the template string comes from user input or database",
          "Check Freemarker configuration — is new_builtin_class_resolver set to restrict class instantiation?",
          "Inspect Struts2 action configurations for OGNL evaluation of user parameters",
        ],
      },
      fewShots: [
        {
          scenario: "Spring endpoint using SpEL with user input",
          vulnerableCode:
            '@GetMapping("/calc")\npublic String calculate(@RequestParam String expression) {\n    SpelExpressionParser parser = new SpelExpressionParser();\n    StandardEvaluationContext ctx = new StandardEvaluationContext();\n    Object result = parser.parseExpression(expression).getValue(ctx);\n    return result.toString();\n}',
          explanation:
            "expression is directly from @RequestParam and evaluated with StandardEvaluationContext. Attacker sends a SpEL expression using type references to invoke runtime methods for RCE.",
        },
      ],
      frameworkGuidance: [
        {
          framework: "Spring Boot",
          defaults: ["Thymeleaf auto-escapes with th:text by default"],
          pitfalls: [
            "SpEL in @Value annotations is safe (compile-time), but dynamic SpEL evaluation of user input is dangerous",
            "Spring Security expressions (@PreAuthorize) use SpEL but are not user-controlled",
            "Thymeleaf preprocessing expressions __${...}__ can evaluate user input as SpEL",
          ],
          configChecks: [
            "Check for SpelExpressionParser usage in controller/service code",
            "Check Thymeleaf templates for __${...}__ preprocessing expressions",
          ],
        },
        {
          framework: "Jakarta EE",
          defaults: ["JSP EL (Expression Language) has limited functionality compared to SpEL"],
          pitfalls: [
            "Unified EL in JSF can evaluate user-controlled expressions",
            "Struts2 OGNL injection has been a recurring critical vulnerability",
            "Custom tag libraries may evaluate expressions unsafely",
          ],
          configChecks: [
            "Check Struts2 version — many OGNL injection CVEs exist in older versions",
            "Check JSF managed bean properties for expression evaluation",
          ],
        },
      ],
      antiHallucinationExtra: [
        'SpEL in @Value("${property}") annotations reads config properties at startup — this is NOT user-controlled and is SAFE',
        "@PreAuthorize(\"hasRole('ADMIN')\") uses SpEL but the expression is hardcoded — NOT injectable",
        'Thymeleaf th:text="${variable}" is SAFE — it escapes output and does not evaluate variable as an expression',
      ],
    },
    "auth-bypass": {
      sinks: [
        {
          api: "Controller methods missing @PreAuthorize/@Secured",
          risk: "Endpoint accessible without authorization check — may expose sensitive operations",
          cwes: ["CWE-862"],
        },
        {
          api: "permitAll() on sensitive endpoints",
          risk: "Spring Security explicitly allows unauthenticated access to endpoints that should be protected",
          cwes: ["CWE-862"],
        },
        {
          api: "IDOR via @PathVariable without ownership check",
          risk: "User can access or modify other users' resources by changing the ID in the path",
          cwes: ["CWE-639"],
        },
        {
          api: "CSRF disabled globally via csrf().disable()",
          risk: "State-changing endpoints vulnerable to cross-site request forgery",
          cwes: ["CWE-352"],
        },
      ],
      safePatterns: [
        {
          api: "Method-level @PreAuthorize with proper role/ownership checks",
          why: "Authorization verified before business logic runs",
        },
        {
          api: "@Secured with role-based access control",
          why: "Spring Security enforces role requirement at method level",
        },
        {
          api: "Ownership check comparing resource owner to authenticated principal",
          why: "Prevents IDOR by verifying the current user owns the resource",
        },
      ],
      investigationHints: {
        grepPatterns: [
          "@PreAuthorize",
          "@Secured",
          "antMatchers",
          "requestMatchers",
          "permitAll",
          "csrf\\(\\)\\.disable",
          "@PathVariable",
          "SecurityFilterChain",
        ],
        fileHints: [
          "Spring Security configuration classes (@EnableWebSecurity)",
          "REST controller classes with @RestController or @Controller",
          "Custom authentication filters and providers",
          "Method-level security configuration (@EnableMethodSecurity)",
        ],
        instructions: [
          "Map all controller endpoints and check each for authorization annotations or SecurityFilterChain rules",
          "Look for permitAll() in SecurityFilterChain — are sensitive endpoints (admin, user data, payment) accidentally unprotected?",
          "Check for IDOR: endpoints with @PathVariable id — is there a check that the authenticated user owns the resource?",
          "Verify that @EnableMethodSecurity or @EnableGlobalMethodSecurity is present when using @PreAuthorize",
          "Check for csrf().disable() — is it a REST-only API with token auth (acceptable) or a web app with session cookies (dangerous)?",
        ],
      },
      fewShots: [
        {
          scenario: "REST endpoint without authorization annotation",
          vulnerableCode:
            '@RestController\n@RequestMapping("/api/admin")\npublic class AdminController {\n    @DeleteMapping("/users/{id}")\n    public ResponseEntity<Void> deleteUser(@PathVariable Long id) {\n        userService.deleteUser(id);\n        return ResponseEntity.noContent().build();\n    }\n}',
          explanation:
            "Admin endpoint has no @PreAuthorize or @Secured annotation and no SecurityFilterChain rule restricting /api/admin/**. Any authenticated user (or unauthenticated if permitAll) can delete users.",
        },
      ],
      frameworkGuidance: [
        {
          framework: "Spring Boot",
          defaults: [
            "Spring Security requires authentication for all endpoints by default when on classpath",
            "CSRF protection is enabled by default for session-based auth",
          ],
          pitfalls: [
            "Overly broad permitAll() rules that match sensitive paths",
            "@EnableMethodSecurity must be present for @PreAuthorize to work — missing it silently disables method security",
            "Custom AuthenticationProvider may accept unexpected credentials",
            "JWT validation without signature verification or expiry check",
          ],
          configChecks: [
            "Check SecurityFilterChain bean for permitAll() rules and their URL patterns",
            "Verify @EnableMethodSecurity is present in a @Configuration class",
            "Check JWT token validation — is the signature verified? Is expiry checked?",
            "Review CORS configuration for overly permissive origins",
          ],
        },
        {
          framework: "Jakarta EE",
          defaults: [
            "Java EE/Jakarta security constraints in web.xml restrict URL patterns by role",
          ],
          pitfalls: [
            "Missing <security-constraint> for new endpoints added after initial deployment descriptor",
            "Programmatic security (HttpServletRequest.isUserInRole) may be inconsistently applied",
            "@RolesAllowed annotation requires container-managed security to be active",
          ],
          configChecks: [
            "Check web.xml for <security-constraint> coverage of all sensitive URL patterns",
            "Verify <login-config> is properly configured",
            "Check @RolesAllowed annotations on EJB and JAX-RS endpoints",
          ],
        },
      ],
      antiHallucinationExtra: [
        "Public endpoints like /login, /register, /health, /actuator/health are EXPECTED to have permitAll() — do NOT flag them",
        "REST APIs using stateless JWT authentication legitimately disable CSRF — do NOT flag csrf().disable() for stateless APIs",
        "Spring Security secures all endpoints by default when spring-boot-starter-security is on the classpath — only flag if explicit permitAll() opens sensitive paths",
      ],
    },
  },
};
