/**
 * Build a filtered environment for agent subprocesses (Claude Code, pi-ai).
 *
 * The full `process.env` of a Kuzushi run typically contains unrelated
 * credentials — cloud provider keys, source-control tokens, database
 * passwords, CI secrets — that the LLM subprocess has no business reading
 * (and that could be echoed back through tool output, logs, or prompts).
 *
 * This function applies a deny-by-pattern filter: variables whose **name**
 * matches a known credential pattern are stripped, unless they are on the
 * explicit allowlist of vars the agent runtime actually needs (e.g.
 * `ANTHROPIC_API_KEY`).
 *
 * The rest of the environment is passed through unchanged so that
 * essentials like `PATH`, `HOME`, proxy settings, custom CA bundles, and
 * locale variables continue to work.
 */

/**
 * Variable names that must always be passed through untouched, even if they
 * match the deny patterns below.
 */
const ALWAYS_ALLOW = new Set<string>([
  "ANTHROPIC_API_KEY",
  "ANTHROPIC_AUTH_TOKEN",
  "ANTHROPIC_BASE_URL",
  "ANTHROPIC_OAUTH_TOKEN",
  "ANTHROPIC_VERTEX_PROJECT_ID",
  "CLAUDE_CODE_MAX_OUTPUT_TOKENS",
  "CLAUDE_CODE_USE_BEDROCK",
  "CLAUDE_CODE_USE_VERTEX",
]);

/**
 * Case-insensitive substring/suffix patterns that mark a variable name as
 * carrying a credential. Matched against the variable **name only**, not
 * the value, so we never log the value during filtering.
 */
const DENY_PATTERNS: readonly RegExp[] = [
  /API[_-]?KEY$/i,
  /SECRET(_KEY|_ACCESS_KEY|_TOKEN)?$/i,
  /(^|_)TOKEN$/i,
  /PASSWORD$/i,
  /PASSWD$/i,
  /PASSPHRASE$/i,
  /^AWS_/i,
  /^GCP_/i,
  /^GOOGLE_APPLICATION_CREDENTIALS$/i,
  /^GITHUB_TOKEN$/i,
  /^GH_TOKEN$/i,
  /^GITLAB_TOKEN$/i,
  /^NPM_TOKEN$/i,
  /^DATABASE_URL$/i,
  /^POSTGRES_PASSWORD$/i,
  /^MYSQL_PASSWORD$/i,
  /^MONGO_INITDB_ROOT_PASSWORD$/i,
  /^REDIS_PASSWORD$/i,
  /^SLACK_(TOKEN|WEBHOOK_URL)$/i,
  /^STRIPE_/i,
  /^TWILIO_/i,
  /^SENDGRID_/i,
  /^OPENAI_API_KEY$/i,
  /^GEMINI_API_KEY$/i,
  /^GOOGLE_API_KEY$/i,
  /^MISTRAL_API_KEY$/i,
  /^GROQ_API_KEY$/i,
  /^COHERE_API_KEY$/i,
  /^HUGGINGFACE_TOKEN$/i,
];

/** Returns true if `name` looks like a credential variable that should be stripped. */
function looksLikeCredential(name: string): boolean {
  if (ALWAYS_ALLOW.has(name)) return false;
  return DENY_PATTERNS.some((re) => re.test(name));
}

/**
 * Build a subprocess environment from the parent process env, stripping
 * credential-shaped variables. Pass `extra` to add or override entries
 * (e.g. the explicit `ANTHROPIC_API_KEY` Kuzushi configured for this run).
 *
 * Stripped variable names are returned via the `stripped` array so callers
 * can log a one-time warning. Values are never returned.
 */
export function buildSubprocessEnv(
  parent: NodeJS.ProcessEnv = process.env,
  extra: Record<string, string | undefined> = {},
): { env: Record<string, string | undefined>; stripped: string[] } {
  const env: Record<string, string | undefined> = {};
  const stripped: string[] = [];

  for (const [name, value] of Object.entries(parent)) {
    if (looksLikeCredential(name)) {
      stripped.push(name);
      continue;
    }
    env[name] = value;
  }

  for (const [name, value] of Object.entries(extra)) {
    env[name] = value;
  }

  return { env, stripped };
}

/** Exposed for tests. */
export const __test__ = { looksLikeCredential, ALWAYS_ALLOW, DENY_PATTERNS };
