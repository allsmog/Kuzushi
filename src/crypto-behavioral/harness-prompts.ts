import path from "node:path";
import { formatRepoContext } from "../repo-context.js";
import type { Finding } from "../scanners/types.js";
import type { RepoContext } from "../types.js";
import type { CryptoBehavioralTestType } from "./types.js";

export interface CryptoBehavioralPromptOptions {
  repoContext?: RepoContext;
  timingIterations?: number;
}

export function resolveCryptoHarnessLanguage(
  finding: Pick<Finding, "filePath">,
  repoContext?: RepoContext,
): "javascript" | "python" | "go" {
  const normalizedLanguages = new Set(
    (repoContext?.languages ?? []).map((value) => value.trim().toLowerCase()),
  );

  if (normalizedLanguages.has("python")) {
    return "python";
  }

  if (normalizedLanguages.has("go")) {
    return "go";
  }

  if (normalizedLanguages.has("typescript") || normalizedLanguages.has("javascript")) {
    return "javascript";
  }

  const ext = path.extname(finding.filePath).toLowerCase();
  if (ext === ".py") {
    return "python";
  }
  if (ext === ".go") {
    return "go";
  }

  return "javascript";
}

export function buildCryptoBehavioralSystemPrompt(repoContext?: RepoContext): string {
  const repoSection = formatRepoContext(repoContext);
  const repoBlock =
    repoSection.length > 0 ? "## Repository Context\n" + repoSection.join("\n") + "\n\n" : "";

  return (
    repoBlock +
    [
      "You generate runnable crypto behavioral harnesses that import and execute REAL repository code.",
      "",
      "## Anti-hallucination constraints",
      "- Do NOT simulate the vulnerable function.",
      "- Import the REAL comparison, encryption, hashing, key-generation, or TLS code path from the repository.",
      "- Do not invent files, exports, algorithms, configuration objects, or helper APIs.",
      "- If the target cannot be isolated with lightweight local setup, set skipped=true and explain why.",
      "- Prefer the smallest runnable harness that confirms or rejects the behavior.",
      "",
      "## Harness contract",
      "- The script must print exactly one line starting with CRYPTO_RESULT: followed by a JSON object.",
      "- The JSON must include fingerprint, testType, verdict, and summary.",
      "- Add type-specific fields when relevant: timing, observedBehavior, expectedBehavior, algorithmConfirmed, keyLengthBits.",
      "- Exit code 0 means vulnerable confirmed, 1 means secure confirmed, 2 means inconclusive, 3 means harness error.",
      "",
      "## Structured output requirements",
      "Return ONLY a JSON object with keys:",
      "fingerprint, test_type, script_content(string|null), language(string|null), skipped(boolean), skip_reason(string|null)",
    ].join("\n")
  );
}

export function buildTimingHarnessPrompt(
  finding: Finding,
  repoRoot: string,
  options: CryptoBehavioralPromptOptions = {},
): string {
  const language = resolveCryptoHarnessLanguage(finding, options.repoContext);
  const iterations = Math.max(1, Math.floor(options.timingIterations ?? 10_000));

  return buildBehavioralHarnessPrompt(finding, repoRoot, "timing", language, [
    "Generate a Dudect-style timing harness.",
    "- Import the real comparison or token validation path.",
    "- Build two input classes: one that shares a correct prefix with the expected secret, and one clearly wrong input.",
    `- Run ${iterations} interleaved iterations.`,
    "- Measure each iteration and compute Welch's t-test inside the script.",
    "- Mark the target as vulnerable when timing differences are statistically significant and constantTime is false.",
    "- Include timing.constantTime, timing.tStatistic, timing.pValue, timing.meanANs, timing.meanBNs, and timing.iterations in CRYPTO_RESULT.",
  ]);
}

export function buildEcbModeHarnessPrompt(
  finding: Finding,
  repoRoot: string,
  options: CryptoBehavioralPromptOptions = {},
): string {
  const language = resolveCryptoHarnessLanguage(finding, options.repoContext);

  return buildBehavioralHarnessPrompt(finding, repoRoot, "ecb-mode", language, [
    "Generate an ECB detection harness.",
    "- Import the real encryption path.",
    "- Encrypt plaintext containing two identical 16-byte blocks.",
    "- Compare ciphertext blocks and report vulnerable only when identical plaintext blocks produce identical ciphertext blocks.",
    "- Include observedBehavior and expectedBehavior in CRYPTO_RESULT.",
    "- When the runtime confirms a different mode, include algorithmConfirmed and return secure or inconclusive accordingly.",
  ]);
}

export function buildWeakHashHarnessPrompt(
  finding: Finding,
  repoRoot: string,
  options: CryptoBehavioralPromptOptions = {},
): string {
  const language = resolveCryptoHarnessLanguage(finding, options.repoContext);

  return buildBehavioralHarnessPrompt(finding, repoRoot, "weak-hash", language, [
    "Generate a weak-hash confirmation harness.",
    "- Import the real hashing or password-storage path.",
    "- Confirm the algorithm at runtime when possible.",
    "- If the code uses MD5, SHA1, or another fast/legacy hash for authentication, password storage, or token security, report vulnerable.",
    "- Include algorithmConfirmed and, when useful, observedBehavior describing the produced digest length or algorithm name.",
    "- Treat non-security-critical hashing as secure only when the harness can prove the callsite is not used for auth, password storage, or token validation.",
  ]);
}

export function buildWeakPrngHarnessPrompt(
  finding: Finding,
  repoRoot: string,
  options: CryptoBehavioralPromptOptions = {},
): string {
  const language = resolveCryptoHarnessLanguage(finding, options.repoContext);

  return buildBehavioralHarnessPrompt(finding, repoRoot, "weak-prng", language, [
    "Generate a weak-PRNG confirmation harness.",
    "- Import the real token, nonce, key-generation, or random-value path.",
    "- Collect multiple outputs from the real code path.",
    "- Detect repeated values, obvious patterns, or use of non-cryptographic randomness such as Math.random equivalents.",
    "- Include observedBehavior and algorithmConfirmed when the runtime reveals the random source.",
    "- Prefer runtime confirmation of the actual PRNG source over theoretical claims.",
  ]);
}

export function buildKeyLengthHarnessPrompt(
  finding: Finding,
  repoRoot: string,
  options: CryptoBehavioralPromptOptions = {},
): string {
  const language = resolveCryptoHarnessLanguage(finding, options.repoContext);

  return buildBehavioralHarnessPrompt(finding, repoRoot, "key-length", language, [
    "Generate a key-length confirmation harness.",
    "- Import the real key creation or crypto initialization path.",
    "- Extract the actual runtime key size in bits.",
    "- Report vulnerable when RSA/DSA keys are below 2048 bits or when the runtime confirms another policy-violating weak key size.",
    "- Include algorithmConfirmed and keyLengthBits in CRYPTO_RESULT.",
  ]);
}

export function buildEdgeCaseHarnessPrompt(
  finding: Finding,
  repoRoot: string,
  options: CryptoBehavioralPromptOptions = {},
): string {
  const language = resolveCryptoHarnessLanguage(finding, options.repoContext);

  return buildBehavioralHarnessPrompt(finding, repoRoot, "edge-case", language, [
    "Generate an edge-case behavioral harness.",
    "- Import the real crypto or TLS configuration path.",
    "- Exercise local negative cases relevant to the finding: self-signed certs, hostname mismatch, expired certs, null bytes, zero-length inputs, invalid ASN.1, or boundary values.",
    "- Report vulnerable only when the real code accepts data or connections that should be rejected.",
    "- Include observedBehavior and expectedBehavior in CRYPTO_RESULT.",
  ]);
}

export function buildPromptForTestType(
  testType: CryptoBehavioralTestType,
  finding: Finding,
  repoRoot: string,
  options: CryptoBehavioralPromptOptions = {},
): string {
  switch (testType) {
    case "timing":
      return buildTimingHarnessPrompt(finding, repoRoot, options);
    case "ecb-mode":
      return buildEcbModeHarnessPrompt(finding, repoRoot, options);
    case "weak-hash":
      return buildWeakHashHarnessPrompt(finding, repoRoot, options);
    case "weak-prng":
      return buildWeakPrngHarnessPrompt(finding, repoRoot, options);
    case "key-length":
      return buildKeyLengthHarnessPrompt(finding, repoRoot, options);
    case "edge-case":
      return buildEdgeCaseHarnessPrompt(finding, repoRoot, options);
  }
}

function buildBehavioralHarnessPrompt(
  finding: Finding,
  repoRoot: string,
  testType: CryptoBehavioralTestType,
  language: "javascript" | "python" | "go",
  testInstructions: string[],
): string {
  return [
    "You are a crypto behavioral harness generator.",
    "Generate a runnable harness that imports and executes REAL repository code.",
    "",
    "## Mandatory code-reading gate",
    `BEFORE generating code, use Read on ${finding.filePath}:${finding.startLine} with at least 50 lines of context.`,
    "Verify the target function signature, import path, and any required setup exist in the repository.",
    "",
    "## Finding",
    `Repo root: ${repoRoot}`,
    `Rule: ${finding.ruleId}`,
    `File: ${finding.filePath}:${finding.startLine}`,
    `Severity: ${finding.severity}`,
    `Message: ${finding.message}`,
    `Evidence: ${finding.evidence ?? "none"}`,
    `Fingerprint: ${finding.fingerprint}`,
    `Test type: ${testType}`,
    "",
    "## Language requirements",
    ...buildLanguageRequirements(language),
    "",
    "## Test requirements",
    ...testInstructions,
    "",
    "## Runtime output requirements",
    "- The script itself must emit exactly one CRYPTO_RESULT JSON line.",
    "- The JSON must contain fingerprint, testType, verdict, and summary.",
    "- Set testType to the requested behavioral test type.",
    "",
    "## Generator output requirements",
    `- Return language=${language}.`,
    "- Return script_content as a complete runnable script.",
    "- If generation is impossible, set skipped=true and explain why.",
  ].join("\n");
}

function buildLanguageRequirements(language: "javascript" | "python" | "go"): string[] {
  if (language === "python") {
    return [
      "- Emit Python only. The script must run with python3.",
      "- Use time.perf_counter_ns() for timing measurements.",
      "- Do not emit TypeScript or shell wrappers.",
    ];
  }

  if (language === "go") {
    return [
      "- Emit Go only. The script must run with go run.",
      "- Use time.Now().UnixNano() for timing measurements.",
      "- Keep dependencies limited to the standard library and repository modules.",
    ];
  }

  return [
    "- Emit JavaScript only. Do NOT emit TypeScript.",
    "- The script must run with node.",
    "- Use process.hrtime.bigint() for timing measurements.",
  ];
}
