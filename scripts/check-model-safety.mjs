#!/usr/bin/env node
import { execFileSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import path from "node:path";

const root = repoRoot();
const MODEL_LITERAL =
  "(?:(?:anthropic|openai|openai-codex):[^\"'`]+|(?:gpt|claude)-[A-Za-z0-9._:-]+)";
const FORBIDDEN_MODEL_DEFAULTS = [
  [
    "hardcoded model fallback expression",
    new RegExp(String.raw`(?:\?\?|unwrap_or(?:_else)?|or_else)\s*\([^)]*["']${MODEL_LITERAL}["']`),
  ],
  [
    "hardcoded model field literal",
    new RegExp(String.raw`\bmodel\s*[:=]\s*["']${MODEL_LITERAL}["']`),
  ],
];
const FORBIDDEN_MODEL_DEFAULT_BLOCKS = [
  [
    "hardcoded multiline model fallback expression",
    new RegExp(String.raw`(?:\?\?|unwrap_or(?:_else)?|or_else)\s*\([\s\S]{0,240}?["']${MODEL_LITERAL}["']`, "g"),
  ],
  [
    "hardcoded multiline model field literal",
    new RegExp(String.raw`\bmodel\s*[:=]\s*[\r\n\t ]+["']${MODEL_LITERAL}["']`, "g"),
  ],
];
const FORBIDDEN_FALLBACK_SURFACES = [
  ["retired TypeScript fallbackModel surface", /\bfallbackModel\b/],
  ["retired TypeScript consentToModelFallback surface", /\bconsentToModelFallback\b/],
  ["retired model fallback env surface", /\bKUZUSHI_ALLOW_MODEL_FALLBACK\b/],
  ["retired silent fallback error surface", /\bKuzushiSilentFallbackError\b/],
];
const REQUIRED_POLICY_COVERAGE = [
  {
    label: "runtime no-silent-fallback policy",
    file: "crates/kuzushi-core/src/runtime/policy/no_silent_fallback.rs",
    required: [
      "require_configured_model",
      "resolve_explicit_model",
      "validate_model_spec",
      "canonical_model_spec",
      "normalize_model_spec",
      "format!(\"{provider}:{model_id}\")",
    ],
  },
  {
    label: "runtime policy exports no-silent-fallback helpers",
    file: "crates/kuzushi-core/src/runtime/policy/mod.rs",
    required: [
      "canonical_model_spec",
      "require_configured_model",
      "resolve_explicit_model",
      "validate_model_spec",
    ],
  },
  {
    label: "config loading stores canonical explicit models",
    file: "crates/kuzushi-core/src/config/apply_env_overrides.rs",
    required: ["normalize_config", "canonical_model_spec"],
  },
  {
    label: "config tests cover canonical stored model output",
    file: "crates/kuzushi-core/src/config/tests.rs",
    required: ["canonicalizes_configured_model_spec", " openai : gpt-5.5 "],
  },
  {
    label: "doctor model check uses shared model policy",
    file: "crates/kuzushi-cli/src/doctor/checks.rs",
    required: ["check_model_config", "canonical_model_spec"],
  },
  {
    label: "doctor tests cover shared model policy",
    file: "crates/kuzushi-cli/src/tests.rs",
    required: [
      "doctor_model_check_uses_shared_model_policy",
      " openai : gpt-5.5 ",
      "no fallback model will be selected",
    ],
  },
  {
    label: "agent router rejects fallback chains",
    file: "crates/kuzushi-core/src/agent_router/router_state.rs",
    required: ["ensure_no_model_fallbacks", "declares model fallbacks"],
  },
  {
    label: "exploit-chain tool boundary uses shared no-silent-fallback policy",
    file: "crates/kuzushi-core/src/modules/native_scanners/register_modules.rs",
    required: ["require_exploit_chain_model", "require_configured_model(\"exploit-chain:scan\""],
  },
  {
    label: "shared runtime requirement policy covers mode parity",
    file: "crates/kuzushi-core/src/modules/runtime_requirements.rs",
    required: [
      "Single source of truth",
      "RUNTIME_TOOL_NAMES",
      "tool_needs_runtime",
      "wants_sast_runtime",
      "sast:scan",
      "allowlist_is_sorted_for_binary_search",
      "tools_that_bail_without_runtime_are_listed",
    ],
  },
  {
    label: "CLI run adapter uses shared runtime requirement policy",
    file: "crates/kuzushi-cli/src/tool_requirements.rs",
    required: [
      "Thin re-export of `kuzushi_core::tool_needs_runtime`",
      "kuzushi_core::tool_needs_runtime(tool, input)",
    ],
  },
  {
    label: "TUI background worker uses shared runtime requirement policy",
    file: "crates/kuzushi-tui/src/app/workers/run_background_tool.rs",
    required: [
      "background_agent_runtime",
      "if !tool_needs_runtime(tool_name, input)",
      "PiAgentCoreRuntime::from_config",
    ],
  },
  {
    label: "runtime no-silent-fallback tests cover canonical model output",
    file: "crates/kuzushi-core/src/runtime/tests.rs",
    required: [
      "governance_normalizes_explicit_model_whitespace",
      " openai : gpt-5.5 ",
      "anthropic:claude-sonnet-4-6",
    ],
  },
];

const failures = [...modelFallbackFailures(), ...policyCoverageFailures()];

if (failures.length > 0) {
  console.error("Kuzushi model safety check failed:");
  for (const failure of failures) console.error(`- ${failure}`);
  process.exit(1);
}

console.log("Model safety check passed.");

function modelFallbackFailures() {
  return trackedFiles()
    .filter(isProductionSource)
    .flatMap((file) => scanFile(file));
}

function policyCoverageFailures() {
  return REQUIRED_POLICY_COVERAGE.flatMap(({ label, file, required }) => {
    const fullPath = path.join(root, file);
    if (!existsSync(fullPath)) return [`${label}: missing ${file}`];
    const source = readFileSync(fullPath, "utf8");
    return required
      .filter((needle) => !source.includes(needle))
      .map((needle) => `${label}: ${file} does not mention ${needle}`);
  });
}

function scanFile(file) {
  const source = readFileSync(path.join(root, file), "utf8");
  return [
    ...source
      .split(/\r?\n/)
      .flatMap((line, index) => lineFailures(file, line, index + 1)),
    ...blockFailures(file, source),
  ];
}

function lineFailures(file, line, lineNumber) {
  return [...FORBIDDEN_MODEL_DEFAULTS, ...FORBIDDEN_FALLBACK_SURFACES]
    .filter(([, pattern]) => pattern.test(line))
    .map(([label]) => `${file}:${lineNumber} ${label}`);
}

function blockFailures(file, source) {
  return FORBIDDEN_MODEL_DEFAULT_BLOCKS.flatMap(([label, pattern]) =>
    [...source.matchAll(pattern)].map((match) => `${file}:${lineNumberAt(source, match.index ?? 0)} ${label}`),
  );
}

function lineNumberAt(source, offset) {
  return source.slice(0, offset).split(/\r?\n/).length;
}

function trackedFiles() {
  return [
    ...new Set([
      ...gitLines(["ls-files"]),
      ...gitLines(["ls-files", "--others", "--exclude-standard"]),
    ]),
  ]
    .filter((file) => existsSync(path.join(root, file)))
    .sort();
}

function isProductionSource(file) {
  return (
    /\.(rs|ts|js|mjs)$/.test(file) &&
    !isIgnored(file) &&
    !isTestFile(file) &&
    !file.startsWith("src/testing/")
  );
}

function isIgnored(file) {
  return (
    file.startsWith("target/") ||
    file.startsWith("dist/") ||
    file.startsWith("coverage/") ||
    file.startsWith("node_modules/") ||
    file === "scripts/check-model-safety.mjs"
  );
}

function isTestFile(file) {
  return (
    file.includes("/tests/") ||
    file.endsWith("/tests.rs") ||
    file.endsWith("_tests.rs") ||
    file.includes(".test.") ||
    file.includes("_test.")
  );
}

function repoRoot() {
  try {
    return execFileSync("git", ["rev-parse", "--show-toplevel"], {
      encoding: "utf8",
    }).trim();
  } catch {
    return process.cwd();
  }
}

function gitLines(args) {
  return execFileSync("git", args, { cwd: root, encoding: "utf8" })
    .split(/\r?\n/)
    .map((file) => file.trim())
    .filter(Boolean);
}
