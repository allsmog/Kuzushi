#!/usr/bin/env node
import { readFileSync } from "node:fs";
import path from "node:path";
import {
  createPublicIdentitySourceScanner,
  repoRoot,
  requiredIdentityReferenceFailures,
} from "./public-identity-source-scanner.mjs";

const root = repoRoot();
const publicSurfaces = [
  "README.md",
  "package.json",
  "bin",
  "docs",
  "crates/kuzushi-cli/src",
  "crates/kuzushi-cli/tests",
  "crates/kuzushi-core/src",
  "crates/kuzushi-tui/src",
  "crates/kuzushi-tui/tests",
];
const forbidden = [
  ["auth codex command", /\bauth\s+codex\b/i],
  ["Codex GPT model label", /\bCodex\s+GPT\b/],
  ["authenticate Codex wording", /\bauthenticate\s+Codex\b/i],
  ["legacy OpenAI OAuth auth command", /\bauth\s+openai-codex\b/i],
  ["legacy OpenAI OAuth login command", /\bauth\s+login\s+openai-codex\b/i],
  ["openai-codex OAuth label", /\bopenai-codex\s+oauth\b/i],
  ["codex OAuth label", /\bcodex\s+oauth\b/i],
  ["upstream Codex OAuth device URL", /auth\.openai\.com\/codex\/device/i],
  ["raw openai-codex selector help", /\bSupported selectors:\s*openai,\s*openai-codex\b/i],
  ["raw auth codex example", /\baliases\s*\/\s*examples:\s*auth\s+codex\b/i],
];
const publicDocForbidden = [
  ["raw Codex wording in public docs", /\bCodex\b|\bcodex\b|\.codex\b|openai-codex/i],
];
const publicSourceForbidden = [
  ["legacy codex auth selector", /Some\("codex"\)|\|\s*"codex"\b/],
  ["legacy codex model selector", /"codex(?::gpt|-[^"]*)"/i],
];
const renderedUiForbidden = [
  ["legacy Codex wording in rendered TUI snapshot", /\bCodex\b|\bcodex\b|openai-codex/i],
];
const requiredIdentityReferences = [
  {
    label: "public prompt docs",
    file: "README.md",
    needles: [
      "kuzushi>",
      "kz>",
      ".kuzushi/v3/runs/<runId>/",
      "native/<platform>-<arch>/kuzushi",
      "argv0 alias",
    ],
  },
  {
    label: "port plan identity contract",
    file: "docs/PORT_PLAN.md",
    needles: [
      "binary: `kuzushi`",
      "alias: `kz`",
      "prompt: `kuzushi>` or `kz>`",
      "header: `KUZUSHI`",
      "state directory: `.kuzushi/`",
    ],
  },
  {
    label: "TUI prompt model",
    file: "crates/kuzushi-tui/src/ui_view_models/prompt.rs",
    needles: [
      "public_prompt_brand",
      'stem.eq_ignore_ascii_case("kz")',
      'stem.eq_ignore_ascii_case("kuzushi")',
      'cli_name == Some("kz")',
      'eq_ignore_ascii_case(".exe")',
      'format!("{brand}> ")',
    ],
  },
  {
    label: "TUI cockpit header",
    file: "crates/kuzushi-tui/src/renderer/chrome/status/context_strip.rs",
    needles: ['Span::styled("KUZUSHI"', "`KUZUSHI route:<m>"],
  },
  {
    label: "Rust CLI binary identity",
    file: "crates/kuzushi-cli/Cargo.toml",
    needles: ['name = "kuzushi-cli"', 'name = "kuzushi"', 'path = "src/main.rs"'],
  },
  {
    label: "native staging alias identity",
    file: "scripts/stage-native-binary.mjs",
    // kz is an argv0 alias; the remaining staged files are the native runtime.
    needles: ["nativeRuntimeBinaries.map", "kuzushi-ts", "kz"],
    /* Retired literal contract kept below only as migration context.
    needles: ['["kuzushi.exe"] : ["kuzushi"]', '"kuzushi-ts", "kz"]'],
  },
    */
  },
  {
    label: "Rust CLI help identity",
    file: "crates/kuzushi-cli/src/cli/mod.rs",
    needles: ['#[command(name = "kuzushi")]', "Kuzushi security-native code agent"],
  },
  {
    label: "TUI auth next-step selector identity",
    file: "crates/kuzushi-tui/src/app/settings/normalize_thinking_level/auth_process.rs",
    needles: [
      "display_model_selector(choice.id)",
      'format!("model {} ({selector})", choice.index)',
    ],
  },
  {
    label: "TUI auth login detail identity",
    file: "crates/kuzushi-tui/src/app/settings/handle_model_command/auth_login.rs",
    needles: ["OpenAI device code flow", "browser PKCE flow with localhost callback"],
  },
  {
    label: "OpenAI bridge safe public failure boundary",
    file: "crates/kuzushi-openai/src/langgraph_runtime/bridge_process.rs",
    needles: [
      "public_bridge_failure(",
      ".and_then(allowed_error_class)",
      "fn allowed_error_class(class: &str) -> Option<&str>",
      '"authentication"\n            | "bridge_internal"',
      '| "cancelled"',
      '| "provider_rejected"',
      '| "provider_response_invalid"',
      '| "provider_unavailable"',
      '| "rate_limited"',
      '| "timeout"',
      '| "transport"',
      ".then_some(class)",
      "Bridge operation failed; raw error details were suppressed",
      "bridge stdout/stderr details were suppressed",
      "OpenAI OAuth authentication failed; run `kuzushi auth login openai`.",
    ],
    forbidden: [
      "public_bridge_bytes(",
      "bridge_error_detail(",
      '.replace("auth login openai-codex"',
      '.replace("openai-codex"',
      "String::from_utf8_lossy(&output.stdout)",
      "String::from_utf8_lossy(&output.stderr)",
    ],
  },
  {
    label: "TUI legacy OpenAI auth selector identity",
    file: "crates/kuzushi-tui/src/app/command_router/unknown_command_message.rs",
    needles: [
      "legacy_auth_selector_message",
      "auth legacy-openai-oauth",
      "OpenAI OAuth login uses `auth login openai`",
    ],
  },
  {
    label: "TUI legacy OpenAI auth parser identity",
    file: "crates/kuzushi-tui/src/commands/parse_auth_command.rs",
    needles: ["legacy_openai_oauth_selector_command", "auth legacy-openai-oauth"],
    forbidden: ['format!("auth login {}", args[1])'],
  },
  {
    label: "Rust PR comment help identity",
    file: "crates/kuzushi-cli/src/command.rs",
    needles: ["Build a Kuzushi PR comment from persisted run artifacts"],
  },
  {
    label: "npm wrapper error identity",
    file: "bin/kuzushi-rs.mjs",
    needles: [
      'invokedName === "kz"',
      "`${cliName}.exe`",
      "const nativeOverride = process.env.KUZUSHI_NATIVE_BIN",
      "KUZUSHI_CLI_NAME: cliName",
      "statSync(nativeOverride).isFile()",
      "isNativeBinaryFile",
      "candidates.find(isNativeBinaryFile)",
      "KUZUSHI_NATIVE_BIN must point to a file",
      'overrideName !== "kuzushi" && overrideName !== "kz"',
      "KUZUSHI_NATIVE_BIN must point to a",
      "native/<platform>-<arch>/kuzushi",
      "Could not find the Kuzushi native binary",
      "kuzushi doctor --target .",
    ],
  },
];
const expectedBinEntries = {
  kuzushi: "./bin/kuzushi-rs.mjs",
  kz: "./bin/kuzushi-rs.mjs",
};

const { publicFiles, scanFile } = createPublicIdentitySourceScanner({
  root,
  publicSurfaces,
  forbidden,
  publicDocForbidden,
  publicSourceForbidden,
  renderedUiForbidden,
});
const files = publicFiles();
const failures = [
  ...identityFailures(),
  ...bridgePublicWordingFailures(),
  ...requiredIdentityReferences.flatMap((contract) =>
    requiredIdentityReferenceFailures(root, contract),
  ),
  ...files.flatMap(scanFile),
];

if (failures.length > 0) {
  console.error("Kuzushi public identity check failed:");
  for (const failure of failures) console.error(`- ${failure}`);
  process.exit(1);
}

console.log(`Public identity check passed for ${files.length} file(s).`);

function identityFailures() {
  const pkg = JSON.parse(readFileSync(path.join(root, "package.json"), "utf8"));
  const bin = pkg.bin ?? {};
  return [
    ...packageIdentityFailures(pkg),
    ...binEntryFailures(bin),
    ...binSurfaceFailures(bin),
    ...binShimAliasFailures(),
  ];
}

function packageIdentityFailures(pkg) {
  const failures = [];
  if (pkg.name !== "kuzushi") failures.push('package.json: name must be "kuzushi"');
  if (!String(pkg.description ?? "").startsWith("Kuzushi")) {
    failures.push("package.json: description must present Kuzushi as the product");
  }
  return failures;
}

function binEntryFailures(bin) {
  return Object.entries(expectedBinEntries).flatMap(([name, expected]) =>
    bin[name] === expected ? [] : [`package.json: bin.${name} must point at "${expected}"`],
  );
}

function binSurfaceFailures(bin) {
  return Object.keys(bin)
    .filter((name) => !Object.hasOwn(expectedBinEntries, name))
    .map((name) => `package.json: bin.${name} must not be published`);
}

function binShimAliasFailures() {
  const failures = [];
  if (!binShimPreservesCompactAlias()) {
    failures.push("bin/kuzushi-rs.mjs: shim must pass KUZUSHI_CLI_NAME=kz when invoked as kz");
  }
  if (!binShimRejectsMismatchedNativeOverride()) {
    failures.push(
      "bin/kuzushi-rs.mjs: shim must reject KUZUSHI_NATIVE_BIN when it points at the wrong public binary",
    );
  }
  return failures;
}

function binShimPreservesCompactAlias() {
  const source = readFileSync(path.join(root, "bin/kuzushi-rs.mjs"), "utf8");
  return source.includes('invokedName === "kz" ? "kz" : "kuzushi"');
}

function binShimRejectsMismatchedNativeOverride() {
  const source = readFileSync(path.join(root, "bin/kuzushi-rs.mjs"), "utf8");
  return (
    source.includes("const nativeOverride = process.env.KUZUSHI_NATIVE_BIN") &&
    source.includes("KUZUSHI_CLI_NAME: cliName") &&
    !source.includes("process.env.KUZUSHI_CLI_NAME ??") &&
    source.includes("statSync(nativeOverride).isFile()") &&
    source.includes("isNativeBinaryFile") &&
    source.includes("candidates.find(isNativeBinaryFile)") &&
    source.includes("KUZUSHI_NATIVE_BIN must point to a file") &&
    source.includes(`overrideName !== "kuzushi" && overrideName !== "kz"`) &&
    source.includes("KUZUSHI_NATIVE_BIN must point to a")
  );
}

function bridgePublicWordingFailures() {
  const source = [
    "scripts/langgraph-bridge.mjs",
    "scripts/langgraph-bridge/model.mjs",
    "scripts/langgraph-bridge/oauth-models.mjs",
    "scripts/langgraph-bridge/mcp.mjs",
    "scripts/langgraph-bridge/schema.mjs",
  ]
    .map((file) => readFileSync(path.join(root, file), "utf8"))
    .join("\n");
  return bridgePublicWordingRules()
    .filter(({ passes }) => !passes(source))
    .map(({ message }) => message);
}

function bridgePublicWordingRules() {
  return [
    {
      passes: (source) => source.includes("ChatOpenAI"),
      message:
        "scripts/langgraph-bridge.mjs: OpenAI path must use the public LangChain OpenAI adapter",
    },
    {
      passes: (source) => source.includes("OPENAI_API_KEY"),
      message: "scripts/langgraph-bridge.mjs: OpenAI credential path must mention OPENAI_API_KEY",
    },
    {
      passes: (source) => !source.includes("authorize openai-codex"),
      message:
        "scripts/langgraph-bridge.mjs: device login must not ask operators to authorize openai-codex",
    },
    {
      passes: (source) => !source.includes("auth login openai-codex, OPENAI_API_KEY"),
      message:
        "scripts/langgraph-bridge.mjs: OpenAI credential errors must not expose auth login openai-codex",
    },
  ];
}
