#!/usr/bin/env node
import { execFileSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import path from "node:path";

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
      ".kuzushi/runs/<runId>/",
      "native/<platform>-<arch>/kuzushi",
      "native/<platform>-<arch>/kz",
    ],
  },
  {
    label: "port plan identity contract",
    file: "PORT_PLAN.md",
    needles: ["binary: `kuzushi`", "alias: `kz`", "prompt: `kuzushi>` or `kz>`", "header: `KUZUSHI`", "state directory: `.kuzushi/`"],
  },
  {
    label: "TUI prompt model",
    file: "crates/kuzushi-tui/src/ui_view_models/prompt.rs",
    needles: ['return "kz";', '_ => "kuzushi"', 'format!("{brand}> ")'],
  },
  {
    label: "TUI cockpit header",
    file: "crates/kuzushi-tui/src/renderer/chrome/status/context_strip.rs",
    needles: ['Span::styled("KUZUSHI"', "`KUZUSHI mode:<m>"],
  },
  {
    label: "Rust CLI binary identity",
    file: "crates/kuzushi-cli/Cargo.toml",
    needles: ['name = "kuzushi-cli"', 'name = "kuzushi"', 'name = "kz"', 'path = "src/main.rs"'],
  },
  {
    label: "native staging alias identity",
    file: "scripts/stage-native-binary.mjs",
    needles: ['["kuzushi.exe", "kz.exe"]', '["kuzushi", "kz"]'],
  },
  {
    label: "Rust CLI help identity",
    file: "crates/kuzushi-cli/src/cli/mod.rs",
    needles: ['#[command(name = "kuzushi")]', 'Kuzushi security-native code agent'],
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
      '`${cliName}.exe`',
      "const nativeOverride = process.env.KUZUSHI_NATIVE_BIN",
      "overrideName !== cliName",
      "KUZUSHI_NATIVE_BIN must point to a",
      "native/<platform>-<arch>/kz",
      "Could not find the Kuzushi native binary",
      "kuzushi doctor --target .",
    ],
  },
];

const files = publicFiles();
const failures = [
  ...identityFailures(),
  ...requiredIdentityReferences.flatMap(requiredIdentityReferenceFailures),
  ...files.flatMap(scanFile),
];

if (failures.length > 0) {
  console.error("Kuzushi public identity check failed:");
  for (const failure of failures) console.error(`- ${failure}`);
  process.exit(1);
}

console.log(`Public identity check passed for ${files.length} file(s).`);

function repoRoot() {
  try {
    return execFileSync("git", ["rev-parse", "--show-toplevel"], {
      encoding: "utf8",
    }).trim();
  } catch {
    return process.cwd();
  }
}

function publicFiles() {
  return [
    ...new Set([
      ...gitLines(["ls-files"]),
      ...gitLines(["ls-files", "--others", "--exclude-standard"]),
    ]),
  ]
    .filter(isPublicSurface)
    .filter((file) => !isIgnored(file))
    .filter((file) => existsSync(path.join(root, file)))
    .sort();
}

function scanFile(file) {
  return readFileSync(path.join(root, file), "utf8")
    .split(/\r?\n/)
    .flatMap((line, index) => lineFailures(file, line, index + 1));
}

function identityFailures() {
  const pkg = JSON.parse(readFileSync(path.join(root, "package.json"), "utf8"));
  const bin = pkg.bin ?? {};
  return [
    ...packageIdentityFailures(pkg),
    ...binEntryFailures(bin),
    ...legacyBinFailures(bin),
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

function requiredIdentityReferenceFailures({ label, file, needles }) {
  const source = readFileSync(path.join(root, file), "utf8");
  return needles
    .filter((needle) => !source.includes(needle))
    .map((needle) => `${file}: missing ${label} reference ${needle}`);
}

function binEntryFailures(bin) {
  const expected = "./bin/kuzushi-rs.mjs";
  return ["kuzushi", "kz"].flatMap((name) =>
    bin[name] === expected ? [] : [`package.json: bin.${name} must point at "${expected}"`],
  );
}

function legacyBinFailures(bin) {
  return ["codex", "kuzushi-ts"]
    .filter((name) => Object.hasOwn(bin, name))
    .map((name) => `package.json: legacy bin.${name} must not be published`);
}

function binShimAliasFailures() {
  const failures = [];
  if (!binShimPreservesCompactAlias()) {
    failures.push("bin/kuzushi-rs.mjs: shim must pass KUZUSHI_CLI_NAME=kz when invoked as kz");
  }
  if (!binShimRejectsMismatchedNativeOverride()) {
    failures.push("bin/kuzushi-rs.mjs: shim must reject KUZUSHI_NATIVE_BIN when it points at the wrong public binary");
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
    source.includes("overrideName !== cliName") &&
    source.includes("KUZUSHI_NATIVE_BIN must point to a")
  );
}

function lineFailures(file, line, lineNumber) {
  const checks = [
    ...forbidden,
    ...(isPublicDoc(file) ? publicDocForbidden : []),
    ...(isProductionPublicSource(file) ? publicSourceForbidden : []),
    ...(isRenderedTuiSnapshot(file) ? renderedUiForbidden : []),
  ];
  return checks
    .filter(([, pattern]) => pattern.test(line))
    .map(([label]) => `${file}:${lineNumber} ${label}`);
}

function gitLines(args) {
  return execFileSync("git", args, { cwd: root, encoding: "utf8" })
    .split(/\r?\n/)
    .map((file) => file.trim())
    .filter(Boolean);
}

function isPublicSurface(file) {
  return publicSurfaces.some((candidate) => file === candidate || file.startsWith(`${candidate}/`));
}

function isIgnored(file) {
  return (
    file === "scripts/check-public-identity.mjs" ||
    file.startsWith("target/") ||
    file.startsWith("node_modules/") ||
    file.startsWith("dist/") ||
    file.startsWith("coverage/")
  );
}

function isPublicDoc(file) {
  return file === "README.md" || file.startsWith("docs/");
}

function isProductionPublicSource(file) {
  return file.includes("/src/") && !file.endsWith("/tests.rs") && !file.endsWith("_tests.rs");
}

function isRenderedTuiSnapshot(file) {
  return file.startsWith("crates/kuzushi-tui/tests/snapshots/") && file.endsWith(".snap");
}
