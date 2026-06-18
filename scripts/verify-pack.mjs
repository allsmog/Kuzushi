#!/usr/bin/env node
import { existsSync, lstatSync, readdirSync, readFileSync, statSync } from "node:fs";
import path from "node:path";
import { checkArtifactSchemaInventory } from "./artifact-schema-inventory-contract.mjs";
import { canonicalRunSchemaFiles } from "./canonical-run-schema-files.mjs";

const repo = process.cwd();
const manifest = readPackageManifest();
const rawPackageFileEntries = manifest.files;
const packageFileShapeFailures = packageFileEntryShapeFailures(rawPackageFileEntries);
const entries = Array.isArray(rawPackageFileEntries)
  ? rawPackageFileEntries.filter((entry) => typeof entry === "string")
  : [];
const manifestRecordFields = [
  "bin",
  "scripts",
  "dependencies",
  "devDependencies",
  "optionalDependencies",
  "exports",
];
const manifestRecordShapeFailures = manifestRecordFields.flatMap((field) =>
  packageRecordFieldFailures(field, manifest[field]),
);
const packageBin = recordOrEmpty(manifest.bin);
const packageScripts = recordOrEmpty(manifest.scripts);
const packageDependencies = recordOrEmpty(manifest.dependencies);
const packageDevDependencies = recordOrEmpty(manifest.devDependencies);
const packageOptionalDependencies = recordOrEmpty(manifest.optionalDependencies);
const packageExports = recordOrEmpty(manifest.exports);
const omitNative = process.env.KUZUSHI_VERIFY_PACK_OMIT_NATIVE === "1";
const includes = entries.filter((entry) => !entry.startsWith("!")).filter(isIncludedEntry);
const excludes = entries.filter((entry) => entry.startsWith("!")).map((entry) => entry.slice(1));
const requiredPackageFiles = [
  "README.md",
  "UPSTREAM_CODEX.md",
  "NOTICE",
  "LICENSES/Apache-2.0.txt",
  "LICENSE",
  "schemas/module.manifest.schema.json",
  ...canonicalRunSchemaFiles,
];
const allowedPackageEntries = [
  "dist",
  "!dist/cli",
  "!dist/cli.d.ts",
  "!dist/cli.js",
  "!dist/cli.js.map",
  "bin",
  "native",
  "scripts/langgraph-bridge.mjs",
  "scripts/langgraph-bridge",
  "scripts/check-native-bindings.mjs",
  "schemas",
  "assets/ascii",
  "assets/pashov-xray",
  "README.md",
  "UPSTREAM_CODEX.md",
  "NOTICE",
  "LICENSES",
  "LICENSE",
];
const expectedPackageBin = {
  kuzushi: "./bin/kuzushi-rs.mjs",
  kz: "./bin/kuzushi-rs.mjs",
};
const allowedLifecycleScripts = {
  postinstall: "node scripts/check-native-bindings.mjs",
};
const requiredReleaseScripts = {
  prepack: "pnpm build:clean && pnpm build:native",
  "verify:pack": "node scripts/verify-pack.mjs",
  "publish:npm": "bash scripts/publish-npm.sh",
  "publish:npm:dry": "bash scripts/publish-npm.sh",
  "publish:npm:go": "bash scripts/publish-npm.sh --publish",
};
const expectedPackageScripts = {
  setup: "bash scripts/bootstrap.sh",
  doctor: "bash scripts/doctor.sh",
  "check:docs":
    "node scripts/check-port-contract.mjs && node scripts/check-public-identity.mjs && node scripts/check-doc-command-drift.mjs && node scripts/check-retired-ts-runtime.mjs",
  "check:retired-ts-runtime": "node scripts/check-retired-ts-runtime.mjs",
  "export:source": "bash scripts/export-clean-source.sh",
  "setup:benchmarks": "bash scripts/setup-benchmarks.sh",
  prepare: "husky",
  postinstall: "node scripts/check-native-bindings.mjs",
  dev: "cargo run -p kuzushi-cli",
  "dev:rust": "cargo run -p kuzushi-cli",
  "link:local": "node scripts/link-local.mjs",
  "link:local:restore": "node scripts/link-local.mjs --restore",
  "clean:dist": "node -e \"require('node:fs').rmSync('dist',{recursive:true,force:true})\"",
  build: "tsc",
  "build:rust": "cargo build --workspace",
  "build:native": "cargo build -p kuzushi-cli --release && node scripts/stage-native-binary.mjs",
  "build:clean": "pnpm clean:dist && tsc",
  prepack: "pnpm build:clean && pnpm build:native",
  "check:types": "node scripts/typecheck-all.mjs",
  typecheck: "tsc --noEmit",
  "typecheck:all": "node scripts/typecheck-all.mjs",
  "typecheck:benchmarks": "tsc -p benchmarks/tsconfig.json --noEmit",
  "typecheck:perf": "tsc -p perf/tsconfig.json --noEmit",
  test: "vitest run",
  "test:rust": "cargo test --workspace",
  "test:e2e": "bash tests/e2e/run-smoke.sh",
  "test:coverage": "vitest run --coverage",
  "quality:crap-risk": "node scripts/crap-risk-gate.mjs",
  "quality:identity": "node scripts/check-public-identity.mjs",
  "quality:architecture":
    "node scripts/check-ddd-boundaries.mjs && node scripts/check-ddd-context-docs.mjs && node scripts/check-artifact-contract.mjs && node scripts/check-result-envelope-contract.mjs && node scripts/check-retired-ts-runtime.mjs && node scripts/check-deferred-surface-contract.mjs && node scripts/check-validated-wording.mjs",
  "quality:model-safety": "node scripts/check-model-safety.mjs",
  "verify:pack": "node scripts/verify-pack.mjs",
  "publish:npm": "bash scripts/publish-npm.sh",
  "publish:npm:dry": "bash scripts/publish-npm.sh",
  "publish:npm:go": "bash scripts/publish-npm.sh --publish",
  benchmark: "tsx benchmarks/harness.ts",
  "benchmark:freeze": "tsx benchmarks/freeze-baseline.ts",
  "benchmark:diff": "tsx benchmarks/sarif-diff.ts",
  "benchmark:regression": "tsx benchmarks/regression-check.ts",
  "benchmark:scoreboard": "tsx benchmarks/scoreboard.ts",
  "eval:kuzushi-whitebox-static": "node --import tsx evals/kuzushi-whitebox-static/run.ts",
  perf: "tsx perf/harness.ts",
  "check:circular": "madge --ts-config tsconfig.json --extensions ts --circular src/",
  complexity: "node scripts/cyclomatic.mjs src --top 30 --min 20",
  "complexity:logic": "node scripts/cyclomatic.mjs src --top 30 --min 20 --logic-only",
  codegen: "tsx scripts/codegen/index.ts",
  "codegen:check": "tsx scripts/codegen/check.ts",
  "typecheck:codegen": "tsc -p scripts/codegen/tsconfig.json --noEmit",
  lint: "biome lint .",
  format: "biome format .",
  check: "biome check .",
  fix: "biome check --write .",
  "fix:unsafe": "biome check --write --unsafe .",
};
const expectedPackageMetadata = {
  name: "kuzushi",
  description: "Kuzushi — security-native code agent for evidence-backed repository scans",
  type: "module",
  types: "./dist/index.d.ts",
  repositoryType: "git",
  repositoryUrl: "https://github.com/allsmog/Kuzushi.git",
  homepage: "https://github.com/allsmog/Kuzushi",
  bugsUrl: "https://github.com/allsmog/Kuzushi/issues",
  nodeEngine: ">=22",
  author: "Shayaun Nejad",
  license: "MIT",
  packageManager:
    "pnpm@10.30.0+sha512.2b5753de015d480eeb88f5b5b61e0051f05b4301808a82ec8b840c9d2adf7748eb352c83f5c1593ca703ff1017295bc3fdd3119abb9686efc96b9fcb18200937",
};
const expectedPackageKeywords = ["sast", "security", "semgrep", "ai", "triage"];
const expectedOnlyBuiltDependencies = ["better-sqlite3", "esbuild"];
const expectedPackageDependencies = {
  "@anthropic-ai/sdk": "^0.81.0",
  "@kuzushi/augur": "^0.1.0",
  "@langchain/anthropic": "^1.0.0",
  "@langchain/core": "^1.0.0",
  "@langchain/langgraph": "^1.0.0",
  "@langchain/mcp-adapters": "^1.0.0",
  "@langchain/openai": "^1.0.0",
  "better-sqlite3": "^12.8.0",
  chalk: "^5.4.1",
  commander: "^13.1.0",
  langchain: "^1.0.0",
  tinyglobby: "^0.2.15",
  typescript: "^5.7.3",
  undici: "^7.22.0",
  yaml: "^2.7.0",
  zod: "^4.3.6",
};
const expectedPnpmLockfileRootDependencyVersions = {
  dependencies: {
    "@anthropic-ai/sdk": "0.81.0(zod@4.3.6)",
    "@kuzushi/augur": "0.1.0",
    "@langchain/anthropic":
      "1.4.0(@langchain/core@1.1.48(openai@6.39.0(ws@8.20.1)(zod@4.3.6))(ws@8.20.1))",
    "@langchain/core": "1.1.48(openai@6.39.0(ws@8.20.1)(zod@4.3.6))(ws@8.20.1)",
    "@langchain/langgraph":
      "1.3.2(@langchain/core@1.1.48(openai@6.39.0(ws@8.20.1)(zod@4.3.6))(ws@8.20.1))(zod-to-json-schema@3.25.1(zod@4.3.6))(zod@4.3.6)",
    "@langchain/mcp-adapters":
      "1.1.3(@cfworker/json-schema@4.1.1)(@langchain/core@1.1.48(openai@6.39.0(ws@8.20.1)(zod@4.3.6))(ws@8.20.1))(@langchain/langgraph@1.3.2(@langchain/core@1.1.48(openai@6.39.0(ws@8.20.1)(zod@4.3.6))(ws@8.20.1))(zod-to-json-schema@3.25.1(zod@4.3.6))(zod@4.3.6))",
    "@langchain/openai":
      "1.4.7(@langchain/core@1.1.48(openai@6.39.0(ws@8.20.1)(zod@4.3.6))(ws@8.20.1))(ws@8.20.1)",
    "better-sqlite3": "12.8.0",
    chalk: "5.6.2",
    commander: "13.1.0",
    langchain:
      "1.4.2(@langchain/core@1.1.48(openai@6.39.0(ws@8.20.1)(zod@4.3.6))(ws@8.20.1))(openai@6.39.0(ws@8.20.1)(zod@4.3.6))(ws@8.20.1)(zod-to-json-schema@3.25.1(zod@4.3.6))",
    tinyglobby: "0.2.15",
    typescript: "5.9.3",
    undici: "7.22.0",
    yaml: "2.8.2",
    zod: "4.3.6",
  },
  devDependencies: {
    "@biomejs/biome": "2.4.12",
    "@commitlint/cli": "19.8.1(@types/node@22.19.11)(typescript@5.9.3)",
    "@commitlint/config-conventional": "19.8.1",
    "@types/better-sqlite3": "7.6.13",
    "@types/node": "22.19.11",
    "@vitest/coverage-v8":
      "3.2.4(vitest@3.2.4(@types/node@22.19.11)(jiti@2.6.1)(tsx@4.21.0)(yaml@2.8.2))",
    husky: "9.1.7",
    "lint-staged": "15.5.2",
    madge: "8.0.0(typescript@5.9.3)",
    tsx: "4.21.0",
    vitest: "3.2.4(@types/node@22.19.11)(jiti@2.6.1)(tsx@4.21.0)(yaml@2.8.2)",
  },
  optionalDependencies: {
    "@kuzushi/tob-skills":
      "https://codeload.github.com/allsmog/tob-security-skills/tar.gz/98dda39a53eb74b90d60f305c8523e47552a9fb2",
    "@kuzushi/vuln-scout":
      "https://codeload.github.com/allsmog/vuln-scout/tar.gz/79df9e804c6a87f0af3c779c55d2fcdb4675f49d",
    "promptarmor-plugin":
      "https://codeload.github.com/allsmog/promptarmor-plugin/tar.gz/690d60a5b4d2136206ef7dedd516d3fcfddd4db9",
    "shinsa-plugin":
      "https://codeload.github.com/allsmog/shinsa-plugin/tar.gz/74b3737d225970d849f5f6f57095cfe65ee7ccdf",
  },
};
const expectedPackageDevDependencies = {
  "@biomejs/biome": "^2.4.12",
  "@commitlint/cli": "^19.8.1",
  "@commitlint/config-conventional": "^19.8.1",
  "@types/better-sqlite3": "^7.6.13",
  "@types/node": "^22.13.4",
  "@vitest/coverage-v8": "^3.0.5",
  husky: "^9.1.7",
  "lint-staged": "^15.5.2",
  madge: "^8.0.0",
  tsx: "^4.19.2",
  vitest: "^3.0.5",
};
const expectedPackageExports = {
  ".": { types: "./dist/index.d.ts", default: "./dist/index.js" },
  "./modules": { types: "./dist/modules/index.d.ts", default: "./dist/modules/index.js" },
  "./testing": { types: "./dist/testing/index.d.ts", default: "./dist/testing/index.js" },
  "./schemas/*": "./schemas/*",
  "./package.json": "./package.json",
};
const expectedPnpmLockfileHeader = {
  lockfileVersion: "lockfileVersion: '9.0'",
  autoInstallPeers: "  autoInstallPeers: true",
  excludeLinksFromLockfile: "  excludeLinksFromLockfile: false",
};
const forbiddenPackageMetadataFields = [
  "workspaces",
  "bundleDependencies",
  "bundledDependencies",
  "peerDependencies",
  "peerDependenciesMeta",
  "overrides",
  "resolutions",
  "config",
  "os",
  "cpu",
];
const expectedOptionalAdapterDependencies = {
  "@kuzushi/tob-skills":
    "github:allsmog/tob-security-skills#98dda39a53eb74b90d60f305c8523e47552a9fb2",
  "@kuzushi/vuln-scout": "github:allsmog/vuln-scout#79df9e804c6a87f0af3c779c55d2fcdb4675f49d",
  "promptarmor-plugin":
    "github:allsmog/promptarmor-plugin#690d60a5b4d2136206ef7dedd516d3fcfddd4db9",
  "shinsa-plugin": "github:allsmog/shinsa-plugin#74b3737d225970d849f5f6f57095cfe65ee7ccdf",
};

const denied = [
  /^(?:.*\/)?\.kuzushi(?:\/|$)/,
  /^(?:.*\/)?\.codex(?:\/|$)/,
  /^(?:.*\/)?\.codex-active(?:\/|$)/,
  /^(?:.*\/)?\.ralph(?:\/|$)/,
  /^(?:.*\/)?\.pnpm-store(?:\/|$)/,
  /^(?:.*\/)?\.claude(?:\/|$)/,
  /^(?:.*\/)?\.serena(?:\/|$)/,
  /^(?:.*\/)?\.playwright-mcp(?:\/|$)/,
  /^(?:.*\/)?\.worktrees(?:\/|$)/,
  /^(?:.*\/)?node_modules(?:\/|$)/,
  /^(?:.*\/)?\.(?:git|hg|svn)(?:\/|$)/,
  /^(?:.*\/)?(?:__pycache__|target|coverage)(?:\/|$)/,
  /^(?:.*\/)?\.(?:pytest_cache|mypy_cache|ruff_cache|cache|turbo|next|vite|parcel-cache)(?:\/|$)/,
  /^(?:.*\/)?\.env(?:\.|$)/,
  /^(?:.*\/)?\.DS_Store$/,
  /^(?:.*\/)?(?:Thumbs\.db|Desktop\.ini)$/,
  /^(?:.*\/)?\.~lock\..*$/,
  /^.*(?:~|\.bak|\.backup|\.tmp|\.swp|\.swo|\.swx)$/,
  /^(?:.*\/)?\.semgrep-(?:findings\.json|triage\.jsonl)$/,
  /^.*\.tsbuildinfo$/,
  /^.*\.map$/,
  /^.*\.sqlite3(?:-|$)/,
  /^.*\.db(?:-|$)/,
  /^.*\.(?:pem|key|p12|pfx|crt|csr|asc|gpg|age)$/,
  /^.*\.(?:zip|tar|tgz|gz|7z|rar)$/,
  /^.*\.(?:log|patch|rej|orig)$/,
  /^coverage(?:\/|$)/,
  /^target(?:\/|$)/,
  /^(?:.*\/)?(?:822|1188|htb_1188|pwn_under_the_web)(?:\/|$)/,
  /^(?:.*\/)?benchmarks\/[^/]+\/(?:repo|results)(?:\/|$)/,
  /^(?:.*\/)?benchmarks\/[^/]+-results\.json$/,
  /^(?:.*\/)?perf\/results\.json$/,
  /^(?:.*\/)?iris\.pdf$/,
  /^(?:.*\/)?kuzushi-.*-prompt\.md$/,
  /^(?:.*\/)?\.tmp-.*\.md$/,
  /^(?:.*\/)?ralph-.*\.md$/,
  /^(?:.*\/)?cc-repo(?:\/|$)/,
  /^(?:.*\/)?vendor(?:\/|$)/,
  /^(?:.*\/)?dist\/cli(?:\/|\.|$)/,
  /^(?:.*\/)?dist\/copilot\/shell(?:-|\.|$)/,
  /^(?:.*\/)?dist\/ui\/(?:App\.|components(?:\/|$)|primitives(?:\/|$)|render\.|setup\.|shell-keybinds\.)/,
  /^(?:.*\/)?src\/copilot\/shell(?:-|\.|$)/,
  /^(?:.*\/)?src\/ui\/(?:App\.tsx|components(?:\/|$)|primitives(?:\/|$)|render\.ts|setup\.ts)/,
  /^(?:.*\/)?(?:codex|kuzushi-ts)(?:\.exe)?$/,
];
const deniedPathFixtures = [
  "assets/.kuzushi/runs/example/run.json",
  "assets/.codex/session.json",
  "assets/node_modules/example/package.json",
  "assets/.git/config",
  "assets/.env.local",
  "assets/.DS_Store",
  "assets/.semgrep-findings.json",
  "assets/benchmarks/sample/repo/package.json",
  "assets/perf/results.json",
  "assets/src/ui/App.tsx",
  "assets/native/linux-x64/codex",
];
const exportPolicyFixtures = {
  allowed: ["dist/index.d.ts", "dist/modules/index.d.ts"],
  denied: [
    "src/index.ts",
    "src/ui/App.tsx",
    "dist/cli.js",
    "dist/copilot/shell.js",
    "dist/ui/App.js",
  ],
};
const packageTypesPolicyFixtures = {
  allowed: ["./dist/index.d.ts", "dist/modules/index.d.ts"],
  denied: ["src/index.ts", "src/ui/App.tsx", "dist/cli.d.ts", "README.md", 42],
};
const packageBinSurfaceFixtures = {
  allowed: [{ ...expectedPackageBin }],
  denied: [
    { ...expectedPackageBin, codex: "./bin/kuzushi-rs.mjs" },
    { ...expectedPackageBin, "kuzushi-ts": "./bin/kuzushi-rs.mjs" },
    { ...expectedPackageBin, "kuzushi-dev": "./bin/kuzushi-rs.mjs" },
  ],
};
const packageScriptRuntimePolicyFixtures = {
  allowed: [
    "cargo run -p kuzushi-cli",
    "pnpm build:clean && pnpm build:native",
    "node scripts/check-native-bindings.mjs",
    "tsx benchmarks/harness.ts",
    "node scripts/check-retired-ts-runtime.mjs",
  ],
  denied: [
    "tsx src/copilot/shell.ts",
    "tsx src/ui/App.tsx",
    "node dist/cli.js",
    "pnpm build:clean && node dist/cli.js",
    "node scripts/check-native-bindings.mjs && tsx src/copilot/shell.ts",
    "node dist/copilot/shell.js",
    "node dist/ui/App.js",
  ],
};

const files = new Set(["package.json"]);
for (const entry of includes) {
  for (const file of walk(entry)) {
    if (!isExcluded(file)) {
      files.add(file);
    }
  }
}

const sorted = [...files].sort();
const offenders = sorted.filter((file) => denied.some((pattern) => pattern.test(file)));
const deniedFixtureFailures = deniedPathFixtureFailures();
const packagePathShapeFailures = packagePayloadPathShapeFailures(includes);
const packageEntryFailures = packageFilesEntryFailures(entries);
const nativeFailures = nativeBinaryFailures(sorted);
const stageNativeScriptFailures = stageNativeScriptContentFailures();
const binFailures = packageBinFailures(packageBin);
const binSurfaceFixtureFailures = packageBinSurfaceFixtureFailures(packageBinSurfaceFixtures);
const binWrapperFailures = binWrapperContentFailures();
const lifecycleFailures = lifecycleScriptFailures(sorted, packageScripts);
const scriptSurfaceFailures = packageScriptSurfaceFailures(packageScripts);
const scriptRuntimePolicyFailures = packageScriptRuntimePolicyFailures(packageScripts);
const scriptRuntimePolicyFixtureFailures = packageScriptRuntimePolicyFixtureFailures(
  packageScriptRuntimePolicyFixtures,
);
const nativeBindingScriptFailures = nativeBindingScriptContentFailures();
const releaseScriptFailures = releaseScriptFailuresFor(packageScripts);
const publishWrapperFailures = publishWrapperContentFailures();
const metadataFailures = packageMetadataFailures(manifest);
const requiredFileFailures = requiredPackageFileFailures(sorted);
const publicDocumentFailures = publicDocumentContentFailures();
const schemaInventoryFailures = checkArtifactSchemaInventory();
const packagedSchemaFailures = packagedRunSchemaFailures(sorted);
const exportFailures = packageExportFailures(packageExports, sorted);
const exportPolicyFixtureFailures = exportPolicyFixtureFailuresFor(exportPolicyFixtures);
const typesPolicyFixtureFailures = packageTypesPolicyFixtureFailures(packageTypesPolicyFixtures);
const legacyEntrypointFailures = packageLegacyEntrypointFailures(manifest);
const lockfileSpecifierFailures = pnpmLockfileSpecifierFailures(manifest);
const optionalLockfileResolutionFailures = optionalLockfilePackageResolutionFailures();
const dependencyFailures = packageDependencyFailures(packageDependencies);
const devDependencyFailures = packageDevDependencyFailures(packageDevDependencies);
const optionalDependencyFailures = packageOptionalDependencyFailures(packageOptionalDependencies);
const deferredDependencyFailures = deferredAdapterDependencyFailures(
  packageDependencies,
  packageOptionalDependencies,
);

if (
  offenders.length > 0 ||
  deniedFixtureFailures.length > 0 ||
  packagePathShapeFailures.length > 0 ||
  packageFileShapeFailures.length > 0 ||
  manifestRecordShapeFailures.length > 0 ||
  packageEntryFailures.length > 0 ||
  nativeFailures.length > 0 ||
  stageNativeScriptFailures.length > 0 ||
  binFailures.length > 0 ||
  binSurfaceFixtureFailures.length > 0 ||
  binWrapperFailures.length > 0 ||
  lifecycleFailures.length > 0 ||
  scriptSurfaceFailures.length > 0 ||
  scriptRuntimePolicyFailures.length > 0 ||
  scriptRuntimePolicyFixtureFailures.length > 0 ||
  nativeBindingScriptFailures.length > 0 ||
  releaseScriptFailures.length > 0 ||
  publishWrapperFailures.length > 0 ||
  metadataFailures.length > 0 ||
  requiredFileFailures.length > 0 ||
  publicDocumentFailures.length > 0 ||
  schemaInventoryFailures.length > 0 ||
  packagedSchemaFailures.length > 0 ||
  exportFailures.length > 0 ||
  exportPolicyFixtureFailures.length > 0 ||
  typesPolicyFixtureFailures.length > 0 ||
  legacyEntrypointFailures.length > 0 ||
  lockfileSpecifierFailures.length > 0 ||
  optionalLockfileResolutionFailures.length > 0 ||
  dependencyFailures.length > 0 ||
  devDependencyFailures.length > 0 ||
  optionalDependencyFailures.length > 0 ||
  deferredDependencyFailures.length > 0
) {
  process.stderr.write("package artifact contract failed:\n");
  for (const offender of offenders) {
    process.stderr.write(`- ${offender}\n`);
  }
  for (const failure of [
    ...nativeFailures,
    ...deniedFixtureFailures,
    ...stageNativeScriptFailures,
    ...packagePathShapeFailures,
    ...packageFileShapeFailures,
    ...manifestRecordShapeFailures,
    ...packageEntryFailures,
    ...binFailures,
    ...binSurfaceFixtureFailures,
    ...binWrapperFailures,
    ...lifecycleFailures,
    ...scriptSurfaceFailures,
    ...scriptRuntimePolicyFailures,
    ...scriptRuntimePolicyFixtureFailures,
    ...nativeBindingScriptFailures,
    ...releaseScriptFailures,
    ...publishWrapperFailures,
    ...metadataFailures,
    ...requiredFileFailures,
    ...publicDocumentFailures,
    ...schemaInventoryFailures,
    ...packagedSchemaFailures,
    ...exportFailures,
    ...exportPolicyFixtureFailures,
    ...typesPolicyFixtureFailures,
    ...legacyEntrypointFailures,
    ...lockfileSpecifierFailures,
    ...optionalLockfileResolutionFailures,
    ...dependencyFailures,
    ...devDependencyFailures,
    ...optionalDependencyFailures,
    ...deferredDependencyFailures,
  ]) {
    process.stderr.write(`- ${failure}\n`);
  }
  process.exit(1);
}

process.stdout.write(
  JSON.stringify(
    {
      name: manifest.name,
      version: manifest.version,
      fileCount: sorted.length,
      lifecycleScripts: "not run",
    },
    null,
    2,
  ),
);
process.stdout.write(
  "\npackage artifact check passed (no local state, bin aliases, and native binary pairs are consistent)\n",
);

function readPackageManifest() {
  try {
    return JSON.parse(readFileSync(path.join(repo, "package.json"), "utf8"));
  } catch (error) {
    process.stderr.write("package artifact contract failed:\n");
    process.stderr.write(`- package.json must be valid JSON: ${error.message}\n`);
    process.exit(1);
  }
}

function readPackageContractText(file) {
  try {
    return { source: readFileSync(path.join(repo, file), "utf8"), failures: [] };
  } catch (error) {
    return { source: "", failures: [`${file} must be readable: ${error.message}`] };
  }
}

function walk(rel) {
  const abs = path.join(repo, rel);
  if (!existsSync(abs)) {
    return [];
  }
  const stat = statSync(abs);
  if (stat.isFile()) {
    return [normalize(rel)];
  }
  if (!stat.isDirectory()) {
    return [];
  }
  return readdirSync(abs).flatMap((entry) => walk(path.join(rel, entry)));
}

function packagePayloadPathShapeFailures(packageEntries) {
  return packageEntries.flatMap(packagePayloadEntryShapeFailures);
}

function packagePayloadEntryShapeFailures(rel) {
  const normalized = normalize(rel);
  if (isExcluded(normalized) || !existsSync(path.join(repo, normalized))) {
    return [];
  }
  const stat = lstatSync(path.join(repo, normalized));
  const shapeFailures = packagePayloadStatShapeFailures(normalized, stat);
  if (shapeFailures.length > 0) return shapeFailures;
  if (stat.isFile()) return [];
  return readdirSync(path.join(repo, normalized)).flatMap((entry) =>
    packagePayloadEntryShapeFailures(path.join(normalized, entry)),
  );
}

function packagePayloadStatShapeFailures(normalized, stat) {
  if (stat.isSymbolicLink()) return [`package payload ${normalized} must not be a symlink`];
  return stat.isFile() || stat.isDirectory()
    ? []
    : [`package payload ${normalized} must be a file or directory`];
}

function isIncludedEntry(entry) {
  return !(omitNative && normalize(entry) === "native");
}

function isExcluded(rel) {
  const normalized = normalize(rel);
  return excludes.some((exclude) => {
    const normalizedExclude = normalize(exclude);
    return normalized === normalizedExclude || normalized.startsWith(`${normalizedExclude}/`);
  });
}

function normalize(value) {
  return value.split(path.sep).join("/");
}

function packageBinFailures(bin) {
  return [
    ...Object.entries(expectedPackageBin)
      .filter(([name, expected]) => bin[name] !== expected)
      .map(([name, expected]) => `package bin.${name} must point to ${expected}`),
    ...packageBinSurfaceFailures(bin),
  ];
}

function packageBinSurfaceFailures(bin) {
  return Object.keys(bin)
    .filter((name) => !Object.hasOwn(expectedPackageBin, name))
    .map((name) => `package bin.${name} must not be published`);
}

function packageBinSurfaceFixtureFailures(fixtures) {
  return [
    ...fixtures.denied
      .filter((bin) => packageBinSurfaceFailures(bin).length === 0)
      .map((bin) => `package bin-surface denied fixture is allowed ${Object.keys(bin).join(",")}`),
    ...fixtures.allowed
      .filter((bin) => packageBinSurfaceFailures(bin).length > 0)
      .map((bin) => `package bin-surface allowed fixture is denied ${Object.keys(bin).join(",")}`),
  ];
}

function packageFilesEntryFailures(entries) {
  return [
    ...duplicateEntryFailures(entries, "package files duplicate entry"),
    ...missingSchemaFiles(allowedPackageEntries, entries, "package files missing required entry"),
    ...missingSchemaFiles(entries, allowedPackageEntries, "package files has uncontracted entry"),
  ];
}

function packageFileEntryShapeFailures(value) {
  if (!Array.isArray(value)) {
    return ["package files must be an array"];
  }
  return value
    .map((entry, index) => [entry, index])
    .filter(([entry]) => typeof entry !== "string")
    .map(([, index]) => `package files[${index}] must be a string`);
}

function packageRecordFieldFailures(field, value) {
  return isPlainRecord(value) ? [] : [`package ${field} must be an object`];
}

function recordOrEmpty(value) {
  return isPlainRecord(value) ? value : {};
}

function isPlainRecord(value) {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function duplicateEntryFailures(entries, label) {
  return [...new Set(entries.filter((entry, index) => entries.indexOf(entry) !== index))].map(
    (entry) => `${label} ${entry}`,
  );
}

function deniedPathFixtureFailures() {
  return deniedPathFixtures
    .filter((file) => !denied.some((pattern) => pattern.test(file)))
    .map((file) => `package forbidden-payload fixture is not denied ${file}`);
}

function binWrapperContentFailures() {
  const content = readPackageContractText("bin/kuzushi-rs.mjs");
  const source = content.source;
  const required = [
    "#!/usr/bin/env node",
    "spawnSync(binary, process.argv.slice(2)",
    'stdio: "inherit"',
    'join(root, "native", `${process.platform}-${process.arch}`, exe)',
    'join(root, "target", "release", exe)',
    'join(root, "target", "debug", exe)',
    'invokedName === "kz" ? "kz" : "kuzushi"',
    "KUZUSHI_CLI_NAME: cliName",
    "native/<platform>-<arch>/kuzushi",
    "kuzushi doctor --target .",
    "KUZUSHI_NATIVE_BIN points to missing file",
    "statSync(nativeOverride).isFile()",
    "isNativeBinaryFile",
    "candidates.find(isNativeBinaryFile)",
    "KUZUSHI_NATIVE_BIN must point to a file",
    "KUZUSHI_NATIVE_BIN must point to a kuzushi or kz binary",
    "argv0: cliName",
    "Could not find the Kuzushi native binary.",
    "process.exit(127)",
    "result.error",
    "process.exit(1)",
    "process.exit(result.status ?? 0)",
  ];
  const forbidden = ["codex", "kuzushi-ts", "process.env.KUZUSHI_CLI_NAME ??"];
  return [
    ...content.failures,
    ...required
      .filter((token) => !source.includes(token))
      .map((token) => `bin/kuzushi-rs.mjs must mention ${token}`),
    ...forbidden
      .filter((token) => source.includes(token))
      .map((token) => `bin/kuzushi-rs.mjs must not mention ${token}`),
    ...executableFileFailures(["bin/kuzushi-rs.mjs"]),
  ];
}

function nativeBinaryFailures(files) {
  if (omitNative) return [];
  const dirs = nativePlatformDirs(files);
  if (dirs.length === 0) {
    return ["missing shipped native directory native/<platform>-<arch>"];
  }
  return dirs.flatMap((dir) => [
    ...missingNativeBinaries(files, dir),
    ...extraNativePayloadFailures(files, dir),
    ...nativeExecutableFailures(dir),
  ]);
}

function nativePlatformDirs(files) {
  return [
    ...new Set(
      files
        .filter((file) => file.startsWith("native/"))
        .map((file) => file.split("/").slice(0, 2).join("/")),
    ),
  ].sort();
}

function missingNativeBinaries(files, dir) {
  // One shipped binary per platform: the bin wrapper resolves `kz` to the
  // `kuzushi` binary via argv0 dispatch.
  const windows = dir.startsWith("native/win32-");
  const names = windows ? ["kuzushi.exe"] : ["kuzushi"];
  return names
    .map((name) => `${dir}/${name}`)
    .filter((file) => !files.includes(file))
    .map((file) => `missing shipped native binary ${file}`);
}

function extraNativePayloadFailures(files, dir) {
  const allowed = new Set(expectedNativeBinaries(dir));
  return files
    .filter((file) => file.startsWith(`${dir}/`))
    .filter((file) => !allowed.has(file))
    .map((file) => `uncontracted shipped native payload ${file}`);
}

function expectedNativeBinaries(dir) {
  const windows = dir.startsWith("native/win32-");
  const names = windows ? ["kuzushi.exe"] : ["kuzushi"];
  return names.map((name) => `${dir}/${name}`);
}

function nativeExecutableFailures(dir) {
  return dir.startsWith("native/win32-") ? [] : executableFileFailures(expectedNativeBinaries(dir));
}

function executableFileFailures(files) {
  return files
    .filter((file) => existsSync(path.join(repo, file)))
    .filter((file) => (statSync(path.join(repo, file)).mode & 0o111) === 0)
    .map((file) => `${file} must be executable`);
}

function stageNativeScriptContentFailures() {
  const content = readPackageContractText("scripts/stage-native-binary.mjs");
  const source = content.source;
  const required = [
    '["kuzushi.exe"] : ["kuzushi"]',
    '["codex.exe", "kuzushi-ts.exe", "kz.exe"]',
    '["codex", "kuzushi-ts", "kz"]',
    'join(root, "target", "release", exe)',
    'join(root, "native", `${process.platform}-${process.arch}`)',
    "cargo build -p kuzushi-cli --release",
    "process.exit(1)",
    "mkdirSync(outDir, { recursive: true })",
    "readdirSync(outDir)",
    "allowedExes",
    "removed uncontracted native payload",
    "copyFileSync(source, destination)",
    'process.platform !== "win32"',
    "rmSync(stale, { force: true })",
    "chmodSync(destination, 0o755)",
    "staged ${destination}",
  ];
  return [
    ...content.failures,
    ...required
      .filter((token) => !source.includes(token))
      .map((token) => `scripts/stage-native-binary.mjs must mention ${token}`),
  ];
}

function lifecycleScriptFailures(files, scripts) {
  return [
    ...lifecycleScriptCommandFailures(scripts),
    ...Object.entries(allowedLifecycleScripts).flatMap(([name, script]) =>
      lifecycleScriptFile(script)
        .filter((file) => !files.includes(file))
        .map((file) => `package scripts.${name} references unshipped file ${file}`),
    ),
  ];
}

function lifecycleScriptCommandFailures(scripts) {
  return ["postinstall", "preinstall", "install"]
    .filter((name) => (scripts[name] ?? null) !== (allowedLifecycleScripts[name] ?? null))
    .map((name) => `package scripts.${name} must be ${allowedLifecycleScripts[name] ?? "absent"}`);
}

function packageScriptSurfaceFailures(scripts) {
  return [
    ...missingSchemaFiles(
      Object.keys(expectedPackageScripts),
      Object.keys(scripts),
      "package scripts missing required command",
    ),
    ...missingSchemaFiles(
      Object.keys(scripts),
      Object.keys(expectedPackageScripts),
      "package scripts has uncontracted command",
    ),
    ...Object.entries(expectedPackageScripts)
      .filter(([name, command]) => scripts[name] !== command)
      .map(([name, command]) => `package scripts.${name} must stay ${command}`),
  ];
}

function packageScriptRuntimePolicyFailures(scripts) {
  return Object.entries(scripts)
    .filter(([, command]) => scriptCommandViolatesRuntimePolicy(command))
    .map(
      ([name, command]) =>
        `package scripts.${name} must not invoke retired TypeScript shell runtime: ${command}`,
    );
}

function scriptCommandViolatesRuntimePolicy(command) {
  return /(?:^|\s)(?:src\/copilot\/shell|src\/ui\/App\.tsx|dist\/cli(?:\.|\/)|dist\/copilot\/shell|dist\/ui\/App\.)/.test(
    String(command),
  );
}

function packageScriptRuntimePolicyFixtureFailures(fixtures) {
  return [
    ...fixtures.denied
      .filter((command) => !scriptCommandViolatesRuntimePolicy(command))
      .map((command) => `package script-runtime denied fixture is allowed ${command}`),
    ...fixtures.allowed
      .filter(scriptCommandViolatesRuntimePolicy)
      .map((command) => `package script-runtime allowed fixture is denied ${command}`),
  ];
}

function nativeBindingScriptContentFailures() {
  const content = readPackageContractText("scripts/check-native-bindings.mjs");
  const source = content.source;
  const required = [
    "[kuzushi postinstall]",
    'const NATIVE_DEPS = ["better-sqlite3"]',
    '["pnpm", ["rebuild", modName]]',
    '["npm", ["rebuild", modName]]',
    "NODE_MODULE_VERSION",
    "result.status === 0",
    'result.error?.code === "ENOENT"',
    "failed to load for an unexpected reason",
    "Skipping auto-rebuild",
    "ABI mismatch on Node ${process.version}",
    "Could not auto-rebuild ${dep}. Manual fix",
    "rebuilt successfully for Node ${process.version}",
    "process.exit(0)",
  ];
  const forbidden = ["OpenAI Codex", "[codex postinstall]", "kuzushi-ts"];
  return [
    ...content.failures,
    ...required
      .filter((token) => !source.includes(token))
      .map((token) => `scripts/check-native-bindings.mjs must mention ${token}`),
    ...forbidden
      .filter((token) => source.includes(token))
      .map((token) => `scripts/check-native-bindings.mjs must not mention ${token}`),
  ];
}

function releaseScriptFailuresFor(scripts) {
  return Object.entries(requiredReleaseScripts)
    .filter(([name, command]) => scripts[name] !== command)
    .map(([name, command]) => `package scripts.${name} must be ${command}`);
}

function publishWrapperContentFailures() {
  const content = readPackageContractText("scripts/publish-npm.sh");
  const source = content.source;
  const required = [
    "typecheck + tests + clean JS/native build + package verification must pass",
    "git diff --quiet",
    "git diff --cached --quiet",
    "git rev-parse --abbrev-ref HEAD",
    'git rev-parse -q --verify "refs/tags/${TAG}"',
    'git rev-list -n 1 "$TAG"',
    "git rev-parse HEAD",
    'git ls-remote --tags origin "refs/tags/${TAG}"',
    "npm whoami",
    'npm view "${PUB_NAME}@${VERSION}" version',
    "pnpm exec tsc --noEmit",
    "pnpm exec vitest run",
    "SKIP_TESTS:-0",
    "pnpm run build:clean",
    "pnpm run build:native",
    "pnpm run verify:pack",
    "npm pack --dry-run --ignore-scripts",
    "PUBLISH_ARGS=(publish --access public --ignore-scripts)",
    "NPM_PROVENANCE:-",
    "PUBLISH_ARGS+=(--provenance)",
    "OTP:-",
    'PUBLISH_ARGS+=(--otp="$OTP")',
    "read -r reply",
    'npm "${PUBLISH_ARGS[@]}"',
    "Dry-run complete (would run: npm ${PUBLISH_ARGS[*]})",
    "Pass --publish to actually publish",
  ];
  return [
    ...content.failures,
    ...required
      .filter((token) => !source.includes(token))
      .map((token) => `scripts/publish-npm.sh must mention ${token}`),
  ];
}

function packageMetadataFailures(packageManifest) {
  const checks = [
    ["name", packageManifest.name, expectedPackageMetadata.name],
    ["description", packageManifest.description, expectedPackageMetadata.description],
    ["type", packageManifest.type, expectedPackageMetadata.type],
    ["types", packageManifest.types, expectedPackageMetadata.types],
    ["repository.type", packageManifest.repository?.type, expectedPackageMetadata.repositoryType],
    ["repository.url", packageManifest.repository?.url, expectedPackageMetadata.repositoryUrl],
    ["homepage", packageManifest.homepage, expectedPackageMetadata.homepage],
    ["bugs.url", packageManifest.bugs?.url, expectedPackageMetadata.bugsUrl],
    ["engines.node", packageManifest.engines?.node, expectedPackageMetadata.nodeEngine],
    ["author", packageManifest.author, expectedPackageMetadata.author],
    ["license", packageManifest.license, expectedPackageMetadata.license],
    ["packageManager", packageManifest.packageManager, expectedPackageMetadata.packageManager],
  ];
  return [
    ...checks
      .filter(([, actual, expected]) => actual !== expected)
      .map(([field, , expected]) => `package ${field} must be ${expected}`),
    ...arrayFieldFailures("keywords", packageManifest.keywords, expectedPackageKeywords),
    ...arrayFieldFailures(
      "pnpm.onlyBuiltDependencies",
      packageManifest.pnpm?.onlyBuiltDependencies,
      expectedOnlyBuiltDependencies,
    ),
    ...packageVersionFailures(packageManifest.version),
    ...packageTypesRuntimePolicyFailures(packageManifest.types),
    ...packagePublishMetadataFailures(packageManifest),
    ...packageForbiddenMetadataFieldFailures(packageManifest),
  ];
}

function packageTypesRuntimePolicyFailures(types) {
  if (typeof types !== "string") return ["package types must be a string"];
  const target = normalizeExportTarget(types);
  return target.startsWith("dist/") &&
    target.endsWith(".d.ts") &&
    !exportTargetViolatesRuntimePolicy(target)
    ? []
    : [`package types must stay on built declaration runtime surface: ${target}`];
}

function packageTypesPolicyFixtureFailures(fixtures) {
  return [
    ...fixtures.denied
      .filter((types) => packageTypesRuntimePolicyFailures(types).length === 0)
      .map((types) => `package types-policy denied fixture is allowed ${types}`),
    ...fixtures.allowed
      .filter((types) => packageTypesRuntimePolicyFailures(types).length > 0)
      .map((types) => `package types-policy allowed fixture is denied ${types}`),
  ];
}

function packageVersionFailures(version) {
  if (typeof version !== "string") return ["package version must be a string"];
  return semverWithoutBuildMetadata(version)
    ? []
    : ["package version must be SemVer without build metadata"];
}

function semverWithoutBuildMetadata(version) {
  const match = version.match(/^(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$/);
  return (
    Boolean(match) &&
    semverNumericIdentifiersAreCanonical(match.slice(1, 4)) &&
    prereleaseIdentifiersAreCanonical(match[4])
  );
}

function semverNumericIdentifiersAreCanonical(identifiers) {
  return identifiers.every((identifier) => identifier === "0" || !identifier.startsWith("0"));
}

function prereleaseIdentifiersAreCanonical(prerelease) {
  return String(prerelease ?? "")
    .split(".")
    .filter(Boolean)
    .every(
      (identifier) =>
        !/^\d+$/.test(identifier) || identifier === "0" || !identifier.startsWith("0"),
    );
}

function packagePublishMetadataFailures(packageManifest) {
  return [
    ...(packageManifest.private === true ? ["package private must not be true"] : []),
    ...(Object.hasOwn(packageManifest, "publishConfig")
      ? ["package publishConfig must be absent; publish behavior belongs in scripts/publish-npm.sh"]
      : []),
  ];
}

function packageForbiddenMetadataFieldFailures(packageManifest) {
  return forbiddenPackageMetadataFields
    .filter((field) => Object.hasOwn(packageManifest, field))
    .map((field) => `package ${field} must be absent`);
}

function arrayFieldFailures(field, actual, expected) {
  return JSON.stringify(actual ?? []) === JSON.stringify(expected)
    ? []
    : [`package ${field} must be ${JSON.stringify(expected)}`];
}

function lifecycleScriptFile(script) {
  const match = String(script ?? "").match(/\bnode\s+(scripts\/[^\s]+)/);
  return match ? [normalize(match[1])] : [];
}

function requiredPackageFileFailures(files) {
  return requiredPackageFiles
    .filter((file) => !files.includes(file))
    .map((file) => `required package file missing ${file}`);
}

function publicDocumentContentFailures() {
  const checks = [
    {
      file: "NOTICE",
      tokens: ["OpenAI Codex", "LICENSES/Apache-2.0.txt", "UPSTREAM_CODEX.md", "Kuzushi-owned"],
    },
    {
      file: "UPSTREAM_CODEX.md",
      tokens: [
        "https://github.com/openai/codex",
        "Apache-2.0",
        "upstream-codex",
        "No upstream Codex source files are currently vendored wholesale",
      ],
    },
  ];
  return checks.flatMap(({ file, tokens }) => missingDocumentTokens(file, tokens));
}

function missingDocumentTokens(file, tokens) {
  const content = readPackageContractText(file);
  return [
    ...content.failures,
    ...tokens
      .filter((token) => !content.source.includes(token))
      .map((token) => `required package document ${file} does not mention ${token}`),
  ];
}

function packagedRunSchemaFailures(files) {
  const shippedSchemas = files.filter((file) => /^schemas\/run\..*\.schema\.json$/.test(file));
  return [
    ...missingSchemaFiles(
      canonicalRunSchemaFiles,
      shippedSchemas,
      "required run schema not shipped",
    ),
    ...missingSchemaFiles(
      shippedSchemas,
      canonicalRunSchemaFiles,
      "uncontracted run schema shipped",
    ),
    ...missingSchemaFiles(
      packagedSchemaFiles(files),
      requiredPackageFiles,
      "uncontracted schema shipped",
    ),
  ];
}

function missingSchemaFiles(source, allowed, label) {
  return source.filter((file) => !allowed.includes(file)).map((file) => `${label} ${file}`);
}

function packagedSchemaFiles(files) {
  return files.filter((file) => /^schemas\/.*\.schema\.json$/.test(file));
}

function packageExportFailures(exports, files) {
  const exportSurfaceFailures = packageExportSurfaceFailures(exports);
  const schemaWildcard = exports["./schemas/*"];
  return [
    ...exportSurfaceFailures,
    ...packageExportTargetPolicyFailures(exports),
    ...packageExportTargetFailures(exports, files),
    ...schemaExportFailures(schemaWildcard),
  ];
}

function packageLegacyEntrypointFailures(packageManifest) {
  return ["main", "module", "browser", "typings"]
    .filter((field) => Object.hasOwn(packageManifest, field))
    .map((field) => `package ${field} must not bypass exports`);
}

function pnpmLockfileSpecifierFailures(packageManifest) {
  const rootImporter = readPnpmRootImporterSpecifiers();
  if (rootImporter.failures.length > 0) {
    return rootImporter.failures;
  }
  const sections = rootImporter.sections;
  const versions = rootImporter.versions;
  return [
    ...lockfileDependencyGroupFailures(
      "dependencies",
      recordOrEmpty(packageManifest.dependencies),
      sections.dependencies,
    ),
    ...lockfileDependencyGroupFailures(
      "devDependencies",
      recordOrEmpty(packageManifest.devDependencies),
      sections.devDependencies,
    ),
    ...lockfileDependencyGroupFailures(
      "optionalDependencies",
      recordOrEmpty(packageManifest.optionalDependencies),
      sections.optionalDependencies,
    ),
    ...lockfileResolvedVersionFailures("dependencies", versions.dependencies),
    ...lockfileResolvedVersionFailures("devDependencies", versions.devDependencies),
    ...lockfileResolvedVersionFailures("optionalDependencies", versions.optionalDependencies),
  ];
}

function lockfileDependencyGroupFailures(field, manifestDeps, lockDeps) {
  return [
    ...missingSchemaFiles(
      Object.keys(manifestDeps),
      Object.keys(lockDeps),
      `pnpm-lock ${field} missing package`,
    ),
    ...missingSchemaFiles(
      Object.keys(lockDeps),
      Object.keys(manifestDeps),
      `pnpm-lock ${field} has uncontracted package`,
    ),
    ...Object.entries(manifestDeps)
      .filter(([name, specifier]) => lockDeps[name] !== specifier)
      .map(([name, specifier]) => `pnpm-lock ${field}.${name} specifier must be ${specifier}`),
  ];
}

function lockfileResolvedVersionFailures(field, actualVersions) {
  const expectedVersions = expectedPnpmLockfileRootDependencyVersions[field];
  return Object.entries(expectedVersions)
    .filter(([name, version]) => actualVersions[name] !== version)
    .map(([name, version]) => `pnpm-lock ${field}.${name} version must be ${version}`);
}

function optionalLockfilePackageResolutionFailures() {
  const lockfile = readPnpmLockfileLines();
  if (!lockfile.ok) return [];
  return Object.entries(expectedPnpmLockfileRootDependencyVersions.optionalDependencies).flatMap(
    ([name, version]) => optionalLockfilePackageFailures(lockfile.lines, name, version),
  );
}

function optionalLockfilePackageFailures(lines, name, version) {
  const packageKey = pnpmLockfilePackageKey(name, version);
  const resolution = `    resolution: {tarball: ${version}}`;
  return [
    ...(lines.includes(packageKey)
      ? []
      : [`pnpm-lock optional package entry missing ${name}@${version}`]),
    ...(lines.includes(resolution)
      ? []
      : [`pnpm-lock optional package resolution missing ${name}@${version}`]),
  ];
}

function pnpmLockfilePackageKey(name, version) {
  const key = `${name}@${version}`;
  return name.startsWith("@") ? `  '${key}':` : `  ${key}:`;
}

function readPnpmRootImporterSpecifiers() {
  const sections = { dependencies: {}, devDependencies: {}, optionalDependencies: {} };
  const versions = { dependencies: {}, devDependencies: {}, optionalDependencies: {} };
  const lockfile = readPnpmLockfileLines();
  if (!lockfile.ok) return { sections, versions, failures: [lockfile.failure] };
  let state = { inRoot: false, foundRootImporter: false, section: null, packageName: null };
  for (const line of lockfile.lines) {
    state = nextPnpmRootImporterState(sections, versions, state, line);
  }
  return {
    sections,
    versions,
    failures: [
      ...pnpmLockfileHeaderFailures(lockfile.lines),
      ...(state.foundRootImporter ? [] : ["pnpm-lock root importer . must be present"]),
    ],
  };
}

function pnpmLockfileHeaderFailures(lines) {
  const actual = {
    lockfileVersion: lines[0] ?? "",
    autoInstallPeers: lines.find((line) => line.trimStart().startsWith("autoInstallPeers:")) ?? "",
    excludeLinksFromLockfile:
      lines.find((line) => line.trimStart().startsWith("excludeLinksFromLockfile:")) ?? "",
  };
  return Object.entries(expectedPnpmLockfileHeader)
    .filter(([field, expected]) => actual[field] !== expected)
    .map(([field, expected]) => `pnpm-lock ${field} must be ${expected}`);
}

function readPnpmLockfileLines() {
  try {
    return {
      ok: true,
      lines: readFileSync(path.join(repo, "pnpm-lock.yaml"), "utf8").split(/\r?\n/),
    };
  } catch (error) {
    return {
      ok: false,
      failure: `pnpm-lock.yaml must be present and readable: ${error.message}`,
    };
  }
}

function nextPnpmRootImporterState(sections, versions, state, line) {
  if (line === "  .:") {
    return { inRoot: true, foundRootImporter: true, section: null, packageName: null };
  }
  if (!state.inRoot) return state;
  if (line === "packages:" || /^ {2}[^ ].*:$/.test(line)) {
    return { ...state, inRoot: false, section: null, packageName: null };
  }
  return nextPnpmRootDependencyState(sections, versions, state, line);
}

function nextPnpmRootDependencyState(sections, versions, state, line) {
  const section = pnpmRootSectionName(line);
  if (section) return { ...state, section, packageName: null };
  const packageName = pnpmRootPackageName(line);
  if (state.section && packageName) return { ...state, packageName };
  recordPnpmRootPackageFields(sections, versions, state, line);
  return state;
}

function recordPnpmRootPackageFields(sections, versions, state, line) {
  if (!state.section || !state.packageName) return;
  recordPnpmRootField(sections[state.section], state.packageName, pnpmRootSpecifier(line));
  recordPnpmRootField(versions[state.section], state.packageName, pnpmRootVersion(line));
}

function recordPnpmRootField(target, packageName, value) {
  if (value !== null) {
    target[packageName] = value;
  }
}

function pnpmRootSectionName(line) {
  return line.match(/^ {4}(dependencies|devDependencies|optionalDependencies):$/)?.[1] ?? null;
}

function pnpmRootPackageName(line) {
  const match = line.match(/^ {6}(.+):$/);
  return match ? stripYamlScalar(match[1]) : null;
}

function pnpmRootSpecifier(line) {
  const match = line.match(/^ {8}specifier: (.+)$/);
  return match ? stripYamlScalar(match[1]) : null;
}

function pnpmRootVersion(line) {
  const match = line.match(/^ {8}version: (.+)$/);
  return match ? stripYamlScalar(match[1]) : null;
}

function stripYamlScalar(value) {
  return value.replace(/^['"]|['"]$/g, "");
}

function packageExportSurfaceFailures(exports) {
  return [
    ...missingSchemaFiles(
      Object.keys(expectedPackageExports),
      Object.keys(exports),
      "package exports missing required key",
    ),
    ...missingSchemaFiles(
      Object.keys(exports),
      Object.keys(expectedPackageExports),
      "package exports has uncontracted key",
    ),
    ...Object.entries(expectedPackageExports)
      .filter(([key, expected]) => JSON.stringify(exports[key]) !== JSON.stringify(expected))
      .map(([key]) => `package exports ${key} must match the Kuzushi public surface`),
  ];
}

function packageExportTargetFailures(exports, files) {
  if (!existsSync(path.join(repo, "dist"))) return [];
  return Object.entries(exports).flatMap(([key, value]) =>
    packageExportTargets(value)
      .filter((target) => target.startsWith("dist/"))
      .filter((target) => !files.includes(target))
      .map((target) => `package exports ${key} target missing from payload ${target}`),
  );
}

function packageExportTargetPolicyFailures(exports) {
  return Object.entries(exports).flatMap(([key, value]) =>
    packageExportTargets(value)
      .filter(exportTargetViolatesRuntimePolicy)
      .map(
        (target) =>
          `package exports ${key} target must stay on built Kuzushi runtime surface: ${target}`,
      ),
  );
}

function exportTargetViolatesRuntimePolicy(target) {
  return (
    target.endsWith(".tsx") ||
    (target.endsWith(".ts") && !target.endsWith(".d.ts")) ||
    /^(?:.*\/)?src\//.test(target) ||
    /^(?:.*\/)?dist\/(?:cli(?:\/|\.|$)|copilot\/shell(?:-|\.|$)|ui\/)/.test(target)
  );
}

function exportPolicyFixtureFailuresFor(fixtures) {
  return [
    ...fixtures.denied
      .filter((target) => !exportTargetViolatesRuntimePolicy(target))
      .map((target) => `package export-policy denied fixture is allowed ${target}`),
    ...fixtures.allowed
      .filter(exportTargetViolatesRuntimePolicy)
      .map((target) => `package export-policy allowed fixture is denied ${target}`),
  ];
}

function packageExportTargets(value) {
  if (typeof value === "string") return [normalizeExportTarget(value)];
  if (!value || typeof value !== "object" || Array.isArray(value)) return [];
  return Object.values(value).flatMap(packageExportTargets);
}

function normalizeExportTarget(value) {
  return normalize(value.replace(/^\.\//, ""));
}

function packageDependencyFailures(dependencies) {
  return [
    ...missingSchemaFiles(
      Object.keys(expectedPackageDependencies),
      Object.keys(dependencies),
      "package dependencies missing required package",
    ),
    ...missingSchemaFiles(
      Object.keys(dependencies),
      Object.keys(expectedPackageDependencies),
      "package dependencies has uncontracted package",
    ),
    ...Object.entries(expectedPackageDependencies)
      .filter(([name, spec]) => dependencies[name] !== spec)
      .map(([name, spec]) => `package dependencies.${name} must be ${spec}`),
  ];
}

function packageDevDependencyFailures(devDependencies) {
  return [
    ...missingSchemaFiles(
      Object.keys(expectedPackageDevDependencies),
      Object.keys(devDependencies),
      "package devDependencies missing required package",
    ),
    ...missingSchemaFiles(
      Object.keys(devDependencies),
      Object.keys(expectedPackageDevDependencies),
      "package devDependencies has uncontracted package",
    ),
    ...Object.entries(expectedPackageDevDependencies)
      .filter(([name, spec]) => devDependencies[name] !== spec)
      .map(([name, spec]) => `package devDependencies.${name} must be ${spec}`),
  ];
}

function packageOptionalDependencyFailures(optionalDependencies) {
  return [
    ...missingSchemaFiles(
      Object.keys(expectedOptionalAdapterDependencies),
      Object.keys(optionalDependencies),
      "package optionalDependencies missing required package",
    ),
    ...missingSchemaFiles(
      Object.keys(optionalDependencies),
      Object.keys(expectedOptionalAdapterDependencies),
      "package optionalDependencies has uncontracted package",
    ),
    ...Object.entries(expectedOptionalAdapterDependencies)
      .filter(([name, spec]) => optionalDependencies[name] !== spec)
      .map(([name, spec]) => `package optionalDependencies.${name} must be ${spec}`),
  ];
}

function deferredAdapterDependencyFailures(dependencies, optionalDependencies) {
  return Object.entries(expectedOptionalAdapterDependencies).flatMap(([name, spec]) => [
    ...(Object.hasOwn(dependencies, name)
      ? [`package dependencies must not install deferred adapter package ${name}`]
      : []),
    ...(optionalDependencies[name] === spec
      ? []
      : [`package optionalDependencies.${name} must be ${spec}`]),
  ]);
}

function schemaExportFailures(schemaWildcard) {
  return requiredPackageFiles
    .filter((file) => file.startsWith("schemas/"))
    .filter((file) => !schemaExportedByWildcard(schemaWildcard, file))
    .map((file) => `required package file ${file} is not exported by ./schemas/*`);
}

function schemaExportedByWildcard(schemaWildcard, file) {
  return schemaWildcard === "./schemas/*" && file.startsWith("schemas/");
}
