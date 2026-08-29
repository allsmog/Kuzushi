#!/usr/bin/env node
import { execFileSync } from "node:child_process";
import { existsSync, lstatSync, readdirSync, readFileSync, statSync } from "node:fs";
import path from "node:path";
import { checkArtifactSchemaInventory } from "./artifact-schema-inventory-contract.mjs";
import { canonicalRunSchemaFiles } from "./canonical-run-schema-files.mjs";
import { nativePlatformPackages } from "./native-runtime-contract.mjs";
import { packedInventoryFailures } from "./npm-pack-inventory-contract.mjs";

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
const includes = entries.filter((entry) => !entry.startsWith("!")).filter(isIncludedEntry);
const excludes = entries.filter((entry) => entry.startsWith("!")).map((entry) => entry.slice(1));
const requiredPackageFiles = [
  "README.md",
  "UPSTREAM_CODEX.md",
  "NOTICE",
  "LICENSES/Apache-2.0.txt",
  "LICENSE",
  "schemas/module.manifest.schema.json",
  "schemas/kuzushi.lock.schema.json",
  "schemas/review-yield.dataset-manifest.schema.json",
  "schemas/review-yield.model.schema.json",
  "schemas/review-yield.training-example.schema.json",
  ...canonicalRunSchemaFiles,
];
const allowedPackageEntries = [
  "bin",
  "scripts/native-runtime-contract.mjs",
  "scripts/langgraph-bridge.mjs",
  "scripts/langgraph-bridge/confined-file-read.mjs",
  "scripts/langgraph-bridge/diagnostics.mjs",
  "scripts/langgraph-bridge/errors.mjs",
  "scripts/langgraph-bridge/file-tools.mjs",
  "scripts/langgraph-bridge/grep-regex-runner.mjs",
  "scripts/langgraph-bridge/grep-regex-worker.mjs",
  "scripts/langgraph-bridge/mcp.mjs",
  "scripts/langgraph-bridge/model.mjs",
  "scripts/langgraph-bridge/next-step-messages.mjs",
  "scripts/langgraph-bridge/oauth-login.mjs",
  "scripts/langgraph-bridge/oauth-models.mjs",
  "scripts/langgraph-bridge/process-exit.mjs",
  "scripts/langgraph-bridge/schema.mjs",
  "scripts/langgraph-bridge/tool-policy-handshake.mjs",
  "scripts/kuzushi-dynamic-module-host.mjs",
  "schemas",
  "examples/kwp/agentic-fuzz",
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
const allowedLifecycleScripts = {};
const requiredReleaseScripts = {
  "verify:pack": "node scripts/verify-pack.mjs && node scripts/smoke-packed-runtime.mjs",
  "pack:native-platforms": "node scripts/pack-platform-packages.mjs",
  "publish:npm": "bash scripts/publish-npm.sh",
  "publish:npm:dry": "bash scripts/publish-npm.sh",
  "publish:npm:go": "bash scripts/publish-npm.sh --publish",
};
// Packaging policy is checked against package.json itself; expectations that
// merely restate manifest content live in the manifest, not here. Only the
// published identity and the release-critical wiring stay explicit.
const expectedPackageIdentity = {
  name: "kuzushi",
  type: "module",
  license: "MIT",
};
const expectedOnlyBuiltDependencies = ["esbuild"];
// devDependencies must never reintroduce the retired TypeScript toolchain.
const forbiddenDevDependencyPatterns = [
  /^typescript$/,
  /^tsx$/,
  /^ts-node$/,
  /^vitest$/,
  /^@vitest\//,
  /^@types\//,
  /^madge$/,
];
const expectedPackageExports = {
  "./schemas/*": "./schemas/*",
  "./package.json": "./package.json",
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
const explicitAdapterPackages = [
  "@kuzushi/tob-skills",
  "@kuzushi/vuln-scout",
  "promptarmor-plugin",
  "shinsa-plugin",
];

const denied = [
  /^(?:.*\/)?\.kuzushi(?:\/|$)/,
  /^(?:.*\/)?\.codex(?:\/|$)/,
  /^(?:.*\/)?\.codex-active(?:\/|$)/,
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
  "assets/.kuzushi/v3/runs/example/run.json",
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
  allowed: ["schemas/module.manifest.schema.json", "package.json"],
  denied: [
    "src/index.ts",
    "src/ui/App.tsx",
    "dist/cli.js",
    "dist/copilot/shell.js",
    "dist/ui/App.js",
  ],
};
const packageTypesPolicyFixtures = {
  allowed: [undefined],
  denied: ["./dist/index.d.ts", "src/index.ts", "src/ui/App.tsx", "README.md", 42],
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
    "pnpm build:native",
    "node scripts/build-native-runtime.mjs",
    "node scripts/check-retired-ts-runtime.mjs",
  ],
  denied: [
    "tsx src/copilot/shell.ts",
    "tsx src/ui/App.tsx",
    "node dist/cli.js",
    "pnpm build:clean && node dist/cli.js",
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
const actualPack = readActualPackMetadata();
const actualInventoryFailures = packedInventoryFailures(actualPack, sorted);
const deniedFixtureFailures = deniedPathFixtureFailures();
const packagePathShapeFailures = packagePayloadPathShapeFailures(includes);
const packageEntryFailures = packageFilesEntryFailures(entries);
const nativeFailures = platformPackageManifestFailures();
const binFailures = packageBinFailures(packageBin);
const binSurfaceFixtureFailures = packageBinSurfaceFixtureFailures(packageBinSurfaceFixtures);
const binWrapperFailures = binWrapperContentFailures();
const lifecycleFailures = lifecycleScriptFailures(sorted, packageScripts);
const scriptSurfaceFailures = scriptFileReferenceFailures(packageScripts);
const scriptRuntimePolicyFailures = packageScriptRuntimePolicyFailures(packageScripts);
const scriptRuntimePolicyFixtureFailures = packageScriptRuntimePolicyFixtureFailures(
  packageScriptRuntimePolicyFixtures,
);
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
const dependencyFailures = unusedDependencyFailures(packageDependencies);
const devDependencyFailures = devDependencyPolicyFailures(packageDevDependencies);
const optionalDependencyFailures = packageOptionalDependencyFailures(packageOptionalDependencies);
const deferredDependencyFailures = deferredAdapterDependencyFailures(
  packageDependencies,
  packageOptionalDependencies,
);
const bridgeDependencyFailures = packagedBridgeDependencyFailures(packageDependencies);

if (
  offenders.length > 0 ||
  actualInventoryFailures.length > 0 ||
  deniedFixtureFailures.length > 0 ||
  packagePathShapeFailures.length > 0 ||
  packageFileShapeFailures.length > 0 ||
  manifestRecordShapeFailures.length > 0 ||
  packageEntryFailures.length > 0 ||
  nativeFailures.length > 0 ||
  binFailures.length > 0 ||
  binSurfaceFixtureFailures.length > 0 ||
  binWrapperFailures.length > 0 ||
  lifecycleFailures.length > 0 ||
  scriptSurfaceFailures.length > 0 ||
  scriptRuntimePolicyFailures.length > 0 ||
  scriptRuntimePolicyFixtureFailures.length > 0 ||
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
  dependencyFailures.length > 0 ||
  devDependencyFailures.length > 0 ||
  optionalDependencyFailures.length > 0 ||
  deferredDependencyFailures.length > 0 ||
  bridgeDependencyFailures.length > 0
) {
  process.stderr.write("package artifact contract failed:\n");
  for (const offender of offenders) {
    process.stderr.write(`- ${offender}\n`);
  }
  for (const failure of [
    ...actualInventoryFailures,
    ...nativeFailures,
    ...deniedFixtureFailures,
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
    ...dependencyFailures,
    ...devDependencyFailures,
    ...optionalDependencyFailures,
    ...deferredDependencyFailures,
    ...bridgeDependencyFailures,
  ]) {
    process.stderr.write(`- ${failure}\n`);
  }
  process.exit(1);
}

runPrivateContextCheck();
runArchitectureContractChecks();

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
  "\npackage artifact check passed (thin launcher and platform package contracts are consistent)\n",
);

function runArchitectureContractChecks() {
  const pnpm = process.platform === "win32" ? "pnpm.cmd" : "pnpm";
  execFileSync(pnpm, ["run", "quality:architecture"], {
    cwd: repo,
    stdio: "inherit",
  });
}

function runPrivateContextCheck() {
  execFileSync(process.execPath, ["scripts/check-private-context.mjs"], {
    cwd: repo,
    stdio: "inherit",
  });
}

function readPackageManifest() {
  try {
    return JSON.parse(readFileSync(path.join(repo, "package.json"), "utf8"));
  } catch (error) {
    process.stderr.write("package artifact contract failed:\n");
    process.stderr.write(`- package.json must be valid JSON: ${error.message}\n`);
    process.exit(1);
  }
}

function readActualPackMetadata() {
  const npm = process.platform === "win32" ? "npm.cmd" : "npm";
  try {
    const output = execFileSync(npm, ["pack", "--dry-run", "--ignore-scripts", "--json"], {
      cwd: repo,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
    });
    const [packed] = JSON.parse(output);
    if (packed && typeof packed === "object") return packed;
    throw new Error("npm pack returned no package record");
  } catch (error) {
    return { files: [], inventoryError: error.message };
  }
}

function readPackageContractText(file) {
  try {
    return { source: readFileSync(path.join(repo, file), "utf8"), failures: [] };
  } catch (error) {
    return { source: "", failures: [`${file} must be readable: ${error.message}`] };
  }
}

function packagedBridgeImports() {
  const files = [
    "scripts/langgraph-bridge.mjs",
    ...sorted.filter((file) => file.startsWith("scripts/langgraph-bridge/")),
    "scripts/kuzushi-dynamic-module-host.mjs",
  ];
  return new Set(files.flatMap(externalImportsFrom));
}

function packagedBridgeDependencyFailures(dependencies) {
  return [...packagedBridgeImports()]
    .filter((packageName) => !Object.hasOwn(dependencies, packageName))
    .map((packageName) => `packaged bridge imports undeclared dependency ${packageName}`);
}

// The published package is CLI-only; runtime dependencies exist solely for the
// shipped bridge scripts. Any dependency no bridge imports is dead weight the
// consumer installs for nothing.
function unusedDependencyFailures(dependencies) {
  const imports = packagedBridgeImports();
  return Object.keys(dependencies)
    .filter((name) => !imports.has(name))
    .map((name) => `package dependencies.${name} is not imported by any shipped bridge script`);
}

function devDependencyPolicyFailures(devDependencies) {
  return Object.keys(devDependencies)
    .filter((name) => forbiddenDevDependencyPatterns.some((pattern) => pattern.test(name)))
    .map((name) => `package devDependencies.${name} reintroduces the retired TypeScript toolchain`);
}

function externalImportsFrom(relativePath) {
  const source = readPackageContractText(relativePath).source;
  return [...source.matchAll(/\bfrom\s+["']([^"']+)["']/g)]
    .map((match) => match[1])
    .filter((specifier) => !specifier.startsWith(".") && !specifier.startsWith("node:"))
    .map(packageNameForSpecifier);
}

function packageNameForSpecifier(specifier) {
  return specifier.startsWith("@")
    ? specifier.split("/").slice(0, 2).join("/")
    : specifier.split("/")[0];
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
  return Boolean(entry);
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

// The wrapper's behavior is exercised end-to-end by smoke-packed-runtime and
// the e2e job; only identity policy and executability are asserted statically.
function binWrapperContentFailures() {
  const content = readPackageContractText("bin/kuzushi-rs.mjs");
  const forbidden = ["codex", "kuzushi-ts"];
  return [
    ...content.failures,
    ...forbidden
      .filter((token) => content.source.includes(token))
      .map((token) => `bin/kuzushi-rs.mjs must not mention ${token}`),
    ...executableFileFailures(["bin/kuzushi-rs.mjs"]),
  ];
}

function platformPackageManifestFailures() {
  return nativePlatformPackages.flatMap(platformPackageManifestEntryFailures);
}

function platformPackageManifestEntryFailures(platformPackage) {
  const relativePath = `npm/platform-packages/${platformPackage.slug}/package.json`;
  if (!existsSync(path.join(repo, relativePath))) return [`missing ${relativePath}`];
  const platformManifest = JSON.parse(readFileSync(path.join(repo, relativePath), "utf8"));
  return [
    ...platformPackageFieldFailures(platformPackage, platformManifest, relativePath),
    ...platformPackageLibcFailures(platformPackage, platformManifest, relativePath),
    ...(platformManifest.publishConfig?.access === "public"
      ? []
      : [`${relativePath} publishConfig.access must be public`]),
  ];
}

function platformPackageFieldFailures(platformPackage, platformManifest, relativePath) {
  const expectedFields = {
    name: platformPackage.packageName,
    version: manifest.version,
    os: [platformPackage.os],
    cpu: [platformPackage.cpu],
    files: ["bin"],
  };
  return Object.entries(expectedFields)
    .filter(
      ([field, expected]) => JSON.stringify(platformManifest[field]) !== JSON.stringify(expected),
    )
    .map(([field, expected]) => `${relativePath} ${field} must be ${JSON.stringify(expected)}`);
}

function platformPackageLibcFailures(platformPackage, platformManifest, relativePath) {
  if (!platformPackage.libc) return [];
  const expected = JSON.stringify([platformPackage.libc]);
  return JSON.stringify(platformManifest.libc) === expected
    ? []
    : [`${relativePath} libc must be ${expected}`];
}

function executableFileFailures(files) {
  return files
    .filter((file) => existsSync(path.join(repo, file)))
    .filter((file) => (statSync(path.join(repo, file)).mode & 0o111) === 0)
    .map((file) => `${file} must be executable`);
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

// Every script/test file a package.json command references must exist; the
// commands themselves are the source of truth and are not mirrored here.
function scriptFileReferenceFailures(scripts) {
  return Object.entries(scripts).flatMap(([name, command]) =>
    referencedScriptFiles(command)
      .filter((file) => !existsSync(path.join(repo, file)))
      .map((file) => `package scripts.${name} references missing file ${file}`),
  );
}

function referencedScriptFiles(command) {
  return [
    ...String(command ?? "").matchAll(
      /\b(?:node(?: --test)?|bash)\s+((?:scripts|tests)\/[^\s&|;]+)/g,
    ),
  ].map((match) => normalize(match[1]));
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

function releaseScriptFailuresFor(scripts) {
  return Object.entries(requiredReleaseScripts)
    .filter(([name, command]) => scripts[name] !== command)
    .map(([name, command]) => `package scripts.${name} must be ${command}`);
}

// Publish safety policy: the publish path must verify the pack and must never
// let npm run lifecycle scripts. Everything else about the script is its own
// business.
function publishWrapperContentFailures() {
  const content = readPackageContractText("scripts/publish-npm.sh");
  const required = [
    "Build and inspect a platform-local npm package without publishing it",
    "Local publishing is disabled",
    "Release assembly is authoritative",
    "git diff --quiet",
    "git diff --cached --quiet",
    "git rev-parse --abbrev-ref HEAD",
    'git rev-parse -q --verify "refs/tags/${TAG}"',
    'git rev-list -n 1 "$TAG"',
    "git rev-parse HEAD",
    'git ls-remote --tags origin "refs/tags/${TAG}"',
    "SKIP_TESTS:-0",
    "pnpm run test",
    "pnpm run test:rust",
    "pnpm run build:native",
    "pnpm run verify:pack",
    "npm pack --dry-run --ignore-scripts",
    "no registry mutation was attempted",
    "multi-platform GitHub workflow",
  ];
  return [
    ...content.failures,
    ...required
      .filter((token) => !content.source.includes(token))
      .map((token) => `scripts/publish-npm.sh must mention ${token}`),
  ];
}

function packageMetadataFailures(packageManifest) {
  const checks = [
    ["name", packageManifest.name, expectedPackageIdentity.name],
    ["type", packageManifest.type, expectedPackageIdentity.type],
    ["license", packageManifest.license, expectedPackageIdentity.license],
  ];
  return [
    ...checks
      .filter(([, actual, expected]) => actual !== expected)
      .map(([field, , expected]) => `package ${field} must be ${expected}`),
    ...(typeof packageManifest.engines?.node === "string" &&
    packageManifest.engines.node.startsWith(">=")
      ? []
      : ["package engines.node must declare a >= floor"]),
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
  return types === undefined
    ? []
    : ["package types must be absent; the npm package ships no TypeScript library surface"];
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

function packageOptionalDependencyFailures(optionalDependencies) {
  const expected = new Map(
    nativePlatformPackages.map(({ packageName }) => [packageName, manifest.version]),
  );
  return [
    ...[...expected]
      .filter(([name, version]) => optionalDependencies[name] !== version)
      .map(([name, version]) => `package optionalDependencies.${name} must be ${version}`),
    ...Object.keys(optionalDependencies)
      .filter((name) => !expected.has(name))
      .map((name) => `package optionalDependencies has uncontracted package ${name}`),
  ];
}

function deferredAdapterDependencyFailures(dependencies, optionalDependencies) {
  return explicitAdapterPackages.flatMap((name) => [
    ...(Object.hasOwn(dependencies, name)
      ? [`package dependencies must not install explicit adapter package ${name}`]
      : []),
    ...(Object.hasOwn(optionalDependencies, name)
      ? [`package optionalDependencies must not auto-install explicit adapter package ${name}`]
      : []),
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
