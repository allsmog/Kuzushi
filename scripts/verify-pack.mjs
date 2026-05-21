#!/usr/bin/env node
import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import path from "node:path";
import { checkArtifactSchemaInventory } from "./artifact-schema-inventory-contract.mjs";
import { canonicalRunSchemaFiles } from "./canonical-run-schema-files.mjs";

const repo = process.cwd();
const manifest = JSON.parse(readFileSync(path.join(repo, "package.json"), "utf8"));
const entries = manifest.files ?? [];
const omitNative = process.env.KUZUSHI_VERIFY_PACK_OMIT_NATIVE === "1";
const includes = entries.filter((entry) => !entry.startsWith("!")).filter(isIncludedEntry);
const excludes = entries.filter((entry) => entry.startsWith("!")).map((entry) => entry.slice(1));
const requiredPackageFiles = ["schemas/module.manifest.schema.json", ...canonicalRunSchemaFiles];

const denied = [
  /^\.kuzushi(?:\/|$)/,
  /^\.codex(?:\/|$)/,
  /^\.codex-active(?:\/|$)/,
  /^\.ralph(?:\/|$)/,
  /^.*\.sqlite3(?:-|$)/,
  /^.*\.db(?:-|$)/,
  /^target(?:\/|$)/,
  /^dist\/cli(?:\/|\.|$)/,
  /^src\/copilot\/shell(?:-|\.|$)/,
  /^src\/ui\/(?:App\.tsx|components(?:\/|$)|primitives(?:\/|$)|render\.ts|setup\.ts)/,
  /^native\/[^/]+\/(?:codex|kuzushi-ts)(?:\.exe)?$/,
];

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
const nativeFailures = nativeBinaryFailures(sorted);
const binFailures = packageBinFailures(manifest.bin ?? {});
const lifecycleFailures = lifecycleScriptFailures(sorted, manifest.scripts ?? {});
const requiredFileFailures = requiredPackageFileFailures(sorted);
const schemaInventoryFailures = checkArtifactSchemaInventory();
const packagedSchemaFailures = packagedRunSchemaFailures(sorted);
const exportFailures = packageExportFailures(manifest.exports ?? {});

if (
  offenders.length > 0 ||
  nativeFailures.length > 0 ||
  binFailures.length > 0 ||
  lifecycleFailures.length > 0 ||
  requiredFileFailures.length > 0 ||
  schemaInventoryFailures.length > 0 ||
  packagedSchemaFailures.length > 0 ||
  exportFailures.length > 0
) {
  process.stderr.write("package artifact contract failed:\n");
  for (const offender of offenders) {
    process.stderr.write(`- ${offender}\n`);
  }
  for (const failure of [
    ...nativeFailures,
    ...binFailures,
    ...lifecycleFailures,
    ...requiredFileFailures,
    ...schemaInventoryFailures,
    ...packagedSchemaFailures,
    ...exportFailures,
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
  const expected = "./bin/kuzushi-rs.mjs";
  return [
    ...["kuzushi", "kz"]
      .filter((name) => bin[name] !== expected)
      .map((name) => `package bin.${name} must point to ${expected}`),
    ...["codex", "kuzushi-ts"]
      .filter((name) => Object.hasOwn(bin, name))
      .map((name) => `package bin.${name} must not be published`),
  ];
}

function nativeBinaryFailures(files) {
  const dirs = nativePlatformDirs(files);
  if (dirs.length === 0) {
    return ["missing shipped native directory native/<platform>-<arch>"];
  }
  return dirs.flatMap((dir) => missingNativeBinaries(files, dir));
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
  const windows = dir.startsWith("native/win32-");
  const names = windows ? ["kuzushi.exe", "kz.exe"] : ["kuzushi", "kz"];
  return names
    .map((name) => `${dir}/${name}`)
    .filter((file) => !files.includes(file))
    .map((file) => `missing shipped native binary ${file}`);
}

function lifecycleScriptFailures(files, scripts) {
  return ["postinstall", "preinstall", "install"].flatMap((name) =>
    lifecycleScriptFile(scripts[name])
      .filter((file) => !files.includes(file))
      .map((file) => `package scripts.${name} references unshipped file ${file}`),
  );
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

function packagedRunSchemaFailures(files) {
  const shippedSchemas = files.filter((file) => /^schemas\/run\..*\.schema\.json$/.test(file));
  return [
    ...missingSchemaFiles(canonicalRunSchemaFiles, shippedSchemas, "required run schema not shipped"),
    ...missingSchemaFiles(shippedSchemas, canonicalRunSchemaFiles, "uncontracted run schema shipped"),
  ];
}

function missingSchemaFiles(source, allowed, label) {
  return source.filter((file) => !allowed.includes(file)).map((file) => `${label} ${file}`);
}

function packageExportFailures(exports) {
  const schemaWildcard = exports["./schemas/*"];
  if (schemaWildcard !== "./schemas/*") {
    return ['package exports["./schemas/*"] must point to ./schemas/*'];
  }
  return schemaExportFailures(schemaWildcard);
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
