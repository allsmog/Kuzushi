import { createHash } from "node:crypto";
import {
  existsSync,
  lstatSync,
  readdirSync,
  readFileSync,
  renameSync,
  statSync,
  writeFileSync,
} from "node:fs";
import path from "node:path";
import { nativePlatformPackages } from "./native-runtime-contract.mjs";
import { safePackagePathFailures } from "./npm-pack-inventory-contract.mjs";

export const ROOT_PACKED_BUDGET = 10 * 1024 * 1024;
export const PLATFORM_PACKED_BUDGET = 60 * 1024 * 1024;
export const PLATFORM_UNPACKED_BUDGET = 180 * 1024 * 1024;
export const RELEASE_MANIFEST = "release-manifest.json";
const manifestKeys = ["commitSha", "files", "schemaVersion", "version"];
const recordKeys = [
  "file",
  "kind",
  "name",
  "npmIntegrity",
  "sha256",
  "size",
  "slug",
  "unpackedSize",
  "version",
];
const artifactKinds = new Set(["root-npm", "platform-npm", "native", "source"]);

export function createArtifactRecord({ directory, specification, npmMetadata }) {
  const absolute = path.join(directory, specification.file);
  const size = statSync(absolute).size;
  return {
    ...specification,
    size,
    unpackedSize: npmMetadata?.unpackedSize ?? null,
    npmIntegrity: npmMetadata ? npmIntegrity(absolute) : null,
    sha256: digestFile(absolute, "sha256"),
  };
}

export function writeReleaseManifest(directory, commitSha, version, files) {
  const manifest = { schemaVersion: 1, commitSha, version, files };
  const destination = path.join(directory, RELEASE_MANIFEST);
  const temporary = `${destination}.tmp-${process.pid}`;
  writeFileSync(temporary, `${JSON.stringify(manifest, null, 2)}\n`, { flag: "wx" });
  renameSync(temporary, destination);
  return manifest;
}

export function verifyReleaseManifest(directory, expectedSha, expectedVersion) {
  const manifest = readManifest(directory);
  const failures = releaseManifestFailures(directory, manifest, expectedSha, expectedVersion);
  if (failures.length > 0) throw new Error(`release manifest failed:\n- ${failures.join("\n- ")}`);
  return manifest;
}

export function releaseManifestFailures(directory, manifest, expectedSha, expectedVersion) {
  if (!isPlainRecord(manifest)) return ["manifest must be an object"];
  const files = Array.isArray(manifest.files) ? manifest.files : [];
  return [
    ...manifestHeaderFailures(manifest, expectedSha, expectedVersion),
    ...recordSetFailures(files, expectedVersion),
    ...bundleInventoryFailures(directory, files),
    ...files.flatMap((record, index) => recordFailures(directory, record, index)),
  ];
}

export function expectedArtifactSpecifications(version) {
  const npm = [rootNpmSpecification(version), ...platformNpmSpecifications(version)];
  const native = nativePlatformPackages.map((platform) => nativeSpecification(platform, version));
  return [...npm, ...native, sourceSpecification(version)];
}

export function npmIntegrity(file) {
  return `sha512-${digestFile(file, "sha512", "base64")}`;
}

export function artifactSizeFailures(record) {
  if (record.kind === "root-npm" && record.size > ROOT_PACKED_BUDGET) {
    return [`${record.file} exceeds the 10 MiB root package budget`];
  }
  if (record.kind !== "platform-npm") return [];
  return [
    ...(record.size > PLATFORM_PACKED_BUDGET
      ? [`${record.file} exceeds the 60 MiB platform package budget`]
      : []),
    ...(record.unpackedSize > PLATFORM_UNPACKED_BUDGET
      ? [`${record.file} exceeds the 180 MiB unpacked platform package budget`]
      : []),
  ];
}

function readManifest(directory) {
  try {
    return JSON.parse(readFileSync(path.join(directory, RELEASE_MANIFEST), "utf8"));
  } catch (error) {
    return { manifestReadError: error.message };
  }
}

function manifestHeaderFailures(manifest, expectedSha, expectedVersion) {
  return [
    ...exactKeyFailures("manifest", manifest, manifestKeys),
    ...(manifest.schemaVersion === 1 ? [] : ["schemaVersion must be 1"]),
    ...(manifest.commitSha === expectedSha ? [] : [`commitSha must equal ${expectedSha}`]),
    ...(manifest.version === expectedVersion ? [] : [`version must equal ${expectedVersion}`]),
    ...(manifest.manifestReadError
      ? [`manifest is unreadable: ${manifest.manifestReadError}`]
      : []),
  ];
}

function recordSetFailures(files, version) {
  const expected = expectedArtifactSpecifications(version);
  const actualKeys = files.map(specificationKey);
  const expectedKeys = expected.map(specificationKey);
  return [
    ...duplicateFailures(actualKeys),
    ...expectedKeys
      .filter((key) => !actualKeys.includes(key))
      .map((key) => `missing artifact ${key}`),
    ...actualKeys
      .filter((key) => !expectedKeys.includes(key))
      .map((key) => `unexpected artifact ${key}`),
  ];
}

function recordFailures(directory, record, index) {
  const shapeFailures = artifactRecordShapeFailures(record, index);
  if (shapeFailures.length > 0) return shapeFailures;
  const pathFailures = safePackagePathFailures(record.file);
  if (pathFailures.length > 0)
    return pathFailures.map((failure) => `artifact ${index}: ${failure}`);
  return artifactFileFailures(directory, record);
}

function artifactFileFailures(directory, record) {
  const absolute = path.join(directory, record.file);
  if (!existsSync(absolute)) return [`artifact file is missing: ${record.file}`];
  const stat = lstatSync(absolute);
  if (stat.isSymbolicLink() || !stat.isFile())
    return [`artifact must be a regular file: ${record.file}`];
  return [...metadataFailures(absolute, record, stat.size), ...artifactSizeFailures(record)];
}

function artifactRecordShapeFailures(record, index) {
  if (!isPlainRecord(record)) return [`artifact ${index} must be an object`];
  const prefix = `artifact ${index}`;
  return [
    ...exactKeyFailures(prefix, record, recordKeys),
    ...(artifactKinds.has(record.kind) ? [] : [`${prefix} kind is invalid`]),
    ...(typeof record.version === "string" ? [] : [`${prefix} version must be a string`]),
    ...(typeof record.file === "string" ? [] : [`${prefix} file must be a string`]),
    ...(validNullableString(record.name) ? [] : [`${prefix} name must be a string or null`]),
    ...(validNullableString(record.slug) ? [] : [`${prefix} slug must be a string or null`]),
    ...(validSize(record.size) ? [] : [`${prefix} size must be a nonnegative integer`]),
    ...(validNullableSize(record.unpackedSize)
      ? []
      : [`${prefix} unpackedSize must be a nonnegative integer or null`]),
    ...(/^[0-9a-f]{64}$/.test(record.sha256) ? [] : [`${prefix} SHA256 must be 64 hex digits`]),
    ...(validNullableString(record.npmIntegrity)
      ? []
      : [`${prefix} npmIntegrity must be a string or null`]),
  ];
}

function metadataFailures(absolute, record, size) {
  const npmExpected = record.kind.endsWith("-npm") ? npmIntegrity(absolute) : null;
  return [
    ...(record.size === size ? [] : [`${record.file} size must be ${size}`]),
    ...(record.sha256 === digestFile(absolute, "sha256")
      ? []
      : [`${record.file} SHA256 does not match`]),
    ...(record.npmIntegrity === npmExpected ? [] : [`${record.file} npm integrity does not match`]),
  ];
}

function bundleInventoryFailures(directory, files) {
  const actual = walkRegularFiles(directory);
  const expected = [RELEASE_MANIFEST, ...files.map((record) => record?.file)].sort();
  return [
    ...expected.filter((file) => !actual.includes(file)).map((file) => `bundle is missing ${file}`),
    ...actual.filter((file) => !expected.includes(file)).map((file) => `bundle adds ${file}`),
  ];
}

function walkRegularFiles(directory, relative = "") {
  const absolute = path.join(directory, relative);
  if (!existsSync(absolute)) return [];
  return walkExistingPath(directory, relative, absolute);
}

function walkExistingPath(directory, relative, absolute) {
  const stat = lstatSync(absolute);
  if (stat.isSymbolicLink()) return [relative];
  if (stat.isFile()) return [relative.split(path.sep).join("/")];
  if (!stat.isDirectory()) return [relative];
  return readdirSync(absolute).flatMap((entry) =>
    walkRegularFiles(directory, path.join(relative, entry)),
  );
}

function rootNpmSpecification(version) {
  return {
    kind: "root-npm",
    name: "kuzushi",
    slug: null,
    version,
    file: `packages/kuzushi-${version}.tgz`,
  };
}

function platformNpmSpecifications(version) {
  return nativePlatformPackages.map(({ packageName, slug }) => ({
    kind: "platform-npm",
    name: packageName,
    slug,
    version,
    file: `packages/kuzushi-${slug}-${version}.tgz`,
  }));
}

function nativeSpecification(platform, version) {
  const extension = platform.os === "win32" ? "zip" : "tar.gz";
  return {
    kind: "native",
    name: null,
    slug: platform.slug,
    version,
    file: `native/kuzushi-v${version}-${platform.slug}.${extension}`,
  };
}

function sourceSpecification(version) {
  return {
    kind: "source",
    name: null,
    slug: null,
    version,
    file: `source/kuzushi-v${version}-source.tar.gz`,
  };
}

function specificationKey(record) {
  return [record?.kind, record?.name, record?.slug, record?.version, record?.file].join("|");
}

function duplicateFailures(values) {
  return [...new Set(values.filter((value, index) => values.indexOf(value) !== index))].map(
    (value) => `duplicate artifact ${value}`,
  );
}

function exactKeyFailures(subject, value, expectedKeys) {
  const actual = Object.keys(value).sort();
  return JSON.stringify(actual) === JSON.stringify(expectedKeys)
    ? []
    : [`${subject} fields must be exactly ${expectedKeys.join(", ")}`];
}

function isPlainRecord(value) {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function validNullableString(value) {
  return value === null || typeof value === "string";
}

function validSize(value) {
  return Number.isSafeInteger(value) && value >= 0;
}

function validNullableSize(value) {
  return value === null || validSize(value);
}

function digestFile(file, algorithm, encoding = "hex") {
  return createHash(algorithm).update(readFileSync(file)).digest(encoding);
}
