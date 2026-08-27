const unsafeSegments = new Set([".kuzushi", ".codex", ".claude", "node_modules", "target"]);

export function packedInventoryFailures(packed, expectedFiles) {
  return [
    ...safePackedInventoryFailures(packed),
    ...inventoryDifferenceFailures(
      Array.isArray(packed?.files) ? packed.files.map((record) => record?.path) : [],
      expectedFiles,
    ),
  ];
}

export function safePackedInventoryFailures(packed) {
  const records = Array.isArray(packed?.files) ? packed.files : [];
  const paths = records.map((record) => record?.path);
  return [...packedFileRecordFailures(records), ...duplicatePathFailures(paths)];
}

export function safePackagePathFailures(value) {
  if (!isNonemptyString(value)) return ["path must be a nonempty string"];
  return safeStringPathFailures(value);
}

function safeStringPathFailures(value) {
  if (/\\|^(?:\/|[A-Za-z]:)/.test(value)) {
    return [`unsafe absolute or non-portable path ${value}`];
  }
  if (/\p{Cc}/u.test(value)) return [`path contains control characters ${JSON.stringify(value)}`];
  const segments = value.split("/");
  if (segments.some(isUnsafeStructuralSegment)) {
    return [`unsafe path segment in ${value}`];
  }
  return segments.some(isLocalStateSegment)
    ? [`generated or local state is not publishable: ${value}`]
    : [];
}

function isNonemptyString(value) {
  return typeof value === "string" && value.length > 0;
}

function isUnsafeStructuralSegment(segment) {
  return segment === "" || segment === "." || segment === "..";
}

function isLocalStateSegment(segment) {
  return unsafeSegments.has(segment);
}

function packedFileRecordFailures(records) {
  return records.flatMap((record, index) => {
    if (!record || typeof record !== "object") return [`packed file ${index} must be an object`];
    const failures = safePackagePathFailures(record.path);
    if (!Number.isSafeInteger(record.size) || record.size < 0) {
      failures.push(`packed file ${record.path ?? index} must report a nonnegative integer size`);
    }
    return failures;
  });
}

function duplicatePathFailures(paths) {
  return [...new Set(paths.filter((value, index) => paths.indexOf(value) !== index))].map(
    (value) => `packed inventory contains duplicate ${value}`,
  );
}

function inventoryDifferenceFailures(actual, expected) {
  if (!Array.isArray(expected)) return ["expected packed inventory must be an array"];
  const actualSet = new Set(actual);
  const expectedSet = new Set(expected);
  return [
    ...expected
      .filter((file) => !actualSet.has(file))
      .map((file) => `packed inventory misses ${file}`),
    ...actual
      .filter((file) => !expectedSet.has(file))
      .map((file) => `packed inventory adds ${file}`),
  ];
}
