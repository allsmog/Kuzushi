import { createHash } from "node:crypto";
import * as path from "node:path";
import { canonicalPathWithinRoots } from "./confined-file-read.mjs";

export const READ_ONLY_SCOPE_POLICY_ID = "source.membership-read-only.v1";
const MAX_FILES = 100_000;
const MAX_BYTES = 8 * 1024 * 1024;

export function readScopeForPolicy(policy, roots) {
  const scope = policy?.readScope ?? policy?.read_scope;
  if (!declaresMembership(policy) && policy?.profile !== READ_ONLY_SCOPE_POLICY_ID) return null;
  validateMembership(scope);
  validateScopeEnvironment(roots);
  return new ReadMembership(roots[0], scope);
}

function declaresMembership(policy) {
  return Object.hasOwn(policy ?? {}, "readScope") || Object.hasOwn(policy ?? {}, "read_scope");
}

function validateScopeEnvironment(roots) {
  if (roots.length !== 1) throw new Error("read membership requires one canonical root");
  if (typeof path.matchesGlob !== "function") {
    throw new Error("this runtime cannot match accepted read membership");
  }
}

function validateMembership(scope) {
  if (scope?.schemaVersion !== 1 || !Array.isArray(scope.files)) {
    throw new Error("unsupported read membership");
  }
  validateFiles(scope.files);
  validateDigest(scope);
}

function validateFiles(files) {
  if (files.length === 0 || files.length > MAX_FILES) throw new Error("read membership exceeds its file limit");
  let bytes = 0;
  for (const file of files) {
    validateFile(file);
    bytes += Buffer.byteLength(file);
    if (bytes > MAX_BYTES) throw new Error("read membership exceeds 8 MiB");
  }
  requireUnique(files);
}

function requireUnique(files) {
  if (new Set(files).size !== files.length) throw new Error("read membership files must be unique");
}

function validateDigest(scope) {
  const encoded = JSON.stringify(scope.files);
  if (Buffer.byteLength(encoded) > MAX_BYTES) throw new Error("read membership exceeds 8 MiB");
  const digest = createHash("sha256").update(encoded).digest("hex");
  if (digest !== scope.sha256) throw new Error("read membership digest differs from its files");
}

function validateFile(file) {
  validateFileShape(file);
  if (file.includes("\\") || [...file].some(isControlCharacter)) {
    throw new Error("unsupported read membership path characters");
  }
  if (!file.split("/").every(validPart)) {
    throw new Error("read membership paths must be canonical and repository-relative");
  }
}

function validateFileShape(file) {
  if (typeof file !== "string" || Buffer.byteLength(file) > 4096) {
    throw new Error("invalid read membership path");
  }
}

function isControlCharacter(char) {
  const code = char.codePointAt(0);
  return code < 32 || (code >= 127 && code <= 159);
}

function validPart(part) {
  return part !== "" && part !== "." && part !== "..";
}

class ReadMembership {
  constructor(root, scope) {
    this.root = root;
    this.sha256 = scope.sha256;
    this.files = scope.files.map((file) => path.resolve(root, file));
    if (this.files.some((file) => !file.startsWith(`${root}${path.sep}`))) {
      throw new Error("read membership path escapes its root");
    }
    this.allowed = new Set(this.files);
  }

  authorizeFile(candidate) {
    const absolute = path.resolve(this.root, candidate);
    const canonical = canonicalPathWithinRoots(absolute, [this.root]);
    this.authorizeOpenedPath(canonical, absolute);
    return absolute;
  }

  authorizeOpenedPath(canonical, requested = canonical) {
    if (canonical !== requested || !this.allowed.has(canonical)) {
      throw new Error("file is outside accepted read membership or has a symlinked path");
    }
  }

  base(candidate = this.root) {
    const absolute = path.resolve(this.root, candidate);
    if (absolute === this.root || this.allowed.has(absolute)) return absolute;
    if (this.files.some((file) => file.startsWith(`${absolute}${path.sep}`))) return absolute;
    throw new Error("path is outside accepted read membership");
  }

  directoryEntries(candidate) {
    const base = this.base(candidate);
    const entries = this.files.filter((file) => file.startsWith(`${base}${path.sep}`));
    const names = entries.map((file) => directoryLabel(path.relative(base, file)));
    return [...new Set(names)].sort();
  }

  candidates(candidate, pattern, quota) {
    const base = this.base(candidate);
    validatePattern(pattern);
    const kept = [];
    for (const file of this.files) {
      if (!matchesMember(file, base, pattern)) continue;
      if (kept.length >= quota) return { kept, truncated: true };
      kept.push({ canonicalPath: file, matchedPath: file });
    }
    return { kept, truncated: false };
  }
}

function validatePattern(pattern) {
  if (pattern === undefined) return;
  if (typeof pattern !== "string" || pattern.length > 512) {
    throw new Error("scoped glob pattern exceeds 512 characters");
  }
}

function matchesMember(file, base, pattern) {
  if (!isWithinBase(file, base)) return false;
  const relative = file === base ? path.basename(file) : path.relative(base, file);
  return pattern === undefined || path.matchesGlob(relative, pattern);
}

function directoryLabel(relative) {
  const parts = relative.split(path.sep);
  return parts.length > 1 ? `${parts[0]}/` : parts[0];
}

function isWithinBase(file, base) {
  return file === base || file.startsWith(`${base}${path.sep}`);
}
