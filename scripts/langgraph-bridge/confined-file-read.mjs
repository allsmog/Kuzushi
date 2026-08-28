import {
  closeSync,
  constants,
  fstatSync,
  openSync,
  readFileSync,
  readSync,
  realpathSync,
  statSync,
} from "node:fs";
import { sep } from "node:path";

export function canonicalPathWithinRoots(path, roots) {
  let canonical;
  try {
    canonical = realpathSync(path);
  } catch {
    return null;
  }
  return pathIsWithinRoots(canonical, roots) ? canonical : null;
}

export function readConfinedText(path, roots, maxBytes, afterValidation) {
  const fd = openSync(path, secureReadFlags());
  try {
    const stats = validateOpenedFile(fd, path, roots);
    if (maxBytes !== null && stats.size > BigInt(maxBytes)) return null;
    afterValidation?.();
    return maxBytes === null ? readFileSync(fd, "utf8") : readBoundedText(fd, maxBytes);
  } finally {
    closeSync(fd);
  }
}

function secureReadFlags() {
  if (!Number.isInteger(constants.O_NOFOLLOW) || constants.O_NOFOLLOW === 0) {
    throw new Error("secure no-follow file reads are unavailable on this platform");
  }
  return constants.O_RDONLY | constants.O_NOFOLLOW;
}

function validateOpenedFile(fd, path, roots) {
  const opened = fstatSync(fd, { bigint: true });
  if (!opened.isFile()) throw new Error("workspace read target is not a regular file");
  const canonical = openedCanonicalPath(fd, path, roots);
  const rebound = statSync(canonical, { bigint: true });
  if (!sameFileIdentity(opened, rebound)) {
    throw new Error("workspace read target changed during authorization");
  }
  return opened;
}

function openedCanonicalPath(fd, path, roots) {
  // Linux exposes the descriptor target directly. On other platforms,
  // recanonicalizing after open and matching dev+ino below proves that the
  // authorized in-root name still denotes this exact descriptor.
  const descriptorPath = descriptorRealpath(fd);
  const canonical = descriptorPath ?? canonicalPathWithinRoots(path, roots);
  if (canonical === null || !pathIsWithinRoots(canonical, roots)) {
    throw new Error("opened file is outside the workspace read roots");
  }
  return canonical;
}

function descriptorRealpath(fd) {
  if (process.platform !== "linux") return null;
  try {
    return realpathSync(`/proc/self/fd/${fd}`);
  } catch {
    throw new Error("could not authenticate the opened file descriptor");
  }
}

function pathIsWithinRoots(canonical, roots) {
  return roots.some((root) => canonical === root || canonical.startsWith(`${root}${sep}`));
}

function sameFileIdentity(left, right) {
  return left.dev === right.dev && left.ino === right.ino;
}

function readBoundedText(fd, maxBytes) {
  const output = Buffer.alloc(maxBytes + 1);
  let length = 0;
  while (length < output.length) {
    const bytesRead = readSync(fd, output, length, output.length - length, null);
    if (bytesRead === 0) break;
    length += bytesRead;
  }
  return length > maxBytes ? null : output.subarray(0, length).toString("utf8");
}
