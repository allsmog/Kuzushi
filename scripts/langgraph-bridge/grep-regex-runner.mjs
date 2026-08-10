import { Worker } from "node:worker_threads";

export const GREP_MAX_PATTERN_CHARS = 4096;
const GREP_REGEX_START_TIMEOUT_MS = 1000;
const GREP_REGEX_FILE_TIMEOUT_MS = 250;
const GREP_REGEX_TOTAL_TIMEOUT_MS = 10_000;
const GREP_REGEX_WORKER_URL = new URL("./grep-regex-worker.mjs", import.meta.url);

class GrepRegexBudgetError extends Error {
  constructor() {
    super("Grep regular-expression evaluation exceeded its time budget; simplify the pattern or narrow the search");
    this.name = "GrepRegexBudgetError";
  }
}

export async function scanBoundedRegex({ pattern, files, maxMatches, readText }) {
  const deadline = Date.now() + GREP_REGEX_TOTAL_TIMEOUT_MS;
  const worker = new Worker(GREP_REGEX_WORKER_URL, { workerData: { pattern } });
  try {
    await ensureWorkerReady(worker, deadline);
    return await scanFiles(worker, files, maxMatches, readText, deadline);
  } finally {
    await worker.terminate();
  }
}

async function ensureWorkerReady(worker, deadline) {
  const message = await workerMessage(worker, timeoutWithin(deadline, GREP_REGEX_START_TIMEOUT_MS));
  if (message?.type === "ready") return;
  if (message?.type === "compile-error") throw new Error("Grep pattern is not a valid regular expression");
  throw new Error("Grep regular-expression worker returned an invalid startup response");
}

async function scanFiles(worker, files, maxMatches, readText, deadline) {
  const matches = [];
  let scanned = 0;
  for (const [fileIndex, file] of files.entries()) {
    scanned += 1;
    const fileMatches = await scanFile(worker, file, readText, deadline, fileIndex + 1, maxMatches - matches.length);
    appendIndexedMatches(matches, fileMatches, fileIndex);
    if (matches.length >= maxMatches) break;
  }
  return { matches, scanned };
}

async function scanFile(worker, file, readText, deadline, requestId, remainingMatches) {
  const text = readText(file);
  if (text === null) return [];
  const responsePromise = workerMessage(worker, timeoutWithin(deadline, GREP_REGEX_FILE_TIMEOUT_MS));
  worker.postMessage({ id: requestId, text, maxMatches: remainingMatches });
  const response = await responsePromise;
  if (response?.type === "matches" && response.id === requestId && Array.isArray(response.matches)) {
    return response.matches;
  }
  throw new Error("Grep regular-expression worker returned an invalid match response");
}

function appendIndexedMatches(out, matches, fileIndex) {
  for (const match of matches) {
    out.push({ fileIndex, ...match });
  }
}

function timeoutWithin(deadline, capMs) {
  const remaining = deadline - Date.now();
  if (remaining <= 0) throw new GrepRegexBudgetError();
  return Math.min(remaining, capMs);
}

function workerMessage(worker, timeoutMs) {
  return new Promise((resolveMessage, rejectMessage) => {
    const timer = setTimeout(() => finish(new GrepRegexBudgetError()), timeoutMs);
    const onMessage = (message) => finish(null, message);
    const onError = () => finish(new Error("Grep regular-expression worker failed"));
    const onExit = () => finish(new Error("Grep regular-expression worker exited before responding"));
    const cleanup = () => {
      clearTimeout(timer);
      worker.off("message", onMessage);
      worker.off("error", onError);
      worker.off("exit", onExit);
    };
    const finish = (error, message) => {
      cleanup();
      if (error) rejectMessage(error);
      else resolveMessage(message);
    };
    worker.once("message", onMessage);
    worker.once("error", onError);
    worker.once("exit", onExit);
  });
}
