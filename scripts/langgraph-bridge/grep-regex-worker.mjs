import { parentPort, workerData } from "node:worker_threads";

const READ_MAX_LINE_CHARS = 500;
const GREP_MAX_MATCHES = 100;

let regex;
try {
  regex = new RegExp(workerData.pattern);
  parentPort.postMessage({ type: "ready" });
} catch {
  parentPort.postMessage({ type: "compile-error" });
}

if (regex) {
  parentPort.on("message", ({ id, text, maxMatches }) => {
    const limit = Math.max(0, Math.min(Number(maxMatches) || 0, GREP_MAX_MATCHES));
    const matches = collectMatches(regex, text, limit);
    parentPort.postMessage({ type: "matches", id, matches });
  });
}

function collectMatches(compiled, text, limit) {
  const matches = [];
  const lines = text.split("\n");
  for (let index = 0; index < lines.length && matches.length < limit; index += 1) {
    compiled.lastIndex = 0;
    if (compiled.test(lines[index])) {
      matches.push({ line: index + 1, preview: lines[index].slice(0, READ_MAX_LINE_CHARS) });
    }
  }
  return matches;
}
