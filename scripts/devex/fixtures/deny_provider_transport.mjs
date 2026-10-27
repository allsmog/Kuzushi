// Test-only guard: a read-only TUI journey must never reach any network fetch.
import { appendFileSync } from "node:fs";

globalThis.fetch = async () => {
  const log = process.env.KUZUSHI_TEST_DENIED_FETCH_LOG;
  if (log) {
    appendFileSync(log, `${JSON.stringify({ blocked: true })}\n`);
  }
  throw new Error("This inspection journey grants no provider or network requests");
};
