import { beforeEach } from "vitest";
import { inflightCache, resetGitHeadCache } from "../src/cache.js";
import { setGlobalLogLevel } from "../src/logger.js";

// Reset the inflight cache between every test to prevent cross-test contamination.
// Tests use mock runtimes that may produce different results for identical prompts,
// so caching must not carry over.
beforeEach(() => {
  setGlobalLogLevel("error");
  inflightCache.invalidate();
  inflightCache.enabled = true;
  resetGitHeadCache();
});
