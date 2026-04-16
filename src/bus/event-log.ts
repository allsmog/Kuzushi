/**
 * Bounded event log: persists pipeline events to NDJSON files
 * with segment rotation (64MB max per segment, 5 segments max).
 */

import type { WriteStream } from "node:fs";
import { createWriteStream, existsSync, mkdirSync, statSync, unlinkSync } from "node:fs";
import path from "node:path";
import type { MessageBus } from "./types.js";

const MAX_SEGMENT_BYTES = 64 * 1024 * 1024; // 64MB
const MAX_SEGMENTS = 5;

export interface EventLogConfig {
  logDir: string;
  runId: string;
}

/**
 * Register an event log writer on the bus.
 * Subscribes to all events and writes NDJSON to disk with rotation.
 */
export function registerEventLogWriter(
  bus: MessageBus,
  config: EventLogConfig,
): { close: () => void } {
  const logDir = config.logDir;
  if (!existsSync(logDir)) {
    mkdirSync(logDir, { recursive: true });
  }

  let segmentIndex = 0;
  let currentStream: WriteStream | null = null;
  let currentBytes = 0;

  function segmentPath(idx: number): string {
    return path.join(logDir, `events-${config.runId}-${idx}.ndjson`);
  }

  function openSegment(): WriteStream {
    const filePath = segmentPath(segmentIndex);
    return createWriteStream(filePath, { flags: "a" });
  }

  function rotateIfNeeded(): void {
    if (currentBytes < MAX_SEGMENT_BYTES) return;

    currentStream?.end();
    segmentIndex++;

    // Remove oldest segment if we exceed max segments
    const oldestIdx = segmentIndex - MAX_SEGMENTS;
    if (oldestIdx >= 0) {
      const oldPath = segmentPath(oldestIdx);
      try {
        if (existsSync(oldPath)) {
          unlinkSync(oldPath);
        }
      } catch {
        // Best-effort cleanup.
      }
    }

    currentStream = openSegment();
    currentBytes = 0;
  }

  // Check if existing segment file has content
  const initialPath = segmentPath(0);
  if (existsSync(initialPath)) {
    try {
      currentBytes = statSync(initialPath).size;
    } catch {
      currentBytes = 0;
    }
  }

  currentStream = openSegment();

  // Subscribe to all events using a wildcard-style pattern.
  // The bus doesn't support wildcards, so we hook into publish.
  const originalPublish = bus.publish.bind(bus);
  const wrappedPublish: typeof bus.publish = async (event) => {
    // Write the event to the log
    const record = {
      timestamp: new Date().toISOString(),
      type: (event as Record<string, unknown>).type,
      meta: (event as Record<string, unknown>).meta,
      payload: redactSecrets((event as Record<string, unknown>).payload),
    };

    const line = JSON.stringify(record) + "\n";
    const lineBytes = Buffer.byteLength(line, "utf-8");

    currentStream?.write(line);
    currentBytes += lineBytes;
    rotateIfNeeded();

    return originalPublish(event);
  };

  // Monkey-patch publish — this is intentional for non-invasive logging.
  // Store original for restoration. We set on the instance to shadow the prototype method.
  const hadOwnPublish = Object.hasOwn(bus, "publish");
  (bus as unknown as Record<string, unknown>).publish = wrappedPublish;

  return {
    close: () => {
      currentStream?.end();
      currentStream = null;
      // Restore original publish: if it was an own property, restore it; otherwise delete to expose prototype
      if (hadOwnPublish) {
        (bus as unknown as Record<string, unknown>).publish = originalPublish;
      } else {
        delete (bus as unknown as Record<string, unknown>).publish;
      }
    },
  };
}

/** Redact strings that look like API keys in event payloads. */
function redactSecrets(payload: unknown): unknown {
  if (typeof payload === "string") {
    return redactString(payload);
  }
  if (Array.isArray(payload)) {
    return payload.map(redactSecrets);
  }
  if (payload !== null && typeof payload === "object") {
    const result: Record<string, unknown> = {};
    for (const [key, value] of Object.entries(payload)) {
      result[key] = redactSecrets(value);
    }
    return result;
  }
  return payload;
}

const API_KEY_PATTERN = /\b(sk-[a-zA-Z0-9_-]{10,})\b/g;

function redactString(str: string): string {
  return str.replace(API_KEY_PATTERN, (match) => {
    if (match.length <= 10) return match;
    return match.slice(0, 6) + "..." + match.slice(-4);
  });
}
