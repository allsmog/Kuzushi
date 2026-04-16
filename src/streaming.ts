import { createServer, type Server, type ServerResponse } from "node:http";
import type {
  PatchCompleteEvent,
  PatchVerifyCompleteEvent,
  PipelineCompleteEvent,
  PipelineErrorEvent,
  PocHarnessResultEvent,
  ScanCompleteEvent,
  TriageCompleteEvent,
  TriageResultEvent,
  VerificationResultEvent,
} from "./bus/events.js";
import type { MessageBus } from "./bus/types.js";
import { createLogger } from "./logger.js";

const log = createLogger({ stage: "streaming" });

/** Minimal SSE event for streaming to clients. */
interface StreamEvent {
  type: string;
  data: Record<string, unknown>;
}

/**
 * Start an SSE server that streams pipeline events to connected clients.
 * Returns the server instance and its port for cleanup.
 */
export function startStreamingServer(
  bus: MessageBus,
  port: number = 0, // 0 = auto-assign
): { server: Server; port: number; close: () => Promise<void> } {
  const clients = new Set<ServerResponse>();

  const server = createServer((req, res) => {
    // CORS for browser clients
    res.setHeader("Access-Control-Allow-Origin", "*");
    res.setHeader("Access-Control-Allow-Methods", "GET");

    if (req.method === "OPTIONS") {
      res.writeHead(204);
      res.end();
      return;
    }

    if (req.url === "/events" || req.url === "/") {
      // SSE endpoint
      res.writeHead(200, {
        "Content-Type": "text/event-stream",
        "Cache-Control": "no-cache",
        Connection: "keep-alive",
      });

      // Send initial connection event
      sendSSE(res, { type: "connected", data: { message: "Streaming pipeline events" } });

      clients.add(res);

      req.on("close", () => {
        clients.delete(res);
      });
    } else if (req.url === "/health") {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ status: "ok", clients: clients.size }));
    } else {
      res.writeHead(404);
      res.end("Not found");
    }
  });

  // Subscribe to key pipeline events and broadcast to SSE clients
  const broadcast = (event: StreamEvent) => {
    for (const client of clients) {
      sendSSE(client, event);
    }
  };

  bus.subscribe<ScanCompleteEvent>("scan:complete", (event) => {
    broadcast({
      type: "scan:complete",
      data: {
        totalFindings: event.payload.totalFindings,
      },
    });
  });

  bus.subscribe<TriageResultEvent>("triage:result", (event) => {
    const { finding, result, index, total } = event.payload;
    broadcast({
      type: "triage:result",
      data: {
        fingerprint: finding.fingerprint,
        filePath: finding.filePath,
        startLine: finding.startLine,
        ruleId: finding.ruleId,
        severity: finding.severity,
        message: finding.message,
        cwe: finding.cwe,
        verdict: result.verdict,
        confidence: result.confidence,
        rationale: result.rationale,
        costUsd: result.triageCostUsd,
        index,
        total,
      },
    });
  });

  bus.subscribe<VerificationResultEvent>("verification:result", (event) => {
    const { finding, result } = event.payload;
    broadcast({
      type: "verification:result",
      data: {
        fingerprint: finding.fingerprint,
        filePath: finding.filePath,
        exploitable: result.exploitable,
        confidence: result.confidence,
        pocPayload: result.pocPayload,
        attackVector: result.attackVector,
        costUsd: result.verifyCostUsd,
      },
    });
  });

  bus.subscribe<PocHarnessResultEvent>("poc-harness:result", (event) => {
    const { finding, result } = event.payload;
    broadcast({
      type: "poc-harness:result",
      data: {
        fingerprint: finding.fingerprint,
        filePath: finding.filePath,
        scriptPath: result.scriptPath,
        language: result.language,
        parsed: result.parsed,
        skipped: result.skipped,
        pocExecVerdict: result.pocExecVerdict,
      },
    });
  });

  bus.subscribe<PatchCompleteEvent>("patch:complete", (event) => {
    broadcast({
      type: "patch:complete",
      data: {
        fingerprint: event.payload.fingerprint,
        status: event.payload.status,
        iterations: event.payload.iterations,
        costUsd: event.payload.costUsd,
      },
    });
  });

  bus.subscribe<PatchVerifyCompleteEvent>("patch-verify:complete", (event) => {
    broadcast({
      type: "patch-verify:complete",
      data: {
        fingerprint: event.payload.fingerprint,
        verified: event.payload.verified,
        depth: event.payload.depth,
      },
    });
  });

  bus.subscribe<PipelineCompleteEvent>("pipeline:complete", (event) => {
    broadcast({
      type: "pipeline:complete",
      data: event.payload.stats as unknown as Record<string, unknown>,
    });
    // Close all SSE connections after pipeline completes
    for (const client of clients) {
      sendSSE(client, { type: "done", data: { message: "Pipeline complete" } });
      client.end();
    }
    clients.clear();
  });

  bus.subscribe<PipelineErrorEvent>("pipeline:error", (event) => {
    broadcast({
      type: "pipeline:error",
      data: {
        error: event.payload.error,
        fatal: event.payload.fatal,
      },
    });
  });

  // Start listening
  server.listen(port, () => {
    const addr = server.address();
    const actualPort = typeof addr === "object" && addr ? addr.port : port;
    log.info(`Streaming server listening on http://localhost:${actualPort}/events`);
  });

  const actualPort = (): number => {
    const addr = server.address();
    return typeof addr === "object" && addr ? addr.port : port;
  };

  return {
    server,
    get port() {
      return actualPort();
    },
    close: () =>
      new Promise<void>((resolve) => {
        for (const client of clients) {
          client.end();
        }
        clients.clear();
        server.close(() => resolve());
      }),
  };
}

function sendSSE(res: ServerResponse, event: StreamEvent): void {
  try {
    res.write(`event: ${event.type}\ndata: ${JSON.stringify(event.data)}\n\n`);
  } catch {
    // Client disconnected
  }
}
