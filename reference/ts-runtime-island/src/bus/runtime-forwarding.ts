/**
 * Wrap an `AgentRuntime` so every `runtime.query(...)` stream (and every
 * `runtime.createSession().query(...)` stream) tees through the message bus
 * as `task:activity` events. Intended to be applied once per task/tool
 * boundary — then every downstream helper that reads `context.runtime`
 * and calls `.query(...)` inherits per-message UI activity for free.
 *
 * Installed at:
 *   - `DagRunContext` construction (scan-worker, patch-verify-worker,
 *     taint-analysis-refinement-worker, orchestrator's nested contexts,
 *     cross-service analyze's per-stage contexts)
 *   - `ExecutionContext` construction (copilot/core.ts executeTool)
 *   - Verifier workers that iterate `runtime.query` outside a DagRunContext
 *     (cheap-verify, verify-gate)
 */

import { randomUUID } from "node:crypto";
import type {
  AgentActivityPhase,
  AgentMessage,
  AgentQueryOptions,
  AgentQueryRequest,
  AgentRuntime,
  AgentSession,
} from "../agent-runtime/types.js";
import { describeRuntimeMessage } from "../agents/tasks/threat-modeling/randori-runner.js";
import { publishAgentActivity, publishTaskActivity } from "./activity.js";
import type { ScanAgentActivityEvent } from "./events.js";
import type { RunContext } from "./run-context.js";
import type { MessageBus } from "./types.js";

const WRAPPED_KEY = Symbol.for("kuzushi.runtime.activity-wrapped.key");
const WRAPPED_ROOT = Symbol.for("kuzushi.runtime.activity-wrapped.root");

function cryptoRandomId(): string {
  return randomUUID();
}

function scanRunContext(taskId: string, runId: string): RunContext {
  // Minimal RunContext for `scan:agent-activity` payloads. The
  // consumers (report-worker / audit-worker) only key off `runId`
  // and `taskId`, so this skeleton is sufficient. Filling repoRoot /
  // dbPath would require threading another arg through every wrap
  // call site — not worth the churn for this purely-cosmetic field.
  return { runId, repoName: taskId, repoRoot: "", dbPath: "" };
}

/**
 * Decorate `inner` so every streamed message is forwarded to `bus` as a
 * `task:activity` event keyed by `taskId`/`runId`, while the caller still
 * sees the exact same message stream.
 *
 * Stack-replace semantics:
 *   - Wrapping an already-wrapped runtime for the same `(taskId,runId)`
 *     returns it unchanged.
 *   - Wrapping an already-wrapped runtime with a different key unwraps
 *     back to the original root runtime first, then rewraps with the new
 *     key. This means a nested layer (e.g. scan-worker's task-level wrap
 *     over the shell's tool-level wrap) supersedes the outer layer rather
 *     than stacking, preventing duplicate `task:activity` emissions for
 *     the same message.
 */
export function wrapRuntimeWithActivityForwarding(
  inner: AgentRuntime,
  bus: MessageBus,
  taskId: string,
  runId: string,
  phase?: AgentActivityPhase,
): AgentRuntime {
  // Tag includes the phase so a scan-time wrap supersedes any prior
  // shell-tool wrap on the same root runtime (the hunt path sets its
  // own phase upstream and we never overwrite caller-set values
  // below — see `stampActivityRouting`).
  const tag = `${taskId}|${runId}|${phase ?? ""}`;
  const tags = inner as unknown as Record<symbol, unknown>;
  if (tags[WRAPPED_KEY] === tag) return inner;

  const root = (tags[WRAPPED_ROOT] as AgentRuntime | undefined) ?? inner;

  const teeStream = async function* (
    stream: AsyncIterable<AgentMessage>,
  ): AsyncIterable<AgentMessage> {
    let sawToolUse = false;
    for await (const message of stream) {
      try {
        for (const line of describeRuntimeMessage(message)) {
          publishTaskActivity(bus, taskId, line, { runId });
        }
      } catch {
        // best-effort — never break the caller's stream on a publish failure
      }

      // Per-tool-use → `scan:agent-activity` (taskId-keyed) so the
      // report-worker turns it into nested `⎿ Read · src/foo.ts` lines
      // under the active scan sub-task. Done from the wrap because the
      // inner runtime's own `this.bus` is left unset by the
      // orchestrator — wiring it from here is robust to future runtime
      // backends and doesn't depend on every detector remembering to
      // set `phase`/`fingerprint` in its query options. The event
      // shape is `ScanAgentActivityEvent` (taskId-keyed) — distinct
      // from carlini-threat-hunt's fingerprint-keyed `TaskAgentActivityEvent`.
      const emitScanActivity = (payload: ScanAgentActivityEvent["payload"]): void => {
        const envelope = {
          type: "scan:agent-activity" as const,
          meta: {
            id: cryptoRandomId(),
            timestamp: new Date().toISOString(),
            runId,
          },
          payload,
        };
        void bus.publish(envelope as unknown as Parameters<typeof bus.publish>[0]).catch(() => {
          /* best-effort */
        });
      };

      if (phase === "scan") {
        try {
          if (message.type === "assistant" && Array.isArray(message.content)) {
            for (const block of message.content as Array<Record<string, unknown>>) {
              if (block?.["type"] !== "tool_use") continue;
              const toolName =
                typeof block["name"] === "string" && block["name"].length > 0
                  ? (block["name"] as string)
                  : "tool";
              const toolInput =
                typeof block["input"] === "object" &&
                block["input"] !== null &&
                !Array.isArray(block["input"])
                  ? (block["input"] as Record<string, unknown>)
                  : undefined;
              sawToolUse = true;
              emitScanActivity({
                context: scanRunContext(taskId, runId),
                taskId,
                kind: "tool-start",
                ...(toolName ? { toolName } : {}),
                ...(toolInput ? { toolInput } : {}),
              });
            }
          } else if (message.type === "tool-progress") {
            emitScanActivity({
              context: scanRunContext(taskId, runId),
              taskId,
              kind: "tool-progress",
              ...(message.toolName ? { toolName: message.toolName } : {}),
              ...(typeof message.elapsedSeconds === "number"
                ? { elapsedSeconds: message.elapsedSeconds }
                : {}),
            });
          } else if (message.type === "tool-summary" && typeof message.summary === "string") {
            emitScanActivity({
              context: scanRunContext(taskId, runId),
              taskId,
              kind: "tool-complete",
              summary: message.summary,
            });
          }
        } catch {
          // best-effort — never break the caller's stream on a publish failure
        }
      } else if (phase) {
        // Non-scan phase wraps (carlini-threat-hunt, etc.) keep the
        // fingerprint-keyed `${phase}:agent-activity` shape that the
        // existing handlers consume.
        try {
          if (message.type === "assistant" && Array.isArray(message.content)) {
            for (const block of message.content as Array<Record<string, unknown>>) {
              if (block?.["type"] !== "tool_use") continue;
              const toolName =
                typeof block["name"] === "string" && block["name"].length > 0
                  ? (block["name"] as string)
                  : "tool";
              const toolInput =
                typeof block["input"] === "object" &&
                block["input"] !== null &&
                !Array.isArray(block["input"])
                  ? (block["input"] as Record<string, unknown>)
                  : undefined;
              sawToolUse = true;
              publishAgentActivity(bus, phase, taskId, "tool-start", {
                ...(toolName ? { toolName } : {}),
                ...(toolInput ? { toolInput } : {}),
              });
            }
          } else if (message.type === "result" && sawToolUse) {
            publishAgentActivity(bus, phase, taskId, "tool-complete", { done: true });
          }
        } catch {
          // best-effort
        }
      }

      yield message;
    }
  };

  // Stamp `phase` + `fingerprint` onto the runtime options so the inner
  // Claude runtime's tool-use → bus pipeline (`emitToolUseActivity` in
  // src/agent-runtime/claude.ts) fires `${phase}:agent-activity` events
  // and the report-worker turns them into per-sub-task `activityLines`
  // under the active scan task. Caller-set values win — carlini-threat-hunt
  // and other modules that already route their own phase keep doing so.
  const stampOptions = (options: AgentQueryOptions): AgentQueryOptions => {
    if (!phase) return options;
    if (options.phase && options.fingerprint) return options;
    return {
      ...options,
      phase: options.phase ?? phase,
      fingerprint: options.fingerprint ?? taskId,
    };
  };

  const wrapped: AgentRuntime = {
    get id() {
      return root.id;
    },
    query(request: AgentQueryRequest) {
      const stamped: AgentQueryRequest = {
        ...request,
        options: stampOptions(request.options),
      };
      return teeStream(root.query(stamped));
    },
    ...(root.createSession
      ? {
          createSession(baseOptions: AgentQueryOptions): AgentSession {
            const session = root.createSession!(stampOptions(baseOptions));
            return {
              query: (prompt: string) => teeStream(session.query(prompt)),
              close: () => session.close(),
            };
          },
        }
      : {}),
    ...(root.queryBatch ? { queryBatch: root.queryBatch.bind(root) } : {}),
  };
  Object.defineProperty(wrapped, WRAPPED_KEY, { value: tag, enumerable: false });
  Object.defineProperty(wrapped, WRAPPED_ROOT, { value: root, enumerable: false });
  return wrapped;
}
