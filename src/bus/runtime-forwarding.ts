/**
 * Wrap an `AgentRuntime` so every `runtime.query(...)` stream (and every
 * `runtime.createSession().query(...)` stream) tees through the message bus
 * as `task:activity` events. Intended to be applied once per task/tool
 * boundary — then every downstream helper that reads `context.runtime`
 * and calls `.query(...)` inherits per-message UI activity for free.
 *
 * Installed at:
 *   - `TaskContext` construction (scan-worker, patch-verify-worker,
 *     taint-analysis-refinement-worker, orchestrator's nested contexts,
 *     cross-service analyze's per-stage contexts)
 *   - `ExecutionContext` construction (copilot/core.ts executeTool)
 *   - Verifier workers that iterate `runtime.query` outside a TaskContext
 *     (cheap-verify, verify-gate)
 */

import type {
  AgentMessage,
  AgentQueryOptions,
  AgentQueryRequest,
  AgentRuntime,
  AgentSession,
} from "../agent-runtime/types.js";
import { describeRuntimeMessage } from "../agents/tasks/threat-modeling/randori-runner.js";
import { publishTaskActivity } from "./activity.js";
import type { MessageBus } from "./types.js";

const WRAPPED_KEY = Symbol.for("kuzushi.runtime.activity-wrapped.key");
const WRAPPED_ROOT = Symbol.for("kuzushi.runtime.activity-wrapped.root");

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
): AgentRuntime {
  const tag = `${taskId}|${runId}`;
  const tags = inner as unknown as Record<symbol, unknown>;
  if (tags[WRAPPED_KEY] === tag) return inner;

  const root = (tags[WRAPPED_ROOT] as AgentRuntime | undefined) ?? inner;

  const teeStream = async function* (
    stream: AsyncIterable<AgentMessage>,
  ): AsyncIterable<AgentMessage> {
    for await (const message of stream) {
      try {
        for (const line of describeRuntimeMessage(message)) {
          publishTaskActivity(bus, taskId, line, { runId });
        }
      } catch {
        // best-effort — never break the caller's stream on a publish failure
      }
      yield message;
    }
  };

  const wrapped: AgentRuntime = {
    get id() {
      return root.id;
    },
    query(request: AgentQueryRequest) {
      return teeStream(root.query(request));
    },
    ...(root.createSession
      ? {
          createSession(baseOptions: AgentQueryOptions): AgentSession {
            const session = root.createSession!(baseOptions);
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
