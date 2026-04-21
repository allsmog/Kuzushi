/**
 * In-place compaction of pi-ai `context.messages` to keep input token
 * usage below the model's context window across many-turn agent runs.
 *
 * Problem: every `ToolResultMessage` appends the full tool output
 * (e.g. a 200-line file read = ~8k tokens) to context.messages. After
 * 15–30 turns of Read/Grep exploration on a real repo the cumulative
 * input tokens exceed Opus 4.6's 1M cap and the provider rejects the
 * next request with a cryptic 400 `prompt is too long`.
 *
 * Strategy: when the LAST turn's `assistant.usage.input` crosses a
 * fraction of `model.contextWindow`, walk `context.messages` from
 * oldest to newest (keeping the MOST RECENT tool results intact so the
 * agent has working context), and replace each stale tool_result's
 * text content with a compact stub:
 *
 *   `[<toolName> result elided for context budget — freed ~N tokens, turn M]`
 *
 * This preserves the conversation shape (ordering, tool_call_id
 * correlation) while cutting the token weight of old tool outputs by
 * 90%+. The model still sees that the tool ran; it just doesn't get to
 * re-read the whole file on every subsequent turn.
 *
 * Intentional non-goals:
 * - Summarizing elided content with an LLM call (too expensive for a
 *   hot path that runs every turn).
 * - Dropping user/assistant text messages (small; dropping breaks the
 *   reasoning chain).
 * - Handling image content (no known case in kuzushi; skip the image
 *   parts and only compact text).
 */
import type { Context as PiAiContext, ToolResultMessage } from "@mariozechner/pi-ai";

export interface CompactOptions {
  /** Model's maximum input-context window in tokens (from `Model.contextWindow`). */
  contextWindow: number;
  /** Input tokens consumed by the most recent LLM call. */
  lastInputTokens: number;
  /**
   * Fraction of `contextWindow` at or above which compaction kicks in.
   * Defaults to 0.75.
   */
  threshold?: number;
  /**
   * Fraction of `contextWindow` we aim to compact down to. Compaction
   * stops as soon as estimated tokens drop below this. Defaults to 0.55.
   */
  target?: number;
  /**
   * Number of most-recent tool-result messages to leave intact. Older
   * ones are eligible for compaction. Defaults to 5.
   */
  keepLastN?: number;
  /**
   * Minimum content size (characters) below which we don't bother
   * compacting an entry — avoids replacing a 50-byte result with a
   * 100-byte stub. Defaults to 200.
   */
  minContentChars?: number;
  /** Current turn number — rendered into the stub for operator visibility. */
  turn?: number;
}

export interface CompactResult {
  /** Whether any compaction was performed. */
  compacted: boolean;
  /** Number of tool-result messages compacted. */
  compactedCount: number;
  /** Estimated input tokens freed (rough: 1 token per 4 chars). */
  estimatedFreedTokens: number;
}

/**
 * Rough char → token estimate. English text averages ~4 chars per
 * token for both GPT-4 and Claude tokenizers. Not exact; used only as
 * a budget signal for "stop compacting when we're under the target."
 */
function estimateTokens(chars: number): number {
  return Math.floor(chars / 4);
}

function isToolResult(msg: unknown): msg is ToolResultMessage {
  return (
    typeof msg === "object" && msg !== null && (msg as { role?: unknown }).role === "toolResult"
  );
}

export function maybeCompactContext(context: PiAiContext, options: CompactOptions): CompactResult {
  const {
    contextWindow,
    lastInputTokens,
    threshold = 0.75,
    target = 0.55,
    keepLastN = 5,
    minContentChars = 200,
    turn,
  } = options;

  // Fast-path: well under threshold, nothing to do.
  if (lastInputTokens < contextWindow * threshold) {
    return { compacted: false, compactedCount: 0, estimatedFreedTokens: 0 };
  }

  const messages = context.messages;
  const toolResultIndices: number[] = [];
  for (let i = 0; i < messages.length; i++) {
    if (isToolResult(messages[i])) toolResultIndices.push(i);
  }

  // Keep the most-recent N intact so the agent has working context.
  const compactable = toolResultIndices.slice(0, Math.max(0, toolResultIndices.length - keepLastN));
  if (compactable.length === 0) {
    return { compacted: false, compactedCount: 0, estimatedFreedTokens: 0 };
  }

  const targetTokens = contextWindow * target;
  let estimatedTokens = lastInputTokens;
  let compactedCount = 0;
  let estimatedFreedTokens = 0;

  for (const idx of compactable) {
    if (estimatedTokens <= targetTokens) break;
    const msg = messages[idx] as ToolResultMessage;

    // Sum text content length; skip images.
    let currentChars = 0;
    for (const block of msg.content) {
      if (
        typeof block === "object" &&
        block !== null &&
        (block as { type?: unknown }).type === "text" &&
        typeof (block as { text?: unknown }).text === "string"
      ) {
        currentChars += ((block as { text: string }).text as string).length;
      }
    }
    if (currentChars < minContentChars) continue;

    const freedTokens = estimateTokens(currentChars);
    const stub = `[${msg.toolName} result elided for context budget — freed ~${freedTokens} tokens${
      typeof turn === "number" ? `, turn ${turn}` : ""
    }]`;

    // Replace text content with the stub. Preserve any image blocks
    // (rare in kuzushi but safe to keep if present).
    const imageBlocks = msg.content.filter(
      (block) =>
        typeof block === "object" &&
        block !== null &&
        (block as { type?: unknown }).type === "image",
    );
    msg.content = [{ type: "text", text: stub }, ...imageBlocks];

    estimatedTokens -= freedTokens;
    estimatedFreedTokens += freedTokens;
    compactedCount += 1;
  }

  return {
    compacted: compactedCount > 0,
    compactedCount,
    estimatedFreedTokens,
  };
}
