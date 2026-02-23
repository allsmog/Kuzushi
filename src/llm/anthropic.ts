import Anthropic from "@anthropic-ai/sdk";
import type { LLMClient } from "../types.js";

/** Anthropic-backed LLM client using the Messages API. */
export function createAnthropicClient(
  model: string = "claude-sonnet-4-20250514",
  maxTokens: number = 1024,
): LLMClient {
  const client = new Anthropic();

  return {
    async complete(system: string, user: string): Promise<string> {
      const response = await client.messages.create({
        model,
        max_tokens: maxTokens,
        system,
        messages: [{ role: "user", content: user }],
      });

      const textBlock = response.content.find((b) => b.type === "text");
      if (!textBlock || textBlock.type !== "text") {
        throw new Error("No text response from LLM");
      }

      return textBlock.text;
    },
  };
}
