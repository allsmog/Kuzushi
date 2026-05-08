/**
 * Slack webhook POST — gated by a URL + bool setg pair. Tests stub
 * fetch so no real network is hit.
 */

import { describe, expect, it, vi } from "vitest";
import { postSlack } from "../../src/ui/slack.js";

describe("postSlack", () => {
  it("POSTs a JSON body with `text` to the webhook URL", async () => {
    const fetchImpl = vi.fn(async () => ({
      ok: true,
      status: 200,
      text: async () => "ok",
    })) as unknown as typeof fetch;
    const result = await postSlack({
      webhookUrl: "https://hooks.slack.com/services/T/B/X",
      text: "hello world",
      fetchImpl,
    });
    expect(result.posted).toBe(true);
    const [url, init] = (fetchImpl as unknown as ReturnType<typeof vi.fn>).mock.calls[0];
    expect(url).toBe("https://hooks.slack.com/services/T/B/X");
    const body = JSON.parse((init as { body: string }).body);
    expect(body.text).toBe("hello world");
    const headers = (init as { headers: Record<string, string> }).headers;
    expect(headers["Content-Type"]).toBe("application/json");
  });

  it("returns a warning on non-2xx", async () => {
    const fetchImpl = vi.fn(async () => ({
      ok: false,
      status: 403,
      text: async () => "forbidden",
    })) as unknown as typeof fetch;
    const result = await postSlack({
      webhookUrl: "https://hooks.slack.com/services/X",
      text: "x",
      fetchImpl,
    });
    expect(result.posted).toBe(false);
    expect(result.warning).toContain("403");
  });

  it("swallows fetch exceptions into warning", async () => {
    const fetchImpl = vi.fn(async () => {
      throw new Error("network down");
    }) as unknown as typeof fetch;
    const result = await postSlack({
      webhookUrl: "https://hooks.slack.com/services/X",
      text: "x",
      fetchImpl,
    });
    expect(result.posted).toBe(false);
    expect(result.warning).toContain("network down");
  });
});
