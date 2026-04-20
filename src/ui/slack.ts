/**
 * Slack webhook notifier — posts a short message when opted in.
 *
 * Configuration:
 *   setg SLACK_WEBHOOK_URL https://hooks.slack.com/services/...
 *   setg SLACK_NOTIFY true
 *
 * Unset SLACK_WEBHOOK_URL and posting is skipped silently (so the
 * downstream code doesn't have to gate on env vars).
 */

export interface SlackPostOptions {
  webhookUrl: string;
  text: string;
  /** Override fetch for tests. */
  fetchImpl?: typeof fetch;
}

export interface SlackPostResult {
  posted: boolean;
  warning?: string;
}

/**
 * POST to a Slack incoming-webhook URL. Returns { posted } — `false` means
 * the webhook rejected the payload (not an exception). Errors are swallowed
 * and surfaced via warning so the JobManager can't fail on a transient
 * Slack outage.
 */
export async function postSlack(opts: SlackPostOptions): Promise<SlackPostResult> {
  const fx = opts.fetchImpl ?? fetch;
  try {
    const res = await fx(opts.webhookUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ text: opts.text }),
    });
    if (!res.ok) {
      const text = await res.text().catch(() => "");
      return { posted: false, warning: `Slack ${res.status}: ${text.slice(0, 120)}` };
    }
    return { posted: true };
  } catch (err) {
    return { posted: false, warning: err instanceof Error ? err.message : String(err) };
  }
}
