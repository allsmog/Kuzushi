/**
 * Completion notifications — terminal bell + OS notification.
 *
 * After a long scan completes, notify the user even if they switched
 * to another window. Uses terminal bell (\x07) + platform-specific
 * notification commands.
 */
import { execSync } from "node:child_process";

/**
 * Send a completion notification.
 *
 * @param title - Notification title
 * @param message - Notification body
 * @param sound - Play a sound (default: true)
 */
export function sendCompletionNotification(title: string, message: string, sound = true): void {
  // Terminal bell — works in all terminals
  if (sound) {
    process.stdout.write("\x07");
  }

  // OS-level notification
  try {
    const platform = process.platform;

    if (platform === "darwin") {
      // macOS: osascript notification
      const escapedTitle = title.replace(/"/g, '\\"');
      const escapedMsg = message.replace(/"/g, '\\"');
      execSync(`osascript -e 'display notification "${escapedMsg}" with title "${escapedTitle}"'`, {
        stdio: "ignore",
        timeout: 3000,
      });
    } else if (platform === "linux") {
      // Linux: notify-send (freedesktop)
      const escapedTitle = title.replace(/'/g, "'\\''");
      const escapedMsg = message.replace(/'/g, "'\\''");
      execSync(
        `notify-send '${escapedTitle}' '${escapedMsg}' --urgency=normal 2>/dev/null || true`,
        { stdio: "ignore", timeout: 3000 },
      );
    }
    // Windows: no native CLI notification without extra tools
  } catch {
    // Notification is best-effort — don't fail if it doesn't work
  }
}

/**
 * Build a scan completion notification message.
 */
export function buildScanNotification(stats: {
  tp?: number;
  fp?: number;
  needsReview?: number;
  totalCostUsd?: number;
  repoName?: string;
}): { title: string; message: string } {
  const tp = stats.tp ?? 0;
  const repoName = stats.repoName ?? "repo";

  const title =
    tp > 0
      ? `Kuzushi: ${tp} finding${tp > 1 ? "s" : ""} in ${repoName}`
      : `Kuzushi: scan complete — ${repoName}`;

  const parts: string[] = [];
  if (tp > 0) parts.push(`${tp} true positive${tp > 1 ? "s" : ""}`);
  if (stats.needsReview && stats.needsReview > 0) parts.push(`${stats.needsReview} need review`);
  if (stats.totalCostUsd) parts.push(`$${stats.totalCostUsd.toFixed(2)}`);

  const message = parts.length > 0 ? parts.join(" · ") : "No issues found";

  return { title, message };
}
