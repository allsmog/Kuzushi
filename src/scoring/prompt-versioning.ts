import { createHash } from "node:crypto";

export function computePromptHash(templates: { triage: string; verify: string }): string {
  return createHash("sha256")
    .update(`${templates.triage}\n---\n${templates.verify}`)
    .digest("hex")
    .slice(0, 16);
}
