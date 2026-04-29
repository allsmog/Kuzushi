/**
 * Rotating tips-of-the-day — surfaced on shell startup and by the `tip` command.
 * Keep each tip to one line, mention the feature by name so operators can look
 * it up, and anchor it in something that works today (not vaporware).
 */

export const TIPS: readonly string[] = [
  "`search rank:gte500 type:module` shows only great/excellent modules.",
  "`set TRIAGE_PROMPT ./my.md` overrides the triage agent's system prompt.",
  "`recipes run deep-audit` replays the full SAST + carlini-threat-hunt chain.",
  "`history -n 20` prints your last 20 commands.",
  "`info <module>` shows rank, references, required upstream modules.",
  "`search category:offense -cve:2020` excludes tokens with leading dash.",
  "Put a `~/.kuzushi/startup.rc` to run commands on every shell launch.",
  "`makerc triage.kzrc.yaml` saves your session's history as a replayable recipe.",
  "Bare `semgrep` at the prompt resolves to `semgrep:scan`. Module names work too.",
  "Pipes work: `modules | grep offense`, `findings list | save out.md`.",
  "`alias qs = recipes run quick-scan` gives you one-letter shortcuts.",
  "`pushm` saves the current module, `popm` pops it back — great for detours.",
  "`why` explains why a `run` preflight failed and how to fix it.",
  "`examples <module>` prints canonical usage recipes for that module.",
];

/** Pick one tip via a fresh random index each call. */
export function randomTip(): string {
  return TIPS[Math.floor(Math.random() * TIPS.length)] ?? "";
}

/** Pick N tips without repetition (or all if N > tip count). */
export function pickTips(n: number): string[] {
  const count = Math.min(n, TIPS.length);
  const indices = new Set<number>();
  while (indices.size < count) {
    indices.add(Math.floor(Math.random() * TIPS.length));
  }
  return [...indices].map((i) => TIPS[i] ?? "");
}
