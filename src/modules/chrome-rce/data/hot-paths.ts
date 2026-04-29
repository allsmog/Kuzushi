/**
 * Hot-path table — Chromium / V8 / Dawn paths that have been the source
 * of multiple in-the-wild RCEs. Used by the chrome-rce:review-trigger
 * DagTool to surface advisory findings when a PR diff touches these paths.
 *
 * Each entry cites its anchor CVE(s). Entries are deliberately conservative:
 * we only list paths with at least one VERIFIED ITW (or KEV-listed) CVE
 * attribution from research. Speculative paths belong elsewhere.
 *
 * The matcher is substring-based (file.includes(pathSubstring)) for path
 * scoping, with optional `pathEndsWith` for exact filename hits. We avoid
 * a glob library to keep this rule dependency-free.
 */

export interface HotPathEntry {
  /** Stable id used as the rule id for findings emitted on this path. */
  ruleId: string;
  /**
   * Substring matched against the changed file path. Use a directory-style
   * substring (e.g. "v8/src/maglev/") for family-scoped entries, or omit and
   * rely on `pathEndsWith` for exact-filename entries.
   */
  pathSubstring?: string;
  /** Optional explicit endsWith match (e.g. exact filename). */
  pathEndsWith?: string;
  /**
   * Severity for findings emitted on this path. Always advisory — the rule
   * is a focusing aid, not a confirmed-bug detection. Severity reflects the
   * historical impact of bugs found in this path.
   */
  severity: "high" | "medium";
  /** Human-readable message that goes into the Finding.message field. */
  message: string;
  /** Anchor CVEs that motivated this hot-path entry. */
  anchorCves: string[];
}

export const HOT_PATHS: ReadonlyArray<HotPathEntry> = [
  // V8 — the Maglev family. CVE-2026-3910 was attributed specifically to
  // maglev-phi-representation-selector.cc; the broader Maglev IR has had
  // multiple typer/range bugs over 2024-2026.
  {
    ruleId: "chrome-rce-hot-path-v8-maglev-phi-representation-selector",
    pathEndsWith: "v8/src/maglev/maglev-phi-representation-selector.cc",
    severity: "high",
    message:
      "v8/src/maglev/maglev-phi-representation-selector.cc was the anchor for CVE-2026-3910 " +
      "(Maglev Phi-Untagging mixed-representation type confusion, ITW, KEV-listed). " +
      "Manual review by a V8 compiler engineer is recommended for any change to this file.",
    anchorCves: ["CVE-2026-3910"],
  },
  {
    ruleId: "chrome-rce-hot-path-v8-maglev",
    pathSubstring: "v8/src/maglev/",
    severity: "medium",
    message:
      "v8/src/maglev/** has been the source of multiple ITW Chrome RCEs (CVE-2026-3910 type " +
      "confusion in the Phi-untagging pass, plus several non-ITW Maglev IR bugs in 2024-2025). " +
      "Maglev IR transformations need careful representation-tracking review.",
    anchorCves: ["CVE-2026-3910"],
  },
  // V8 — the ARM64 backend. CVE-2024-7965 was a 32-bit-vs-64-bit register
  // codegen bug in TurboFan's ARM64 instruction selector.
  {
    ruleId: "chrome-rce-hot-path-v8-arm64-codegen",
    pathSubstring: "v8/src/compiler/backend/arm64/",
    severity: "medium",
    message:
      "v8/src/compiler/backend/arm64/** was the anchor for CVE-2024-7965 (TurboFan ARM64 " +
      "32-bit W-register write where IR expected 64-bit X-register; ARM64 leaves the high " +
      "half undefined unlike x64). Any change to ARM64 codegen needs cross-arch verification.",
    anchorCves: ["CVE-2024-7965"],
  },
  // V8 — typer family. CVE-2025-6554 was a type-confusion bug mitigated
  // first via Stable-channel config push, then patched in a typer pass.
  {
    ruleId: "chrome-rce-hot-path-v8-typer",
    pathEndsWith: "v8/src/compiler/typer.cc",
    severity: "medium",
    message:
      "v8/src/compiler/typer.cc has been the source of multiple ITW V8 type-confusion bugs " +
      "(CVE-2025-6554 family). Type narrowing without re-checking maps before object access " +
      "is the recurring shape — ensure CheckMaps follows speculative type narrowing.",
    anchorCves: ["CVE-2025-6554"],
  },
  {
    ruleId: "chrome-rce-hot-path-v8-redundancy-elimination",
    pathEndsWith: "v8/src/compiler/redundancy-elimination.cc",
    severity: "medium",
    message:
      "v8/src/compiler/redundancy-elimination.cc has been historically associated with " +
      "missing-CheckMaps bugs in the V8 typer family. Eliminating redundant checks before " +
      "an object access is the bug pattern.",
    anchorCves: ["CVE-2025-6554"],
  },
  // Dawn / WebGPU — wire/server. Three Dawn CVEs landed in Mar-Apr 2026
  // (CVE-2026-4675, CVE-2026-4676, CVE-2026-5281), with CVE-2026-5281
  // confirmed ITW and KEV-listed. The recurring shape is wire-server
  // dispatch reusing an objects_.Get(id) pointer across re-entrant calls.
  {
    ruleId: "chrome-rce-hot-path-dawn-wire-server",
    pathSubstring: "third_party/dawn/src/dawn/wire/server/",
    severity: "high",
    message:
      "third_party/dawn/src/dawn/wire/server/** was the source of CVE-2026-4675, CVE-2026-4676, " +
      "and CVE-2026-5281 (Dawn UAFs, with -5281 confirmed ITW and KEV-listed). The recurring " +
      "shape is dispatcher methods that call objects_.Get(id), make a re-entrant procs.* call, " +
      "then dereference the original pointer. Re-fetch after re-entrant calls or hold a Ref<T> " +
      "for the dispatcher's scope.",
    anchorCves: ["CVE-2026-4675", "CVE-2026-4676", "CVE-2026-5281"],
  },
  {
    ruleId: "chrome-rce-hot-path-dawn-wire-server-templates",
    pathSubstring: "third_party/dawn/generator/templates/dawn/wire/server/",
    severity: "high",
    message:
      "third_party/dawn/generator/templates/dawn/wire/server/** generates the dispatcher " +
      "code anchored by CVE-2026-5281. Template changes propagate to every Dawn object " +
      "dispatcher — review for the objects_.Get + re-entrant call + use-after pattern.",
    anchorCves: ["CVE-2026-5281"],
  },
];
