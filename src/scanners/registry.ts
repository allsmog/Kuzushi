import type { KuzushiConfig, ScanOpts } from "../types.js";
import { isRecord } from "../utils.js";
import type { Finding, ScannerConfig, ScannerId, ScannerPlugin } from "./types.js";

/** Registry and orchestrator for scanner plugins (throws/waza). */
export class ScannerRegistry {
  private readonly plugins = new Map<ScannerId, ScannerPlugin>();

  register(plugin: ScannerPlugin): void {
    this.plugins.set(plugin.id, plugin);
  }

  get(id: ScannerId): ScannerPlugin {
    const plugin = this.plugins.get(id);
    if (!plugin) {
      throw new Error(`Unknown scanner plugin: ${id}`);
    }
    return plugin;
  }

  has(id: ScannerId): boolean {
    return this.plugins.has(id);
  }

  ids(): ScannerId[] {
    return [...this.plugins.keys()];
  }

  resolveEnabled(opts: ScanOpts, config: KuzushiConfig): ScannerId[] {
    // When the user explicitly passes --scanners, use that list as-is.
    // Non-plugin IDs (e.g. "newaza") are silently filtered out — they're
    // agent tasks, not scanner plugins.  An empty result is valid when the
    // user only asked for agent tasks.
    const isExplicitOverride = opts.scanners !== undefined;

    if (isExplicitOverride) {
      // Keep only IDs that are registered scanner plugins.
      // An empty result is valid (e.g. "--scanners newaza" → no scanner plugins).
      const normalized = opts.scanners!
        .map((id) => id.trim())
        .filter(Boolean);
      return [...new Set(normalized.filter((id) => this.has(id)))];
    }

    const selected = config.scanners;

    const normalized = selected
      .map((id) => id.trim())
      .filter(Boolean);

    // Default path (no explicit override): all IDs must be known plugins.
    if (normalized.length === 0) {
      throw new Error("At least one scanner must be configured.");
    }

    const unknown = normalized.filter((id) => !this.has(id));
    if (unknown.length > 0) {
      throw new Error(`Unknown scanner(s): ${unknown.join(", ")}. Registered: ${this.ids().join(", ")}`);
    }

    return [...new Set(normalized)];
  }

  async runAll(repoRoot: string, opts: ScanOpts, config: KuzushiConfig): Promise<Finding[]> {
    const enabled = this.resolveEnabled(opts, config);
    const findings: Finding[] = [];

    for (const id of enabled) {
      const plugin = this.get(id);
      const pluginConfig = resolvePluginConfig(config.scannerConfig, id);

      if (plugin.init) {
        await plugin.init(pluginConfig);
      }

      const result = await plugin.scan(repoRoot, opts, pluginConfig);
      findings.push(...result);
    }

    return dedupeFindings(findings, opts.maxFindings);
  }
}

function resolvePluginConfig(
  allConfig: Record<string, ScannerConfig>,
  scannerId: ScannerId,
): ScannerConfig {
  const cfg = allConfig[scannerId];
  if (!isRecord(cfg)) return {};
  return cfg;
}

function dedupeFindings(findings: Finding[], maxFindings?: number): Finding[] {
  const seen = new Map<string, Finding>();

  for (const finding of findings) {
    const existing = seen.get(finding.fingerprint);
    if (!existing || finding.score > existing.score) {
      seen.set(finding.fingerprint, finding);
    }
  }

  return [...seen.values()]
    .sort((a, b) => b.score - a.score)
    .slice(0, maxFindings);
}
