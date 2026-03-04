import type { KuzushiConfig, ScanOpts } from "../types.js";
import { isRecord } from "../utils.js";
import type { Finding, ScannerConfig, ScannerId, ScannerPlugin } from "./types.js";

const NON_PLUGIN_SCANNER_ALIASES = new Set([
  "taint-analysis",
  "crypto-misuse",
  "auth-access",
  "race-condition",
  "invariant-analysis",
  "threat-model",
]);

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
    // When the user explicitly passes --scanners, validate unknown IDs.
    // Keep non-plugin aliases that intentionally map to AgentTasks (e.g. "taint-analysis").
    const isExplicitOverride = opts.scanners !== undefined;

    if (isExplicitOverride) {
      const normalized = [...new Set(opts.scanners!
        .map((id) => id.trim())
        .filter(Boolean))];

      const unknown = normalized.filter((id) => !this.has(id) && !NON_PLUGIN_SCANNER_ALIASES.has(id));
      if (unknown.length > 0) {
        throw new Error(`Unknown scanner(s): ${unknown.join(", ")}. Registered: ${this.ids().join(", ")}`);
      }

      // An empty result is valid (e.g. "--scanners taint-analysis" -> no scanner plugins).
      return normalized.filter((id) => this.has(id));
    }

    const selected = config.scanners;

    const normalized = selected
      .map((id) => id.trim())
      .filter(Boolean);

    // Default path (no explicit override): IDs must be known plugins or non-plugin aliases.
    if (normalized.length === 0) {
      throw new Error("At least one scanner must be configured.");
    }

    const unknown = normalized.filter((id) => !this.has(id) && !NON_PLUGIN_SCANNER_ALIASES.has(id));
    if (unknown.length > 0) {
      throw new Error(`Unknown scanner(s): ${unknown.join(", ")}. Registered: ${this.ids().join(", ")}`);
    }

    return [...new Set(normalized.filter((id) => this.has(id)))];
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
