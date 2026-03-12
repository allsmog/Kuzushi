import type {
  KnowledgeModule,
  KnowledgeQuery,
  KnowledgeRegistry,
} from "./types.js";

/**
 * In-memory knowledge registry with CWE/tag/language indexes for fast lookup.
 */
export class InMemoryKnowledgeRegistry implements KnowledgeRegistry {
  private readonly modules = new Map<string, KnowledgeModule>();
  private readonly byCwe = new Map<string, Set<string>>();
  private readonly byTag = new Map<string, Set<string>>();
  private readonly byLanguage = new Map<string, Set<string>>();
  private readonly byFramework = new Map<string, Set<string>>();

  register(module: KnowledgeModule): void {
    this.modules.set(module.id, module);

    for (const cwe of module.cwes) {
      const normalized = cwe.replace(/^CWE-/i, "").trim();
      this.addToIndex(this.byCwe, normalized, module.id);
      this.addToIndex(this.byCwe, cwe.toUpperCase(), module.id);
    }

    for (const tag of module.tags) {
      this.addToIndex(this.byTag, tag.toLowerCase(), module.id);
    }

    if (module.languages) {
      for (const lang of module.languages) {
        this.addToIndex(this.byLanguage, lang.toLowerCase(), module.id);
      }
    }

    if (module.frameworks) {
      for (const fw of module.frameworks) {
        this.addToIndex(this.byFramework, fw.toLowerCase(), module.id);
      }
    }
  }

  query(q: KnowledgeQuery): KnowledgeModule[] {
    const candidates = new Set<string>();
    let hasFilter = false;

    if (q.cwes && q.cwes.length > 0) {
      hasFilter = true;
      for (const cwe of q.cwes) {
        const normalized = cwe.replace(/^CWE-/i, "").trim();
        const ids = this.byCwe.get(normalized) ?? this.byCwe.get(cwe.toUpperCase());
        if (ids) {
          for (const id of ids) candidates.add(id);
        }
      }
    }

    if (q.vulnType) {
      hasFilter = true;
      const normalized = q.vulnType.toLowerCase();
      // Check by ID, tag, or partial match
      for (const [id, mod] of this.modules) {
        if (
          id.toLowerCase().includes(normalized) ||
          mod.tags.some((t) => t.toLowerCase().includes(normalized))
        ) {
          candidates.add(id);
        }
      }
    }

    if (q.tags && q.tags.length > 0) {
      hasFilter = true;
      for (const tag of q.tags) {
        const ids = this.byTag.get(tag.toLowerCase());
        if (ids) {
          for (const id of ids) candidates.add(id);
        }
      }
    }

    if (!hasFilter) {
      return [...this.modules.values()];
    }

    // Post-filter by language/framework if specified
    const results: KnowledgeModule[] = [];
    for (const id of candidates) {
      const mod = this.modules.get(id);
      if (!mod) continue;

      if (q.language && mod.languages && mod.languages.length > 0) {
        if (!mod.languages.some((l) => l.toLowerCase() === q.language!.toLowerCase())) {
          continue;
        }
      }

      if (q.framework && mod.frameworks && mod.frameworks.length > 0) {
        if (!mod.frameworks.some((f) => f.toLowerCase() === q.framework!.toLowerCase())) {
          continue;
        }
      }

      results.push(mod);
    }

    return results;
  }

  getById(id: string): KnowledgeModule | undefined {
    return this.modules.get(id);
  }

  formatForPrompt(
    modules: KnowledgeModule[],
    section?: string,
  ): string[] {
    if (modules.length === 0) return [];

    const lines: string[] = [];

    for (const mod of modules) {
      if (section === "dangerous" || !section) {
        if (mod.dangerousPatterns.length > 0) {
          lines.push(`### Dangerous Patterns (${mod.id})`);
          for (const p of mod.dangerousPatterns) {
            lines.push(`- ${p.pattern}: ${p.why} [${p.severity}]`);
          }
        }
      }

      if (section === "safe" || !section) {
        if (mod.safePatterns.length > 0) {
          lines.push(`### Safe Patterns (${mod.id})`);
          for (const p of mod.safePatterns) {
            lines.push(`- ${p.pattern}: ${p.why}`);
          }
        }
      }

      if (section === "bypass" || !section) {
        if (mod.bypassTechniques.length > 0) {
          lines.push(`### Bypass Techniques (${mod.id})`);
          for (const t of mod.bypassTechniques) {
            lines.push(`- ${t}`);
          }
        }
      }

      if (section === "fix" || !section) {
        if (mod.fixExamples.length > 0) {
          lines.push(`### Fix Examples (${mod.id})`);
          for (const f of mod.fixExamples) {
            lines.push(`${f.language}: ${f.explanation}`);
          }
        }
      }
    }

    return lines;
  }

  ids(): string[] {
    return [...this.modules.keys()];
  }

  private addToIndex(index: Map<string, Set<string>>, key: string, id: string): void {
    let set = index.get(key);
    if (!set) {
      set = new Set();
      index.set(key, set);
    }
    set.add(id);
  }
}
