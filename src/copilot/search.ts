/**
 * Keyword-based search over modules + tools.
 *
 * Mirrors `search` in lib/msf/ui/console/command_dispatcher/modules.rb. Supports:
 *
 *   search ssrf                       # free-text across name/description
 *   search type:tool category:offense # key-based filter
 *   search rank:gte400                # numeric op: gte/gt/lte/lt/eq
 *   search -cve:2020                  # leading dash = exclude
 *   search ssrf -S '/v1/'             # post-filter with regex (separate token)
 *
 * Recognized keys: name, type (module|tool), category, rank, cve, cwe,
 * platform, ref, refid, headless, author, mod, tool.
 */

import type { CopilotModule, ModuleRank, ModuleTool } from "../modules/types.js";
import { RANK_VALUE } from "../modules/types.js";

export interface SearchHit {
  /** "module" or "tool". */
  kind: "module" | "tool";
  /** "module" returns moduleId; "tool" returns "module:action". */
  ref: string;
  module: CopilotModule;
  tool?: ModuleTool;
  rank: ModuleRank;
  description: string;
}

export interface ParsedQuery {
  freeText: string[];
  filters: Filter[];
  /** Optional post-filter regex from `-S /pattern/`. */
  postRegex?: RegExp;
}

export interface Filter {
  key: string;
  /** Compiled comparator returning true if the hit matches. */
  predicate: (hit: SearchHit) => boolean;
  /** Original raw token, useful for diagnostics. */
  raw: string;
}

const NUMERIC_OP_RE = /^(gte|gt|lte|lt|eq)(\d+)$/;

function rankOf(hit: SearchHit): number {
  return RANK_VALUE[hit.rank];
}

function buildPredicate(rawKey: string, value: string, negate: boolean): Filter["predicate"] {
  const key = rawKey.toLowerCase();
  const lc = value.toLowerCase();

  const test = (hit: SearchHit): boolean => {
    switch (key) {
      case "name":
        return (hit.tool?.name ?? hit.module.id).toLowerCase().includes(lc);
      case "type":
        return hit.kind === lc;
      case "category":
        return hit.module.category.toLowerCase() === lc;
      case "headless":
        return hit.kind === "tool" && String(hit.tool?.headless ?? false) === lc;
      case "mod":
      case "module":
        return hit.module.id.toLowerCase() === lc;
      case "tool":
        return hit.tool?.name.toLowerCase() === lc;
      case "author": {
        return (hit.module.authors ?? []).some((a) => a.toLowerCase().includes(lc));
      }
      case "rank": {
        const m = NUMERIC_OP_RE.exec(lc);
        if (m) {
          const op = m[1] as "gte" | "gt" | "lte" | "lt" | "eq";
          const n = Number.parseInt(m[2] ?? "0", 10);
          const r = rankOf(hit);
          return op === "gte"
            ? r >= n
            : op === "gt"
              ? r > n
              : op === "lte"
                ? r <= n
                : op === "lt"
                  ? r < n
                  : r === n;
        }
        return hit.rank === lc;
      }
      case "platform":
        return (
          hit.module.id.toLowerCase().includes(lc) || hit.description.toLowerCase().includes(lc)
        );
      case "cve":
      case "cwe":
      case "ref":
      case "refid": {
        const refType = key === "ref" || key === "refid" ? null : key.toUpperCase();
        const refs = [...(hit.module.references ?? []), ...(hit.tool?.references ?? [])];
        return refs.some((r) => {
          if (refType && r.type !== refType) return false;
          return r.value.toLowerCase().includes(lc);
        });
      }
      default:
        return false;
    }
  };

  return negate ? (h) => !test(h) : test;
}

export function parseQuery(raw: string): ParsedQuery {
  const tokens = raw.match(/(?:[^\s"]+|"[^"]*")+/g) ?? [];
  const freeText: string[] = [];
  const filters: Filter[] = [];
  let postRegex: RegExp | undefined;

  for (let i = 0; i < tokens.length; i++) {
    const tok = tokens[i] ?? "";
    if (tok === "-S" && i + 1 < tokens.length) {
      const next = tokens[++i] ?? "";
      const m = /^\/(.*)\/(\w*)$/.exec(next);
      try {
        postRegex = m ? new RegExp(m[1] ?? "", m[2] ?? "i") : new RegExp(next, "i");
      } catch {
        postRegex = undefined;
      }
      continue;
    }

    const negate = tok.startsWith("-") && tok.includes(":");
    const trimmed = negate ? tok.slice(1) : tok;
    const colon = trimmed.indexOf(":");
    if (colon > 0) {
      const key = trimmed.slice(0, colon);
      const value = trimmed.slice(colon + 1).replace(/^"|"$/g, "");
      filters.push({ key, raw: tok, predicate: buildPredicate(key, value, negate) });
    } else {
      freeText.push(trimmed.replace(/^"|"$/g, "").toLowerCase());
    }
  }

  const result: ParsedQuery = { freeText, filters };
  if (postRegex) result.postRegex = postRegex;
  return result;
}

function modulesAndToolsToHits(modules: ReadonlyArray<CopilotModule>): SearchHit[] {
  const hits: SearchHit[] = [];
  for (const mod of modules) {
    const modRank = mod.rank ?? "normal";
    hits.push({
      kind: "module",
      ref: mod.id,
      module: mod,
      rank: modRank,
      description: mod.description,
    });
    for (const tool of mod.tools) {
      hits.push({
        kind: "tool",
        ref: tool.name,
        module: mod,
        tool,
        rank: tool.rank ?? modRank,
        description: tool.description,
      });
    }
  }
  return hits;
}

export interface SearchResult {
  hits: SearchHit[];
  query: ParsedQuery;
}

export function searchCatalog(modules: ReadonlyArray<CopilotModule>, raw: string): SearchResult {
  const query = parseQuery(raw);
  const all = modulesAndToolsToHits(modules);

  const filtered = all.filter((hit) => {
    for (const filt of query.filters) if (!filt.predicate(hit)) return false;
    if (query.freeText.length > 0) {
      const haystack = `${hit.ref} ${hit.description}`.toLowerCase();
      for (const token of query.freeText) if (!haystack.includes(token)) return false;
    }
    if (query.postRegex && !query.postRegex.test(`${hit.ref} ${hit.description}`)) return false;
    return true;
  });

  filtered.sort((a, b) => {
    const r = rankOf(b) - rankOf(a);
    if (r !== 0) return r;
    return a.ref.localeCompare(b.ref);
  });

  return { hits: filtered, query };
}

/** Render a search result as a `show`-style table. */
export function formatSearchResult(result: SearchResult): string {
  if (result.hits.length === 0) return "  No results.";

  const rows = result.hits.map((h, i) => ({
    idx: String(i),
    rank: h.rank,
    type: h.kind,
    ref: h.ref,
    description: h.description.length > 60 ? `${h.description.slice(0, 57)}...` : h.description,
  }));

  const pad = (s: string, w: number) => s + " ".repeat(Math.max(0, w - s.length));
  const w = {
    idx: Math.max(1, ...rows.map((r) => r.idx.length)),
    rank: Math.max(4, ...rows.map((r) => r.rank.length)),
    type: Math.max(4, ...rows.map((r) => r.type.length)),
    ref: Math.max(3, ...rows.map((r) => r.ref.length)),
  };

  const header = `  ${pad("#", w.idx)}  ${pad("Rank", w.rank)}  ${pad("Type", w.type)}  ${pad("Ref", w.ref)}  Description`;
  const sep = `  ${"-".repeat(w.idx)}  ${"-".repeat(w.rank)}  ${"-".repeat(w.type)}  ${"-".repeat(w.ref)}  -----------`;
  const body = rows
    .map(
      (r) =>
        `  ${pad(r.idx, w.idx)}  ${pad(r.rank, w.rank)}  ${pad(r.type, w.type)}  ${pad(r.ref, w.ref)}  ${r.description}`,
    )
    .join("\n");

  return [header, sep, body].join("\n");
}
