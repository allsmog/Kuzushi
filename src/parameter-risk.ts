/** Risk profile for a parameter name. */
export interface ParameterRisk {
  name: string;
  categories: string[];
  boost: number;
}

const SQLI_PRONE: string[] = [
  "id",
  "uid",
  "rid",
  "cid",
  "pid",
  "aid",
  "sort_id",
  "type",
  "typeId",
  "action",
  "act",
  "mod",
  "username",
  "s",
  "keyword",
  "search",
  "page",
  "order",
  "cat_id",
  "category_id",
  "product_id",
  "item_id",
  "user_id",
  "group_id",
  "dept_id",
  "org_id",
];

const SSRF_PRONE: string[] = [
  "url",
  "target",
  "imageUrl",
  "callback",
  "s_url",
  "link",
  "src",
  "ref",
  "inputFile",
  "image_url",
  "redirect_url",
  "return_url",
  "next",
  "dest",
  "destination",
  "uri",
  "endpoint",
];

const PATH_TRAVERSAL_PRONE: string[] = [
  "file",
  "path",
  "filename",
  "filepath",
  "dir",
  "template",
  "include",
  "download",
  "hdfile",
  "document",
  "folder",
  "root",
  "pg",
  "style",
  "pdf",
  "img",
  "attachment",
];

const AUTH_SENSITIVE: string[] = [
  "password",
  "token",
  "session",
  "role",
  "admin",
  "user_id",
  "account",
  "secret",
  "key",
  "auth",
  "credential",
  "api_key",
  "access_token",
];

interface ParameterEntry {
  categories: string[];
  boost: number;
}

const PARAMETER_MAP = new Map<string, ParameterEntry>();

for (const name of SQLI_PRONE) {
  const existing = PARAMETER_MAP.get(name.toLowerCase());
  PARAMETER_MAP.set(name.toLowerCase(), {
    categories: [...(existing?.categories ?? []), "SQLi-prone"],
    boost: Math.max(existing?.boost ?? 0, 0.15),
  });
}

for (const name of SSRF_PRONE) {
  const existing = PARAMETER_MAP.get(name.toLowerCase());
  PARAMETER_MAP.set(name.toLowerCase(), {
    categories: [...(existing?.categories ?? []), "SSRF-prone"],
    boost: Math.max(existing?.boost ?? 0, 0.15),
  });
}

for (const name of PATH_TRAVERSAL_PRONE) {
  const existing = PARAMETER_MAP.get(name.toLowerCase());
  PARAMETER_MAP.set(name.toLowerCase(), {
    categories: [...(existing?.categories ?? []), "Path traversal-prone"],
    boost: Math.max(existing?.boost ?? 0, 0.15),
  });
}

for (const name of AUTH_SENSITIVE) {
  const existing = PARAMETER_MAP.get(name.toLowerCase());
  PARAMETER_MAP.set(name.toLowerCase(), {
    categories: [...(existing?.categories ?? []), "Auth-sensitive"],
    boost: Math.max(existing?.boost ?? 0, 0.1),
  });
}

/**
 * Look up risk profile for a parameter name.
 * Uses case-insensitive matching.
 * Returns undefined if the parameter name is not in the high-risk list.
 */
export function getParameterRisk(paramName: string): ParameterRisk | undefined {
  const entry = PARAMETER_MAP.get(paramName.toLowerCase());
  if (!entry) return undefined;

  return {
    name: paramName,
    categories: entry.categories,
    boost: entry.boost,
  };
}

/**
 * Extract parameter names from a finding message and return the highest-risk match.
 * Looks for common parameter reference patterns in finding text.
 */
export function extractParameterRisk(message: string): ParameterRisk | undefined {
  // Extract words that look like parameter names from the message
  const candidates = new Set<string>();

  // Match parameter-like references: param=, "param", 'param', `param`, param:, req.param
  const patterns = [
    /\b(?:param|parameter|field|column|key|name|input)\s*[=:]\s*["'`]?(\w+)/gi,
    /\breq(?:uest)?\.(?:query|body|params|headers)\[["'`](\w+)["'`]\]/gi,
    /\breq(?:uest)?\.(?:query|body|params)\.(\w+)\b/gi,
    /["'`](\w+)["'`]\s*(?:parameter|param|field|input)/gi,
    /\bsource\s*(?:parameter|param|:)\s*["'`]?(\w+)/gi,
  ];

  for (const pattern of patterns) {
    let match;
    while ((match = pattern.exec(message)) !== null) {
      if (match[1]) candidates.add(match[1]);
    }
  }

  // Also try matching standalone known parameter names in the message
  const words = message.split(/[^a-zA-Z0-9_]+/);
  for (const word of words) {
    if (word.length >= 2 && PARAMETER_MAP.has(word.toLowerCase())) {
      candidates.add(word);
    }
  }

  let bestRisk: ParameterRisk | undefined;
  for (const candidate of candidates) {
    const risk = getParameterRisk(candidate);
    if (risk && (!bestRisk || risk.boost > bestRisk.boost)) {
      bestRisk = risk;
    }
  }

  return bestRisk;
}
