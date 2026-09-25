//! Variant patterns: confirmed findings compacted onto the threats they
//! realize, so later scans hunt siblings of what was already proven.
//!
//! A pattern is deterministic and source-grounded: the finding's CWE, its
//! location, the exact vulnerable line read from the repository, and the
//! identifiers on that line. Nothing here calls a model or reads the
//! filesystem; callers supply the line.

use regex::Regex;
use serde_json::{json, Value};
use std::sync::OnceLock;

pub(crate) const MAX_VARIANT_PATTERNS_PER_THREAT: usize = 8;
const MAX_PATTERN_CODE_CHARS: usize = 200;
const MAX_PATTERN_KEYWORDS: usize = 8;
const MIN_KEYWORD_CHARS: usize = 4;

/// Words too common in source to discriminate a vulnerable call site:
/// language keywords and the request/response plumbing every handler has.
const KEYWORD_STOPLIST: &[&str] = &[
    "async", "await", "body", "class", "const", "default", "else", "export", "extends", "false",
    "from", "function", "import", "interface", "next", "nextfunction", "null", "private",
    "public", "request", "require", "response", "return", "self", "static", "that", "then",
    "this", "true", "type", "undefined", "void", "with",
];

/// What a confirmed finding contributes to its threat.
pub(crate) struct VariantPatternSeed<'a> {
    pub(crate) fingerprint: &'a str,
    pub(crate) title: &'a str,
    pub(crate) file_path: &'a str,
    pub(crate) start_line: u32,
    pub(crate) cwe: Option<&'a str>,
    pub(crate) code_line: Option<&'a str>,
}

/// First `CWE-<n>` named in any of `texts`, normalized to upper case.
pub(crate) fn cwe_from_texts(texts: &[&str]) -> Option<String> {
    static CWE: OnceLock<Regex> = OnceLock::new();
    let pattern = CWE.get_or_init(|| Regex::new(r"(?i)\bCWE-(\d{1,5})\b").expect("valid regex"));
    texts
        .iter()
        .find_map(|text| pattern.captures(text))
        .map(|captures| format!("CWE-{}", &captures[1]))
}

/// Distinctive identifiers on the vulnerable line, in order of appearance.
pub(crate) fn code_keywords(code: &str) -> Vec<String> {
    static IDENT: OnceLock<Regex> = OnceLock::new();
    let pattern =
        IDENT.get_or_init(|| Regex::new(r"[A-Za-z_$][A-Za-z0-9_$]*").expect("valid regex"));
    let mut keywords: Vec<String> = Vec::new();
    for word in pattern.find_iter(code).map(|found| found.as_str()) {
        if is_distinctive(word) && !keywords.iter().any(|kept| kept == word) {
            keywords.push(word.to_string());
        }
    }
    keywords.truncate(MAX_PATTERN_KEYWORDS);
    keywords
}

fn is_distinctive(word: &str) -> bool {
    word.len() >= MIN_KEYWORD_CHARS && !KEYWORD_STOPLIST.contains(&word.to_ascii_lowercase().as_str())
}

pub(crate) fn variant_pattern_json(seed: &VariantPatternSeed<'_>) -> Value {
    let code = seed.code_line.and_then(call_site_code);
    json!({
        "findingRef": seed.fingerprint,
        "title": seed.title,
        "cwe": seed.cwe,
        "location": format!("{}:{}", seed.file_path, seed.start_line),
        "code": code,
        "keywords": code.as_deref().map(code_keywords).unwrap_or_default(),
        "addedBy": "refine",
    })
}

/// The first line of `code` that contains a call, bounded. A finding anchored
/// on an import or a function declaration has no call site worth hunting for.
fn call_site_code(code: &str) -> Option<String> {
    code.lines()
        .map(str::trim)
        .find(|line| line.contains('(') && !is_function_declaration(line))
        .map(|line| line.chars().take(MAX_PATTERN_CODE_CHARS).collect())
}

fn is_function_declaration(line: &str) -> bool {
    line.contains("=>") || line.split_whitespace().any(|word| word == "function" || word == "fn")
}

/// Append `pattern` to the threat unless its finding is already recorded or
/// the threat holds its cap. Returns whether it was recorded.
pub(crate) fn record_variant_pattern(threat: &mut Value, pattern: Value) -> bool {
    if !threat.get("variantPatterns").is_some_and(Value::is_array) {
        threat["variantPatterns"] = json!([]);
    }
    let Some(patterns) = threat.get_mut("variantPatterns").and_then(Value::as_array_mut) else {
        return false;
    };
    let duplicate = patterns
        .iter()
        .any(|existing| existing.get("findingRef") == pattern.get("findingRef"));
    if duplicate || patterns.len() >= MAX_VARIANT_PATTERNS_PER_THREAT {
        return false;
    }
    patterns.push(pattern);
    true
}

/// Every variant pattern the document's threats carry.
pub(crate) fn threat_variant_patterns(document: &Value) -> Vec<&Value> {
    document
        .get("threats")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|threat| threat.get("variantPatterns").and_then(Value::as_array))
        .flatten()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seed<'a>(fingerprint: &'a str, code: Option<&'a str>) -> VariantPatternSeed<'a> {
        VariantPatternSeed {
            fingerprint,
            title: "SQL Injection via Product Search",
            file_path: "routes/search.ts",
            start_line: 23,
            cwe: Some("CWE-89"),
            code_line: code,
        }
    }

    #[test]
    fn the_first_cwe_is_found_across_texts() {
        assert_eq!(
            cwe_from_texts(&["no id", "[cwe-89] SQL Injection", "CWE-22"]),
            Some("CWE-89".to_string())
        );
        assert_eq!(cwe_from_texts(&["SQL injection"]), None);
    }

    #[test]
    fn keywords_keep_distinctive_identifiers_once_in_order() {
        let code = "models.sequelize.query(`SELECT * FROM Products WHERE name LIKE '%${criteria}%'`, { this: true })";

        assert_eq!(
            code_keywords(code),
            vec!["models", "sequelize", "query", "SELECT", "Products", "WHERE", "name", "LIKE"]
        );
        assert!(code_keywords("return this").is_empty());
        assert!(code_keywords("import { UserModel } from '../models/user'")
            .iter()
            .all(|word| word != "import" && word != "from"));
    }

    #[test]
    fn a_pattern_carries_the_grounded_line_and_its_keywords() {
        let pattern = variant_pattern_json(&seed("fp-1", Some("  db.query(sql + id)  ")));

        assert_eq!(pattern["findingRef"], "fp-1");
        assert_eq!(pattern["cwe"], "CWE-89");
        assert_eq!(pattern["location"], "routes/search.ts:23");
        assert_eq!(pattern["code"], "db.query(sql + id)");
        assert_eq!(pattern["keywords"], json!(["query"]));
    }

    #[test]
    fn a_line_without_a_call_contributes_no_code() {
        let pattern = variant_pattern_json(&seed("fp-2", Some("import * as utils from '../lib/utils'")));

        assert!(pattern["code"].is_null());
        assert_eq!(pattern["keywords"], json!([]));
        assert_eq!(pattern["cwe"], "CWE-89");
    }

    #[test]
    fn handler_declarations_and_request_plumbing_are_not_call_sites() {
        let handler = "return async (req: Request, res: Response, next: NextFunction) => {";
        assert!(variant_pattern_json(&seed("fp-4", Some(handler)))["code"].is_null());
        assert!(variant_pattern_json(&seed("fp-5", Some("export function login(req) {")))["code"]
            .is_null());
        assert_eq!(code_keywords("render(req.body.next, response)"), vec!["render"]);
    }

    #[test]
    fn the_first_call_line_of_a_multiline_snippet_is_used() {
        let snippet = "const criteria = req.query.q\nmodels.sequelize.query(`SELECT ${criteria}`)";

        let pattern = variant_pattern_json(&seed("fp-3", Some(snippet)));

        assert_eq!(pattern["code"], "models.sequelize.query(`SELECT ${criteria}`)");
    }

    #[test]
    fn a_threat_records_each_finding_once_up_to_its_cap() {
        let mut threat = json!({"id": "T-1"});

        assert!(record_variant_pattern(&mut threat, variant_pattern_json(&seed("fp-1", None))));
        assert!(!record_variant_pattern(&mut threat, variant_pattern_json(&seed("fp-1", None))));
        for index in 2..=MAX_VARIANT_PATTERNS_PER_THREAT + 1 {
            let fingerprint = format!("fp-{index}");
            record_variant_pattern(&mut threat, variant_pattern_json(&seed(&fingerprint, None)));
        }

        assert_eq!(
            threat["variantPatterns"].as_array().unwrap().len(),
            MAX_VARIANT_PATTERNS_PER_THREAT
        );
        let document = json!({"threats": [threat, {"id": "T-2"}]});
        assert_eq!(threat_variant_patterns(&document).len(), MAX_VARIANT_PATTERNS_PER_THREAT);
    }
}
