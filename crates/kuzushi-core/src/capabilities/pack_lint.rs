//! `pack:lint` — deterministic knowledge-pack validator, runnable
//! pre-install. Checks `pack.toml` shape, each product's shard manifest and
//! threat model against the exact schemas campaign planning consumes, and
//! prompt fragments against the `<module>/<verb>.md` destination contract.
//! Read-only, no model calls; the tool result fails when any ERROR row
//! exists so `kuzushi run pack:lint` exits nonzero in CI.

mod resources;
use crate::modules::ToolExecutionContext;
use anyhow::Result;
use resources::{LintLimits, LintResources};
use serde_json::{json, Value};
use std::fmt;
use std::path::{Path, PathBuf};

/// Shard scopes above this file count get a WARN: measured job cost grows
/// sharply past it (a 116-file scope cost ~$32 in the pilot).
const SHARD_FILE_WARN_THRESHOLD: usize = 50;
/// Bound the per-scope file walk so a mispointed path (e.g. a checkout
/// root) cannot stall the linter; counts are reported as "N+".
const SHARD_FILE_COUNT_CAP: usize = 5000;

const VALID_SEVERITIES: [&str; 5] = ["critical", "high", "medium", "low", "info"];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LintLevel {
    Error,
    Warn,
    Ok,
}

impl fmt::Display for LintLevel {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Error => "ERROR",
            Self::Warn => "WARN",
            Self::Ok => "OK",
        })
    }
}

#[derive(Debug)]
pub struct LintRow {
    pub level: LintLevel,
    pub check: &'static str,
    pub subject: String,
    pub detail: String,
}

fn row(level: LintLevel, check: &'static str, subject: &str, detail: impl Into<String>) -> LintRow {
    LintRow {
        level,
        check,
        subject: subject.to_string(),
        detail: detail.into(),
    }
}

pub fn execute_pack_lint(input: &Value, ctx: &ToolExecutionContext<'_>) -> Result<Value> {
    let Some(pack_dir) = pack_dir_input(input) else {
        anyhow::bail!("pack:lint requires packDir=<pack directory>");
    };
    let product = string_input(input, &["product"]);
    let target_root = ctx
        .workspace
        .map(|workspace| workspace.root().to_path_buf());
    let limits = LintLimits::parse(input)?;
    let canceled = || ctx.is_cancelled();
    let resources = LintResources::new(&pack_dir, limits, &canceled);
    let rows = lint_with_resources(product.as_deref(), target_root.as_deref(), &resources);
    Ok(lint_result_with_coverage(
        &pack_dir,
        &rows,
        Some(resources.coverage()),
    ))
}

fn pack_dir_input(input: &Value) -> Option<PathBuf> {
    string_input(input, &["packDir", "pack_dir", "pack"]).map(PathBuf::from)
}

fn string_input(input: &Value, keys: &[&str]) -> Option<String> {
    keys.iter()
        .filter_map(|key| input.get(*key))
        .filter_map(Value::as_str)
        .map(str::trim)
        .find(|value| !value.is_empty())
        .map(str::to_string)
}

#[cfg(test)]
fn lint_result(pack_dir: &Path, rows: &[LintRow]) -> Value {
    lint_result_with_coverage(pack_dir, rows, None)
}

fn lint_result_with_coverage(pack_dir: &Path, rows: &[LintRow], coverage: Option<Value>) -> Value {
    let errors = rows.iter().filter(|r| r.level == LintLevel::Error).count();
    let warnings = rows.iter().filter(|r| r.level == LintLevel::Warn).count();
    let mut output = format!(
        "{}\npack:lint {}: {} error(s), {} warning(s), {} check(s)",
        render_table(rows),
        pack_dir.display(),
        errors,
        warnings,
        rows.len()
    );
    let mut data = json!({
        "packDir": pack_dir.display().to_string(),
        "errors": errors,
        "warnings": warnings,
        "rows": rows.iter().map(row_json).collect::<Vec<_>>(),
    });
    let partial = coverage
        .as_ref()
        .is_some_and(|value| value["complete"] == false);
    if let Some(coverage) = coverage {
        output.push_str(&coverage_text(&coverage));
        data["coverage"] = coverage;
    }
    finish_lint_result(errors, warnings, partial, output, data)
}

fn coverage_text(coverage: &Value) -> String {
    let mut output = format!(
        "\nInspection: complete={} | entries {}/{} | captured bytes {} | reserved bytes {}/{}\nIgnored hidden entries: {} | omitted checks: {} | canceled={}\n{}",
        coverage["complete"], coverage["entriesExamined"], coverage["maxWalkEntries"],
        coverage["capturedReadBytes"], coverage["reservedReadBytes"], coverage["maxReadBytes"],
        coverage["ignoredHiddenEntries"], coverage["omittedChecks"], coverage["canceled"],
        coverage["meaning"].as_str().unwrap_or_default(),
    );
    if let Some(reasons) = coverage["reasonSamples"].as_array() {
        for reason in reasons.iter().filter_map(Value::as_str) {
            output.push_str(&format!("\nNot inspected: {reason}"));
        }
    }
    output
}

fn finish_lint_result(
    errors: usize,
    warnings: usize,
    partial: bool,
    output: String,
    data: Value,
) -> Value {
    if errors > 0 {
        return crate::module_result::failed_output_result(
            format!("pack:lint found {errors} error(s)"),
            output,
            data,
        );
    }
    if partial {
        return crate::module_result::partial_output_result(
            "pack:lint incomplete",
            output,
            vec![json!(
                "Some pack or target checks were not inspected; see coverage."
            )],
            data,
        );
    }
    crate::module_result::completed_output_result(
        format!("pack:lint checked: {warnings} warning(s)"),
        output,
        data,
    )
}

fn row_json(row: &LintRow) -> Value {
    json!({
        "level": row.level.to_string(),
        "check": row.check,
        "subject": row.subject,
        "detail": row.detail,
    })
}

fn render_table(rows: &[LintRow]) -> String {
    rows.iter()
        .map(|row| {
            format!(
                "{:<5} {:<18} {:<32} {}",
                row.level.to_string(),
                row.check,
                row.subject,
                row.detail
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

pub fn lint_pack(
    pack_dir: &Path,
    product: Option<&str>,
    target_root: Option<&Path>,
) -> Vec<LintRow> {
    let resources = LintResources::new(pack_dir, LintLimits::default(), &|| false);
    lint_with_resources(product, target_root, &resources)
}

fn lint_with_resources(
    product: Option<&str>,
    target_root: Option<&Path>,
    resources: &LintResources<'_>,
) -> Vec<LintRow> {
    let mut rows = Vec::new();
    if let Some(manifest) = lint_pack_manifest(&resources.root, resources, &mut rows) {
        lint_products(
            &resources.root,
            &manifest,
            product,
            target_root,
            resources,
            &mut rows,
        );
    }
    if resources.partial() {
        rows.push(row(LintLevel::Warn, "coverage", "inspection", "Incomplete inspection. Some checks were omitted; finding validity and repository coverage are not assessed."));
    }
    rows
}

fn lint_pack_manifest(
    pack_dir: &Path,
    resources: &LintResources<'_>,
    rows: &mut Vec<LintRow>,
) -> Option<toml::Value> {
    let path = pack_dir.join("pack.toml");
    let body = match resources.read(&path) {
        Ok(body) => body,
        Err(error) => {
            rows.push(row(
                LintLevel::Error,
                "pack.toml",
                "pack.toml",
                format!("unreadable: {error}"),
            ));
            return None;
        }
    };
    let manifest = match toml::from_str::<toml::Value>(&body) {
        Ok(manifest) => manifest,
        Err(error) => {
            rows.push(row(
                LintLevel::Error,
                "pack.toml",
                "pack.toml",
                format!("parse error: {error}"),
            ));
            return None;
        }
    };
    lint_pack_header(&manifest, rows);
    Some(manifest)
}

fn lint_pack_header(manifest: &toml::Value, rows: &mut Vec<LintRow>) {
    let name = manifest
        .get("pack")
        .and_then(|pack| pack.get("name"))
        .and_then(toml::Value::as_str)
        .map(str::trim)
        .unwrap_or_default();
    if name.is_empty() {
        rows.push(row(
            LintLevel::Error,
            "pack.toml",
            "[pack].name",
            "missing or empty",
        ));
    } else {
        rows.push(row(LintLevel::Ok, "pack.toml", "[pack].name", name));
    }
}

fn lint_products(
    pack_dir: &Path,
    manifest: &toml::Value,
    filter: Option<&str>,
    target_root: Option<&Path>,
    resources: &LintResources<'_>,
    rows: &mut Vec<LintRow>,
) {
    let Some(products) = manifest.get("products").and_then(toml::Value::as_table) else {
        rows.push(row(
            LintLevel::Error,
            "pack.toml",
            "[products]",
            "no [products.<name>] blocks",
        ));
        return;
    };
    let mut matched = false;
    for (name, product) in products {
        if filter.is_some_and(|wanted| wanted != name) {
            continue;
        }
        matched = true;
        lint_product(pack_dir, name, product, target_root, resources, rows);
    }
    if !matched {
        rows.push(row(
            LintLevel::Error,
            "pack.toml",
            "[products]",
            format!("product {:?} not found", filter.unwrap_or_default()),
        ));
    }
}

fn lint_product(
    pack_dir: &Path,
    name: &str,
    product: &toml::Value,
    target_root: Option<&Path>,
    resources: &LintResources<'_>,
    rows: &mut Vec<LintRow>,
) {
    if product_str(product, "target_hint").is_none() {
        rows.push(row(
            LintLevel::Warn,
            "product",
            name,
            "no target_hint (which checkout are shard paths relative to?)",
        ));
    }
    match declared_file(pack_dir, product, "shards") {
        DeclaredFile::Ok(path) => lint_shards_file(name, &path, target_root, resources, rows),
        DeclaredFile::Missing(path) => {
            rows.push(row(
                LintLevel::Error,
                "shards",
                name,
                format!("declared file missing: {}", path.display()),
            ));
        }
        DeclaredFile::Undeclared => {
            rows.push(row(LintLevel::Warn, "shards", name, "no shards= declared"));
        }
    }
    match declared_file(pack_dir, product, "threat_model") {
        DeclaredFile::Ok(path) => lint_threat_model_closure(name, &path, resources, rows),
        DeclaredFile::Missing(path) => {
            rows.push(row(
                LintLevel::Error,
                "threat-model",
                name,
                format!("declared file missing: {}", path.display()),
            ));
        }
        DeclaredFile::Undeclared => {
            rows.push(row(
                LintLevel::Warn,
                "threat-model",
                name,
                "no threat_model= declared",
            ));
        }
    }
    lint_prompts_dir(name, &product_dir_guess(pack_dir, product), resources, rows);
}

enum DeclaredFile {
    Ok(PathBuf),
    Missing(PathBuf),
    Undeclared,
}

fn declared_file(pack_dir: &Path, product: &toml::Value, key: &str) -> DeclaredFile {
    let Some(relative) = product_str(product, key) else {
        return DeclaredFile::Undeclared;
    };
    let path = pack_dir.join(relative);
    match std::fs::symlink_metadata(&path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => DeclaredFile::Missing(path),
        _ => DeclaredFile::Ok(path),
    }
}

fn product_str<'a>(product: &'a toml::Value, key: &str) -> Option<&'a str> {
    product
        .get(key)
        .and_then(toml::Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

/// The conventional product directory (`products/<p>/`) holding optional
/// `prompts/` and `threat-models/` siblings — derived from the declared
/// shards path so the layout stays a convention, not a requirement.
fn product_dir_guess(pack_dir: &Path, product: &toml::Value) -> PathBuf {
    product_str(product, "shards")
        .and_then(|shards| pack_dir.join(shards).parent().map(Path::to_path_buf))
        .unwrap_or_else(|| pack_dir.to_path_buf())
}

fn lint_shards_file(
    product: &str,
    path: &Path,
    target_root: Option<&Path>,
    resources: &LintResources<'_>,
    rows: &mut Vec<LintRow>,
) {
    let manifest = match resources
        .read(path)
        .map_err(|e| e.to_string())
        .and_then(|body| toml::from_str::<toml::Value>(&body).map_err(|e| e.to_string()))
    {
        Ok(manifest) => manifest,
        Err(error) => {
            rows.push(row(
                LintLevel::Error,
                "shards",
                product,
                format!("{}: {error}", path.display()),
            ));
            return;
        }
    };
    let Some(shards) = manifest.get("shards").and_then(toml::Value::as_table) else {
        rows.push(row(
            LintLevel::Error,
            "shards",
            product,
            "no [shards.<name>] tables",
        ));
        return;
    };
    if shards.is_empty() {
        rows.push(row(
            LintLevel::Error,
            "shards",
            product,
            "empty shard manifest",
        ));
        return;
    }
    for (shard_name, shard) in shards {
        lint_shard(product, shard_name, shard, target_root, resources, rows);
    }
    rows.push(row(
        LintLevel::Ok,
        "shards",
        product,
        format!("{} shard(s)", shards.len()),
    ));
}

fn lint_shard(
    product: &str,
    shard_name: &str,
    shard: &toml::Value,
    target_root: Option<&Path>,
    resources: &LintResources<'_>,
    rows: &mut Vec<LintRow>,
) {
    let subject = format!("{product}/{shard_name}");
    let paths = shard_paths(shard);
    if paths.is_empty() {
        rows.push(row(
            LintLevel::Error,
            "shard",
            &subject,
            "empty or missing paths = [...]",
        ));
        return;
    }
    let Some(root) = target_root else {
        resources.omit("No active target: shard path existence and file counts were not checked");
        return;
    };
    lint_shard_scope(&subject, &paths, root, resources, rows);
}

fn lint_shard_scope(
    subject: &str,
    paths: &[String],
    root: &Path,
    resources: &LintResources<'_>,
    rows: &mut Vec<LintRow>,
) {
    let root = root.canonicalize().unwrap_or_else(|_| root.to_path_buf());
    let mut files = 0usize;
    for relative in paths {
        let scope = root.join(relative);
        if let Err(error) = std::fs::symlink_metadata(&scope) {
            resources.omit(format!("Target scope not inspected: {relative}: {error}"));
            rows.push(row(
                LintLevel::Error,
                "shard-path",
                subject,
                format!("unavailable under target: {relative}: {error}"),
            ));
            continue;
        }
        files += resources
            .walk(
                &root,
                &scope,
                SHARD_FILE_COUNT_CAP.saturating_sub(files),
                true,
                true,
            )
            .len();
    }
    if files > SHARD_FILE_WARN_THRESHOLD {
        rows.push(row(
            LintLevel::Warn,
            "shard-size",
            subject,
            format!("{}{} inspected files in scope (> {SHARD_FILE_WARN_THRESHOLD}; model-backed jobs get expensive)",
                files,
                if files >= SHARD_FILE_COUNT_CAP { "+" } else { "" }),
        ));
    }
}

fn shard_paths(shard: &toml::Value) -> Vec<String> {
    shard
        .get("paths")
        .and_then(toml::Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(toml::Value::as_str)
                .map(str::trim)
                .filter(|path| !path.is_empty())
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

/// Lint the top-level threat model together with an optional sibling
/// `threat-models/` directory: campaign planning needs threats[] from at
/// least one of them.
fn lint_threat_model_closure(
    product: &str,
    path: &Path,
    resources: &LintResources<'_>,
    rows: &mut Vec<LintRow>,
) {
    let top_threats = lint_threat_model_file(product, path, resources, rows);
    let models_dir = path.parent().map(|dir| dir.join("threat-models"));
    let dir_threats = models_dir
        .as_deref()
        .filter(|dir| resources.optional_directory(dir))
        .map(|dir| lint_models_dir(product, dir, resources, rows))
        .unwrap_or(0);
    match (top_threats, dir_threats) {
        (0, 0) => rows.push(row(
            LintLevel::Error,
            "threats",
            product,
            "no threats[] in the threat model or a threat-models/ directory; campaign:plan would produce zero jobs",
        )),
        (0, n) => rows.push(row(
            LintLevel::Ok,
            "threats",
            product,
            format!("{n} threat(s) via threat-models/ (compound planning; pass modelsDir)"),
        )),
        (n, _) => rows.push(row(LintLevel::Ok, "threats", product, format!("{n} threat(s)"))),
    }
}

/// Returns the number of threats found; schema problems land as rows.
fn lint_threat_model_file(
    product: &str,
    path: &Path,
    resources: &LintResources<'_>,
    rows: &mut Vec<LintRow>,
) -> usize {
    let subject = format!("{product}/{}", file_stem(path));
    let document: Value = match resources
        .read(path)
        .map_err(|e| e.to_string())
        .and_then(|body| serde_json::from_str(&body).map_err(|e| e.to_string()))
    {
        Ok(document) => document,
        Err(error) => {
            rows.push(row(
                LintLevel::Error,
                "threat-model",
                &subject,
                format!("{}: {error}", path.display()),
            ));
            return 0;
        }
    };
    let canonical = canonical_threat_document(&document);
    let Some(threats) = canonical.get("threats").and_then(Value::as_array) else {
        return 0;
    };
    for (index, threat) in threats.iter().enumerate() {
        lint_threat(&subject, index, threat, rows);
    }
    threats.len()
}

fn lint_models_dir(
    product: &str,
    dir: &Path,
    resources: &LintResources<'_>,
    rows: &mut Vec<LintRow>,
) -> usize {
    let entries = resources.walk(&resources.root, dir, usize::MAX, false, false);
    let mut total = 0usize;
    for path in entries
        .iter()
        .filter(|path| path.extension().is_some_and(|ext| ext == "json"))
    {
        let count = lint_threat_model_file(product, path, resources, rows);
        if count == 0 {
            rows.push(row(
                LintLevel::Warn,
                "threat-model",
                &format!("{product}/{}", file_stem(path)),
                "no inspected threats[]; contributes nothing to compound planning",
            ));
        }
        total += count;
    }
    total
}

fn lint_threat(subject: &str, index: usize, threat: &Value, rows: &mut Vec<LintRow>) {
    let id = threat_string(threat, &["id", "threatId", "threat_id"]);
    let label = if id.is_empty() {
        format!("{subject}[{index}]")
    } else {
        format!("{subject}/{id}")
    };
    if threat_string(threat, &["title", "name"]).is_empty()
        && threat_string(threat, &["description", "summary", "detail"]).is_empty()
    {
        rows.push(row(
            LintLevel::Warn,
            "threat",
            &label,
            "no title/name or description",
        ));
    }
    lint_threat_severity(&label, threat, rows);
    lint_threat_cwes(&label, threat, rows);
}

fn lint_threat_severity(label: &str, threat: &Value, rows: &mut Vec<LintRow>) {
    let severity = threat_string(threat, &["severity", "risk", "priority"]).to_lowercase();
    if severity.is_empty() {
        rows.push(row(
            LintLevel::Warn,
            "severity",
            label,
            "missing (job priority falls to the default band)",
        ));
    } else if !VALID_SEVERITIES.contains(&severity.as_str()) {
        rows.push(row(
            LintLevel::Error,
            "severity",
            label,
            format!(
                "invalid value {severity:?} (accepted: {})",
                VALID_SEVERITIES.join("/")
            ),
        ));
    }
}

fn lint_threat_cwes(label: &str, threat: &Value, rows: &mut Vec<LintRow>) {
    let Some(value) = threat
        .get("relatedCwe")
        .or_else(|| threat.get("related_cwe"))
        .or_else(|| threat.get("cwe"))
    else {
        return;
    };
    match value {
        Value::String(single) => lint_cwe_token(label, single, rows),
        Value::Array(items) => {
            for item in items {
                match item.as_str() {
                    Some(token) => lint_cwe_token(label, token, rows),
                    None => rows.push(row(
                        LintLevel::Error,
                        "cwe",
                        label,
                        format!("non-string entry: {item}"),
                    )),
                }
            }
        }
        other => rows.push(row(
            LintLevel::Error,
            "cwe",
            label,
            format!("relatedCwe must be a string or string array, got {other}"),
        )),
    }
}

fn lint_cwe_token(label: &str, token: &str, rows: &mut Vec<LintRow>) {
    let trimmed = token.trim();
    let well_formed = trimmed
        .to_ascii_uppercase()
        .strip_prefix("CWE-")
        .is_some_and(|digits| !digits.is_empty() && digits.chars().all(|c| c.is_ascii_digit()));
    if !well_formed {
        rows.push(row(
            LintLevel::Warn,
            "cwe",
            label,
            format!("{trimmed:?} is not CWE-<digits>"),
        ));
    }
}

fn lint_prompts_dir(
    product: &str,
    product_dir: &Path,
    resources: &LintResources<'_>,
    rows: &mut Vec<LintRow>,
) {
    let prompts = product_dir.join("prompts");
    if !resources.optional_directory(&prompts) {
        return;
    }
    let files = resources.walk(&resources.root, &prompts, usize::MAX, true, false);
    for path in &files {
        lint_prompt_fragment(&prompts, path, product, rows);
    }
    if !files.is_empty() {
        rows.push(row(
            LintLevel::Ok,
            "prompts",
            product,
            format!(
                "{} inspected fragment destination(s); contents not checked",
                files.len()
            ),
        ));
    }
}

/// A fragment installs to `.kuzushi/prompts/<module>/<verb>.md` — exactly
/// two path segments under `prompts/`, `.md` extension.
fn lint_prompt_fragment(root: &Path, path: &Path, product: &str, rows: &mut Vec<LintRow>) {
    let relative = path.strip_prefix(root).unwrap_or(path);
    let subject = format!("{product}/prompts/{}", relative.display());
    let segments: Vec<String> = relative
        .components()
        .map(|component| component.as_os_str().to_string_lossy().to_string())
        .collect();
    if segments.len() != 2 || !segments[1].ends_with(".md") {
        rows.push(row(
            LintLevel::Error,
            "prompt",
            &subject,
            "must be prompts/<module>/<verb>.md to land at .kuzushi/prompts/<module>/<verb>.md",
        ));
    }
}

fn threat_string(row: &Value, keys: &[&str]) -> String {
    keys.iter()
        .filter_map(|key| row.get(*key))
        .filter_map(Value::as_str)
        .map(str::trim)
        .find(|value| !value.is_empty())
        .unwrap_or_default()
        .to_string()
}

fn canonical_threat_document(value: &Value) -> &Value {
    value
        .get("document")
        .or_else(|| value.pointer("/data/document"))
        .unwrap_or(value)
}

fn file_stem(path: &Path) -> String {
    path.file_stem()
        .map(|stem| stem.to_string_lossy().to_string())
        .unwrap_or_else(|| path.display().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(path: &Path, body: &str) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, body).unwrap();
    }

    fn levels(rows: &[LintRow], check: &'static str) -> Vec<(LintLevel, String)> {
        rows.iter()
            .filter(|row| row.check == check)
            .map(|row| (row.level, row.detail.clone()))
            .collect()
    }

    fn error_count(rows: &[LintRow]) -> usize {
        rows.iter().filter(|r| r.level == LintLevel::Error).count()
    }

    /// TEMPLATE-shaped pack: one product, top-level threats[], one prompt
    /// fragment at a valid destination.
    fn template_shaped_pack(dir: &Path) {
        write(
            &dir.join("pack.toml"),
            r#"
[pack]
name = "template-shaped"
version = "0.1.0"

[products.example]
target_hint = "~/checkouts/example"
shards = "products/example/shards.toml"
threat_model = "products/example/threat-model.json"
"#,
        );
        write(
            &dir.join("products/example/shards.toml"),
            "[shards.parsers]\npaths = [\"src/codec\"]\n",
        );
        write(
            &dir.join("products/example/threat-model.json"),
            r#"{ "threats": [
                { "id": "T1", "title": "Parse OOB", "severity": "critical", "relatedCwe": ["CWE-787"] },
                { "id": "T2", "title": "Weak compare", "severity": "low", "cwe": "CWE-208" }
            ]}"#,
        );
        write(
            &dir.join("products/example/prompts/triage/run.md"),
            "severity anchors\n",
        );
    }

    /// Acme-shaped pack: distillation top-level model with NO threats[],
    /// plus a threat-models/ directory of subsystem docs that carry them.
    fn distillation_shaped_pack(dir: &Path) {
        write(
            &dir.join("pack.toml"),
            r#"
[pack]
name = "distillation-shaped"

[products.core]
target_hint = "~/checkouts/core"
shards = "products/core/shards.toml"
threat_model = "products/core/threat-model.json"
"#,
        );
        write(
            &dir.join("products/core/shards.toml"),
            "[shards.wire]\npaths = [\"src/wire\"]\n",
        );
        write(
            &dir.join("products/core/threat-model.json"),
            r#"{ "name": "distillation", "attackSurface": { "entryPoints": ["wire"] } }"#,
        );
        write(
            &dir.join("products/core/threat-models/subsystem.json"),
            r#"{ "threats": [ { "id": "s-1", "title": "peer parser", "severity": "high", "relatedCwe": ["CWE-125"] } ] }"#,
        );
    }

    #[test]
    fn template_shaped_pack_lints_clean() {
        let tmp = tempfile::tempdir().unwrap();
        template_shaped_pack(tmp.path());

        let rows = lint_pack(tmp.path(), None, None);

        assert_eq!(error_count(&rows), 0, "{rows:?}");
        assert_eq!(
            levels(&rows, "threats"),
            vec![(LintLevel::Ok, "2 threat(s)".to_string())]
        );
    }

    #[test]
    fn distillation_pack_counts_threats_from_models_dir() {
        let tmp = tempfile::tempdir().unwrap();
        distillation_shaped_pack(tmp.path());

        let rows = lint_pack(tmp.path(), None, None);

        assert_eq!(error_count(&rows), 0, "{rows:?}");
        let threats = levels(&rows, "threats");
        assert_eq!(threats.len(), 1);
        assert!(threats[0].1.contains("via threat-models/"), "{threats:?}");
    }

    #[test]
    fn schema_problems_produce_error_rows() {
        let tmp = tempfile::tempdir().unwrap();
        write(
            &tmp.path().join("pack.toml"),
            r#"
[pack]
name = ""

[products.broken]
shards = "products/broken/shards.toml"
threat_model = "products/broken/threat-model.json"
"#,
        );
        write(
            &tmp.path().join("products/broken/shards.toml"),
            "[shards.empty]\n",
        );
        write(
            &tmp.path().join("products/broken/threat-model.json"),
            r#"{ "threats": [
                { "id": "B1", "title": "bad sev", "severity": "urgent", "relatedCwe": [787] },
                { "id": "B2", "title": "odd cwe", "severity": "high", "cwe": "787" }
            ]}"#,
        );

        let rows = lint_pack(tmp.path(), None, None);

        let details = rows
            .iter()
            .map(|row| format!("{} {} {} {}", row.level, row.check, row.subject, row.detail))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(details.contains("ERROR pack.toml [pack].name"), "{details}");
        assert!(details.contains("ERROR shard broken/empty"), "{details}");
        assert!(
            details.contains("ERROR severity") && details.contains("urgent"),
            "{details}"
        );
        assert!(
            details.contains("ERROR cwe") && details.contains("non-string"),
            "{details}"
        );
        assert!(
            details.contains("WARN cwe") && details.contains("\"787\""),
            "{details}"
        );
        assert!(
            details.contains("WARN product broken no target_hint"),
            "{details}"
        );
    }

    #[test]
    fn missing_declared_files_and_no_threats_anywhere_are_errors() {
        let tmp = tempfile::tempdir().unwrap();
        write(
            &tmp.path().join("pack.toml"),
            r#"
[pack]
name = "gaps"

[products.gappy]
target_hint = "~/x"
shards = "products/gappy/shards.toml"
threat_model = "products/gappy/threat-model.json"
"#,
        );
        // shards file missing entirely; threat model exists but has no threats
        // and there is no threat-models/ directory.
        write(
            &tmp.path().join("products/gappy/threat-model.json"),
            r#"{ "name": "empty" }"#,
        );

        let rows = lint_pack(tmp.path(), None, None);

        let details = rows
            .iter()
            .map(|row| format!("{} {} {}", row.level, row.check, row.detail))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            details.contains("ERROR shards declared file missing"),
            "{details}"
        );
        assert!(details.contains("ERROR threats no threats[]"), "{details}");
    }

    #[test]
    fn target_root_enables_path_existence_and_size_checks() {
        let tmp = tempfile::tempdir().unwrap();
        template_shaped_pack(tmp.path());
        let target = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(target.path().join("src/codec")).unwrap();
        for index in 0..(SHARD_FILE_WARN_THRESHOLD + 3) {
            std::fs::write(
                target.path().join(format!("src/codec/f{index}.c")),
                "int x;",
            )
            .unwrap();
        }

        let rows = lint_pack(tmp.path(), None, Some(target.path()));
        assert_eq!(error_count(&rows), 0, "{rows:?}");
        let sizes = levels(&rows, "shard-size");
        assert_eq!(sizes.len(), 1);
        assert!(sizes[0].1.contains("53 inspected files"), "{sizes:?}");

        // Now point the shard at a path the target does not have.
        write(
            &tmp.path().join("products/example/shards.toml"),
            "[shards.parsers]\npaths = [\"src/absent\"]\n",
        );
        let rows = lint_pack(tmp.path(), None, Some(target.path()));
        let missing = levels(&rows, "shard-path");
        assert_eq!(missing.len(), 1);
        assert!(missing[0].1.contains("src/absent"), "{missing:?}");
    }

    #[test]
    fn misplaced_prompt_fragment_is_an_error() {
        let tmp = tempfile::tempdir().unwrap();
        template_shaped_pack(tmp.path());
        write(&tmp.path().join("products/example/prompts/loose.md"), "x");
        write(
            &tmp.path()
                .join("products/example/prompts/triage/deep/run.md"),
            "x",
        );

        let rows = lint_pack(tmp.path(), None, None);

        let prompt_errors = rows
            .iter()
            .filter(|row| row.check == "prompt" && row.level == LintLevel::Error)
            .count();
        assert_eq!(prompt_errors, 2, "{rows:?}");
    }

    #[test]
    fn unknown_product_filter_is_an_error_and_result_envelope_fails_on_errors() {
        let tmp = tempfile::tempdir().unwrap();
        template_shaped_pack(tmp.path());

        let rows = lint_pack(tmp.path(), Some("nope"), None);
        assert!(rows
            .iter()
            .any(|row| row.level == LintLevel::Error && row.detail.contains("nope")));

        let failed = lint_result(tmp.path(), &rows);
        assert_eq!(failed["ok"], false);
        assert_eq!(failed["status"], "failed");
        let clean = lint_result(tmp.path(), &lint_pack(tmp.path(), None, None));
        assert_eq!(clean["ok"], true);
    }
}
