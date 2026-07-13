use anyhow::{Context, Result};
use globset::{GlobBuilder, GlobMatcher};

const GENERATED_PROBES: &[&str] = &[
    ".gitignore",
    "v3/latest",
    "v3/run-history.index.sqlite3",
    "v3/run-history.index.dirty",
    "v3/index.sqlite3",
    "v3/log/kuzushi-ignore-probe/event.json",
    "v3/objects/kuzushi-ignore-probe",
    "v3/runs/kuzushi-ignore-probe/summary.json",
    "worktrees/kuzushi-ignore-probe/source.rs",
];
const TRACKABLE_PROBES: &[&str] = &[
    "scope.toml",
    "prompts/kuzushi-ignore-probe.md",
    "v3/config.toml",
];
const GENERATED_TREE_RULE: &str = "v3/*";
const TRACKABLE_CONFIG_RULE: &str = "v3/config.toml";
const STATE_ROOT_RULE: &str = "*";

pub(super) fn validate_local_policy(bytes: &[u8]) -> Result<()> {
    let text = std::str::from_utf8(bytes)
        .context("Workspace state ignore policy must be UTF-8 so Kuzushi can validate it")?;
    let rules = parse_rules(text)?;
    anyhow::ensure!(
        !rules.is_empty(),
        "Workspace state ignore policy is empty; preserve custom rules and add Kuzushi's generated-state exclusions"
    );
    validate_generated_tree_ownership(&rules)?;
    validate_probes(&rules, GENERATED_PROBES, true)?;
    validate_probes(&rules, TRACKABLE_PROBES, false)
}

fn validate_generated_tree_ownership(rules: &[IgnoreRule]) -> Result<()> {
    let ownership_index = rules
        .iter()
        .rposition(|rule| {
            rule.ignores && !rule.directory_only && rule.pattern == GENERATED_TREE_RULE
        })
        .context(
            "Workspace state ignore policy must contain `v3/*` so every generated v3 path is ignored by construction",
        )?;
    validate_state_root_ownership(rules, ownership_index)?;
    for rule in &rules[ownership_index + 1..] {
        if !rule.ignores && rule.pattern != TRACKABLE_CONFIG_RULE {
            anyhow::bail!(
                "Workspace state ignore policy may only negate `!v3/config.toml` after `v3/*`; place other trackable exceptions before the generated-tree rule"
            );
        }
    }
    anyhow::ensure!(
        rules[ownership_index + 1..]
            .iter()
            .any(|rule| !rule.ignores && rule.pattern == TRACKABLE_CONFIG_RULE),
        "Workspace state ignore policy must leave `v3/config.toml` trackable after `v3/*`"
    );
    Ok(())
}

fn validate_state_root_ownership(rules: &[IgnoreRule], v3_ownership_index: usize) -> Result<()> {
    let ownership_index = rules[..v3_ownership_index]
        .iter()
        .rposition(|rule| {
            rule.ignores && !rule.directory_only && rule.pattern == STATE_ROOT_RULE
        })
        .context(
            "Workspace state ignore policy must contain `*` so every non-trackable .kuzushi path is ignored by construction",
        )?;
    for rule in &rules[ownership_index + 1..v3_ownership_index] {
        if !rule.ignores && !is_trackable_root_exception(rule) {
            anyhow::bail!(
                "Workspace state ignore policy may only expose scope.toml, prompts/**, and v3/config.toml after the root `*` rule"
            );
        }
    }
    Ok(())
}

fn is_trackable_root_exception(rule: &IgnoreRule) -> bool {
    matches!(
        (rule.pattern.as_str(), rule.directory_only),
        ("scope.toml", false) | ("prompts", true) | ("prompts/**", false) | ("v3", true)
    )
}

fn validate_probes(rules: &[IgnoreRule], probes: &[&str], expected: bool) -> Result<()> {
    for probe in probes {
        let actual = is_ignored(rules, probe);
        anyhow::ensure!(
            actual == expected,
            "Workspace state ignore policy must {verb} `{probe}`",
            verb = if expected {
                "ignore"
            } else {
                "leave trackable"
            }
        );
    }
    Ok(())
}

fn is_ignored(rules: &[IgnoreRule], path: &str) -> bool {
    let components = path.split('/').collect::<Vec<_>>();
    for end in 1..=components.len() {
        let candidate = components[..end].join("/");
        let is_directory = end < components.len();
        if ignored_candidate(rules, &candidate, is_directory) {
            return true;
        }
    }
    false
}

fn ignored_candidate(rules: &[IgnoreRule], path: &str, is_directory: bool) -> bool {
    rules
        .iter()
        .filter(|rule| rule.matches(path, is_directory))
        .fold(false, |_, rule| rule.ignores)
}

fn parse_rules(text: &str) -> Result<Vec<IgnoreRule>> {
    text.lines()
        .enumerate()
        .filter_map(|(index, line)| parse_rule(index + 1, line).transpose())
        .collect()
}

fn parse_rule(line_number: usize, raw: &str) -> Result<Option<IgnoreRule>> {
    let raw = raw.strip_suffix('\r').unwrap_or(raw);
    if raw.is_empty() || raw.starts_with('#') {
        return Ok(None);
    }
    let (ignores, pattern) = match raw.strip_prefix('!') {
        Some(pattern) => (false, pattern),
        None => (true, raw),
    };
    anyhow::ensure!(
        !pattern.is_empty(),
        "Workspace state ignore policy line {line_number} has an empty negation"
    );
    IgnoreRule::compile(ignores, pattern)
        .with_context(|| format!("Invalid workspace state ignore rule on line {line_number}"))
        .map(Some)
}

struct IgnoreRule {
    ignores: bool,
    directory_only: bool,
    pattern: String,
    matchers: Vec<GlobMatcher>,
}

impl IgnoreRule {
    fn compile(ignores: bool, raw: &str) -> Result<Self> {
        let directory_only = raw.ends_with('/');
        let pattern = raw.trim_start_matches('/').trim_end_matches('/');
        anyhow::ensure!(!pattern.is_empty(), "ignore rule has no path pattern");
        let patterns = if pattern.contains('/') {
            vec![pattern.to_string()]
        } else {
            vec![pattern.to_string(), format!("**/{pattern}")]
        };
        let matchers = patterns
            .iter()
            .map(|pattern| compile_matcher(pattern))
            .collect::<Result<Vec<_>>>()?;
        Ok(Self {
            ignores,
            directory_only,
            pattern: pattern.to_string(),
            matchers,
        })
    }

    fn matches(&self, path: &str, is_directory: bool) -> bool {
        (!self.directory_only || is_directory)
            && self.matchers.iter().any(|matcher| matcher.is_match(path))
    }
}

fn compile_matcher(pattern: &str) -> Result<GlobMatcher> {
    let mut builder = GlobBuilder::new(pattern);
    builder.literal_separator(true).backslash_escape(true);
    Ok(builder.build()?.compile_matcher())
}
