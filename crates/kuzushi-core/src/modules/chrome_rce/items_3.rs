use super::prelude::*;
use super::*;

pub(in crate::modules) fn changed_files(target: &Path, diff_base: &str) -> Result<Vec<String>> {
    let verify = Command::new("git")
        .args(["rev-parse", "--verify", diff_base])
        .current_dir(target)
        .output()
        .with_context(|| "chrome-rce:review-trigger requires git; install git or omit diffBase")?;
    if !verify.status.success() {
        anyhow::bail!(
            "chrome-rce:review-trigger could not resolve diffBase {:?}: {}",
            diff_base,
            String::from_utf8_lossy(&verify.stderr).trim()
        );
    }
    let output = Command::new("git")
        .args(["diff", "--name-only", &format!("{diff_base}...HEAD")])
        .current_dir(target)
        .output()
        .with_context(|| "chrome-rce:review-trigger requires git; install git or omit diffBase")?;
    if !output.status.success() {
        anyhow::bail!(
            "chrome-rce:review-trigger git diff failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(ToString::to_string)
        .collect())
}

pub(in crate::modules) fn hot_path_finding(file: &str) -> Option<Finding> {
    let rule = hot_path_rule(file)?;
    Some(Finding::new_tool(
        "chrome-rce",
        rule.rule_id,
        file.to_string(),
        1,
        None,
        rule.severity,
        rule.message,
    ))
}

pub(in crate::modules) fn hot_path_rule(file: &str) -> Option<&'static HotPathRule> {
    HOT_PATH_RULES.iter().find(|rule| rule.matches(file))
}

#[derive(Clone, Copy)]
pub(in crate::modules) struct HotPathRule {
    pub(in crate::modules) matcher: HotPathMatcher,
    pub(in crate::modules) rule_id: &'static str,
    pub(in crate::modules) severity: Severity,
    pub(in crate::modules) message: &'static str,
}

impl HotPathRule {
    pub(in crate::modules) fn matches(&self, file: &str) -> bool {
        match self.matcher {
            HotPathMatcher::EndsWith(suffix) => file.ends_with(suffix),
            HotPathMatcher::Contains(fragment) => file.contains(fragment),
        }
    }
}

#[derive(Clone, Copy)]
pub(in crate::modules) enum HotPathMatcher {
    EndsWith(&'static str),
    Contains(&'static str),
}

pub(in crate::modules) const HOT_PATH_RULES: &[HotPathRule] = &[
    HotPathRule {
        matcher: HotPathMatcher::EndsWith("v8/src/maglev/maglev-phi-representation-selector.cc"),
        rule_id: "chrome-rce-hot-path-v8-maglev-phi-representation-selector",
        severity: Severity::High,
        message: "V8 Maglev phi representation selector changed; this path is anchored to CVE-2026-3910 and needs compiler-specialist review.",
    },
    HotPathRule {
        matcher: HotPathMatcher::Contains("v8/src/maglev/"),
        rule_id: "chrome-rce-hot-path-v8-maglev",
        severity: Severity::Medium,
        message: "V8 Maglev IR path changed; review representation tracking and type narrowing against historical Chrome RCE shapes.",
    },
    HotPathRule {
        matcher: HotPathMatcher::Contains("v8/src/compiler/backend/arm64/"),
        rule_id: "chrome-rce-hot-path-v8-arm64-codegen",
        severity: Severity::Medium,
        message: "V8 ARM64 backend path changed; review cross-architecture register-width assumptions against CVE-2024-7965.",
    },
    HotPathRule {
        matcher: HotPathMatcher::EndsWith("v8/src/compiler/typer.cc"),
        rule_id: "chrome-rce-hot-path-v8-typer",
        severity: Severity::Medium,
        message: "V8 typer changed; review type narrowing and CheckMaps preservation against CVE-2025-6554-family issues.",
    },
    HotPathRule {
        matcher: HotPathMatcher::EndsWith("v8/src/compiler/redundancy-elimination.cc"),
        rule_id: "chrome-rce-hot-path-v8-redundancy-elimination",
        severity: Severity::Medium,
        message: "V8 redundancy elimination changed; review removed checks before object access against historical CheckMaps issues.",
    },
    HotPathRule {
        matcher: HotPathMatcher::Contains("third_party/dawn/src/dawn/wire/server/"),
        rule_id: "chrome-rce-hot-path-dawn-wire-server",
        severity: Severity::High,
        message: "Dawn wire server path changed; review objects_.Get plus re-entrant call plus reuse patterns anchored to CVE-2026-5281-family UAFs.",
    },
    HotPathRule {
        matcher: HotPathMatcher::Contains("third_party/dawn/generator/templates/dawn/wire/server/"),
        rule_id: "chrome-rce-hot-path-dawn-wire-server-templates",
        severity: Severity::High,
        message: "Dawn wire server template changed; generated dispatcher code needs review for re-entrant pointer reuse.",
    },
];
