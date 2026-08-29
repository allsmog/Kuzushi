//! Package-token matching for manifest framework needles.
//!
//! A framework row is a security claim: it tells the operator which routing,
//! authentication, and deserialization surface the target exposes. A raw
//! substring test over whole manifest text cannot support that claim, because
//! any coincidental spelling produces it — a Python package of its own named
//! `falcon-benchmarks`, a gem named `guardrails`, a crate named `warp-tunnel`.
//! Callers therefore narrow the text to declaration lines and require the
//! needle to stand there as a whole package token.
//!
//! Only `key = value` metadata is recognized here, which covers the TOML,
//! `requirements.txt`, and `Gemfile` manifests whose needles are bare package
//! names. JSON manifests declare their frameworks through needles that carry
//! their own quotes (`"express"`), so their metadata fields cannot collide.
//! A metadata value spread over several lines is excluded whole, not just at
//! its assignment line.

/// Manifest fields that describe the package itself rather than what it
/// depends on. A framework name spelled in one of them is prose, not evidence.
const SELF_DESCRIPTION_KEYS: &[&str] = &[
    "authors",
    "categories",
    "description",
    "documentation",
    "homepage",
    "keywords",
    "license",
    "name",
    "readme",
    "repository",
    "summary",
    "url",
];

/// The lines of a lowercased manifest that can carry a dependency.
pub(crate) fn manifest_declaration_lines(lower: &str) -> Vec<&str> {
    let mut self_description = SelfDescription::default();
    lower
        .lines()
        .filter(|line| self_description.admits(line))
        .collect()
}

/// Tracks a self-description value that a formatter spread over several lines,
/// so `keywords = [` followed by `"falcon",` is excluded whole rather than
/// leaving its contents behind as declarations.
#[derive(Default)]
struct SelfDescription {
    terminator: Option<&'static str>,
}

impl SelfDescription {
    fn admits(&mut self, line: &str) -> bool {
        if self.terminator.is_some() {
            self.consume_continuation(line);
            return false;
        }
        let trimmed = line.trim_start();
        !trimmed.starts_with('#') && !self.begins_at(trimmed)
    }

    fn consume_continuation(&mut self, line: &str) {
        if self.terminator.is_some_and(|end| line.contains(end)) {
            self.terminator = None;
        }
    }

    fn begins_at(&mut self, trimmed: &str) -> bool {
        let Some(value) = self_description_value(trimmed) else {
            return false;
        };
        self.terminator = continuation_terminator(value);
        true
    }
}

fn self_description_value(trimmed: &str) -> Option<&str> {
    let (key, value) = trimmed.split_once('=')?;
    SELF_DESCRIPTION_KEYS
        .contains(&key.trim())
        .then_some(value)
}

/// What has to appear before a self-description value is over. A value the
/// line already closes needs nothing; one left open by a trailing bracket or
/// an opening block string runs until its counterpart. A malformed manifest
/// that never closes such a value suppresses the framework claims below it,
/// which under-reports rather than inventing evidence.
fn continuation_terminator(value: &str) -> Option<&'static str> {
    let value = value.trim();
    match value {
        "\"\"\"" => Some("\"\"\""),
        "'''" => Some("'''"),
        _ if value.ends_with('[') => Some("]"),
        _ if value.ends_with('{') => Some("}"),
        _ => None,
    }
}

/// Whether `needle` appears in `line` as a whole package token.
pub(crate) fn declares_package_token(line: &str, needle: &str) -> bool {
    line.match_indices(needle)
        .any(|(start, matched)| stands_alone(line, start, matched.len()))
}

fn stands_alone(line: &str, start: usize, len: usize) -> bool {
    let before = line[..start].chars().next_back();
    let after = line[start + len..].chars().next();
    !before.is_some_and(continues_a_package_name) && !after.is_some_and(continues_a_package_name)
}

/// `.` and `/` are deliberately absent: they separate the segments of a Go
/// module path, a Java package prefix, an ASP.NET SDK id, and a Cargo
/// `[dependencies.axum]` table header, each of which must keep matching.
fn continues_a_package_name(character: char) -> bool {
    character.is_ascii_alphanumeric() || character == '-' || character == '_'
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_longer_package_name_does_not_declare_the_framework_it_spells() {
        assert!(!declares_package_token("falcon-benchmarks", "falcon"));
        assert!(!declares_package_token("gem 'guardrails'", "rails"));
        assert!(!declares_package_token("djangorestframework", "django"));
        assert!(!declares_package_token("axum-extra = \"0.9\"", "axum"));
        assert!(!declares_package_token("flask_admin", "flask"));
    }

    #[test]
    fn a_declared_dependency_still_declares_its_framework() {
        assert!(declares_package_token("falcon>=3.1.3", "falcon"));
        assert!(declares_package_token("gem 'rails'", "rails"));
        assert!(declares_package_token("axum = \"0.7\"", "axum"));
        assert!(declares_package_token("    \"falcon\",", "falcon"));
        assert!(declares_package_token("falcon", "falcon"));
    }

    #[test]
    fn dotted_and_slashed_segments_stay_matchable() {
        assert!(declares_package_token(
            "[dependencies.axum]",
            "axum"
        ));
        assert!(declares_package_token(
            "implementation 'org.springframework.boot:spring-boot-starter-web'",
            "org.springframework"
        ));
        assert!(declares_package_token(
            "<project sdk=\"microsoft.net.sdk.web\">",
            "microsoft.net.sdk.web"
        ));
        assert!(declares_package_token(
            "\trequire github.com/gin-gonic/gin v1.9.0",
            "github.com/gin-gonic/gin"
        ));
        assert!(declares_package_token(
            "{\"require\":{\"laravel/framework\":\"^10\"}}",
            "laravel/framework"
        ));
    }

    #[test]
    fn comments_and_self_description_cannot_declare_a_dependency() {
        let manifest = concat!(
            "# falcon is not used here\n",
            "[project]\n",
            "name = \"falcon-benchmarks\"\n",
            "description = \"benchmarks shaped like falcon\"\n",
            "keywords = [\"falcon\"]\n",
            "dependencies = [\"numpy\"]\n",
        );

        let declarations = manifest_declaration_lines(manifest);

        assert!(!declarations
            .iter()
            .any(|line| declares_package_token(line, "falcon")));
        assert!(declarations.contains(&"dependencies = [\"numpy\"]"));
    }

    #[test]
    fn a_metadata_value_spread_over_lines_is_excluded_whole() {
        let manifest = concat!(
            "[project]\n",
            "keywords = [\n",
            "  \"falcon\",\n",
            "  \"benchmarks\",\n",
            "]\n",
            "description = \"\"\"\n",
            "shaped like falcon\n",
            "\"\"\"\n",
            "dependencies = [\n",
            "  \"numpy\",\n",
            "]\n",
        );

        let declarations = manifest_declaration_lines(manifest);

        assert!(!declarations
            .iter()
            .any(|line| declares_package_token(line, "falcon")));
        assert!(declarations.contains(&"  \"numpy\","));
    }

    #[test]
    fn a_multiline_dependency_array_keeps_declaring_its_framework() {
        let manifest = concat!(
            "[project]\n",
            "name = \"gateway\"\n",
            "dependencies = [\n",
            "  \"falcon>=3.1.3\",\n",
            "]\n",
        );

        let declarations = manifest_declaration_lines(manifest);

        assert!(declarations
            .iter()
            .any(|line| declares_package_token(line, "falcon")));
    }

    #[test]
    fn a_dependency_named_like_a_metadata_field_is_still_a_declaration() {
        let declarations = manifest_declaration_lines("falcon = \"^3.1\"\nurl = \"docs/falcon\"\n");

        assert_eq!(declarations, vec!["falcon = \"^3.1\""]);
    }
}
