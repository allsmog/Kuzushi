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

/// Manifest fields that describe the package itself rather than what it
/// depends on. A framework name spelled in one of them is prose, not evidence.
/// The exclusion is line-scoped: a metadata value continued onto later lines
/// is only covered by the package-token rule below.
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
    lower.lines().filter(|line| can_declare(line)).collect()
}

fn can_declare(line: &str) -> bool {
    let trimmed = line.trim_start();
    !trimmed.starts_with('#') && !describes_the_package_itself(trimmed)
}

fn describes_the_package_itself(trimmed: &str) -> bool {
    trimmed
        .split_once('=')
        .is_some_and(|(key, _)| SELF_DESCRIPTION_KEYS.contains(&key.trim()))
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
    fn a_dependency_named_like_a_metadata_field_is_still_a_declaration() {
        let declarations = manifest_declaration_lines("falcon = \"^3.1\"\nurl = \"docs/falcon\"\n");

        assert_eq!(declarations, vec!["falcon = \"^3.1\""]);
    }
}
