//! Per-language centralized validator/guard catalogs injected into the deep
//! auditor and other guard-aware prompts. The catalog tells the model which
//! upstream validators to look for before voting a missing-local-check finding
//! true-positive.

/// Canonical language grouping for validator-catalog selection. Kept narrow and
/// derived from the repository's detected language strings; unknown languages
/// fall back to [`PromptLanguage::Other`] (common catalog only).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PromptLanguage {
    CorCpp,
    Go,
    TypeScript,
    Python,
    JavaSpring,
    Other,
}

impl PromptLanguage {
    /// Map a detected language string (as produced by the scattered
    /// `infer_language`/`detect_language` helpers) to a catalog group. Matching
    /// is case-insensitive to absorb the `"TypeScript"` vs `"typescript"`
    /// inconsistency in the existing language tables.
    pub fn from_language_str(language: &str) -> Self {
        match language.trim().to_ascii_lowercase().as_str() {
            "c" | "cpp" | "c++" | "cxx" | "cc" | "kernel" => Self::CorCpp,
            "go" | "golang" => Self::Go,
            "ts" | "tsx" | "typescript" | "js" | "jsx" | "javascript" | "node" | "nodejs" => {
                Self::TypeScript
            }
            "py" | "python" => Self::Python,
            "java" | "kotlin" | "spring" => Self::JavaSpring,
            _ => Self::Other,
        }
    }

    /// Map a file path/extension to a catalog group. Used when only a finding's
    /// `file_path` is available rather than a repo-level language name.
    pub fn from_path(path: &str) -> Self {
        let ext = path
            .rsplit('.')
            .next()
            .filter(|ext| !ext.contains('/'))
            .unwrap_or("");
        match ext.to_ascii_lowercase().as_str() {
            "c" | "h" | "cc" | "cpp" | "cxx" | "hpp" | "hh" => Self::CorCpp,
            "go" => Self::Go,
            "ts" | "tsx" | "js" | "jsx" | "mjs" | "cjs" => Self::TypeScript,
            "py" | "pyi" => Self::Python,
            "java" | "kt" | "kts" => Self::JavaSpring,
            _ => Self::Other,
        }
    }

    fn specific_catalog(self) -> &'static str {
        match self {
            Self::CorCpp => KERNEL_C_CATALOG,
            Self::Go => GO_CATALOG,
            Self::TypeScript => TYPESCRIPT_CATALOG,
            Self::Python => PYTHON_CATALOG,
            Self::JavaSpring => JAVA_SPRING_CATALOG,
            Self::Other => "",
        }
    }
}

/// Return the common catalog plus the language-specific catalog for `language`.
/// `Other` returns just the common catalog.
pub fn centralized_validator_catalog(language: PromptLanguage) -> String {
    let specific = language.specific_catalog();
    if specific.is_empty() {
        COMMON_CATALOG.to_string()
    } else {
        format!("{COMMON_CATALOG}\n\n{specific}")
    }
}

pub const COMMON_CATALOG: &str = "Common validator/guard classes to check:
- route-level authn/authz middleware;
- schema validators and deserializers that reject invalid fields;
- parser-level bounds checks before per-handler dispatch;
- framework auto-escaping and context-sensitive encoders;
- content-type and file-type validators;
- allowlists and canonicalization order;
- privilege gates such as admin/superuser/role checks;
- feature flags and deployment constraints that make a path unreachable.";

pub const KERNEL_C_CATALOG: &str = "C/C++ and kernel validator examples:
- dispatcher-level protocol validators before per-handler dispatch;
- length fields with u8/u16/u32 bit-width constraints;
- allocation-time guards such as checked struct-size calculations;
- parser functions that compute data-area length before copies;
- netlink, ioctl, packet, filesystem, or driver dispatch validators;
- object lifetime and reference-count ownership checks.";

pub const GO_CATALOG: &str = "Go validator examples:
- chi/gin/echo/net/http middleware chains for auth, CSRF, request size, and content type;
- request binding and validation tags before handler use;
- database/sql placeholder semantics vs fmt.Sprintf/query concatenation;
- html/template contextual escaping vs text/template/raw HTML;
- context-based tenant/role checks propagated through service layers;
- path.Clean/filepath.Clean plus prefix checks after canonicalization.";

pub const TYPESCRIPT_CATALOG: &str = "TypeScript/Node validator examples:
- Express/Fastify/Nest middleware and guards;
- zod/joi/class-validator schemas applied before controller/service calls;
- ORM parameterization vs raw query fragments;
- React/Next escaping vs dangerouslySetInnerHTML, raw template rendering, DOM sinks;
- multer/busboy upload filters plus storage path canonicalization;
- child_process exec vs execFile/spawn argument arrays.";

pub const PYTHON_CATALOG: &str = "Python validator examples:
- Django/Flask/FastAPI route dependencies and decorators;
- pydantic/marshmallow/form validators before use;
- ORM parameterization vs raw SQL/text fragments;
- Jinja/Django auto-escape vs mark_safe/raw filters;
- pathlib/os.path canonicalization and prefix checks;
- subprocess shell=True vs argument-array execution.";

pub const JAVA_SPRING_CATALOG: &str = "Java/Spring validator examples:
- Spring Security filters, method annotations, and role gates;
- Bean Validation annotations and controller binding;
- PreparedStatement/JPA parameters vs string-built JPQL/SQL;
- Thymeleaf/JSP escaping vs unescaped output;
- Path normalization and Zip Slip extraction guards;
- ProcessBuilder argument separation vs shell invocation.";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn language_strings_map_to_groups() {
        assert_eq!(
            PromptLanguage::from_language_str("c"),
            PromptLanguage::CorCpp
        );
        assert_eq!(
            PromptLanguage::from_language_str("TypeScript"),
            PromptLanguage::TypeScript
        );
        assert_eq!(
            PromptLanguage::from_language_str("golang"),
            PromptLanguage::Go
        );
        assert_eq!(
            PromptLanguage::from_language_str("rust"),
            PromptLanguage::Other
        );
    }

    #[test]
    fn catalog_varies_by_language() {
        let c = centralized_validator_catalog(PromptLanguage::CorCpp);
        let py = centralized_validator_catalog(PromptLanguage::Python);
        assert!(c.contains("netlink, ioctl"));
        assert!(!c.contains("Django/Flask/FastAPI"));
        assert!(py.contains("Django/Flask/FastAPI"));
        // Both include the common catalog.
        assert!(c.contains("route-level authn/authz middleware"));
        assert!(py.contains("route-level authn/authz middleware"));
    }

    #[test]
    fn other_language_is_common_only() {
        let other = centralized_validator_catalog(PromptLanguage::Other);
        assert_eq!(other, COMMON_CATALOG);
    }
}
