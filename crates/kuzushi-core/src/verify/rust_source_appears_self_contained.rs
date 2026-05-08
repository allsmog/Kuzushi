pub(crate) fn rust_source_appears_self_contained(source: &str) -> bool {
    for line in source.lines().take(200) {
        let trimmed = line.trim();
        if trimmed.starts_with("extern crate ") {
            return false;
        }
        if let Some(rest) = trimmed.strip_prefix("use ") {
            // `use crate::...` and `use self::...` cross module boundaries
            // we haven't replicated; refuse rather than hand the compiler
            // a guaranteed-fail build.
            if rest.starts_with("crate::") || rest.starts_with("super::") {
                return false;
            }
        }
        if trimmed.starts_with("#[macro_use") || trimmed.starts_with("#[derive(") {
            // Conservative: `derive` macros may pull in dep types we
            // haven't declared. Allow only the std-derives.
            if let Some(inner) = trimmed
                .strip_prefix("#[derive(")
                .and_then(|s| s.strip_suffix(")]"))
            {
                if !inner.split(',').all(|name| {
                    matches!(
                        name.trim(),
                        "Debug"
                            | "Clone"
                            | "Copy"
                            | "PartialEq"
                            | "Eq"
                            | "PartialOrd"
                            | "Ord"
                            | "Hash"
                            | "Default"
                    )
                }) {
                    return false;
                }
            }
        }
    }
    true
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RustSignature {
    pub fn_name: String,
    pub args: Vec<String>,
    pub return_type: Option<String>,
}
