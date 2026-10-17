//! Name the requested operation when a shared source guard refuses execution.
pub(in crate::modules) fn source_guard_error(name: &str, error: anyhow::Error) -> anyhow::Error {
    let message = error.to_string();
    let cause = message.strip_prefix("patch:finding ").unwrap_or(&message);
    let context = format!("{name} source check refused: {cause}");
    error.context(context)
}

/// Some older source adapters carry their original operation label in the
/// message. Preserve unrelated compiler or transport failures unchanged.
pub(in crate::modules) fn contextualize_source_failure(
    name: &str,
    error: anyhow::Error,
) -> anyhow::Error {
    if error.to_string().starts_with("patch:finding ") {
        return source_guard_error(name, error);
    }
    error
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_refusal_names_the_operation_and_retains_the_original_cause() {
        let original = "patch:finding bound tree contains an unsafe symbolic link";
        let error = source_guard_error("codeql:create-db", anyhow::anyhow!(original));
        assert_eq!(
            error.to_string(),
            "codeql:create-db source check refused: bound tree contains an unsafe symbolic link"
        );
        assert_eq!(error.chain().last().unwrap().to_string(), original);
    }

    #[test]
    fn other_source_errors_keep_their_full_cause() {
        let error = source_guard_error(
            "owned:inspect",
            anyhow::anyhow!("source checkout changed during preparation"),
        );
        assert_eq!(
            error.to_string(),
            "owned:inspect source check refused: source checkout changed during preparation"
        );
        assert!(source_guard_error(
            "owned:inspect",
            anyhow::anyhow!("an inner patch:finding label")
        )
        .to_string()
        .contains("an inner patch:finding label"));
    }
    #[test]
    fn compiler_failures_remain_compiler_failures() {
        let error = contextualize_source_failure(
            "codeql:scan",
            anyhow::anyhow!("query compilation failed"),
        );
        assert_eq!(error.to_string(), "query compilation failed");
        let error = contextualize_source_failure(
            "codeql:scan",
            anyhow::anyhow!("patch:finding source checkout changed"),
        );
        assert_eq!(
            error.to_string(),
            "codeql:scan source check refused: source checkout changed"
        );
    }
}
