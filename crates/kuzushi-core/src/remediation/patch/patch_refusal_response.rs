use serde_json::{json, Value};

pub(super) fn missing_patch_finding_response(fingerprint: &str) -> Value {
    let output = format!("[-] No finding with fingerprint '{fingerprint}'.");
    refused_patch_response(fingerprint, "missing-finding", output)
}

pub(super) fn untriaged_patch_finding_response(fingerprint: &str) -> Value {
    let output = format!("[-] Finding '{fingerprint}' has no triage verdict. Run triage:run first.");
    refused_patch_response(fingerprint, "missing-triage", output)
}

pub(super) fn unconfirmed_patch_finding_response(fingerprint: &str) -> Value {
    let output = format!(
        "[-] Finding '{fingerprint}' is not confirmed true_positive; patch:finding only patches confirmed findings."
    );
    refused_patch_response(fingerprint, "not-confirmed-true-positive", output)
}

fn refused_patch_response(fingerprint: &str, reason: &str, output: String) -> Value {
    crate::module_result::failed_output_result(
        "patch:finding failed",
        output,
        json!({
            "fingerprint": fingerprint,
            "reason": reason,
        }),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refused_patch_response_uses_failed_result_envelope() {
        let response = missing_patch_finding_response("missing");

        assert_eq!(response["ok"], json!(false));
        assert_eq!(response["status"], json!("failed"));
        assert_eq!(response["summary"], json!("patch:finding failed"));
        assert_eq!(response["data"]["reason"], json!("missing-finding"));
        assert!(response["errors"][0]
            .as_str()
            .unwrap()
            .contains("No finding with fingerprint 'missing'"));
    }
}
