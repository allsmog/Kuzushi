use super::*;

pub(crate) const HARNESS_CARGO_TOML: &str = r#"[package]
name = "kuzushi-verify-harness"
version = "0.0.0"
edition = "2021"
publish = false

[dependencies]

[lib]
path = "src/lib.rs"

[[test]]
name = "trigger"
path = "tests/trigger.rs"
"#;

pub(in crate::verify) fn build_rust_trigger(finding: &Finding) -> RustTriggerSource {
    let payload = synth_payload_from_finding(finding);
    let suspect_path = std::path::Path::new(&finding.file_path);
    let suspect = extract_enclosing_function(suspect_path, finding.start_line);
    let suspect_source = std::fs::read_to_string(suspect_path).ok();

    let parsed_sig = suspect
        .as_ref()
        .and_then(|f| parse_rust_signature(&f.signature));
    let call_plan = parsed_sig.as_ref().and_then(plan_call_expression);

    let suspect_comment = match (&suspect, &call_plan) {
        (Some(f), Some(plan)) => format!(
            "// Suspect: {file}:{line} (signature at {sig_line}) — calling `{name}(...)` via {kind}",
            file = finding.file_path,
            line = f.line,
            sig_line = f.signature_line,
            name = plan.fn_name,
            kind = plan.call_kind
        ),
        (Some(f), None) => format!(
            "// Suspect: {file}:{line} (signature at {sig_line}) → `{sig}`\n\
             // Couldn't synthesize a call (signature not in the supported pattern set);\n\
             // falling back to payload-only harness.",
            file = finding.file_path,
            line = f.line,
            sig_line = f.signature_line,
            sig = f.signature.trim()
        ),
        (None, _) => format!(
            "// No enclosing function located near {}:{}; payload-only harness.",
            finding.file_path, finding.start_line
        ),
    };

    let (lib_rs, call_block) = match (&suspect_source, &call_plan) {
        (Some(src), Some(plan)) if rust_source_appears_self_contained(src) => {
            // Wrap the suspect file as `pub mod suspect;` inside the
            // harness lib so the test can name-resolve into it.
            let lib = "// kuzushi-verify-harness\n\
                 #![allow(unused, dead_code, deprecated, clippy::all)]\n\
                 pub mod suspect;\n"
                .to_string();
            let call = format!(
                "             // Real sink call (synthesized from {fname}'s signature).\n\
                 {invoke}",
                fname = plan.fn_name,
                invoke = plan.call_expression
            );
            (lib, call)
        }
        _ => (
            "// kuzushi-verify-harness\n".to_string(),
            "             // Payload-only harness — no sink call wired.\n\
             let _ = std::hint::black_box(payload);\n"
                .to_string(),
        ),
    };

    let body = format!(
        "// Synthesised by kuzushi verify for finding {fp}\n\
         {suspect_comment}\n\
         #[test]\n\
         fn trigger() {{\n\
             let payload: Vec<u8> = vec!{payload:?};\n\
             let _ = std::hint::black_box(&payload);\n\
{call_block}\
         }}\n",
        fp = finding.fingerprint,
        suspect_comment = suspect_comment,
        payload = payload,
        call_block = call_block,
    );

    RustTriggerSource {
        cargo_toml: HARNESS_CARGO_TOML.to_string(),
        lib_rs,
        trigger_test: body,
        suspect_source: suspect_source.clone(),
    }
}
