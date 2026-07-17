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

pub(in crate::verification) fn build_rust_trigger(
    finding: &Finding,
    workspace_root: &Path,
) -> Result<RustTriggerSource> {
    let payload = synth_payload_from_finding(finding);
    let suspect = plan_rust_suspect(finding, workspace_root)?;
    let suspect_comment = rust_suspect_comment(finding, &suspect);
    let (lib_rs, call_block) = rust_harness_modules(&suspect);
    let trigger_test = rust_trigger_body(finding, &payload, &suspect_comment, &call_block);
    Ok(RustTriggerSource {
        cargo_toml: HARNESS_CARGO_TOML.to_string(),
        lib_rs,
        trigger_test,
        suspect_source: suspect.source,
    })
}

struct RustSuspectPlan {
    enclosing: Option<EnclosingFunction>,
    source: Option<String>,
    call: Option<CallPlan>,
}

fn plan_rust_suspect(finding: &Finding, workspace_root: &Path) -> Result<RustSuspectPlan> {
    let suspect_path = Path::new(&finding.file_path);
    let source = read_finding_source(workspace_root, suspect_path, "Rust")?;
    let enclosing = source
        .as_deref()
        .and_then(|body| extract_enclosing_function_from_source(body, finding.start_line));
    let call = enclosing
        .as_ref()
        .and_then(|function| parse_rust_signature(&function.signature))
        .and_then(|signature| plan_call_expression(&signature));
    Ok(RustSuspectPlan {
        enclosing,
        source,
        call,
    })
}

pub(in crate::verification) fn read_finding_source(
    workspace_root: &Path,
    suspect_path: &Path,
    language: &str,
) -> Result<Option<String>> {
    match crate::bounded_file::read_utf8_text_within(workspace_root, suspect_path, 8 * 1024 * 1024)
    {
        Ok(source) => Ok(Some(source)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error).with_context(|| {
            format!(
                "could not read {language} finding source {} inside workspace {}",
                suspect_path.display(),
                workspace_root.display()
            )
        }),
    }
}

fn rust_suspect_comment(finding: &Finding, suspect: &RustSuspectPlan) -> String {
    match (&suspect.enclosing, &suspect.call) {
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
    }
}

fn rust_harness_modules(suspect: &RustSuspectPlan) -> (String, String) {
    match (&suspect.source, &suspect.call) {
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
    }
}

fn rust_trigger_body(
    finding: &Finding,
    payload: &[u8],
    suspect_comment: &str,
    call_block: &str,
) -> String {
    format!(
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
    )
}
