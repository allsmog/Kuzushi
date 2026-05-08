use super::*;

/// Heuristic analog of `rust_source_appears_self_contained`. Refuses
/// copies that pull in project-relative headers (`#include "foo.h"`)
/// because we can't follow them; accepts files that only use system
/// headers (`#include <stddef.h>`). Also refuses files that declare
/// `static` callbacks referring to other TU symbols by undeclared
/// names — but that's the codeindex facade's job to detect; for this
/// preview the include-form check is the gate.
pub(crate) fn c_source_appears_self_contained(source: &str) -> bool {
    for line in source.lines().take(400) {
        let trimmed = line.trim();
        if trimmed.starts_with("#include") && trimmed.contains('"') && !trimmed.contains('<') {
            return false;
        }
    }
    true
}

#[derive(Debug, Clone)]
pub(in crate::verify) struct CTriggerSource {
    /// `trigger.c` — main + payload, calls `kuzushi_verify_call_target`.
    pub(in crate::verify) trigger_c: String,
    /// `target.c` — defines `kuzushi_verify_call_target`. Either the
    /// payload-only stub or the real trampoline that #includes the
    /// suspect file and forwards into the located function.
    pub(in crate::verify) target_c: String,
    /// Optional `suspect_source.c` — copy of the suspect file to be
    /// included from `target.c`. `None` when the source isn't
    /// self-contained or no suspect was located.
    pub(in crate::verify) suspect_source: Option<String>,
}

/// Build the C harness sources. When the suspect file is readable,
/// self-contained, and contains a parseable function near the finding's
/// line, generate a real trampoline. Otherwise produce the
/// payload-only stub.
pub(in crate::verify) fn build_c_trigger(finding: &Finding) -> CTriggerSource {
    let payload = synth_payload_from_finding(finding);
    let payload_decl = format!(
        "    static const uint8_t payload[{}] = {{ {} }};",
        payload.len(),
        payload
            .iter()
            .map(|b| format!("0x{b:02x}"))
            .collect::<Vec<_>>()
            .join(", ")
    );
    let trigger_c = C_HARNESS_TEMPLATE.replace("{payload_decl}", &payload_decl);

    let suspect_path = std::path::Path::new(&finding.file_path);
    let suspect_source = std::fs::read_to_string(suspect_path).ok();
    let enclosing = suspect_source
        .as_deref()
        .and_then(|_| extract_enclosing_function(suspect_path, finding.start_line));
    let parsed_sig = enclosing
        .as_ref()
        .and_then(|f| parse_c_signature(&f.signature));
    let call_plan = parsed_sig.as_ref().and_then(plan_c_call_expression);

    match (&suspect_source, &call_plan) {
        (Some(src), Some(plan)) if c_source_appears_self_contained(src) => {
            // Real trampoline: include the suspect file and forward.
            let target_c = format!(
                "// kuzushi-verify generated trampoline for `{name}`.\n\
                 // Call kind: {kind}.\n\
                 #include <stdint.h>\n\
                 #include <stddef.h>\n\
                 #include \"suspect_source.c\"\n\
                 \n\
                 void kuzushi_verify_call_target(const uint8_t *data, size_t len) {{\n\
                 {call}\
                 }}\n",
                name = plan.fn_name,
                kind = plan.call_kind,
                call = plan.call_expression,
            );
            CTriggerSource {
                trigger_c,
                target_c,
                suspect_source: Some(src.clone()),
            }
        }
        _ => CTriggerSource {
            trigger_c,
            target_c: C_TARGET_STUB.to_string(),
            suspect_source: None,
        },
    }
}

pub(in crate::verify) fn synth_payload_from_finding(finding: &Finding) -> Vec<u8> {
    // Pull a few characteristic byte sequences out of the finding
    // message so the harness has *something* attacker-shaped without
    // needing model help. Real triggers will come from a future
    // model-driven step.
    let mut out: Vec<u8> = vec![0xff; 8];
    out.extend(finding.message.bytes().take(64));
    out
}
