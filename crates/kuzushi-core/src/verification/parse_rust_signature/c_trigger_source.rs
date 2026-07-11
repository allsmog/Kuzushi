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
pub(in crate::verification) struct CTriggerSource {
    /// `trigger.c` — main + payload, calls `kuzushi_verify_call_target`.
    pub(in crate::verification) trigger_c: String,
    /// `target.c` — defines `kuzushi_verify_call_target`. Either the
    /// payload-only stub or the real trampoline that #includes the
    /// suspect file and forwards into the located function.
    pub(in crate::verification) target_c: String,
    /// Optional `suspect_source.c` — copy of the suspect file to be
    /// included from `target.c`. `None` when the source isn't
    /// self-contained or no suspect was located.
    pub(in crate::verification) suspect_source: Option<String>,
}

/// Build the C harness sources. When the suspect file is readable,
/// self-contained, and contains a parseable function near the finding's
/// line, generate a real trampoline. Otherwise produce the
/// payload-only stub.
pub(in crate::verification) fn build_c_trigger(
    finding: &Finding,
    workspace_root: &Path,
) -> Result<CTriggerSource> {
    let payload = synth_payload_from_finding(finding);
    let trigger_c = C_HARNESS_TEMPLATE.replace("{payload_decl}", &c_payload_declaration(&payload));
    let suspect = plan_c_suspect(finding, workspace_root)?;
    let (target_c, suspect_source) = c_target_sources(&suspect);
    Ok(CTriggerSource {
        trigger_c,
        target_c,
        suspect_source,
    })
}

fn c_payload_declaration(payload: &[u8]) -> String {
    format!(
        "    static const uint8_t payload[{}] = {{ {} }};",
        payload.len(),
        payload
            .iter()
            .map(|b| format!("0x{b:02x}"))
            .collect::<Vec<_>>()
            .join(", ")
    )
}

struct CSuspectPlan {
    source: Option<String>,
    call: Option<CCallPlan>,
}

fn plan_c_suspect(finding: &Finding, workspace_root: &Path) -> Result<CSuspectPlan> {
    let suspect_path = Path::new(&finding.file_path);
    let source = read_finding_source(workspace_root, suspect_path, "C")?;
    let call = source
        .as_deref()
        .and_then(|body| extract_enclosing_function_from_source(body, finding.start_line))
        .and_then(|function| parse_c_signature(&function.signature))
        .and_then(|signature| plan_c_call_expression(&signature));
    Ok(CSuspectPlan { source, call })
}

fn c_target_sources(suspect: &CSuspectPlan) -> (String, Option<String>) {
    match (&suspect.source, &suspect.call) {
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
            (target_c, Some(src.clone()))
        }
        _ => (C_TARGET_STUB.to_string(), None),
    }
}

pub(in crate::verification) fn synth_payload_from_finding(finding: &Finding) -> Vec<u8> {
    // Pull a few characteristic byte sequences out of the finding
    // message so the harness has *something* attacker-shaped without
    // needing model help. Real triggers will come from a future
    // model-driven step.
    let mut out: Vec<u8> = vec![0xff; 8];
    out.extend(finding.message.bytes().take(64));
    out
}
