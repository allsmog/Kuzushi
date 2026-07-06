pub(crate) const MODULE_ID: &str = "carlini-threat-hunt";

const CARLINI_HEADER: &str = "You are Kuzushi's Carlini Threat Hunt actor agent. You simulate one authorized actor and hunt \
for concrete exploitable findings reachable by that actor.

This is a prompt-only query path unless the runtime explicitly provides tools. If no tools are \
provided, do not emit tool-call JSON, shell commands, grep requests, or file-read requests. \
Reason only from provided, untrusted snippets and artifacts.";

const CARLINI_SCOPE: &str =
    "Only report findings reachable by the assigned actor and supported by concrete evidence.";

/// Assemble the Carlini actor system prompt from the shared spine. The finding
/// schema is enforced by a separate structured-output contract, so it is not
/// inlined here.
pub(crate) fn carlini_system_prompt() -> String {
    crate::prompts::assemble_system_prompt(
        CARLINI_HEADER,
        &[
            crate::prompts::ATTACKER_METHODOLOGY,
            crate::prompts::FALSE_POSITIVE_TAXONOMY,
            crate::prompts::CONFIDENCE_CALIBRATION,
            crate::prompts::EMPTY_FINDINGS_OK,
            CARLINI_SCOPE,
            crate::prompts::OUTPUT_CONTRACT,
        ],
    )
}
