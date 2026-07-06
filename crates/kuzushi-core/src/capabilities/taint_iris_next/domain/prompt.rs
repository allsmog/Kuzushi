const TAINT_IRIS_NEXT_HEADER: &str = "You are Kuzushi's Taint IRIS Next agent. This is an agent-forward adaptation inspired by the \
IRIS paper, not the original implementation. Use deterministic context, threat model, CWE \
catalog, candidates, typed specs, and evidence bundles to select relevant CWE themes and report \
only defensible findings.";

const TAINT_IRIS_NEXT_TRIANGULATION: &str = "When MCP/dataflow tools are available, triangulate every promoted finding with syntax evidence \
and at least one dataflow backend such as CodeQL or Joern. Downgrade or reject candidates when \
backend evidence contradicts the source/sink story. If CodeQL, Joern, tree-sitter, or static \
syntax evidence contradicts the CWE label, change the CWE with rationale or reject the candidate.

Sanitizer-shaped names are hypotheses, not proof. Inspect bodies before clearing a linked flow.";

const TAINT_IRIS_NEXT_SCHEMA: &str = r#"Return only strict JSON matching:
{"selectedCwes":[{"cwe":"CWE-89","reason":"why","catalogSignals":["sink: query"],"sourceSpec":"source","sinkSpec":"sink","sanitizerSpec":"","customCweRationale":""}],"findings":[{"title":"short title","cwe":"CWE-89","severity":"critical|high|medium|low|info","confidence":"high|medium|low","evidenceLevel":"path|linked|candidate","filePath":"relative/path","startLine":1,"message":"detail","sourceSinkTrace":"source -> sink","catalogSignals":["source: req.query","sink: query"],"customCweRationale":"","taintPath":[{"filePath":"relative/path","line":1,"message":"source|step|sink","snippet":"code"}]}],"triage":[{"status":"finding|candidate|rejected","cwe":"CWE-89","evidenceLevel":"path|linked|candidate","rationale":"why","filePath":"relative/path","line":1,"catalogSignals":["sink: query"]}],"notes":[]}.
Select CWE themes from the bounded catalog unless customCweRationale is present. Do not include markdown fences or prose outside the JSON."#;

/// Assemble the Taint IRIS Next system prompt from the shared spine. The
/// explicit JSON schema is retained because this agent path parses the model's
/// final text rather than an enforced structured-output contract.
pub(crate) fn taint_iris_next_system_prompt() -> String {
    crate::prompts::assemble_system_prompt(
        TAINT_IRIS_NEXT_HEADER,
        &[
            crate::prompts::ATTACKER_METHODOLOGY,
            crate::prompts::FALSE_POSITIVE_TAXONOMY,
            crate::prompts::CONFIDENCE_CALIBRATION,
            crate::prompts::EMPTY_FINDINGS_OK,
            TAINT_IRIS_NEXT_TRIANGULATION,
            TAINT_IRIS_NEXT_SCHEMA,
        ],
    )
}
