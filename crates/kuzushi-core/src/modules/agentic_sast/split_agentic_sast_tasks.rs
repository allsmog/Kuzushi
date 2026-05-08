pub(in crate::modules) fn split_agentic_sast_tasks(
    tasks: Vec<String>,
) -> (Vec<String>, bool, bool, bool, bool, bool) {
    let mut native = Vec::new();
    let mut agentic = false;
    let mut carlini = false;
    let mut taint_iris = false;
    let mut taint_iris_next = false;
    let mut systems_hunt = false;
    for task in tasks {
        match task.trim() {
            "agentic" | "agentic-sast" | "agentic-sast:scan" => agentic = true,
            "carlini" | "threat-hunt" | "carlini-threat-hunt" | "carlini-threat-hunt:run" => {
                carlini = true
            }
            "taint" | "iris" | "taint-iris" | "taint-iris:hunt" => taint_iris = true,
            "taint-iris-next" | "iris-next" | "taint-next" | "taint-iris-next:hunt" => {
                taint_iris_next = true
            }
            "systems"
            | "systems-hunt"
            | "systems-hunt:systems-hunt"
            | "systems-hunt:systems-context-gatherer"
            | "systems-hunt:systems-invariant-extract"
            | "systems-hunt:systems-trigger-synth"
            | "deep-semantic"
            | "deep-semantic-hunt"
            | "systems-hunt:deep-semantic-hunt" => systems_hunt = true,
            _ => native.push(task),
        }
    }
    (
        native,
        agentic,
        carlini,
        taint_iris,
        taint_iris_next,
        systems_hunt,
    )
}

#[derive(Debug, Clone)]
pub(in crate::modules) struct AgenticSastInput {
    pub(in crate::modules) max_findings: usize,
    pub(in crate::modules) passes: usize,
    pub(in crate::modules) severity: Vec<String>,
    pub(in crate::modules) exclude_patterns: Vec<String>,
}
