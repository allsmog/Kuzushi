pub(crate) fn split_agentic_sast_tasks(
    tasks: Vec<String>,
) -> (Vec<String>, bool, bool, bool, bool) {
    let mut native = Vec::new();
    let mut agentic = false;
    let mut carlini = false;
    let mut taint_iris_next = false;
    let mut systems_hunt = false;
    for task in tasks {
        if let Some(flags) = agentic_task_flags(task.trim()) {
            agentic |= flags.agentic;
            carlini |= flags.carlini;
            taint_iris_next |= flags.taint_iris_next;
            systems_hunt |= flags.systems_hunt;
        } else {
            native.push(task);
        }
    }
    (native, agentic, carlini, taint_iris_next, systems_hunt)
}

#[derive(Clone, Copy)]
struct AgenticTaskFlags {
    agentic: bool,
    carlini: bool,
    taint_iris_next: bool,
    systems_hunt: bool,
}

const fn task_flags(
    agentic: bool,
    carlini: bool,
    taint_iris_next: bool,
    systems_hunt: bool,
) -> AgenticTaskFlags {
    AgenticTaskFlags {
        agentic,
        carlini,
        taint_iris_next,
        systems_hunt,
    }
}

const AGENTIC_TASK_ALIASES: &[(&str, AgenticTaskFlags)] = &[
    ("agentic", task_flags(true, false, false, false)),
    ("agentic-sast", task_flags(true, false, false, false)),
    ("agentic-sast:scan", task_flags(true, false, false, false)),
    ("carlini", task_flags(false, true, false, false)),
    ("threat-hunt", task_flags(false, true, false, false)),
    ("carlini-threat-hunt", task_flags(false, true, false, false)),
    (
        "carlini-threat-hunt:run",
        task_flags(false, true, false, false),
    ),
    ("offense-review", task_flags(false, true, false, false)),
    (
        "offense-review:threat-hunt",
        task_flags(false, true, false, false),
    ),
    ("taint", task_flags(false, false, true, false)),
    ("iris", task_flags(false, false, true, false)),
    ("taint-iris", task_flags(false, false, true, false)),
    ("taint-iris:hunt", task_flags(false, false, true, false)),
    ("taint-iris-next", task_flags(false, false, true, false)),
    ("iris-next", task_flags(false, false, true, false)),
    ("taint-next", task_flags(false, false, true, false)),
    (
        "taint-iris-next:hunt",
        task_flags(false, false, true, false),
    ),
    ("systems", task_flags(false, false, false, true)),
    ("systems-hunt", task_flags(false, false, false, true)),
    (
        "systems-hunt:systems-hunt",
        task_flags(false, false, false, true),
    ),
];

fn agentic_task_flags(task: &str) -> Option<AgenticTaskFlags> {
    AGENTIC_TASK_ALIASES
        .iter()
        .find_map(|(alias, flags)| (*alias == task).then_some(*flags))
}

const STANDALONE_STAGE_SCAN_ALIASES: &[&str] = &[
    "systems-hunt:systems-context-gatherer",
    "systems-hunt:systems-invariant-extract",
    "systems-hunt:systems-trigger-synth",
    "deep-semantic",
    "deep-semantic-hunt",
    "systems-hunt:deep-semantic-hunt",
];

pub(crate) fn is_standalone_stage_scan_alias(task: &str) -> bool {
    STANDALONE_STAGE_SCAN_ALIASES.contains(&task.trim())
}

pub(crate) fn validate_sast_stage_aliases(tasks: &[String]) -> anyhow::Result<()> {
    let Some(task) = tasks
        .iter()
        .find(|task| is_standalone_stage_scan_alias(task))
    else {
        return Ok(());
    };
    anyhow::bail!("sast:scan tasks contains standalone stage {task:?}; it cannot expand into the legacy systems pipeline. Plan the exact standalone tool separately. No scan engine was substituted.")
}
