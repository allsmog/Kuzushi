pub(crate) fn split_agentic_sast_tasks(
    tasks: Vec<String>,
) -> (Vec<String>, bool, bool, bool, bool, bool) {
    let mut native = Vec::new();
    let mut agentic = false;
    let mut carlini = false;
    let mut taint_iris = false;
    let mut taint_iris_next = false;
    let mut systems_hunt = false;
    for task in tasks {
        if let Some(flags) = agentic_task_flags(task.trim()) {
            agentic |= flags.agentic;
            carlini |= flags.carlini;
            taint_iris |= flags.taint_iris;
            taint_iris_next |= flags.taint_iris_next;
            systems_hunt |= flags.systems_hunt;
        } else {
            native.push(task);
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

#[derive(Clone, Copy)]
struct AgenticTaskFlags {
    agentic: bool,
    carlini: bool,
    taint_iris: bool,
    taint_iris_next: bool,
    systems_hunt: bool,
}

const fn task_flags(
    agentic: bool,
    carlini: bool,
    taint_iris: bool,
    taint_iris_next: bool,
    systems_hunt: bool,
) -> AgenticTaskFlags {
    AgenticTaskFlags {
        agentic,
        carlini,
        taint_iris,
        taint_iris_next,
        systems_hunt,
    }
}

const AGENTIC_TASK_ALIASES: &[(&str, AgenticTaskFlags)] = &[
    ("agentic", task_flags(true, false, false, false, false)),
    ("agentic-sast", task_flags(true, false, false, false, false)),
    ("agentic-sast:scan", task_flags(true, false, false, false, false)),
    ("carlini", task_flags(false, true, false, false, false)),
    ("threat-hunt", task_flags(false, true, false, false, false)),
    ("carlini-threat-hunt", task_flags(false, true, false, false, false)),
    (
        "carlini-threat-hunt:run",
        task_flags(false, true, false, false, false),
    ),
    ("offense-review", task_flags(false, true, false, false, false)),
    (
        "offense-review:threat-hunt",
        task_flags(false, true, false, false, false),
    ),
    ("taint", task_flags(false, false, true, false, false)),
    ("iris", task_flags(false, false, true, false, false)),
    ("taint-iris", task_flags(false, false, true, false, false)),
    ("taint-iris:hunt", task_flags(false, false, true, false, false)),
    (
        "taint-iris-next",
        task_flags(false, false, false, true, false),
    ),
    ("iris-next", task_flags(false, false, false, true, false)),
    ("taint-next", task_flags(false, false, false, true, false)),
    (
        "taint-iris-next:hunt",
        task_flags(false, false, false, true, false),
    ),
    ("systems", task_flags(false, false, false, false, true)),
    (
        "systems-hunt",
        task_flags(false, false, false, false, true),
    ),
    (
        "systems-hunt:systems-hunt",
        task_flags(false, false, false, false, true),
    ),
    (
        "systems-hunt:systems-context-gatherer",
        task_flags(false, false, false, false, true),
    ),
    (
        "systems-hunt:systems-invariant-extract",
        task_flags(false, false, false, false, true),
    ),
    (
        "systems-hunt:systems-trigger-synth",
        task_flags(false, false, false, false, true),
    ),
    (
        "deep-semantic",
        task_flags(false, false, false, false, true),
    ),
    (
        "deep-semantic-hunt",
        task_flags(false, false, false, false, true),
    ),
    (
        "systems-hunt:deep-semantic-hunt",
        task_flags(false, false, false, false, true),
    ),
];

fn agentic_task_flags(task: &str) -> Option<AgenticTaskFlags> {
    AGENTIC_TASK_ALIASES
        .iter()
        .find_map(|(alias, flags)| (*alias == task).then_some(*flags))
}
