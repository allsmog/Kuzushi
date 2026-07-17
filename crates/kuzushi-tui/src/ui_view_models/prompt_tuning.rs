use crate::app::PromptMutationsState;
use crate::{HouseRulesRead, ShellApp, TuneAction, ViewDataState};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TuneModel {
    pub(crate) module: String,
    pub(crate) severity_floor: &'static str,
    pub(crate) triage_confidence: &'static str,
    pub(crate) scan_concurrency: &'static str,
    pub(crate) house_rules_path: String,
    pub(crate) actions: Vec<TuneActionRow>,
    pub(crate) house_rules: TuneHouseRules,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TuneActionRow {
    pub(crate) label: &'static str,
    pub(crate) hint: &'static str,
    pub(crate) selected: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum TuneHouseRules {
    Present(Vec<String>),
    Unreadable(String),
    Empty,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PromptsModel {
    pub(crate) module: String,
    pub(crate) rows: Vec<PromptRow>,
    pub(crate) stack: Option<PromptStackModel>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PromptRow {
    pub(crate) role: String,
    pub(crate) verb: String,
    pub(crate) source: String,
    pub(crate) path: String,
    pub(crate) selected: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PromptStackModel {
    pub(crate) verb: String,
    pub(crate) layers: Vec<PromptStackLayer>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PromptStackLayer {
    pub(crate) layer: &'static str,
    pub(crate) state: String,
    pub(crate) path: String,
    pub(crate) hash: String,
}

pub(crate) fn tune_model(app: &ShellApp, house_rule_limit: usize) -> TuneModel {
    let module = focused_module(app);
    TuneModel {
        house_rules_path: kuzushi_core::relative_house_rule_path(&module)
            .display()
            .to_string(),
        actions: tune_action_rows(app),
        house_rules: house_rules(app, house_rule_limit),
        module,
        severity_floor: "medium",
        triage_confidence: "0.70",
        scan_concurrency: "adaptive",
    }
}

pub(crate) fn prompts_model(app: &ShellApp) -> PromptsModel {
    let module = focused_module(app);
    let prompts = app.focused_prompt_specs();
    let cursor = app.prompts_cursor_clamped();
    let override_states: Vec<_> = prompts
        .iter()
        .map(|prompt| prompt_override_layer_state(app, &prompt.module_id, &prompt.verb))
        .collect();
    let rows = prompts
        .iter()
        .enumerate()
        .map(|(index, prompt)| PromptRow {
            role: prompt.role.clone(),
            verb: prompt.verb.clone(),
            source: override_states[index].source_label().to_string(),
            path: kuzushi_core::relative_prompt_override_path(&prompt.module_id, &prompt.verb)
                .display()
                .to_string(),
            selected: index == cursor,
        })
        .collect();
    let stack = prompts.get(cursor).and_then(|prompt| {
        override_states
            .get(cursor)
            .cloned()
            .map(|state| prompt_stack_model(app, prompt, state))
    });
    PromptsModel {
        module,
        rows,
        stack,
    }
}

fn focused_module(app: &ShellApp) -> String {
    app.focused_module().unwrap_or("semgrep").to_string()
}

fn tune_action_rows(app: &ShellApp) -> Vec<TuneActionRow> {
    let cursor = app.tune_cursor_clamped();
    TuneAction::ORDER
        .iter()
        .enumerate()
        .map(|(index, action)| TuneActionRow {
            label: action.label(),
            hint: action.hint(),
            selected: index == cursor,
        })
        .collect()
}

fn house_rules(app: &ShellApp, limit: usize) -> TuneHouseRules {
    match app.router.tune().house_rules() {
        HouseRulesRead::Present(text) => {
            TuneHouseRules::Present(text.lines().take(limit).map(ToString::to_string).collect())
        }
        HouseRulesRead::Unreadable(path) => TuneHouseRules::Unreadable(path.display().to_string()),
        _ => TuneHouseRules::Empty,
    }
}

fn prompt_stack_model(
    app: &ShellApp,
    prompt: &kuzushi_core::modules::PromptSpec,
    override_state: PromptOverrideLayerState,
) -> PromptStackModel {
    let mutation_state = prompt_mutation_layer_state(app, &prompt.module_id, &prompt.verb);
    let base_hash = kuzushi_core::prompt_content_sha256(&prompt.default_content);
    let final_layer = prompt_final_layer(&override_state, &mutation_state, &base_hash);
    PromptStackModel {
        verb: prompt.verb.clone(),
        layers: vec![
            prompt_stack_layer(
                "base",
                format!("{} default", prompt.role),
                "built-in",
                base_hash,
            ),
            override_state.layer(),
            prompt_stack_layer("variant", "inactive", "not configured", "-"),
            mutation_state.layer(),
            prompt_stack_layer("correction", "inactive", "not configured", "-"),
            final_layer,
        ],
    }
}

fn prompt_stack_layer(
    layer: &'static str,
    state: impl Into<String>,
    path: impl Into<String>,
    hash: impl Into<String>,
) -> PromptStackLayer {
    PromptStackLayer {
        layer,
        state: state.into(),
        path: path.into(),
        hash: hash.into(),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum PromptOverrideLayerState {
    Present { path: String, hash: String },
    Missing { path: String },
    NoTarget { path: String },
    Unreadable { path: String },
}

impl PromptOverrideLayerState {
    fn layer(&self) -> PromptStackLayer {
        match self {
            Self::Present { path, hash } => {
                prompt_stack_layer("project override", "present", path, hash)
            }
            Self::Missing { path } => prompt_stack_layer("project override", "missing", path, "-"),
            Self::NoTarget { path } => {
                prompt_stack_layer("project override", "no target", path, "-")
            }
            Self::Unreadable { path } => {
                prompt_stack_layer("project override", "unreadable", path, "invalid")
            }
        }
    }

    fn final_layer(&self, base_hash: &str) -> PromptStackLayer {
        match self {
            Self::Present { path, hash } => {
                prompt_stack_layer("final", "override active", path, hash)
            }
            _ => prompt_stack_layer("final", "base active", "built-in", base_hash),
        }
    }

    fn source_label(&self) -> &'static str {
        match self {
            Self::Present { .. } => "file",
            Self::Missing { .. } => "none",
            Self::NoTarget { .. } => "no target",
            Self::Unreadable { .. } => "invalid",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum PromptMutationLayerState {
    Present {
        id: String,
        status: kuzushi_core::PromptMutationStatus,
        hash: String,
    },
    Missing,
    NoTarget,
    Unreadable,
}

impl PromptMutationLayerState {
    fn layer(&self) -> PromptStackLayer {
        match self {
            Self::Present { id, status, hash } => prompt_stack_layer(
                "mutation",
                mutation_status_label(*status),
                prompt_mutation_layer_path(id),
                hash,
            ),
            Self::Missing => prompt_stack_layer("mutation", "inactive", "not configured", "-"),
            Self::NoTarget => prompt_stack_layer(
                "mutation",
                "no target",
                prompt_mutations_relative_path(),
                "-",
            ),
            Self::Unreadable => prompt_stack_layer(
                "mutation",
                "unreadable",
                prompt_mutations_relative_path(),
                "invalid",
            ),
        }
    }
}

fn prompt_final_layer(
    override_state: &PromptOverrideLayerState,
    mutation_state: &PromptMutationLayerState,
    base_hash: &str,
) -> PromptStackLayer {
    match mutation_state {
        PromptMutationLayerState::Present {
            id,
            status: kuzushi_core::PromptMutationStatus::Pending,
            ..
        } => prompt_stack_layer(
            "final",
            "blocked: mutation pending approval",
            prompt_mutation_layer_path(id),
            "-",
        ),
        PromptMutationLayerState::Present {
            id,
            status: kuzushi_core::PromptMutationStatus::Approved,
            hash,
        } => prompt_stack_layer(
            "final",
            "approved mutation active",
            prompt_mutation_layer_path(id),
            hash,
        ),
        _ => override_state.final_layer(base_hash),
    }
}

fn mutation_status_label(status: kuzushi_core::PromptMutationStatus) -> &'static str {
    match status {
        kuzushi_core::PromptMutationStatus::Pending => "pending approval",
        kuzushi_core::PromptMutationStatus::Approved => "approved",
        kuzushi_core::PromptMutationStatus::Rejected => "rejected",
    }
}

fn prompt_mutation_layer_state(
    app: &ShellApp,
    module: &str,
    verb: &str,
) -> PromptMutationLayerState {
    let Some(target) = app.target_path_buf() else {
        return PromptMutationLayerState::NoTarget;
    };
    match app
        .workbench_cache()
        .borrow()
        .cached_prompt_mutations(Some(target))
    {
        ViewDataState::Ready(PromptMutationsState::Ready(mutations)) => {
            let Some(mutation) = mutations
                .into_iter()
                .rev()
                .find(|mutation| mutation.module_id == module && mutation.verb == verb)
            else {
                return PromptMutationLayerState::Missing;
            };
            let hash = mutation.content_hash();
            PromptMutationLayerState::Present {
                id: mutation.id,
                status: mutation.status,
                hash,
            }
        }
        ViewDataState::Ready(PromptMutationsState::Unreadable) => {
            PromptMutationLayerState::Unreadable
        }
        ViewDataState::NotRequested | ViewDataState::Loading => PromptMutationLayerState::Missing,
    }
}

fn prompt_mutation_layer_path(id: &str) -> String {
    format!("{}:{id}", prompt_mutations_relative_path())
}

fn prompt_mutations_relative_path() -> String {
    format!(
        "{}/{}/{}",
        kuzushi_core::KUZUSHI_STATE_DIR,
        kuzushi_core::WORKSPACE_STATE_VERSION_DIR,
        kuzushi_core::PROMPT_MUTATIONS_FILE
    )
}

fn prompt_override_layer_state(
    app: &ShellApp,
    module: &str,
    verb: &str,
) -> PromptOverrideLayerState {
    let relative = kuzushi_core::relative_prompt_override_path(module, verb)
        .display()
        .to_string();
    let Some(target) = app.target_path_buf() else {
        return PromptOverrideLayerState::NoTarget { path: relative };
    };
    let path = kuzushi_core::prompt_override_path(target, module, verb);
    match app
        .workbench_cache()
        .borrow()
        .cached_prompt_override_hash(target, &path)
    {
        ViewDataState::Ready(Ok(Some(hash))) => PromptOverrideLayerState::Present {
            path: relative,
            hash,
        },
        ViewDataState::Ready(Ok(None)) => PromptOverrideLayerState::Missing { path: relative },
        ViewDataState::Ready(Err(_)) => PromptOverrideLayerState::Unreadable { path: relative },
        ViewDataState::NotRequested | ViewDataState::Loading => {
            PromptOverrideLayerState::Missing { path: relative }
        }
    }
}

#[cfg(test)]
mod tests;
