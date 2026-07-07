use super::*;

impl ShellApp {
    pub(crate) fn prompt_mutate(&mut self, args: &str) -> Vec<ShellEffect> {
        let Some((verb, text)) = prompt_mutation_args(args) else {
            self.log(
                "prompt",
                "mutate requires a verb and quoted value: prompt mutate triage \"focus on auth\"",
            );
            return Vec::new();
        };
        let Some((target, module)) = self.prompt_mutation_effect_scope("mutate") else {
            return Vec::new();
        };
        vec![ShellEffect::RecordPromptMutation(PromptMutationRecord {
            target: Some(target),
            module,
            verb: verb.to_string(),
            text: text.to_string(),
        })]
    }

    pub(crate) fn record_prompt_mutation_effect(&mut self, record: PromptMutationRecord) {
        let Some(workspace) = self.prompt_mutation_workspace(record.target.as_ref(), "mutate")
        else {
            return;
        };
        let mutation = kuzushi_core::PromptMutation::new_at(
            unix_time_ms(),
            record.module,
            &record.verb,
            &record.text,
            "operator",
        );
        match kuzushi_core::append_prompt_mutation(&workspace, &mutation) {
            Ok(()) => self.log_recorded_prompt_mutation(&mutation),
            Err(error) => self.log(
                "error",
                format!("could not record prompt mutation: {error}"),
            ),
        }
    }

    fn log_recorded_prompt_mutation(&mut self, mutation: &kuzushi_core::PromptMutation) {
        self.workbench_cache()
            .borrow_mut()
            .invalidate_prompt_mutations();
        self.log(
            "prompt",
            format!(
                "mutation {} pending for {}:{} ({} bytes); approve with prompt approve {}",
                mutation.id,
                mutation.module_id,
                mutation.verb,
                mutation.text.len(),
                mutation.id
            ),
        );
    }

    pub(crate) fn prompt_approve_mutation(&mut self, args: &str) -> Vec<ShellEffect> {
        self.reduce_prompt_mutation_status(args, kuzushi_core::PromptMutationStatus::Approved)
    }

    pub(crate) fn prompt_reject_mutation(&mut self, args: &str) -> Vec<ShellEffect> {
        self.reduce_prompt_mutation_status(args, kuzushi_core::PromptMutationStatus::Rejected)
    }

    fn reduce_prompt_mutation_status(
        &mut self,
        args: &str,
        status: kuzushi_core::PromptMutationStatus,
    ) -> Vec<ShellEffect> {
        let Some((id, reason)) = prompt_mutation_status_args(args) else {
            self.log(
                "prompt",
                format!("{} requires a mutation id", status.label()),
            );
            return Vec::new();
        };
        let Some((target, _module)) = self.prompt_mutation_effect_scope(status.label()) else {
            return Vec::new();
        };
        vec![ShellEffect::UpdatePromptMutationStatus(
            PromptMutationStatusUpdate {
                target: Some(target),
                id: id.to_string(),
                status,
                reason: reason.map(ToString::to_string),
            },
        )]
    }

    pub(crate) fn update_prompt_mutation_status_effect(
        &mut self,
        update: PromptMutationStatusUpdate,
    ) {
        let Some(workspace) =
            self.prompt_mutation_workspace(update.target.as_ref(), update.status.label())
        else {
            return;
        };
        if update.status == kuzushi_core::PromptMutationStatus::Approved {
            self.approve_prompt_mutation(&workspace, &update.id, update.reason.as_deref());
        } else {
            self.set_prompt_mutation_status(
                &workspace,
                &update.id,
                update.status,
                update.reason.as_deref(),
            );
        }
    }

    fn approve_prompt_mutation(
        &mut self,
        workspace: &kuzushi_core::WorkspaceTarget,
        id: &str,
        reason: Option<&str>,
    ) {
        match kuzushi_core::approve_prompt_mutation(workspace, id, reason) {
            Ok(Some(_)) => {
                self.workbench_cache()
                    .borrow_mut()
                    .invalidate_prompt_mutations();
                self.log("prompt", format!("approved prompt mutation {id}"));
            }
            Ok(None) => self.log("prompt", format!("no prompt mutation named {id}")),
            Err(error) => self.log(
                "error",
                format!("could not approve prompt mutation {id}: {error}"),
            ),
        }
    }

    fn set_prompt_mutation_status(
        &mut self,
        workspace: &kuzushi_core::WorkspaceTarget,
        id: &str,
        status: kuzushi_core::PromptMutationStatus,
        reason: Option<&str>,
    ) {
        match kuzushi_core::set_prompt_mutation_status(workspace, id, status, reason) {
            Ok(true) => {
                self.workbench_cache()
                    .borrow_mut()
                    .invalidate_prompt_mutations();
                self.log("prompt", format!("{} prompt mutation {id}", status.label()));
            }
            Ok(false) => self.log("prompt", format!("no prompt mutation named {id}")),
            Err(error) => self.log(
                "error",
                format!("could not {} prompt mutation {id}: {error}", status.label()),
            ),
        }
    }

    fn prompt_mutation_effect_scope(&mut self, action: &str) -> Option<(PathBuf, String)> {
        let target = self.target_owned().or_else(|| {
            self.log(
                "prompt",
                format!("prompt {action} requires a workspace target"),
            );
            None
        })?;
        let module = self.focused_module_owned().or_else(|| {
            self.log("prompt", format!("prompt {action} requires /use <module>"));
            None
        })?;
        Some((target, module))
    }

    fn prompt_mutation_workspace(
        &mut self,
        target: Option<&PathBuf>,
        action: &str,
    ) -> Option<kuzushi_core::WorkspaceTarget> {
        let Some(target) = target else {
            self.log(
                "prompt",
                format!("prompt {action} requires a workspace target"),
            );
            return None;
        };
        match kuzushi_core::WorkspaceTarget::new(target) {
            Ok(workspace) => Some(workspace),
            Err(error) => {
                self.log("prompt", format!("target unavailable: {error}"));
                None
            }
        }
    }
}

fn prompt_mutation_args(args: &str) -> Option<(&str, &str)> {
    let mut parts = args.splitn(2, char::is_whitespace);
    let verb = parts.next().unwrap_or("").trim();
    let text = parts.next().unwrap_or("").trim();
    if prompt_mutation_verb_invalid(verb) || text.is_empty() {
        return None;
    }
    Some((verb, unquote_prompt_mutation_text(text)))
}

fn prompt_mutation_status_args(args: &str) -> Option<(&str, Option<&str>)> {
    let mut parts = args.splitn(2, char::is_whitespace);
    let id = parts.next().unwrap_or("").trim();
    if id.is_empty() {
        return None;
    }
    let reason = parts
        .next()
        .map(str::trim)
        .filter(|value| !value.is_empty());
    Some((id, reason))
}

fn prompt_mutation_verb_invalid(verb: &str) -> bool {
    verb.is_empty() || verb.contains('/') || verb.contains('\\')
}

fn unquote_prompt_mutation_text(value: &str) -> &str {
    value
        .strip_prefix('"')
        .and_then(|stripped| stripped.strip_suffix('"'))
        .unwrap_or(value)
}
