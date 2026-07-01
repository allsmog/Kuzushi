use super::*;

impl ShellApp {
    pub(crate) fn prompt_mutate(&mut self, args: &str) {
        let Some((verb, text)) = prompt_mutation_args(args) else {
            self.log(
                "prompt",
                "mutate requires a verb and quoted value: prompt mutate triage \"focus on auth\"",
            );
            return;
        };
        let Some((workspace, module)) = self.prompt_mutation_scope("mutate") else {
            return;
        };
        let mutation = kuzushi_core::PromptMutation::new(module, verb, text, "operator");
        match kuzushi_core::append_prompt_mutation(&workspace, &mutation) {
            Ok(()) => self.log(
                "prompt",
                format!(
                    "mutation {} pending for {}:{} ({} bytes); approve with prompt approve {}",
                    mutation.id,
                    mutation.module_id,
                    mutation.verb,
                    mutation.text.len(),
                    mutation.id
                ),
            ),
            Err(error) => self.log(
                "error",
                format!("could not record prompt mutation: {error}"),
            ),
        }
    }

    pub(crate) fn prompt_approve_mutation(&mut self, args: &str) {
        self.prompt_set_mutation_status(args, kuzushi_core::PromptMutationStatus::Approved);
    }

    pub(crate) fn prompt_reject_mutation(&mut self, args: &str) {
        self.prompt_set_mutation_status(args, kuzushi_core::PromptMutationStatus::Rejected);
    }

    fn prompt_set_mutation_status(
        &mut self,
        args: &str,
        status: kuzushi_core::PromptMutationStatus,
    ) {
        let Some((id, reason)) = prompt_mutation_status_args(args) else {
            self.log(
                "prompt",
                format!("{} requires a mutation id", status.label()),
            );
            return;
        };
        let Some((workspace, _module)) = self.prompt_mutation_scope(status.label()) else {
            return;
        };
        let approved_mutation = if status == kuzushi_core::PromptMutationStatus::Approved {
            prompt_mutation_by_id(&workspace, id)
        } else {
            None
        };
        match kuzushi_core::set_prompt_mutation_status(&workspace, id, status, reason) {
            Ok(true) => {
                if let Some(mutation) = approved_mutation {
                    if let Err(error) = apply_approved_prompt_mutation(&workspace, &mutation) {
                        self.log(
                            "error",
                            format!("approved mutation {id} but could not write prompt override: {error}"),
                        );
                        return;
                    }
                }
                self.log("prompt", format!("{} prompt mutation {id}", status.label()));
            }
            Ok(false) => self.log("prompt", format!("no prompt mutation named {id}")),
            Err(error) => self.log(
                "error",
                format!("could not {} prompt mutation {id}: {error}", status.label()),
            ),
        }
    }

    fn prompt_mutation_scope(
        &mut self,
        action: &str,
    ) -> Option<(kuzushi_core::WorkspaceTarget, String)> {
        let Some(target) = self.target.as_deref() else {
            self.log(
                "prompt",
                format!("prompt {action} requires a workspace target"),
            );
            return None;
        };
        let Some(module) = self.focused_module.clone() else {
            self.log("prompt", format!("prompt {action} requires /use <module>"));
            return None;
        };
        match kuzushi_core::WorkspaceTarget::new(target) {
            Ok(workspace) => Some((workspace, module)),
            Err(error) => {
                self.log("prompt", format!("target unavailable: {error}"));
                None
            }
        }
    }
}

fn prompt_mutation_by_id(
    workspace: &kuzushi_core::WorkspaceTarget,
    id: &str,
) -> Option<kuzushi_core::PromptMutation> {
    kuzushi_core::load_prompt_mutations(workspace)
        .ok()?
        .into_iter()
        .find(|mutation| mutation.id == id)
}

fn apply_approved_prompt_mutation(
    workspace: &kuzushi_core::WorkspaceTarget,
    mutation: &kuzushi_core::PromptMutation,
) -> anyhow::Result<()> {
    let path =
        kuzushi_core::prompt_override_path(workspace.root(), &mutation.module_id, &mutation.verb);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, &mutation.text)?;
    Ok(())
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
