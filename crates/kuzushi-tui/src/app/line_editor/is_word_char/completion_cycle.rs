use super::*;

impl ShellApp {
    pub fn completion_candidates(&self, input: &str) -> Vec<String> {
        let request = CompletionRequest::parse(input);
        if let Some(prefix) = request.command_prefix() {
            return command_completion_candidates(prefix, request.slash);
        }

        let prefix_words = request.prefix_words();
        let current = request.current();
        if let Some(values) = primary_completion_values(self, request.command()) {
            return complete_value_candidates(request.slash, prefix_words, current, values);
        }
        nested_completion_candidates(
            self,
            request.command(),
            request.slash,
            prefix_words,
            current,
        )
        .unwrap_or_default()
    }

    pub(crate) fn apply_completion(&mut self) {
        // First Tab: snapshot the operator's prefix and produce the candidate
        // list. Subsequent Tabs advance through the list without recomputing,
        // so cycling stays stable even after we've replaced `input` with a
        // longer candidate that would otherwise filter the candidates down.
        let active_cycle = self.editor_mut().take_completion_cycle();
        let cycle = match active_cycle {
            Some(cycle)
                if !cycle.candidates.is_empty()
                    && self.input().eq(cycle.candidates[cycle.index].as_str()) =>
            {
                cycle
            }
            _ => {
                let candidates = self.completion_candidates(self.input());
                if candidates.is_empty() {
                    return;
                }
                CompletionCycle {
                    prefix: self.input().to_string(),
                    candidates,
                    index: usize::MAX, // pre-increment in next step lands on 0
                }
            }
        };
        let next_index = if cycle.index == usize::MAX {
            0
        } else {
            (cycle.index + 1) % cycle.candidates.len()
        };
        let candidate = cycle.candidates[next_index].clone();
        self.set_input(candidate);
        self.editor_mut().set_completion_cycle(CompletionCycle {
            prefix: cycle.prefix,
            candidates: cycle.candidates,
            index: next_index,
        });
    }

    pub(crate) fn reset_completion_cycle(&mut self) {
        self.editor_mut().reset_completion_cycle();
    }

    /// Inline ghost-text suggestion shown after the cursor when the cursor sits
    /// at the end of the line. Returns the *tail* — the chars the operator would
    /// gain by pressing Tab — or `None` if there is no completion or the cursor
    /// is mid-line. Empty inputs return `None` so the cold-start prompt isn't
    /// noisy.
    pub fn completion_preview(&self) -> Option<String> {
        self.completion_preview_ref()
            .map(|preview| preview.to_string())
    }

    pub(crate) fn completion_preview_ref(&self) -> Option<std::cell::Ref<'_, str>> {
        let key = self.completion_preview_key();
        if !self.editor().completion_preview_matches(key, self.target()) {
            let preview = self.compute_completion_preview();
            self.editor()
                .store_completion_preview(key, self.target(), preview);
        }
        self.editor().completion_preview()
    }

    fn compute_completion_preview(&self) -> Option<String> {
        if self.input().is_empty() || self.cursor() != self.input().chars().count() {
            return None;
        }
        let candidate = self
            .completion_candidates(self.input())
            .into_iter()
            .next()?;
        completion_preview_tail(self.input(), &candidate)
    }

    fn completion_preview_key(&self) -> CompletionPreviewKey {
        let (cache_generation, command_provider_generation) =
            self.workbench_cache().borrow().completion_generations();
        CompletionPreviewKey {
            editor_revision: self.editor().revision(),
            cursor: self.cursor(),
            input_mode: self.input_mode(),
            cache_generation,
            command_provider_generation,
        }
    }

    #[cfg(test)]
    pub(crate) fn completion_preview_recomputations_for_test(&self) -> usize {
        self.editor().completion_preview_recomputations()
    }

    #[cfg(test)]
    pub(crate) fn completion_source_reads_for_test(&self) -> usize {
        self.workbench_cache().borrow().completion_source_reads()
    }
}

fn completion_preview_tail(input: &str, candidate: &str) -> Option<String> {
    if candidate == input {
        return None;
    }
    candidate
        .strip_prefix(input)
        .filter(|tail| !tail.is_empty())
        .map(str::to_string)
        .or_else(|| Some(format!(" -> {candidate}")))
}
