use super::*;

const PROMPT_VERB_HELP: &str =
    "verbs: edit/show/diff/reset/set/list | mutate <name> \"value\" | approve <id> | reject <id>";
const UNKNOWN_PROMPT_VERB_HELP: &str = "try edit/show/diff/reset/set/list/mutate/approve/reject";

struct PromptVerbInput<'a> {
    verb: &'a str,
    rest: &'a str,
}

impl ShellApp {
    pub(crate) fn handle_prompt_verb(&mut self, raw: &str) -> Vec<ShellEffect> {
        self.reduce_prompt_verb(raw)
    }

    pub(crate) fn reduce_prompt_verb(&mut self, raw: &str) -> Vec<ShellEffect> {
        let input = parse_prompt_verb(raw);
        if input.verb.is_empty() {
            self.log_prompt_verb_help();
            return Vec::new();
        }
        self.reduce_prompt_verb_input(input)
    }

    fn reduce_prompt_verb_input(&mut self, input: PromptVerbInput<'_>) -> Vec<ShellEffect> {
        match input.verb {
            "diff" => self.reduce_prompt_diff(input.rest),
            "edit" => self.reduce_prompt_edit(input.rest),
            "list" => self.reduce_prompt_list(),
            "mutate" | "mutation" => self.prompt_mutate(input.rest),
            "approve" => self.prompt_approve_mutation(input.rest),
            "reject" => self.prompt_reject_mutation(input.rest),
            "reset" => self.reduce_prompt_reset(input.rest),
            "set" => self.reduce_prompt_set(input.rest),
            "show" => self.reduce_prompt_show(input.rest),
            other => {
                self.log_unknown_prompt_verb(other);
                Vec::new()
            }
        }
    }

    fn log_prompt_verb_help(&mut self) {
        self.log("prompt", PROMPT_VERB_HELP);
    }

    fn log_unknown_prompt_verb(&mut self, verb: &str) {
        self.log(
            "prompt",
            format!("unknown prompt verb {verb:?}; {UNKNOWN_PROMPT_VERB_HELP}"),
        );
    }
}

fn parse_prompt_verb(raw: &str) -> PromptVerbInput<'_> {
    let raw = raw.trim();
    let mut parts = raw.splitn(2, char::is_whitespace);
    PromptVerbInput {
        verb: parts.next().unwrap_or(""),
        rest: parts.next().unwrap_or("").trim(),
    }
}
