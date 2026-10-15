use super::*;

impl ShellApp {
    pub(crate) fn provider_label(&self) -> String {
        self.config()
            .model
            .as_deref()
            .and_then(|model| model.split_once(':').map(|(provider, _)| provider))
            .map(display_model_provider)
            .filter(|provider| !provider.trim().is_empty())
            .unwrap_or("— none active (open /model)")
            .to_string()
    }

    pub(crate) fn handle_provider_command(&mut self, provider: Option<String>) {
        self.set_shell_view(ShellView::Config);
        if let Some(provider) = provider {
            let provider = provider.trim();
            if provider.is_empty() || provider.contains(':') {
                self.log(
                    "error",
                    "provider expects only the provider prefix. Next: model 1, model 5, or model provider:model-id",
                );
                return;
            }
            self.log(
                "provider",
                format!(
                    "{provider} requested. Rust uses LangGraph only; providers are selected through explicit model ids. Next: model {provider}:<model-id>"
                ),
            );
            return;
        }

        self.log(
            "provider",
            format!(
                "{} via LangGraph. Supported selectors: openai, anthropic. Next: model",
                self.provider_label()
            ),
        );
    }

    pub(crate) fn handle_backend_command(&mut self, backend: Option<String>) {
        self.set_shell_view(ShellView::Config);
        if let Some(backend) = backend {
            let normalized = backend.trim().to_ascii_lowercase();
            if normalized == "LangGraph" || normalized == "langgraph_runtime" {
                self.log("backend", "LangGraph already selected");
            } else {
                self.log(
                    "error",
                    format!(
                        "unsupported Rust backend {backend:?}. Supported: LangGraph. Next: backend LangGraph"
                    ),
                );
            }
            return;
        }

        self.log(
            "backend",
            format!(
                "{}; bridge {}",
                runtime_backend_label(self.config()),
                bridge_command_status(self.config())
            ),
        );
    }

    pub(crate) fn show_cost_status(&mut self) {
        self.set_shell_view(ShellView::Cost);
        let [session, last] = crate::ui_view_models::cost_model(self).auth_spend_cells;
        self.log(
            "cost",
            format!("session {session}; last tool {last}. Use report for saved-run consumption."),
        );
    }
}
