use super::*;

impl ShellApp {
    fn browser_option_spec(&self, option: &str) -> Option<OptionSpec> {
        self.registry()
            .resolve_tool(&self.router.options().tool_name)?
            .options
            .iter()
            .find(|spec| spec.name == option)
            .cloned()
    }

    pub(super) fn begin_browser_option_edit(&mut self) {
        let Some(option) = self.selected_browser_option() else {
            return;
        };
        let Some(spec) = self.browser_option_spec(&option) else {
            return;
        };
        if !option_is_operator_editable(&spec) {
            self.router.options_browser_mut().notice = Some("This value is supplied by the workflow. Review it in the approved plan or context picker.".into());
            return;
        }
        self.open_browser_option_editor(spec);
    }

    fn open_browser_option_editor(&mut self, spec: OptionSpec) {
        let tool = self.router.options().tool_name.clone();
        let value = self
            .option_store()
            .effective_stored_values(&tool)
            .get(&spec.name)
            .cloned()
            .or(spec.default.clone());
        let draft = self
            .router
            .options_browser_mut()
            .drafts
            .remove(&(tool.clone(), spec.name.clone()))
            .unwrap_or_else(|| {
                FieldEditor::new(value.as_ref().map(format_option_value).unwrap_or_default())
            });
        let edit = ToolOptionEdit {
            tool,
            option: spec.name.clone(),
            field: draft,
            global: Self::tool_option_has_global_scope(&spec.name),
            error: None,
            error_scroll: 0,
        };
        let state = self.router.options_browser_mut();
        state.selected = Some(spec.name);
        state.edit = Some(edit);
        state.notice = None;
    }

    pub(crate) fn handle_tool_option_editor_key(&mut self, key: KeyEvent) -> Option<InputUpdate> {
        if !self.tool_option_editor_open() || is_quit_chord(key) {
            return None;
        }
        if option_editor_save(key) {
            return Some(self.save_browser_option(
                key.modifiers == KeyModifiers::CONTROL && key.code == KeyCode::Char('g'),
            ));
        }
        self.update_browser_option_editor(key);
        Some(InputUpdate::handled())
    }

    pub(crate) fn tool_option_editor_open(&self) -> bool {
        self.shell_view() == ShellView::Options
            && self.advisory().pending_confirm.is_none()
            && self.router.options_browser().edit.is_some()
    }

    fn update_browser_option_editor(&mut self, key: KeyEvent) {
        if key.code == KeyCode::Esc && key.modifiers.is_empty() {
            self.keep_browser_option_draft();
            return;
        }
        if matches!(key.code, KeyCode::PageUp | KeyCode::PageDown) {
            self.page_browser_option_error(key.code == KeyCode::PageDown);
            return;
        }
        let edit = self.router.options_browser_mut().edit.as_mut().unwrap();
        let mut field = edit.field.clone();
        if key.code == KeyCode::Enter && key.modifiers == KeyModifiers::SHIFT {
            field.insert("\n");
        } else {
            field.handle_key(key);
        }
        apply_browser_field(edit, field);
    }

    fn keep_browser_option_draft(&mut self) {
        let state = self.router.options_browser_mut();
        let edit = state.edit.take().unwrap();
        state.drafts.insert((edit.tool, edit.option), edit.field);
        state.notice = Some("Draft kept. Enter reopens it; no stored value changed.".into());
    }

    pub(crate) fn paste_browser_option(&mut self, text: &str) -> bool {
        if !self.tool_option_editor_open() {
            return false;
        }
        let edit = self.router.options_browser_mut().edit.as_mut().unwrap();
        let mut field = edit.field.clone();
        field.insert(text);
        apply_browser_field(edit, field);
        true
    }

    fn page_browser_option_error(&mut self, down: bool) {
        let (page, maximum) = crate::renderer::option_error_page_bounds(self);
        let edit = self.router.options_browser_mut().edit.as_mut().unwrap();
        let offset = edit.error_scroll.min(maximum);
        edit.error_scroll = if down {
            offset.saturating_add(page).min(maximum)
        } else {
            offset.saturating_sub(page)
        };
    }

    fn save_browser_option(&mut self, global: bool) -> InputUpdate {
        let edit = self.router.options_browser().edit.as_ref().unwrap().clone();
        match self.validate_browser_edit(&edit) {
            Ok((spec, value)) => self.commit_browser_edit(edit, spec, value, global),
            Err(error) => {
                let edit = self.router.options_browser_mut().edit.as_mut().unwrap();
                edit.error = Some(error.to_string());
                edit.error_scroll = 0;
                InputUpdate::handled()
            }
        }
    }

    fn validate_browser_edit(
        &self,
        edit: &ToolOptionEdit,
    ) -> Result<(OptionSpec, serde_json::Value)> {
        anyhow::ensure!(
            edit.tool == self.router.options().tool_name,
            "Tool changed. Reopen its options before saving."
        );
        let spec = self
            .browser_option_spec(&edit.option)
            .context("This option is no longer registered")?;
        let value = coerce_editor_value(&spec, edit.field.text())?;
        Ok((spec, value))
    }

    fn commit_browser_edit(
        &mut self,
        edit: ToolOptionEdit,
        spec: OptionSpec,
        value: serde_json::Value,
        global: bool,
    ) -> InputUpdate {
        let global = global || edit.global;
        let effects = self.store_edited_tool_option(&edit.tool, spec, value, global);
        let state = self.router.options_browser_mut();
        state.edit = None;
        state.detail_scroll = 0;
        state.pending_save = global.then_some((edit.tool, edit.option));
        state.notice = Some(
            if global {
                "Global value updated. Saving to operator settings."
            } else {
                "Saved for this session. Ctrl+G in the editor saves globally."
            }
            .into(),
        );
        InputUpdate {
            handled: true,
            effects,
        }
    }

    pub(crate) fn complete_browser_option_save(&mut self, scope: OptionScope, persisted: bool) {
        if scope != OptionScope::Global {
            return;
        }
        let Some((tool, option)) = self.router.options_browser_mut().pending_save.take() else {
            return;
        };
        let message = if persisted {
            self.global_option_save_notice(&tool, &option)
        } else {
            "Global value changed in memory, but could not be saved. Inspect logs, then retry Ctrl+G.".into()
        };
        self.router.options_browser_mut().notice = Some(message);
    }

    fn global_option_save_notice(&self, tool: &str, option: &str) -> String {
        match self.option_store().effective_stored_value_scope(tool, option) {
            Some(OptionScope::Session) => format!("Saved globally. A session override still applies. Use unset {option} to use the global value here."),
            Some(OptionScope::Workspace) => "Saved globally. A workspace override still applies. Review workspace settings to change the effective value.".into(),
            _ => "Saved globally. This setting survives restart.".into(),
        }
    }
}

fn apply_browser_field(edit: &mut ToolOptionEdit, field: FieldEditor) {
    edit.error_scroll = 0;
    if field.text().contains('\0') || field.text().len() > 65536 {
        edit.error = Some(
            "Keep this field within 64 KiB and omit null characters. Your draft is unchanged."
                .into(),
        );
        return;
    }
    edit.field = field;
    edit.error = None;
}

fn option_editor_save(key: KeyEvent) -> bool {
    (key.code == KeyCode::Enter && key.modifiers.is_empty())
        || (key.modifiers == KeyModifiers::CONTROL && matches!(key.code, KeyCode::Char('s' | 'g')))
}

fn coerce_editor_value(spec: &OptionSpec, text: &str) -> Result<serde_json::Value> {
    if matches!(spec.option_type, OptionType::String | OptionType::Path) {
        return kuzushi_core::modules::coerce_option_value(
            spec,
            serde_json::Value::String(text.into()),
        );
    }
    coerce_raw_option_value(spec, text)
}
