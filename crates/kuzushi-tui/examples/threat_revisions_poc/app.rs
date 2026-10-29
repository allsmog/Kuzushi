//! PoC state, actions and key handling. Five tabs, one focus each:
//! Summary · DFD · Model (THREAT_MODEL.md) · Chat · History.

use crate::ai::{self, AiEvent, AiRequest, ChildSlot, Purpose};
use crate::chat::{self, Msg, Proposal};
use crate::md;
use crate::store::{dropped_paths, evolve, file_name, Rev, RevRef, Store};
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use kuzushi_core::capabilities::{diff_threat_model_documents, ThreatModelDocumentDiff};
use kuzushi_tui::poc_map_gallery::{selectable_count, MapGalleryPage};
use serde_json::{json, Value};
use std::path::PathBuf;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::time::Instant;

#[derive(Clone, Copy, PartialEq)]
pub enum Tab {
    Summary,
    Dfd,
    Model,
    Chat,
    History,
}

pub const TABS: [Tab; 5] = [Tab::Summary, Tab::Dfd, Tab::Model, Tab::Chat, Tab::History];

impl Tab {
    pub fn title(self) -> &'static str {
        match self {
            Tab::Summary => "Summary",
            Tab::Dfd => "DFD",
            Tab::Model => "Model",
            Tab::Chat => "Chat",
            Tab::History => "History",
        }
    }
}

#[derive(Clone, Copy, PartialEq)]
pub enum ModelView {
    Rendered,
    Raw,
    Diff,
}

pub struct ResultCard {
    pub produced: RevRef,
    pub pre_active: Option<RevRef>,
    pub derivation: &'static str,
    /// How a model-produced result was made, so `g` can redo it.
    pub recipe: Option<Recipe>,
}

/// The inputs of a refine: operator context, attached files, attempt number.
#[derive(Clone)]
pub struct Recipe {
    pub seed: String,
    pub files: Vec<String>,
    pub attempt: u32,
}

/// A request for the main loop to suspend the TUI and run `$EDITOR`.
pub struct ExternalEdit {
    pub path: PathBuf,
    pub base: RevRef,
    pub original: String,
}

pub struct Busy {
    pub label: &'static str,
    pub since: Instant,
}

pub struct App {
    pub store: Store,
    pub tab: Tab,
    pub summary_sel: usize,
    pub dfd_sel: usize,
    pub model_view: ModelView,
    pub model_scroll: u16,
    /// Revision shown on the Model tab; `None` follows the active one.
    pub viewing: Option<RevRef>,
    /// Diff baseline override (result review); `None` = previous version.
    pub diff_base: Option<RevRef>,
    pub hist_sel: usize,
    pub chat: Vec<Msg>,
    pub composer: String,
    pub attachments: Vec<PathBuf>,
    pub pending: Option<Proposal>,
    pub chat_scroll: u16,
    pub busy: Option<Busy>,
    session_id: Option<String>,
    /// Revision whose THREAT_MODEL.md the chat session has already seen.
    context_sent: Option<RevRef>,
    /// The in-flight refine, attached to its result when it lands.
    refine_recipe: Option<Recipe>,
    /// Result set aside by `g`; restored if the regeneration fails.
    set_aside: Option<ResultCard>,
    ai_tx: Sender<AiEvent>,
    ai_rx: Receiver<AiEvent>,
    ai_child: ChildSlot,
    pub external_edit: Option<ExternalEdit>,
    pub card: Option<ResultCard>,
    pub stale: bool,
    pub confirm_restore: Option<RevRef>,
    pub help: bool,
    pub status: String,
    sim_runs: usize,
    pub quit: bool,
}

impl App {
    pub fn new(store: Store) -> Self {
        let stale = store.active.as_ref().and_then(|a| store.rev(a)).and_then(|r| r.verification.as_deref()) == Some("stale");
        let (ai_tx, ai_rx) = channel();
        let mut app = Self {
            store,
            tab: Tab::Summary,
            summary_sel: 0,
            dfd_sel: 0,
            model_view: ModelView::Rendered,
            model_scroll: 0,
            viewing: None,
            diff_base: None,
            hist_sel: 0,
            chat: Vec::new(),
            composer: String::new(),
            attachments: Vec::new(),
            pending: None,
            chat_scroll: 0,
            busy: None,
            session_id: None,
            context_sent: None,
            refine_recipe: None,
            set_aside: None,
            ai_tx,
            ai_rx,
            ai_child: Default::default(),
            external_edit: None,
            card: None,
            stale,
            confirm_restore: None,
            help: false,
            status: String::new(),
            sim_runs: 0,
            quit: false,
        };
        app.hist_sel = app.history_rows().iter().position(|r| Some(r) == app.store.active.as_ref()).unwrap_or(0);
        app
    }

    // ───────────────────────── queries ─────────────────────────

    pub fn system_name(&self) -> String {
        self.store.target.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_else(|| "target".into())
    }

    pub fn md_for(&self, rev: &Rev) -> String {
        md::render(&rev.document, &self.system_name(), &self.store.origin)
    }

    pub fn shown(&self) -> Option<RevRef> {
        self.viewing.clone().or_else(|| self.store.active.clone())
    }

    pub fn diff_baseline(&self) -> Option<RevRef> {
        self.diff_base.clone().or_else(|| self.shown().and_then(|s| self.store.previous(&s)))
    }

    pub fn history_rows(&self) -> Vec<RevRef> {
        self.store
            .lineages
            .iter()
            .enumerate()
            .flat_map(|(i, l)| l.revisions.iter().map(move |r| RevRef { lineage: i, rev: r.id.clone() }))
            .collect()
    }

    pub fn is_active(&self, r: &RevRef) -> bool {
        self.store.active.as_ref() == Some(r)
    }

    pub fn active_doc(&self) -> Option<Value> {
        self.store.active.as_ref().and_then(|a| self.store.rev(a)).map(|r| r.document.clone())
    }

    /// Where the model runs: the target repo when real, else a scratch dir.
    fn ai_cwd(&self) -> PathBuf {
        if self.store.target.is_dir() {
            return self.store.target.clone();
        }
        let dir = std::env::temp_dir().join("kuzushi-threat-poc");
        let _ = std::fs::create_dir_all(&dir);
        dir
    }

    // ───────────────────────── model versions ─────────────────────────

    fn event(&mut self, msg: impl Into<String>) {
        let msg = msg.into();
        self.status = msg.trim_start().trim_start_matches('⎿').trim().to_string();
        self.chat.push(Msg::Event(msg));
    }

    fn activate(&mut self, r: RevRef) {
        self.event(format!("threat-model:activate → {} is active", self.store.label(&r)));
        self.store.active = Some(r);
        self.viewing = None;
    }

    fn restore(&mut self, r: RevRef) {
        let Some(doc) = self.store.rev(&r).map(|x| x.document.clone()) else { return };
        let from = self.store.label(&r);
        let new_ref = self.store.commit(r.lineage, "Restore", doc);
        self.store.active = Some(new_ref.clone());
        self.event(format!("threat-model:restore {from} → {} (active)", self.store.vlabel(&new_ref)));
        self.hist_sel = self.history_rows().iter().position(|x| *x == new_ref).unwrap_or(0);
    }

    /// Commit a new active version in the active lineage and raise the banner.
    fn commit_result(&mut self, source: &str, derivation: &'static str, document: Value, recipe: Option<Recipe>) {
        let Some(active) = self.store.active.clone() else { return };
        let produced = self.store.commit(active.lineage, source, document);
        self.store.active = Some(produced.clone());
        self.stale = false;
        self.event(format!("{} created · v review · u keep · g regenerate · x discard", self.store.label(&produced)));
        self.card = Some(ResultCard { produced, pre_active: Some(active), derivation, recipe });
    }

    /// Demo helper: a Map-phase build finishing (no model call).
    fn simulate_map_run(&mut self) {
        let Some(doc) = self.active_doc() else { return };
        self.sim_runs += 1;
        self.commit_result("Build", "Build", evolve(&doc, self.sim_runs % 2 == 0, self.sim_runs), None);
    }

    fn accept_card(&mut self) {
        if let Some(card) = self.card.take() {
            self.event(format!("kept {}", self.store.label(&card.produced)));
        }
        self.diff_base = None;
    }

    /// Discarding rolls the pointer back; the version stays in History.
    fn discard_card(&mut self) {
        let Some(card) = self.card.take() else { return };
        self.diff_base = None;
        self.viewing = None;
        if let Some(pre) = card.pre_active {
            self.event(format!("discarded {} · {} active again (kept in History)", self.store.label(&card.produced), self.store.vlabel(&pre)));
            self.store.active = Some(pre);
        }
    }

    pub fn review_card(&mut self) {
        let Some(card) = self.card.as_ref() else { return };
        self.viewing = Some(card.produced.clone());
        self.diff_base = card.pre_active.clone();
        self.model_view = ModelView::Diff;
        self.model_scroll = 0;
        self.tab = Tab::Model;
    }

    // ───────────────────────── editing in $EDITOR ─────────────────────────

    fn request_edit(&mut self) {
        let Some(active) = self.store.active.clone() else { return };
        if self.viewing.as_ref().is_some_and(|v| *v != active) {
            self.status = "edits apply to the active version — press a to activate this one first".into();
            return;
        }
        let Some(rev) = self.store.rev(&active) else { return };
        let original = self.md_for(rev);
        let path = std::env::temp_dir().join(format!("THREAT_MODEL.{}.{}.md", self.system_name(), self.store.vlabel(&active)));
        if let Err(e) = std::fs::write(&path, &original) {
            self.status = format!("could not write {}: {e}", path.display());
            return;
        }
        self.external_edit = Some(ExternalEdit { path, base: active, original });
    }

    /// Called by the main loop after the editor exits.
    pub fn finish_edit(&mut self, edit: ExternalEdit, editor_result: Result<(), String>) {
        if let Err(e) = editor_result {
            self.status = e;
            return;
        }
        let edited = std::fs::read_to_string(&edit.path).unwrap_or_default();
        let _ = std::fs::remove_file(&edit.path);
        if edited.trim_end() == edit.original.trim_end() {
            self.status = "no changes".into();
            return;
        }
        let Some(doc) = self.store.rev(&edit.base).map(|r| r.document.clone()) else { return };
        let outcome = md::compile_edits(&doc, &edit.original, &edited);
        if outcome.patch.as_object().is_some_and(|m| !m.is_empty()) {
            self.commit_result("OperatorEdit", "Edit", outcome.document, None);
            self.event(format!("  ⎿  apply_threat_model_patch_revision: {}", outcome.applied.join(", ")));
            self.review_card();
        }
        if !outcome.unmapped.is_empty() {
            let sections = outcome.unmapped.join(", ");
            self.start_refine(format!(
                "The operator hand-edited THREAT_MODEL.md sections {sections}. Apply the intent of these edits.\n\nEdited THREAT_MODEL.md:\n{edited}"
            ));
        }
    }

    // ───────────────────────── model calls ─────────────────────────

    fn attachment_strings(&self) -> Vec<String> {
        self.attachments.iter().map(|p| p.display().to_string()).collect()
    }

    fn add_dirs(&self) -> Vec<PathBuf> {
        let mut dirs: Vec<PathBuf> = self.attachments.iter().filter_map(|p| p.parent().map(PathBuf::from)).collect();
        dirs.dedup();
        dirs
    }

    fn send_chat(&mut self) {
        let text = std::mem::take(&mut self.composer).trim().to_string();
        self.chat_scroll = 0;
        if let Some(cmd) = text.strip_prefix('/') {
            return self.slash(cmd);
        }
        if text.is_empty() && self.attachments.is_empty() {
            return;
        }
        if self.busy.is_some() {
            self.composer = text;
            self.status = "still thinking — Esc to interrupt".into();
            return;
        }
        let Some(active) = self.store.active.clone() else { return };
        let question = if text.is_empty() { "I attached design docs — what do they change about the threat model?".to_string() } else { text };
        let mut shown = question.clone();
        for p in &self.attachments {
            shown.push_str(&format!("\n📎 {}", file_name(&p.display().to_string())));
        }
        self.chat.push(Msg::User(shown));
        // Resend THREAT_MODEL.md only when the session hasn't seen this version.
        let context = (self.context_sent.as_ref() != Some(&active)).then(|| {
            let rev = self.store.rev(&active).unwrap();
            format!("Active threat model: {} ({}).\n\n{}", self.store.label(&active), rev.source, self.md_for(rev))
        });
        let prompt = chat::chat_prompt(&question, context.as_deref(), &self.attachment_strings());
        let request = AiRequest {
            system_prompt: chat::CHAT_SYSTEM.to_string(),
            prompt,
            cwd: self.ai_cwd(),
            add_dirs: self.add_dirs(),
            resume: self.session_id.clone(),
            purpose: Purpose::Chat,
        };
        self.context_sent = Some(active);
        self.pending = None;
        self.attachments.clear();
        self.busy = Some(Busy { label: "Consulting the threat model", since: Instant::now() });
        ai::spawn(request, self.ai_tx.clone(), self.ai_child.clone());
    }

    fn start_refine(&mut self, seed: String) {
        let recipe = Recipe { seed, files: self.attachment_strings(), attempt: 1 };
        self.attachments.clear();
        self.run_refine(recipe, None);
    }

    /// `note` steers a regeneration without changing the recipe's seed.
    fn run_refine(&mut self, recipe: Recipe, note: Option<String>) {
        let Some(doc) = self.active_doc() else { return };
        if self.busy.is_some() {
            self.status = "still thinking — Esc to interrupt".into();
            return;
        }
        let names: Vec<String> = recipe.files.iter().map(|f| file_name(f)).collect();
        self.chat.push(Msg::Event(format!(
            "threat-model:build {}",
            json!({"mode": "refine", "seed": crate::store::truncate(&recipe.seed, 80), "designDocs": names, "attempt": recipe.attempt})
        )));
        let seed = match &note {
            Some(note) => format!("{}\n\n{note}", recipe.seed),
            None => recipe.seed.clone(),
        };
        let mut add_dirs: Vec<PathBuf> = recipe.files.iter().filter_map(|f| std::path::Path::new(f).parent().map(PathBuf::from)).collect();
        add_dirs.dedup();
        let request = AiRequest {
            system_prompt: chat::REFINE_SYSTEM.to_string(),
            prompt: chat::refine_prompt(&doc, &seed, &recipe.files),
            cwd: self.ai_cwd(),
            add_dirs,
            resume: None,
            purpose: Purpose::Refine,
        };
        let label = if recipe.attempt > 1 { "Regenerating the threat model" } else { "Refining the threat model" };
        self.refine_recipe = Some(recipe);
        self.busy = Some(Busy { label, since: Instant::now() });
        self.tab = Tab::Chat;
        ai::spawn(request, self.ai_tx.clone(), self.ai_child.clone());
    }

    /// Set the current result aside (previous version active again, the
    /// rejected one stays in History) and redo it, optionally with feedback.
    fn regenerate(&mut self, feedback: Option<String>) {
        if self.busy.is_some() {
            self.status = "still thinking — Esc to interrupt".into();
            return;
        }
        let Some(card) = self.card.take() else { return };
        let (derivation, recipe) = (card.derivation, card.recipe.clone());
        if recipe.is_none() && derivation != "Build" {
            self.status = "this version is your own edit — x discards it, e edits again".into();
            self.card = Some(card);
            return;
        }
        let rejected = card
            .pre_active
            .as_ref()
            .and_then(|p| self.store.rev(p))
            .zip(self.store.rev(&card.produced))
            .map(|(a, b)| headline(&diff_threat_model_documents(&a.document, &b.document)))
            .unwrap_or_default();
        let set_aside = self.store.label(&card.produced);
        if let Some(pre) = card.pre_active.clone() {
            self.store.active = Some(pre);
        }
        self.set_aside = Some(card);
        self.viewing = None;
        self.diff_base = None;
        self.event(format!("set aside {set_aside} (kept in History) · regenerating"));
        let Some(mut recipe) = recipe else { return self.simulate_map_run() };
        recipe.attempt += 1;
        let mut note = format!(
            "The operator rejected a previous attempt at this refine (it produced: {rejected}). Produce a different, better-grounded result."
        );
        if let Some(fb) = feedback.filter(|f| !f.trim().is_empty()) {
            note.push_str(&format!(" Operator feedback on that attempt: {}", fb.trim()));
        }
        self.run_refine(recipe, Some(note));
    }

    /// Main loop tick: apply finished model work.
    pub fn drain_ai(&mut self) {
        while let Ok(event) = self.ai_rx.try_recv() {
            match event {
                AiEvent::Tool(call) => self.chat.push(Msg::Tool(call)),
                AiEvent::Failed { purpose, error } => {
                    self.busy = None;
                    if purpose == Purpose::Chat {
                        self.context_sent = None;
                    }
                    self.status = format!("model call failed: {error}");
                    self.chat.push(Msg::Error(error));
                    if purpose == Purpose::Refine {
                        self.restore_set_aside();
                    }
                }
                AiEvent::Done { purpose, text, session_id, cost_usd, duration_ms } => {
                    self.busy = None;
                    self.status = format!("{:.1}s · ${cost_usd:.3}", duration_ms as f64 / 1000.0);
                    match purpose {
                        Purpose::Chat => self.finish_chat(text, session_id),
                        Purpose::Refine => self.finish_refine(&text),
                    }
                }
            }
        }
    }

    fn finish_chat(&mut self, text: String, session_id: Option<String>) {
        if session_id.is_some() {
            self.session_id = session_id;
        }
        let (markdown, action) = chat::split_action(&text);
        if !markdown.is_empty() {
            self.chat.push(Msg::Assistant(markdown));
        }
        match action {
            Ok(proposal) => self.pending = proposal,
            Err(e) => self.chat.push(Msg::Error(e)),
        }
    }

    fn finish_refine(&mut self, text: &str) {
        let Some(mut doc) = self.active_doc() else { return };
        match chat::parse_refine_patch(text) {
            Ok(patch) => {
                let keys: Vec<String> = patch.keys().cloned().collect();
                for (k, v) in patch {
                    doc[k.as_str()] = v;
                }
                let recipe = self.refine_recipe.take();
                if let Some(labels) = doc.pointer_mut("/provenance/sourceLabels").and_then(Value::as_array_mut) {
                    labels.push(json!("operator-context"));
                    for f in recipe.iter().flat_map(|r| &r.files) {
                        labels.push(json!(format!("designDoc:{}", file_name(f))));
                    }
                }
                self.chat.push(Msg::Event(format!("  ⎿  refine changed {}", keys.join(", "))));
                self.set_aside = None;
                self.commit_result("Refine", "Refine", doc, recipe);
            }
            Err(e) => {
                self.chat.push(Msg::Error(format!("refine not applied: {e}")));
                self.restore_set_aside();
            }
        }
    }

    /// A failed regeneration brings back the result it was replacing.
    fn restore_set_aside(&mut self) {
        self.refine_recipe = None;
        let Some(card) = self.set_aside.take() else { return };
        self.store.active = Some(card.produced.clone());
        self.chat.push(Msg::Event(format!("  ⎿  kept {} as the pending result · g to try again", self.store.label(&card.produced))));
        self.card = Some(card);
    }

    fn apply_proposal(&mut self) {
        match self.pending.take() {
            Some(Proposal::Refine { seed }) => self.start_refine(seed),
            Some(Proposal::UpdateThreats { summary, updates }) => {
                let Some(doc) = self.active_doc() else { return };
                match chat::apply_threat_updates(&doc, &updates) {
                    Ok(next) => {
                        self.chat.push(Msg::Event(format!("apply_threat_model_patch_revision: {summary}")));
                        self.commit_result("OperatorEdit", "Edit", next, None);
                    }
                    Err(e) => self.chat.push(Msg::Error(format!("edit not applied: {e}"))),
                }
            }
            None => {}
        }
    }

    fn slash(&mut self, cmd: &str) {
        let (name, arg) = cmd.split_once(' ').unwrap_or((cmd, ""));
        match name {
            "refine" if !arg.trim().is_empty() => {
                self.chat.push(Msg::User(format!("/refine {arg}")));
                self.start_refine(arg.trim().to_string());
            }
            "use" | "keep" if self.card.is_some() => self.accept_card(),
            "review" if self.card.is_some() => self.review_card(),
            "discard" if self.card.is_some() => self.discard_card(),
            "regen" | "regenerate" if self.card.is_some() => {
                self.chat.push(Msg::User(format!("/{name} {arg}").trim_end().to_string()));
                self.regenerate(Some(arg.to_string()));
            }
            "edit" => self.request_edit(),
            "raw" | "diff" => {
                self.model_view = if name == "raw" { ModelView::Raw } else { ModelView::Diff };
                self.tab = Tab::Model;
            }
            "clear" => {
                self.chat.clear();
                self.pending = None;
                self.session_id = None;
                self.context_sent = None;
            }
            _ => self.chat.push(Msg::Event("commands: /refine <what changed> · /review · /keep · /regen [feedback] · /discard · /edit · /raw · /diff · /clear".into())),
        }
    }

    pub fn on_paste(&mut self, text: String) {
        let paths = dropped_paths(&text);
        self.tab = Tab::Chat;
        if paths.is_empty() {
            self.composer.push_str(text.trim());
            return;
        }
        for path in paths {
            if !self.attachments.contains(&path) {
                self.status = format!("attached {}", file_name(&path.display().to_string()));
                self.attachments.push(path);
            }
        }
    }

    // ───────────────────────── keys ─────────────────────────

    pub fn on_key(&mut self, key: KeyEvent) {
        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
        if ctrl && key.code == KeyCode::Char('c') {
            if self.tab == Tab::Chat && !self.composer.is_empty() {
                return self.composer.clear();
            }
            self.quit = true;
            return;
        }
        if self.help {
            self.help = false;
            return;
        }
        if let Some(r) = self.confirm_restore.take() {
            if matches!(key.code, KeyCode::Char('y') | KeyCode::Enter) {
                self.restore(r);
            }
            return;
        }
        match key.code {
            KeyCode::Tab => return self.cycle_tab(1),
            KeyCode::BackTab => return self.cycle_tab(TABS.len() - 1),
            _ => {}
        }
        if self.tab == Tab::Chat {
            return self.chat_key(key);
        }
        if self.global_key(key) {
            return;
        }
        match self.tab {
            Tab::Summary | Tab::Dfd => self.map_key(key),
            Tab::Model => self.model_key(key),
            Tab::History => self.history_key(key),
            Tab::Chat => {}
        }
    }

    fn cycle_tab(&mut self, step: usize) {
        let i = TABS.iter().position(|t| *t == self.tab).unwrap_or(0);
        self.tab = TABS[(i + step) % TABS.len()];
    }

    fn global_key(&mut self, key: KeyEvent) -> bool {
        match key.code {
            KeyCode::Char('q') => self.quit = true,
            KeyCode::Char('?') => self.help = true,
            KeyCode::Char(c @ '1'..='5') => self.tab = TABS[(c as u8 - b'1') as usize],
            KeyCode::Char('u') if self.card.is_some() => self.accept_card(),
            KeyCode::Char('v') if self.card.is_some() => self.review_card(),
            KeyCode::Char('x') if self.card.is_some() => self.discard_card(),
            KeyCode::Char('g') if self.card.is_some() => self.regenerate(None),
            KeyCode::Char('e') => self.request_edit(),
            KeyCode::Enter if self.stale && self.card.is_none() && self.tab != Tab::History => {
                self.start_refine("The repository moved since this model was built. Re-check the modeled components, entry points and threats against the current code and update what changed.".into())
            }
            KeyCode::Char('!') => self.simulate_map_run(),
            KeyCode::Char('S') => {
                self.stale = !self.stale;
                self.status = format!("demo: stale = {}", self.stale);
            }
            _ => return false,
        }
        true
    }

    fn map_key(&mut self, key: KeyEvent) {
        let page = if self.tab == Tab::Dfd { MapGalleryPage::Dfd } else { MapGalleryPage::Summary };
        let bound = selectable_count(page, self.active_doc().as_ref()).saturating_sub(1);
        let sel = if self.tab == Tab::Dfd { &mut self.dfd_sel } else { &mut self.summary_sel };
        match key.code {
            KeyCode::Char('j') | KeyCode::Down => *sel = (*sel + 1).min(bound),
            KeyCode::Char('k') | KeyCode::Up => *sel = sel.saturating_sub(1),
            KeyCode::Char('g') | KeyCode::Home => *sel = 0,
            KeyCode::Char('G') | KeyCode::End => *sel = bound,
            _ => {}
        }
    }

    fn model_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Char('r') => {
                self.model_view = if self.model_view == ModelView::Raw { ModelView::Rendered } else { ModelView::Raw };
                self.model_scroll = 0;
            }
            KeyCode::Char('d') => {
                self.model_view = if self.model_view == ModelView::Diff { ModelView::Rendered } else { ModelView::Diff };
                self.model_scroll = 0;
            }
            KeyCode::Char('a') => {
                if let Some(v) = self.viewing.clone().filter(|v| !self.is_active(v)) {
                    self.activate(v);
                }
            }
            KeyCode::Esc => {
                self.viewing = None;
                self.diff_base = None;
            }
            KeyCode::Char('j') | KeyCode::Down => self.model_scroll = self.model_scroll.saturating_add(1),
            KeyCode::Char('k') | KeyCode::Up => self.model_scroll = self.model_scroll.saturating_sub(1),
            KeyCode::PageDown | KeyCode::Char(' ') => self.model_scroll = self.model_scroll.saturating_add(15),
            KeyCode::PageUp => self.model_scroll = self.model_scroll.saturating_sub(15),
            KeyCode::Char('g') | KeyCode::Home => self.model_scroll = 0,
            KeyCode::Char('G') | KeyCode::End => self.model_scroll = u16::MAX / 2,
            _ => {}
        }
    }

    fn history_key(&mut self, key: KeyEvent) {
        let rows = self.history_rows();
        let Some(sel) = rows.get(self.hist_sel).cloned() else { return };
        match key.code {
            KeyCode::Char('j') | KeyCode::Down => self.hist_sel = (self.hist_sel + 1).min(rows.len() - 1),
            KeyCode::Char('k') | KeyCode::Up => self.hist_sel = self.hist_sel.saturating_sub(1),
            KeyCode::Enter => {
                self.viewing = (!self.is_active(&sel)).then_some(sel);
                self.diff_base = None;
                self.model_view = ModelView::Rendered;
                self.model_scroll = 0;
                self.tab = Tab::Model;
            }
            KeyCode::Char('a') if !self.is_active(&sel) => self.activate(sel),
            KeyCode::Char('R') => self.confirm_restore = Some(sel),
            _ => {}
        }
    }

    fn chat_key(&mut self, key: KeyEvent) {
        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
        match key.code {
            KeyCode::Esc if self.busy.is_some() => {
                if ai::interrupt(&self.ai_child) {
                    self.status = "interrupted".into();
                }
            }
            KeyCode::Enter if self.pending.is_some() && self.composer.trim().is_empty() => self.apply_proposal(),
            KeyCode::Esc if self.pending.is_some() => {
                self.pending = None;
                self.chat.push(Msg::Event("  ⎿  declined".into()));
            }
            KeyCode::Esc if !self.attachments.is_empty() && self.composer.is_empty() => {
                self.attachments.clear();
                self.status = "attachments cleared".into();
            }
            KeyCode::Enter => self.send_chat(),
            KeyCode::Backspace => {
                self.composer.pop();
            }
            KeyCode::Up | KeyCode::PageUp => self.chat_scroll = self.chat_scroll.saturating_add(if key.code == KeyCode::Up { 1 } else { 10 }),
            KeyCode::Down | KeyCode::PageDown => self.chat_scroll = self.chat_scroll.saturating_sub(if key.code == KeyCode::Down { 1 } else { 10 }),
            KeyCode::Char(c) if !ctrl => self.composer.push(c),
            _ => {}
        }
    }
}

pub fn headline(d: &ThreatModelDocumentDiff) -> String {
    if d.is_empty() {
        return "no structural differences".into();
    }
    let mut parts = Vec::new();
    for (n, what) in [(d.threats.added.len(), "added"), (d.threats.removed.len(), "removed"), (d.threats.changed.len(), "changed")] {
        if n > 0 {
            parts.push(format!("{n} threat(s) {what}"));
        }
    }
    let dfd = d.dfd.nodes_added.len() + d.dfd.flows_added.len() + d.dfd.boundaries_added.len();
    if dfd > 0 {
        parts.push(format!("{dfd} DFD element(s) added"));
    }
    if parts.is_empty() {
        parts.push("document text changed".into());
    }
    parts.join(" · ")
}
