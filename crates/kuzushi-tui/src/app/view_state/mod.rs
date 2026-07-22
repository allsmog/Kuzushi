use super::*;
pub(crate) use super::*;

use self::PendingConfirm;
pub(crate) use activity::*;
pub(crate) use boot_splash::*;
use kuzushi_core::{AttachmentRecord, KnownArtifact, ReconHost, ReconNote, ReconService};
pub(crate) use label::*;
pub(crate) use quit_confirm::*;
pub(crate) use rank::*;
pub(crate) use sast_task_row::*;
use std::path::PathBuf;
use std::time::Instant;
mod activity;
mod auth_screen;
mod boot_splash;
mod campaign_deck;
mod command_palette;
mod config_screen;
mod confirm_dialog;
mod context_screen;
mod cost_screen;
mod coverage_deck;
mod engagement;
mod health;
mod help_screen;
mod input_mode;
mod interruption;
mod keymap;
mod label;
mod options_screen;
mod quit_confirm;
mod rank;
mod routes;
mod sast_task_row;
mod sast_tasks_snapshot;
/// Cached structured snapshot of the most recent recon tool result. The TUI
/// renderer prefers reading from this snapshot (when populated) rather than
/// grepping the freeform log lines, so transcript truncation does not erase
/// recon evidence.

#[cfg(test)]
mod tests;
mod theme_picker;
mod update_available;
mod workbench_cache;
mod workbench_review_state;
mod workbench_zoom;
pub use activity::is_hidden_module_id;
pub use activity::ActivityRouteState;
pub use activity::ActivitySession;
pub use activity::DagTaskDetail;
pub use activity::DagTaskDetailState;
pub use activity::DagTaskRow;
pub use activity::DagTaskState;
pub use activity::PaneFocus;
pub use activity::RecordedTraceEvent;
pub use activity::SubsystemAggregate;
pub use activity::ACTIVITY_FEED_RING_CAPACITY;
pub use activity::{RunFocusOrigin, RunFocusReceipt, RunFocusSteerEditor};
pub use auth_screen::{AuthScreenFooter, AuthScreenSnapshot, AuthScreenStatus};
pub use boot_splash::{BootSplashCheck, BootSplashCheckState, BootSplashSnapshot};
pub(crate) use campaign_deck::dispatcher_args;
pub use campaign_deck::CampaignRouteState;
pub use command_palette::{CommandPaletteFooter, CommandPaletteSnapshot, CommandPaletteStatus};
pub use config_screen::{ConfigScreenFooter, ConfigScreenSnapshot, ConfigScreenStatus};
pub use confirm_dialog::{ConfirmDialogFooter, ConfirmDialogSnapshot, ConfirmDialogStatus};
pub use context_screen::{ContextScreenFooter, ContextScreenSnapshot, ContextScreenStatus};
pub use cost_screen::{CostScreenFooter, CostScreenSnapshot, CostScreenStatus};
pub use coverage_deck::CoverageRouteState;
pub use engagement::EngagementState;
pub use health::{HealthFooter, HealthSnapshot, HealthStatus};
pub use help_screen::{HelpScreenFooter, HelpScreenSnapshot, HelpScreenStatus};
pub use input_mode::InputMode;
pub use interruption::{InterruptionFooter, InterruptionSnapshot, InterruptionStatus};
pub use keymap::{KeymapBindingRow, KeymapFooter, KeymapSection, KeymapSnapshot, KeymapStatus};
pub use label::ActorDetailFilter;
pub use label::OptionsFilter;
pub use label::OptionsView;
pub use label::PromptsAction;
pub(crate) use label::SastTaskMode;
pub use label::ScanPanelState;
pub use label::ThreatPatch;
pub use options_screen::{OptionsScreenFooter, OptionsScreenSnapshot, OptionsScreenStatus};
pub use quit_confirm::{
    QuitConfirmFooter, QuitConfirmSection, QuitConfirmSnapshot, QuitConfirmStatus,
};
pub use rank::AdvisoryState;
pub use rank::BudgetHalt;
pub use rank::ChainSeverity;
pub use rank::ExploitChain;
pub use rank::Notice;
pub use rank::NoticeSeverity;
pub use rank::PlanChange;
pub use rank::PlanProposal;
pub use rank::ThrottleAdvisory;
pub use rank::TuneAction;
pub(crate) use routes::ReportOrigin;
pub use routes::{
    AuthPickerRouteState, AuthRouteState, CatalogRouteState, CommandPaletteRouteState,
    DefaultScrollRouteState, FilePickerRouteState, FindingsRouteState, HelpRouteState,
    InvestigationBoundary, ModelCatalogRouteState, ModelPickerRouteState, NavigationRouteState,
    PlanningPickerRouteState, PromptDocumentMode, PromptDocumentState, ReportReceipt,
    ReportRouteState, RouterState, SceneRouteState, ScrollRouteState, SetupEditor, SetupRouteState,
    SetupRowId, TargetPickerRouteState, ToolsRouteState, WorkbenchRouteState,
};
pub use sast_task_row::AuthLoginView;
pub use sast_task_row::CompletionCycle;
pub use sast_task_row::ContextSnapshotView;
pub use sast_task_row::HistorySearch;
pub use sast_task_row::InterruptionView;
pub use sast_task_row::KnowledgeBaseView;
pub use sast_task_row::PwnView;
pub use sast_task_row::ReconSnapshot;
pub(crate) use sast_task_row::SastTaskRow;
pub use sast_task_row::ShellView;
pub use sast_task_row::ThreatView;
pub use sast_task_row::WorkbenchPage;
pub use sast_task_row::WorkbenchPaneScroll;
pub use sast_task_row::WorkspaceView;
pub use sast_tasks_snapshot::{SastTasksFooter, SastTasksSnapshot, SastTasksStatus};
pub use theme_picker::{
    ThemePaletteRow, ThemePickerFooter, ThemePickerSnapshot, ThemePickerStatus,
};
pub use update_available::{UpdateAvailableFooter, UpdateAvailableSnapshot, UpdateAvailableStatus};
pub(crate) use workbench_cache::{
    harness_file_path, DfdModelCacheKey, DirectoryListingState, JsonFileState, PathState,
    ProjectScopeTreeState, PromptMutationsState, ReviewQueueCacheKey, RiskByModuleCacheKey,
    RunTraceCacheState, StrategyQueueState, VisibleFindingProjection, VisibleFindingsCacheKey,
    WorkbenchCache,
};
#[cfg(test)]
pub use workbench_review_state::ReviewCommand;
pub use workbench_review_state::{
    BacklogUndoEntry, PendingDecision, ReviewMode, ReviewRow, WorkbenchReviewState,
};
pub use workbench_zoom::WorkbenchZoom;
