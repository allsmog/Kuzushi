use super::*;
use crate::commands::PatchCommand;

pub(crate) fn handle_patch_command(app: &mut ShellApp, command: &ShellCommand) -> bool {
    let ShellCommand::Patch(command) = command else {
        return false;
    };
    app.handle_patch_review_command(command);
    true
}

impl ShellApp {
    fn handle_patch_review_command(&mut self, command: &PatchCommand) {
        match command {
            PatchCommand::Apply => {
                let effects = self.reduce_patch_apply();
                self.execute_effects(effects);
            }
            PatchCommand::Reject => self.reject_pending_reviewed_patch(),
            PatchCommand::Regen { style } => {
                let effects = self.reduce_patch_regen(style);
                self.execute_effects(effects);
            }
            PatchCommand::Unsupported(raw) => self.log(
                "patch",
                format!(
                    "unsupported patch command `{raw}`. Next: patch apply, patch reject, or patch regen"
                ),
            ),
        }
    }

    fn reject_pending_reviewed_patch(&mut self) {
        let Some(patch) = self.engagement.take_pending_patch() else {
            self.log("patch", "no pending patch to reject");
            return;
        };
        self.shell_view = ShellView::Workbench;
        self.workbench_page = Some(crate::app::WorkbenchPage::Ship);
        self.log(
            "patch",
            format!("discarded pending patch for {}", patch.alias),
        );
    }
}
