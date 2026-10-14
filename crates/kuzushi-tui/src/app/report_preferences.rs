use super::*;
use kuzushi_core::workspace::report_preferences::{
    load_report_preferences, save_report_preferences,
};
use std::path::Path;

impl ShellApp {
    pub(crate) fn restore_report_choices(&mut self) {
        let Some(target) = self.target_owned() else {
            return;
        };
        if self.router.report().choices_target() == Some(target.as_path()) {
            return;
        }
        self.router.report_mut().prepare_choices_target(target);
        match kuzushi_core::ConfigPaths::from_target(None) {
            Ok(paths) => self.restore_report_choices_from(&paths.home_dir),
            Err(error) => self
                .router
                .report_mut()
                .record_choices_save(Err(error.to_string())),
        }
    }

    pub(crate) fn restore_report_choices_from(&mut self, home: &Path) {
        let Some(target) = self.target_owned() else {
            return;
        };
        let result = load_report_preferences(home, &target).map_err(|error| format!("{error:#}"));
        match result {
            Ok(Some(choices)) => {
                let restored = self.router.report_mut().restore_choices(choices);
                if let Err(error) = restored {
                    self.router.report_mut().record_choices_save(Err(error));
                }
            }
            Ok(None) => {}
            Err(error) => self.router.report_mut().record_choices_save(Err(error)),
        }
    }

    pub(crate) fn persist_report_choices(&mut self) {
        match kuzushi_core::ConfigPaths::from_target(None) {
            Ok(paths) => self.persist_report_choices_to(&paths.home_dir),
            Err(error) => self
                .router
                .report_mut()
                .record_choices_save(Err(error.to_string())),
        }
    }

    pub(crate) fn persist_report_export_choices(&mut self) {
        let Some(target) = self.target_owned() else {
            return;
        };
        let result =
            kuzushi_core::ConfigPaths::from_target(None).map_err(|error| error.to_string());
        let home = match result {
            Ok(paths) => paths.home_dir,
            Err(error) => {
                self.router.report_mut().record_choices_save(Err(error));
                return;
            }
        };
        self.persist_report_export_choices_to(&home, &target);
    }

    pub(crate) fn persist_report_export_choices_to(&mut self, home: &Path, target: &Path) {
        if let Err(error) = load_report_preferences(home, target) {
            self.router.report_mut().record_choices_save(Err(format!(
                "{error:#}. S explicitly replaces saved choices with the current values"
            )));
            return;
        }
        self.persist_report_choices_to(home);
    }

    pub(crate) fn persist_report_choices_to(&mut self, home: &Path) {
        let Some(target) = self.target_owned() else {
            self.router
                .report_mut()
                .record_choices_save(Err("Select a target before saving report choices".into()));
            return;
        };
        let choices = self.router.report().captured_choices(target);
        let result = save_report_preferences(home, &choices)
            .map(|_| ())
            .map_err(|error| format!("{error:#}"));
        self.router.report_mut().record_choices_save(result);
    }
}

#[cfg(test)]
mod tests;
