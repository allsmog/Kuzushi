use anyhow::Result;
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DoctorStatus {
    Ok,
    Warn,
    Fail,
}

impl DoctorStatus {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Warn => "warn",
            Self::Fail => "fail",
        }
    }

    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Ok => "OK",
            Self::Warn => "WARN",
            Self::Fail => "FAIL",
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct DoctorCheck {
    pub(crate) name: &'static str,
    pub(crate) status: DoctorStatus,
    pub(crate) detail: String,
    pub(crate) next: Option<String>,
}

impl DoctorCheck {
    pub(crate) fn ok(name: &'static str, detail: impl Into<String>) -> Self {
        Self {
            name,
            status: DoctorStatus::Ok,
            detail: detail.into(),
            next: None,
        }
    }

    pub(crate) fn warn(
        name: &'static str,
        detail: impl Into<String>,
        next: impl Into<String>,
    ) -> Self {
        Self {
            name,
            status: DoctorStatus::Warn,
            detail: detail.into(),
            next: Some(next.into()),
        }
    }

    pub(crate) fn fail(
        name: &'static str,
        detail: impl Into<String>,
        next: impl Into<String>,
    ) -> Self {
        Self {
            name,
            status: DoctorStatus::Fail,
            detail: detail.into(),
            next: Some(next.into()),
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct DoctorReport {
    pub(crate) target: PathBuf,
    pub(crate) checks: Vec<DoctorCheck>,
}

impl DoctorReport {
    pub(crate) fn count(&self, status: DoctorStatus) -> usize {
        self.checks
            .iter()
            .filter(|check| check.status == status)
            .count()
    }

    pub(crate) fn failures(&self) -> usize {
        self.count(DoctorStatus::Fail)
    }

    pub(crate) fn has_failures(&self) -> bool {
        self.failures() > 0
    }
}

pub(crate) fn doctor_command(target: PathBuf, json: bool) -> Result<()> {
    let report = super::build_doctor_report(target);
    if json {
        super::print_doctor_json(&report)?;
    } else {
        super::print_doctor_plain(&report);
    }

    if report.has_failures() {
        anyhow::bail!(
            "doctor found {} failing check(s). Fix the listed next steps and rerun `kuzushi doctor`.",
            report.failures()
        );
    }
    Ok(())
}
