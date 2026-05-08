use super::{DoctorReport, DoctorStatus};
use anyhow::Result;

pub(crate) fn print_doctor_json(report: &DoctorReport) -> Result<()> {
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "target": report.target,
            "checks": report.checks.iter().map(|check| serde_json::json!({
                "name": check.name,
                "status": check.status.as_str(),
                "detail": check.detail,
                "next": check.next,
            })).collect::<Vec<_>>(),
            "summary": {
                "ok": report.count(DoctorStatus::Ok),
                "warn": report.count(DoctorStatus::Warn),
                "fail": report.count(DoctorStatus::Fail),
            },
        }))?
    );
    Ok(())
}

pub(crate) fn print_doctor_plain(report: &DoctorReport) {
    println!("Kuzushi doctor");
    println!("Target: {}", report.target.display());
    for check in &report.checks {
        println!(
            "[{}] {:<20} {}",
            check.status.label(),
            check.name,
            check.detail
        );
        if let Some(next) = &check.next {
            println!("      Next: {next}");
        }
    }
    println!(
        "Summary: {} ok, {} warn, {} fail",
        report.count(DoctorStatus::Ok),
        report.count(DoctorStatus::Warn),
        report.count(DoctorStatus::Fail)
    );
}
