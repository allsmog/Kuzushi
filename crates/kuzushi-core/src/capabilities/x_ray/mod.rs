mod adapters;
mod application;
mod domain;

#[cfg(test)]
mod reader_contract_tests;
#[cfg(test)]
mod tests;

pub use adapters::execute_x_ray_tool;
pub use application::read_x_ray_report_artifacts;
pub(crate) use application::x_ray_system_prompt;
pub use domain::{
    XRayArtifactPaths, XRayEntryPointCounts, XRayInvariantCounts, XRayReportData, XRayVerdict,
};
