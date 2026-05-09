mod adapters;
mod application;
mod domain;

#[cfg(test)]
mod tests;

pub use adapters::execute_x_ray_tool;
pub use application::read_x_ray_report_artifacts;
pub use domain::{
    XRayArtifactPaths, XRayEntryPointCounts, XRayInvariantCounts, XRayReportData, XRayVerdict,
};
