mod entry_point_counts;
mod markdown_analysis;
mod report;
mod verdict;

pub(crate) use entry_point_counts::*;
pub(crate) use markdown_analysis::*;
pub(crate) use report::{XRayArtifactContent, REQUIRED_ARCHITECTURE_SVG, REQUIRED_ENTRY_POINTS_MD};
pub use report::{
    XRayArtifactPaths, XRayEntryPointCounts, XRayInvariantCounts, XRayReportData, XRayVerdict,
};
pub(crate) use report::{REQUIRED_INVARIANTS_MD, REQUIRED_X_RAY_MD};
pub(crate) use verdict::*;

use std::collections::BTreeSet;
use std::path::Path;
