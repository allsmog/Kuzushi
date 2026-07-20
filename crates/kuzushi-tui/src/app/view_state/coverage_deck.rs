//! Coverage matrix deck route state. The report is computed on open (one
//! disk fold, never per frame) and re-rendered read-only; `coverage` again
//! refreshes it.

use kuzushi_core::capabilities::campaign::coverage::CoverageReport;

#[derive(Debug, Clone, Default, PartialEq)]
pub struct CoverageRouteState {
    pub report: Option<CoverageReport>,
    pub notice: Option<String>,
}
