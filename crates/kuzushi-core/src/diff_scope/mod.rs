mod prelude;
use prelude::*;
mod siblings;
pub(crate) use siblings::*;
mod items_1;
mod items_2;
mod items_3;
mod parse_name_status;
mod status_from_name_status;
pub use status_from_name_status::*;
#[cfg(test)]
mod tests;

pub use items_1::git_diff_files;
pub use items_1::ChangedFile;
pub use items_1::DiffScope;
pub use items_1::WhiteboxDiffScopeReport;
pub use items_2::ChangedLineRange;
pub use items_2::DiffContext;
pub use items_2::DiffContextKind;
pub use items_2::DiffFileStatus;
pub use items_2::DiffFindingStatus;
pub use items_2::DiffFindingTag;
pub use items_2::DiffRangeKind;
pub use items_2::DiffScopeSummary;
pub use items_3::build_whitebox_diff_scope_report;
