mod prelude;
use prelude::*;
mod siblings;
pub(crate) use siblings::*;
mod items_1;
mod items_2;
#[cfg(test)]
mod tests;

pub use items_1::build_static_narrative_report;
pub use items_1::validate_static_narrative_text;
pub use items_1::StaticFindingNarrative;
pub use items_1::StaticNarrativeReport;
