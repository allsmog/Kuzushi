pub(crate) mod availability;
mod build_registry;
mod function_handlers;
mod graph_handlers;
mod health;
mod method_at;
mod parse_query_handlers;
mod tool_types;

#[cfg(test)]
mod tests;
pub use build_registry::build_registry;
#[cfg(test)]
pub(crate) use build_registry::build_registry_with_capability;
pub use health::health_summary;

#[cfg(test)]
pub(crate) use availability::parse_raw_json_or_string;
#[cfg(test)]
pub(crate) use method_at::{method_at_json, method_at_request, MethodAtRequest};
#[cfg(test)]
pub(crate) use parse_query_handlers::{function_query_json, parse_repo_path};
#[cfg(test)]
pub(crate) use tool_types::*;
