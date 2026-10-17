mod arguments;
mod build_registry;
mod call_hierarchy;
mod document;
mod file_macro_handlers;
mod health_compile_handlers;
mod health_handle;
mod navigation_handlers;
mod tool_types;
mod type_ast_handlers;

#[cfg(test)]
mod selection_tests;
#[cfg(test)]
mod tests;
pub use build_registry::build_registry;
#[cfg(test)]
pub(crate) use build_registry::build_registry_with_capability;
pub use health_handle::health_summary;

#[cfg(test)]
pub(crate) use arguments::{FileRequest, PositionRequest};
#[cfg(test)]
pub(crate) use call_hierarchy::{extend_with_json_array, json_array};
#[cfg(test)]
pub(crate) use document::clang_language_id;
#[cfg(test)]
pub(crate) use file_macro_handlers::extract_first_code_fence;
#[cfg(test)]
pub(crate) use health_handle::ClangdHandle;
#[cfg(test)]
pub(crate) use navigation_handlers::{position_locations, range_locations};
#[cfg(test)]
pub(crate) use tool_types::*;
