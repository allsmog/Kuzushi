pub(crate) mod clang_subprocess;
mod compile_database;
mod input;
pub(crate) mod local_limits;
mod output;
mod tool_execution;

pub(crate) use input::parse_uaf_hunt_input;
#[cfg(test)]
pub(crate) use input::resolve_compile_commands_path;
pub use tool_execution::execute_uaf_hunt_tool;
