mod builders;

#[cfg(test)]
mod tests;

pub(crate) use builders::{
    callees_of, callers_of, cpg_size_query, ffi_boundaries, method_at, reaching_def, taint_paths,
    unsafe_blocks,
};

#[cfg(test)]
pub(crate) use builders::escape_scala_string;

#[cfg(test)]
pub(crate) use builders::{
    TAINT_PATHS_DEFAULT_CALL_DEPTH, TAINT_PATHS_MAX_CALL_DEPTH_CEILING,
};
