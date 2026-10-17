pub(in crate::modules) use crate::capabilities::agentic_sast::{
    run_agentic_sast_report, split_agentic_sast_tasks,
};

pub use crate::capabilities::agentic_sast::{AgenticSastPersistedRun, AgenticSastReport};

mod strategy_options;
pub(in crate::modules) use strategy_options::{
    describe_strategy_options, prepare_strategy_options, strategy_supports_option,
};
