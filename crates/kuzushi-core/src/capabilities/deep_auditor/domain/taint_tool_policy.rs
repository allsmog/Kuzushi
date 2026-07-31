use anyhow::{bail, Result};

/// Dataflow-tool policy offered to the deep auditor.
///
/// `Off` never touches the CPG on disk. `Available` LOADS an existing on-disk
/// graph and serves it as a recall-first hint — it never builds or rebuilds
/// from source, so a stale graph (sources newer than the artifact) is loaded
/// as-is rather than triggering an implicit whole-repo rebuild inside a bulk
/// triage; a genuinely missing graph stays `Missing`. `Build` is the only
/// variant allowed to compile the graph from source before the audit. Every
/// variant resolves readiness once per (root, thread): a `Ready` graph is
/// cached, and a failed load/build is cached too, so a persistently failing
/// root is not re-attempted per finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TaintToolPolicy {
    /// Do not offer dataflow tools; do not read or build any graph.
    Off,
    /// Offer dataflow tools backed by an existing on-disk graph, loaded as-is
    /// (even when stale) and never rebuilt from source.
    #[default]
    Available,
    /// Build the graph first (rebuilding on staleness), then offer dataflow
    /// tools.
    Build,
}

impl TaintToolPolicy {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Available => "available",
            Self::Build => "build",
        }
    }

    pub fn parse(value: &str) -> Result<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "off" => Ok(Self::Off),
            "available" => Ok(Self::Available),
            "build" => Ok(Self::Build),
            other => bail!("taintTools must be one of off, available, build; got {other:?}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::TaintToolPolicy;

    #[test]
    fn parse_round_trips_and_rejects_unknown() {
        for policy in [
            TaintToolPolicy::Off,
            TaintToolPolicy::Available,
            TaintToolPolicy::Build,
        ] {
            assert_eq!(TaintToolPolicy::parse(policy.as_str()).unwrap(), policy);
        }
        assert_eq!(TaintToolPolicy::default(), TaintToolPolicy::Available);
        assert!(TaintToolPolicy::parse("nope").is_err());
        assert_eq!(
            TaintToolPolicy::parse("  BUILD ").unwrap(),
            TaintToolPolicy::Build
        );
    }
}
