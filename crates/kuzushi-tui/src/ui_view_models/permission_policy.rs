#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PermissionPolicyModel {
    pub(crate) title: &'static str,
    pub(crate) scope: &'static str,
    pub(crate) rows: Vec<PermissionPolicyRow>,
    pub(crate) limitation: &'static str,
    pub(crate) next_commands: &'static [&'static str],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PermissionPolicyRow {
    pub(crate) label: &'static str,
    pub(crate) state: &'static str,
    pub(crate) policy: &'static str,
    pub(crate) boundary: &'static str,
}

pub(crate) fn permission_policy_model() -> PermissionPolicyModel {
    PermissionPolicyModel {
        title: "PERMISSION POLICY",
        scope: "Current Kuzushi application-level dispatch policy",
        rows: vec![
            policy_row(
                "MODEL / RUNTIME",
                "ENFORCED",
                "Runtime-backed execution does not silently substitute a model, provider, or agent runtime. Missing, incompatible, and fallback-chain selections are rejected after policy resolution.",
                "shared no-silent-fallback policy and agent router",
            ),
            policy_row(
                "HEADLESS TOOL",
                "ENFORCED",
                "`kuzushi run` requires an explicit <module>:<tool> name. Shell focused-module shorthand is not accepted by headless run.",
                "CLI command parsing and shared descriptor dispatch",
            ),
            policy_row(
                "DESCRIPTOR EFFECTS",
                "ENFORCED",
                "Tools declaring target-write, repository-execute, or external-action effects require explicit authorization bound to that dispatch.",
                "ToolPolicy metadata and shared registry authorization",
            ),
            policy_row(
                "SHELL RISK GATES",
                "PRE-DISPATCH",
                "Recognized network egress and filesystem writes outside .kuzushi or staged patch flows ask for approval. Recognized destructive verbs are refused.",
                "interactive shell approval classifier",
            ),
            policy_row(
                "DENIAL",
                "NOT LAUNCHED",
                "A denied pending shell action is not dispatched. The shell records the decision; it does not claim that arbitrary tool internals are OS-sandboxed.",
                "shell confirmation state and operation-bound authorization",
            ),
        ],
        limitation: "Scope note: this is a policy-boundary report, not an OS sandbox or host firewall status page.",
        next_commands: &["doctor", "config", "runs"],
    }
}

fn policy_row(
    label: &'static str,
    state: &'static str,
    policy: &'static str,
    boundary: &'static str,
) -> PermissionPolicyRow {
    PermissionPolicyRow {
        label,
        state,
        policy,
        boundary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_copy_names_enforced_boundaries_without_claiming_os_isolation() {
        let model = permission_policy_model();
        let policies = model
            .rows
            .iter()
            .map(|row| row.policy)
            .collect::<Vec<_>>()
            .join(" ");

        assert!(policies.contains("silently substitute"));
        assert!(policies.contains("explicit <module>:<tool>"));
        assert!(policies.contains("network egress"));
        assert!(policies.contains("filesystem writes"));
        assert!(policies.contains("destructive verbs are refused"));
        assert!(policies.contains("denied pending shell action is not dispatched"));
        assert!(model.limitation.contains("not an OS sandbox"));
    }
}
