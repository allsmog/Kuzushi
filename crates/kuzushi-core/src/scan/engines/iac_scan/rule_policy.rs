use super::IacScanKind;

const RULES: &[(IacScanKind, &[&str])] = &[
    (
        IacScanKind::Dockerfile,
        &[
            "iac-scan/dockerfile-missing-non-root-user",
            "iac-scan/dockerfile-floating-image",
            "iac-scan/dockerfile-unpinned-image",
            "iac-scan/dockerfile-root-user",
            "iac-scan/dockerfile-remote-add",
            "iac-scan/dockerfile-broad-copy",
        ],
    ),
    (
        IacScanKind::GithubActions,
        &[
            "iac-scan/actions-pull-request-target",
            "iac-scan/actions-write-all-permissions",
            "iac-scan/actions-untrusted-pr-context",
            "iac-scan/actions-write-permission-scope",
            "iac-scan/actions-mutable-action-reference",
        ],
    ),
    (
        IacScanKind::Terraform,
        &[
            "iac-scan/terraform-public-ingress",
            "iac-scan/terraform-public-s3-acl",
            "iac-scan/terraform-public-database",
            "iac-scan/terraform-hardcoded-cloud-credential",
        ],
    ),
];

pub(crate) fn enabled_rule_ids(kind: IacScanKind) -> Vec<String> {
    RULES
        .iter()
        .filter(|(family, _)| kind.includes(*family))
        .flat_map(|(_, rules)| rules.iter().map(|rule| (*rule).to_string()))
        .collect()
}
