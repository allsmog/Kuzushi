use super::prelude::*;
use super::*;

pub(crate) fn source_sink_score(corpus: &str, reasons: &mut Vec<String>) -> i32 {
    let classes: &[(&str, i32, &[&str])] = &[
        (
            "command_execution_sink",
            30,
            &[
                "child_process.exec",
                "os.system",
                "subprocess",
                "shell=true",
                "command execution",
            ],
        ),
        (
            "sql_sink",
            28,
            &[
                "sql injection",
                ".query(",
                "cursor.execute",
                "database query",
                "sequelize.query",
                "knex(",
            ],
        ),
        (
            "deserialization_sink",
            24,
            &[
                "deserialize",
                "pickle.loads",
                "yaml.load",
                "json.parse",
                "protobuf.decode",
            ],
        ),
        (
            "authz_boundary",
            22,
            &[
                "authorization",
                "authz",
                "access control",
                "permission",
                "tenant",
            ],
        ),
        (
            "file_write_or_path_sink",
            20,
            &[
                "path traversal",
                "file write",
                "writefile",
                "readfile",
                "open(",
            ],
        ),
        (
            "xss_sink",
            16,
            &[
                "cross-site scripting",
                "xss",
                "res.send",
                "innerhtml",
                "render(",
            ],
        ),
    ];

    for (label, score, needles) in classes {
        if contains_any(corpus, needles) {
            reasons.push((*label).to_string());
            return *score;
        }
    }
    0
}

pub(crate) fn data_sensitivity_score(corpus: &str, reasons: &mut Vec<String>) -> i32 {
    let sensitive = [
        "password",
        "secret",
        "token",
        "credential",
        "session",
        "cookie",
        "jwt",
        "ssn",
        "payment",
        "credit card",
        "admin",
        "tenant",
        "email",
        "pii",
    ];
    let hits = sensitive
        .iter()
        .filter(|needle| corpus.contains(**needle))
        .count() as i32;
    let score = (hits * 4).min(16);
    if score > 0 {
        reasons.push("sensitive_data_context".to_string());
    }
    score
}
