pub(crate) fn hot_path_rule_id(file: &str) -> Option<&'static str> {
    hot_path_rule(file).map(|rule| rule.rule_id)
}

fn hot_path_rule(file: &str) -> Option<&'static HotPathRule> {
    HOT_PATH_RULES.iter().find(|rule| rule.matches(file))
}

#[derive(Clone, Copy)]
struct HotPathRule {
    matcher: HotPathMatcher,
    rule_id: &'static str,
}

impl HotPathRule {
    fn matches(&self, file: &str) -> bool {
        match self.matcher {
            HotPathMatcher::EndsWith(suffix) => file.ends_with(suffix),
            HotPathMatcher::Contains(fragment) => file.contains(fragment),
        }
    }
}

#[derive(Clone, Copy)]
enum HotPathMatcher {
    EndsWith(&'static str),
    Contains(&'static str),
}

const HOT_PATH_RULES: &[HotPathRule] = &[
    HotPathRule {
        matcher: HotPathMatcher::EndsWith("v8/src/maglev/maglev-phi-representation-selector.cc"),
        rule_id: "chrome-rce-hot-path-v8-maglev-phi-representation-selector",
    },
    HotPathRule {
        matcher: HotPathMatcher::Contains("v8/src/maglev/"),
        rule_id: "chrome-rce-hot-path-v8-maglev",
    },
    HotPathRule {
        matcher: HotPathMatcher::Contains("v8/src/compiler/backend/arm64/"),
        rule_id: "chrome-rce-hot-path-v8-arm64-codegen",
    },
    HotPathRule {
        matcher: HotPathMatcher::EndsWith("v8/src/compiler/typer.cc"),
        rule_id: "chrome-rce-hot-path-v8-typer",
    },
    HotPathRule {
        matcher: HotPathMatcher::EndsWith("v8/src/compiler/redundancy-elimination.cc"),
        rule_id: "chrome-rce-hot-path-v8-redundancy-elimination",
    },
    HotPathRule {
        matcher: HotPathMatcher::Contains("third_party/dawn/src/dawn/wire/server/"),
        rule_id: "chrome-rce-hot-path-dawn-wire-server",
    },
    HotPathRule {
        matcher: HotPathMatcher::Contains("third_party/dawn/generator/templates/dawn/wire/server/"),
        rule_id: "chrome-rce-hot-path-dawn-wire-server-templates",
    },
];
