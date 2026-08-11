"""Reference evaluator for a model artifact — the Python twin of PR 4's scorer.

Addition to the §15 layout, and the reason is the parity contract: without an
evaluator on this side, `fixtures/parity/expected-scores.json` would be a table
only one language ever checks. Here both check it, so a divergence shows up as a
failing test rather than as a disagreement in production.

The algorithm mirrors the PR 4 plan exactly: bounded walk (never recursion),
`value <= threshold` goes left, an absent feature follows `missingDirection`,
`ineligible` and unknown categories and under-supported leaves all fail closed
with a named reason.
"""

from __future__ import annotations

from typing import Any, Mapping

MAX_WALK_DEPTH = 6

ELIGIBLE = "eligible"
MISSING_REQUIRED_FEATURE = "missingRequiredFeature"
UNKNOWN_CATEGORY = "unknownCategory"
INSUFFICIENT_LEAF_SUPPORT = "insufficientLeafSupport"
OUT_OF_DISTRIBUTION = "outOfDistribution"


def evaluate_artifact(
    artifact: Mapping[str, Any], features: Mapping[str, Any]
) -> dict[str, Any]:
    """Scores one feature vector. Returns leaf stats, path, and eligibility."""
    nodes = artifact["nodes"]
    node = nodes[0]
    path: list[str] = []
    for _ in range(MAX_WALK_DEPTH + 1):
        if node["nodeType"] == "leaf":
            return _leaf_result(artifact, node, path)
        step = _step(node, features)
        if step.get("eligibility"):
            return _ineligible(step["eligibility"], step.get("detail", {}), path)
        path.append(step["step"])
        node = nodes[step["next"]]
    return _ineligible(OUT_OF_DISTRIBUTION, {"reason": "depth guard exceeded"}, path)


def _step(node: Mapping[str, Any], features: Mapping[str, Any]) -> dict[str, Any]:
    name = node["feature"]
    if name not in features:
        return {"eligibility": MISSING_REQUIRED_FEATURE, "detail": {"feature": name}}
    value = features[name]
    if value is None:
        return _missing_step(node, name)
    if node["nodeType"] == "numeric":
        return _numeric_step(node, name, value)
    return _categorical_step(node, name, value)


def _missing_step(node: Mapping[str, Any], name: str) -> dict[str, Any]:
    direction = node["missingDirection"]
    if direction == "ineligible":
        return {"eligibility": MISSING_REQUIRED_FEATURE, "detail": {"feature": name}}
    branch = node["left"] if direction == "left" else node["right"]
    return {"step": f"{node['id']}:{name}:missing-{direction}", "next": branch}


def _numeric_step(node: Mapping[str, Any], name: str, value: Any) -> dict[str, Any]:
    number = _as_number(value)
    if number is None:
        return {"eligibility": MISSING_REQUIRED_FEATURE, "detail": {"feature": name}}
    goes_left = number <= node["threshold"]
    return {
        "step": f"{node['id']}:{name}<={node['threshold']}:{'left' if goes_left else 'right'}",
        "next": node["left"] if goes_left else node["right"],
    }


def _categorical_step(node: Mapping[str, Any], name: str, value: Any) -> dict[str, Any]:
    token = _as_token(value)
    branches = node["branches"]
    if token not in branches:
        return {
            "eligibility": UNKNOWN_CATEGORY,
            "detail": {"feature": name, "value": token},
        }
    return {"step": f"{node['id']}:{name}=={token}", "next": branches[token]}


def _as_number(value: Any) -> float | None:
    if isinstance(value, bool):
        return 1.0 if value else 0.0
    if isinstance(value, (int, float)):
        return float(value)
    return None


def _as_token(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def _leaf_result(
    artifact: Mapping[str, Any], leaf: Mapping[str, Any], path: list[str]
) -> dict[str, Any]:
    support = leaf["positiveCount"] + leaf["negativeCount"]
    minimum = artifact["eligibility"]["minimumLeafSupport"]
    if support < minimum:
        return {
            **_leaf_stats(leaf),
            "path": path,
            "eligibility": {"kind": INSUFFICIENT_LEAF_SUPPORT, "support": support},
        }
    return {**_leaf_stats(leaf), "path": path, "eligibility": {"kind": ELIGIBLE}}


def _leaf_stats(leaf: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "leafId": leaf["id"],
        "smoothedPositiveRate": leaf["smoothedPositiveRate"],
        "positiveCount": leaf["positiveCount"],
        "negativeCount": leaf["negativeCount"],
    }


def _ineligible(kind: str, detail: Mapping[str, Any], path: list[str]) -> dict[str, Any]:
    return {
        "leafId": None,
        "smoothedPositiveRate": None,
        "positiveCount": None,
        "negativeCount": None,
        "path": path,
        "eligibility": {"kind": kind, **detail},
    }
