"""Validate the owned investigation journey's per-launch isolation before it starts."""

def require_isolated_launches(journey):
    """Harness env directives are consumed by each launch, not persisted."""
    environment, removed, launches = {}, set(), 0
    required = {"ANTHROPIC_API_KEY", "OPENAI_API_KEY", "NODE_OPTIONS", "KUZUSHI_MODEL", "KUZUSHI_LANGGRAPH_BRIDGE"}
    for line in journey.splitlines():
        if line.startswith("env:"):
            environment.update(item.split("=", 1) for item in line[4:].split())
        elif line.startswith("env-unset:"):
            removed.update(line.split(":", 1)[1].split())
        elif line.startswith("launch:"):
            assert environment.get("HOME") == "@TMP_HOME", "Every launch needs its own isolated HOME"
            assert required <= removed, "Every launch must exclude inherited provider settings"
            environment, removed = {}, set()
            launches += 1
    assert launches == 3, "The owned investigation has exactly three launches"
