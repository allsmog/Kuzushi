# Kuzushi recipes

Resource-script bundles that compose the per-capability SAST sub-modules into
common workflows. Run from the shell:

```
kuzushi> recipes                    # list available
kuzushi> recipes run quick-scan     # replay the commands from quick-scan.kzrc.yaml
```

Or directly via `resource`:

```
kuzushi> resource recipes/quick-scan.kzrc.yaml
```

| Recipe              | Stages                                                               |
|---------------------|----------------------------------------------------------------------|
| `quick-scan`        | context → semgrep → triage                                           |
| `deep-audit`        | context → randori → threat-hunt → agentic-sast → taint-iris → triage → verify |
| `ci-fast`           | semgrep → triage                                                     |
| `ci-deep`           | context → codeql → taint-iris → triage → verify → patch              |
| `threat-model-only` | context → randori                                                    |

Recipes are plain YAML replay of dispatcher commands. Use as templates — copy
into your workspace and tweak freely.
