"""Owned combined export references, omissions and unchanged source evidence."""
import json
import sys
import uuid
from pathlib import Path

import sbom_spdx


def inspect(root, evidence, stage):
    sbom_spdx.inspect(root, evidence, stage)
    paths = list((root / ".kuzushi/v3/runs").glob("*/result.json"))
    assert len(paths) == 1, paths
    result = json.loads(paths[0].read_text())
    data = result["data"]
    document = data["cycloneDx"]
    refs = {item["bom-ref"] for item in document["components"]}
    assert len(refs) == len(document["components"]) == 5
    known = refs | {document["metadata"]["component"]["bom-ref"]}
    nodes = document["dependencies"]
    assert len(nodes) == 1 and nodes[0]["ref"] == "kuzushi:root", nodes
    assert len(nodes[0]["dependsOn"]) == 2, nodes
    for node in nodes:
        assert node["ref"] in known
        assert all(target in known for target in node["dependsOn"])
    composition = document["compositions"][0]
    assert composition["aggregate"] == "incomplete", composition
    assert set(composition["dependencies"]) == known, composition
    serial = document["serialNumber"]
    assert serial.startswith("urn:uuid:"), serial
    uuid.UUID(serial[len("urn:uuid:"):])
    properties = {item["name"]: item["value"] for item in document["metadata"]["properties"]}
    assert properties["kuzushi:dependencyGraphCompleteness"] == "incomplete"
    omitted = json.loads(properties["kuzushi:omittedDependencyRelationships"])
    assert len(omitted) == 3
    diagnostics = data["cycloneDxExport"]
    assert diagnostics["omittedRelationshipCount"] == 3
    assert diagnostics["dependencyRelationshipCount"] == 2
    assert diagnostics["omittedRelationships"] == omitted
    assert result["output"].count("omitted") == 1, result["output"]
    sbom_spdx.save(evidence, stage + "-cyclonedx-check", {
        "components": 5, "distinctReferences": 5, "undefinedReferences": 0,
        "rawDependencyLinks": 5, "exportedDependencyLinks": 2, "disclosedOmissions": 3,
        "graphCompleteness": "incomplete", "sourceUnchanged": True,
        "liveProviderRequests": 0, "targetExecuted": False,
        "fullConformanceQualified": False})


if __name__ == "__main__":
    root, evidence = [Path(value).resolve() for value in sys.argv[1:3]]
    stage = sys.argv[3]
    if stage == "prepare":
        sbom_spdx.prepare(root, evidence)
    elif stage == "warning-pages":
        sbom_spdx.inspect_warning_pages(evidence)
    else:
        inspect(root, evidence, stage)
