import { mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import type { Finding } from "../../../scanners/types.js";
import type { SystemsHuntArtifact } from "./types.js";

export const SYSTEMS_HUNT_ARTIFACT_PREFIX = "Systems hunt artifact:";

export function buildSystemsHuntArtifactPath(artifactRoot: string, fingerprint: string): string {
  return path.join(artifactRoot, `${fingerprint}.json`);
}

export async function writeSystemsHuntArtifact(
  artifactRoot: string,
  artifact: SystemsHuntArtifact,
): Promise<string> {
  await mkdir(artifactRoot, { recursive: true });
  const artifactPath = buildSystemsHuntArtifactPath(artifactRoot, artifact.fingerprint);
  await writeFile(artifactPath, `${JSON.stringify(artifact, null, 2)}\n`, "utf-8");
  return artifactPath;
}

export async function readSystemsHuntArtifactByPath(
  artifactPath: string,
): Promise<SystemsHuntArtifact | undefined> {
  try {
    const content = await readFile(artifactPath, "utf-8");
    const parsed = JSON.parse(content);
    if (!parsed || typeof parsed !== "object") return undefined;
    return parsed as SystemsHuntArtifact;
  } catch {
    return undefined;
  }
}

export function extractSystemsHuntArtifactPath(finding: Finding): string | undefined {
  for (const entry of finding.engineProvenance ?? []) {
    if (entry.kind !== "agentic") continue;
    if (!entry.detail.startsWith(SYSTEMS_HUNT_ARTIFACT_PREFIX)) continue;
    const artifactPath = entry.detail.slice(SYSTEMS_HUNT_ARTIFACT_PREFIX.length).trim();
    if (artifactPath) return artifactPath;
  }
  return undefined;
}

export function buildSystemsHuntArtifactDetail(artifactPath: string): string {
  return `${SYSTEMS_HUNT_ARTIFACT_PREFIX} ${artifactPath}`;
}
