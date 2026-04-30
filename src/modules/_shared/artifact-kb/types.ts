export interface ArtifactKbSourceInput {
  path: string;
  content?: string;
  chunks: ArtifactKbChunkInput[];
  metadata?: Record<string, unknown>;
}

export interface ArtifactKbChunkInput {
  id?: string;
  kind: string;
  title: string;
  summary?: string;
  body: string;
  refs?: string[];
  metadata?: Record<string, unknown>;
}

export interface ArtifactKbIndexInput {
  repoRoot: string;
  moduleId: string;
  runId?: string;
  artifacts: ArtifactKbSourceInput[];
  now?: () => Date;
}

export interface ArtifactKbIndexResult {
  path: string;
  sources: number;
  chunks: number;
}

export interface ArtifactKbSearchInput {
  query?: string;
  moduleId?: string;
  kinds?: string[];
  runId?: string;
  path?: string;
  limit?: number;
  maxChunkChars?: number;
}

export interface ArtifactKbSearchHit {
  chunkId: string;
  sourceId: string;
  moduleId: string;
  kind: string;
  title: string;
  summary: string;
  body: string;
  refs: string[];
  sourcePath: string;
  runId?: string;
  score: number;
}

export interface ArtifactKbSearchResult {
  path: string;
  query: string;
  results: ArtifactKbSearchHit[];
}

export interface ArtifactKbChunkRow {
  id: string;
  source_id: string;
  module_id: string;
  run_id: string | null;
  kind: string;
  title: string;
  summary: string;
  body: string;
  refs_json: string;
  metadata_json: string;
  source_path: string;
  score?: number;
}
