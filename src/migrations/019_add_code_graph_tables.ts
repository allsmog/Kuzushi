import type { Migration } from "./types.js";

export const migration019: Migration = {
  version: 19,
  name: "add_code_graph_tables",
  up(db) {
    db.exec(`
      CREATE TABLE IF NOT EXISTS code_graph_nodes (
        node_id         TEXT PRIMARY KEY,
        repo            TEXT NOT NULL,
        run_id          TEXT NOT NULL,
        file_path       TEXT NOT NULL,
        start_line      INTEGER NOT NULL,
        symbol          TEXT,
        node_kind       TEXT NOT NULL,
        framework       TEXT,
        metadata_json   TEXT,
        confidence      REAL NOT NULL DEFAULT 1.0,
        source          TEXT NOT NULL DEFAULT 'static',
        created_at      TEXT NOT NULL DEFAULT (datetime('now')),
        updated_at      TEXT NOT NULL DEFAULT (datetime('now'))
      );

      CREATE INDEX IF NOT EXISTS idx_cgn_repo
        ON code_graph_nodes(repo);
      CREATE INDEX IF NOT EXISTS idx_cgn_file
        ON code_graph_nodes(repo, file_path);
      CREATE INDEX IF NOT EXISTS idx_cgn_kind
        ON code_graph_nodes(repo, node_kind);

      CREATE TABLE IF NOT EXISTS code_graph_edges (
        edge_id         TEXT PRIMARY KEY,
        repo            TEXT NOT NULL,
        run_id          TEXT NOT NULL,
        from_node_id    TEXT NOT NULL REFERENCES code_graph_nodes(node_id),
        to_node_id      TEXT NOT NULL REFERENCES code_graph_nodes(node_id),
        edge_kind       TEXT NOT NULL,
        data_label      TEXT,
        ordinal         INTEGER,
        confidence      REAL NOT NULL DEFAULT 1.0,
        source          TEXT NOT NULL DEFAULT 'static',
        created_at      TEXT NOT NULL DEFAULT (datetime('now'))
      );

      CREATE INDEX IF NOT EXISTS idx_cge_repo
        ON code_graph_edges(repo);
      CREATE INDEX IF NOT EXISTS idx_cge_from
        ON code_graph_edges(from_node_id);
      CREATE INDEX IF NOT EXISTS idx_cge_to
        ON code_graph_edges(to_node_id);

      CREATE TABLE IF NOT EXISTS code_graph_paths (
        path_id           TEXT PRIMARY KEY,
        repo              TEXT NOT NULL,
        run_id            TEXT NOT NULL,
        entry_node_id     TEXT NOT NULL REFERENCES code_graph_nodes(node_id),
        target_node_id    TEXT NOT NULL REFERENCES code_graph_nodes(node_id),
        hop_count         INTEGER NOT NULL,
        path_node_ids     TEXT NOT NULL,
        path_edge_ids     TEXT NOT NULL,
        has_sanitizer     INTEGER NOT NULL DEFAULT 0,
        sanitizer_nodes   TEXT,
        confidence        REAL NOT NULL,
        created_at        TEXT NOT NULL DEFAULT (datetime('now'))
      );

      CREATE INDEX IF NOT EXISTS idx_cgp_target
        ON code_graph_paths(repo, target_node_id);
      CREATE INDEX IF NOT EXISTS idx_cgp_entry
        ON code_graph_paths(repo, entry_node_id);
    `);
  },
};
