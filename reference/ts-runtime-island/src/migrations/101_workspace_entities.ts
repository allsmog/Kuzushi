import type { Migration } from "./types.js";

/**
 * v101 — workspace entity tables (msfconsole-inspired).
 *
 * Adds the core relational model for security engagements, mirroring
 * Metasploit's db_manager layout (lib/msf/core/db_manager/*). Every table is
 * workspace-scoped; deleting a workspace cascades through the children.
 *
 *   workspaces (from v100)
 *     ├── hosts          (IP / hostname + OS fingerprint)
 *     │     └── services (open port + protocol + fingerprint)
 *     │           └── vulns
 *     ├── creds          (Core → public/private/realm)
 *     │     └── cred_logins (cred × service)
 *     ├── loot           (exfil'd files / screenshots / notes)
 *     ├── notes          (free-form typed observations)
 *     └── sessions       (long-lived connections: ssh, browser, honeypot, etc.)
 */
export const migration101: Migration = {
  version: 101,
  name: "workspace_entities",
  up(db) {
    db.exec(`
      ----------------------------------------------------------------------
      -- hosts
      ----------------------------------------------------------------------
      CREATE TABLE hosts (
        id             TEXT PRIMARY KEY,
        workspace_id   TEXT NOT NULL
                       REFERENCES workspaces(id) ON DELETE CASCADE,
        address        TEXT NOT NULL,
        hostname       TEXT,
        os_name        TEXT,
        os_flavor      TEXT,
        os_version     TEXT,
        arch           TEXT,
        purpose        TEXT,
        state          TEXT NOT NULL DEFAULT 'alive'
                       CHECK (state IN ('alive', 'down', 'unknown')),
        comm           TEXT,
        metadata_json  TEXT NOT NULL DEFAULT '{}',
        created_at     TEXT NOT NULL DEFAULT (datetime('now')),
        updated_at     TEXT NOT NULL DEFAULT (datetime('now')),
        UNIQUE (workspace_id, address)
      );
      CREATE INDEX idx_hosts_workspace ON hosts(workspace_id);

      ----------------------------------------------------------------------
      -- services
      ----------------------------------------------------------------------
      CREATE TABLE services (
        id            TEXT PRIMARY KEY,
        host_id       TEXT NOT NULL
                      REFERENCES hosts(id) ON DELETE CASCADE,
        port          INTEGER NOT NULL CHECK (port >= 0 AND port <= 65535),
        proto         TEXT NOT NULL DEFAULT 'tcp'
                      CHECK (proto IN ('tcp', 'udp', 'icmp', 'sctp')),
        name          TEXT,
        banner        TEXT,
        state         TEXT NOT NULL DEFAULT 'open'
                      CHECK (state IN ('open', 'closed', 'filtered', 'unknown')),
        info_json     TEXT NOT NULL DEFAULT '{}',
        created_at    TEXT NOT NULL DEFAULT (datetime('now')),
        updated_at    TEXT NOT NULL DEFAULT (datetime('now')),
        UNIQUE (host_id, port, proto)
      );
      CREATE INDEX idx_services_host ON services(host_id);

      ----------------------------------------------------------------------
      -- vulns
      ----------------------------------------------------------------------
      CREATE TABLE vulns (
        id             TEXT PRIMARY KEY,
        workspace_id   TEXT NOT NULL
                       REFERENCES workspaces(id) ON DELETE CASCADE,
        host_id        TEXT
                       REFERENCES hosts(id) ON DELETE SET NULL,
        service_id     TEXT
                       REFERENCES services(id) ON DELETE SET NULL,
        finding_fp     TEXT,   -- fingerprint from findings table, if any
        name           TEXT NOT NULL,
        description    TEXT,
        severity       TEXT
                       CHECK (severity IS NULL OR severity IN ('info','low','medium','high','critical')),
        references_json TEXT NOT NULL DEFAULT '[]',   -- [{type: 'CVE', value: '...'}]
        check_code     TEXT
                       CHECK (check_code IS NULL
                              OR check_code IN ('unknown','safe','detected','appears','vulnerable','unsupported')),
        check_reason   TEXT,
        metadata_json  TEXT NOT NULL DEFAULT '{}',
        created_at     TEXT NOT NULL DEFAULT (datetime('now')),
        updated_at     TEXT NOT NULL DEFAULT (datetime('now'))
      );
      CREATE INDEX idx_vulns_workspace ON vulns(workspace_id);
      CREATE INDEX idx_vulns_host      ON vulns(host_id);
      CREATE INDEX idx_vulns_service   ON vulns(service_id);
      CREATE INDEX idx_vulns_finding   ON vulns(finding_fp);

      ----------------------------------------------------------------------
      -- loot
      ----------------------------------------------------------------------
      CREATE TABLE loot (
        id            TEXT PRIMARY KEY,
        workspace_id  TEXT NOT NULL
                      REFERENCES workspaces(id) ON DELETE CASCADE,
        host_id       TEXT
                      REFERENCES hosts(id) ON DELETE SET NULL,
        ltype         TEXT NOT NULL,              -- mimic msf: "credential.ssh_key"
        content_type  TEXT,                        -- mime-ish; optional
        name          TEXT NOT NULL,
        path          TEXT,                        -- on-disk path, optional
        data          BLOB,                        -- inline storage (small loot)
        info          TEXT,                        -- short description
        metadata_json TEXT NOT NULL DEFAULT '{}',
        created_at    TEXT NOT NULL DEFAULT (datetime('now'))
      );
      CREATE INDEX idx_loot_workspace ON loot(workspace_id);
      CREATE INDEX idx_loot_type      ON loot(workspace_id, ltype);

      ----------------------------------------------------------------------
      -- notes
      ----------------------------------------------------------------------
      CREATE TABLE notes (
        id            TEXT PRIMARY KEY,
        workspace_id  TEXT NOT NULL
                      REFERENCES workspaces(id) ON DELETE CASCADE,
        host_id       TEXT
                      REFERENCES hosts(id) ON DELETE SET NULL,
        service_id    TEXT
                      REFERENCES services(id) ON DELETE SET NULL,
        ntype         TEXT NOT NULL,
        data_json     TEXT NOT NULL DEFAULT '{}',
        created_at    TEXT NOT NULL DEFAULT (datetime('now'))
      );
      CREATE INDEX idx_notes_workspace ON notes(workspace_id);

      ----------------------------------------------------------------------
      -- creds — normalized Core{public, private, realm}
      ----------------------------------------------------------------------
      CREATE TABLE creds (
        id              TEXT PRIMARY KEY,
        workspace_id    TEXT NOT NULL
                        REFERENCES workspaces(id) ON DELETE CASCADE,
        public_username TEXT,
        private_type    TEXT
                        CHECK (private_type IS NULL OR private_type IN
                               ('password','hash','ssh_key','token','api_key','cookie','other')),
        private_data    TEXT,
        realm_kind      TEXT,
        realm_value     TEXT,
        origin_type     TEXT,
        origin_detail   TEXT,
        metadata_json   TEXT NOT NULL DEFAULT '{}',
        created_at      TEXT NOT NULL DEFAULT (datetime('now')),
        updated_at      TEXT NOT NULL DEFAULT (datetime('now'))
      );
      CREATE INDEX idx_creds_workspace ON creds(workspace_id);
      CREATE INDEX idx_creds_user      ON creds(workspace_id, public_username);

      ----------------------------------------------------------------------
      -- cred_logins — join between creds and services
      ----------------------------------------------------------------------
      CREATE TABLE cred_logins (
        id           TEXT PRIMARY KEY,
        cred_id      TEXT NOT NULL
                     REFERENCES creds(id) ON DELETE CASCADE,
        service_id   TEXT NOT NULL
                     REFERENCES services(id) ON DELETE CASCADE,
        status       TEXT NOT NULL DEFAULT 'untried'
                     CHECK (status IN ('untried','successful','failed','locked_out','disabled')),
        access_level TEXT,
        last_tried_at TEXT,
        created_at   TEXT NOT NULL DEFAULT (datetime('now')),
        UNIQUE (cred_id, service_id)
      );
      CREATE INDEX idx_logins_service ON cred_logins(service_id);

      ----------------------------------------------------------------------
      -- sessions — long-lived connections (ssh/browser/honeypot/agent)
      ----------------------------------------------------------------------
      CREATE TABLE sessions (
        id             TEXT PRIMARY KEY,
        workspace_id   TEXT NOT NULL
                       REFERENCES workspaces(id) ON DELETE CASCADE,
        host_id        TEXT
                       REFERENCES hosts(id) ON DELETE SET NULL,
        service_id     TEXT
                       REFERENCES services(id) ON DELETE SET NULL,
        kind           TEXT NOT NULL,    -- 'shell' | 'ssh' | 'browser' | 'honeypot' | ...
        state          TEXT NOT NULL DEFAULT 'open'
                       CHECK (state IN ('open','closed','error')),
        tunnel_peer    TEXT,
        tunnel_local   TEXT,
        description    TEXT,
        via_module     TEXT,
        via_tool       TEXT,
        opened_at      TEXT NOT NULL DEFAULT (datetime('now')),
        closed_at      TEXT,
        metadata_json  TEXT NOT NULL DEFAULT '{}'
      );
      CREATE INDEX idx_sessions_workspace ON sessions(workspace_id);
      CREATE INDEX idx_sessions_state     ON sessions(workspace_id, state);
    `);
  },
};
