use super::*;

impl ReconWorkspaceStore {
    pub fn open(workspace: &WorkspaceTarget) -> Result<Self> {
        workspace.ensure_state_dir()?;
        let db_path = workspace.findings_db_path();
        let conn = crate::sqlite_connection::open_file(&db_path)?;
        let store = Self {
            conn,
            db_path: db_path.display().to_string(),
        };
        store.init()?;
        Ok(store)
    }

    pub fn db_path(&self) -> &str {
        &self.db_path
    }

    pub(crate) fn init(&self) -> Result<()> {
        self.conn.execute_batch(
            r#"
            pragma foreign_keys = on;

            create table if not exists workspaces (
              id text primary key,
              name text not null unique,
              targets_json text not null default '[]',
              created_at text not null,
              last_accessed_at text not null,
              metadata_json text not null default '{}',
              updated_at text not null default (datetime('now'))
            );

            create table if not exists hosts (
              id text primary key,
              workspace_id text not null references workspaces(id) on delete cascade,
              address text not null,
              hostname text,
              os_name text,
              os_flavor text,
              os_version text,
              arch text,
              purpose text,
              state text not null default 'alive' check (state in ('alive','down','unknown')),
              comm text,
              metadata_json text not null default '{}',
              created_at text not null default (datetime('now')),
              updated_at text not null default (datetime('now')),
              unique(workspace_id, address)
            );
            create index if not exists idx_hosts_workspace on hosts(workspace_id);

            create table if not exists services (
              id text primary key,
              host_id text not null references hosts(id) on delete cascade,
              port integer not null check (port >= 0 and port <= 65535),
              proto text not null default 'tcp' check (proto in ('tcp','udp','icmp','sctp')),
              name text,
              banner text,
              state text not null default 'open' check (state in ('open','closed','filtered','unknown')),
              info_json text not null default '{}',
              created_at text not null default (datetime('now')),
              updated_at text not null default (datetime('now')),
              unique(host_id, port, proto)
            );
            create index if not exists idx_services_host on services(host_id);

            create table if not exists notes (
              id text primary key,
              workspace_id text not null references workspaces(id) on delete cascade,
              host_id text references hosts(id) on delete set null,
              service_id text references services(id) on delete set null,
              ntype text not null,
              data_json text not null default '{}',
              created_at text not null default (datetime('now'))
            );
            create index if not exists idx_notes_workspace on notes(workspace_id);
            "#,
        )?;
        Ok(())
    }
}
