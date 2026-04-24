import type { Migration } from "./types.js";

const credentialIdentityMatch = `
  existing.workspace_id = NEW.workspace_id
  AND IFNULL(existing.public_username, '') = IFNULL(NEW.public_username, '')
  AND IFNULL(existing.private_type, '') = IFNULL(NEW.private_type, '')
  AND IFNULL(existing.private_data, '') = IFNULL(NEW.private_data, '')
  AND IFNULL(existing.realm_kind, '') = IFNULL(NEW.realm_kind, '')
  AND IFNULL(existing.realm_value, '') = IFNULL(NEW.realm_value, '')
`;

const validScheduleInterval = `
  lower(substr(trim(NEW.interval_spec), length(trim(NEW.interval_spec)), 1)) IN ('s','m','h','d')
  AND length(trim(substr(trim(NEW.interval_spec), 1, length(trim(NEW.interval_spec)) - 1))) > 0
  AND trim(substr(trim(NEW.interval_spec), 1, length(trim(NEW.interval_spec)) - 1)) NOT GLOB '*[^0-9]*'
  AND CAST(trim(substr(trim(NEW.interval_spec), 1, length(trim(NEW.interval_spec)) - 1)) AS INTEGER) > 0
`;

const validScheduleTimes = `
  typeof(NEW.next_fire_at) = 'integer'
  AND NEW.next_fire_at >= 0
  AND (
    NEW.last_fired_at IS NULL
    OR (typeof(NEW.last_fired_at) = 'integer' AND NEW.last_fired_at >= 0)
  )
`;

/**
 * v104 — integrity guards for post-v100 tables.
 *
 * SQLite cannot add NOT VALID CHECK/FK/UNIQUE constraints with ALTER TABLE.
 * These triggers enforce the same high-confidence invariants for future
 * writes without validating or rewriting existing rows.
 */
export const migration104: Migration = {
  version: 104,
  name: "workspace_integrity_guards",
  up(db) {
    db.exec(`
      ----------------------------------------------------------------------
      -- Credential identity uniqueness.
      --
      -- CredStore.upsert dedupes by these six fields using IFNULL(..., '').
      -- Enforce the same identity rule below the store API without creating
      -- a UNIQUE index that duplicates private_data into a second B-tree.
      ----------------------------------------------------------------------
      CREATE TRIGGER IF NOT EXISTS trg_creds_identity_unique_insert
      BEFORE INSERT ON creds
      WHEN EXISTS (
        SELECT 1
        FROM creds AS existing
        WHERE ${credentialIdentityMatch}
      )
      BEGIN
        SELECT RAISE(ABORT, 'duplicate credential identity');
      END;

      CREATE TRIGGER IF NOT EXISTS trg_creds_identity_unique_update
      BEFORE UPDATE OF workspace_id, public_username, private_type, private_data, realm_kind, realm_value ON creds
      WHEN EXISTS (
        SELECT 1
        FROM creds AS existing
        WHERE existing.id <> NEW.id
          AND ${credentialIdentityMatch}
      )
      BEGIN
        SELECT RAISE(ABORT, 'duplicate credential identity');
      END;

      ----------------------------------------------------------------------
      -- Workspace-scoped child links.
      ----------------------------------------------------------------------
      CREATE TRIGGER IF NOT EXISTS trg_vulns_workspace_links_insert
      BEFORE INSERT ON vulns
      WHEN
        (
          NEW.host_id IS NOT NULL
          AND NOT EXISTS (
            SELECT 1 FROM hosts
            WHERE hosts.id = NEW.host_id
              AND hosts.workspace_id = NEW.workspace_id
          )
        )
        OR (
          NEW.service_id IS NOT NULL
          AND NOT EXISTS (
            SELECT 1
            FROM services
            JOIN hosts ON hosts.id = services.host_id
            WHERE services.id = NEW.service_id
              AND hosts.workspace_id = NEW.workspace_id
          )
        )
        OR (
          NEW.host_id IS NOT NULL
          AND NEW.service_id IS NOT NULL
          AND NOT EXISTS (
            SELECT 1 FROM services
            WHERE services.id = NEW.service_id
              AND services.host_id = NEW.host_id
          )
        )
      BEGIN
        SELECT RAISE(ABORT, 'vuln host/service must belong to the vuln workspace');
      END;

      CREATE TRIGGER IF NOT EXISTS trg_vulns_workspace_links_update
      BEFORE UPDATE OF workspace_id, host_id, service_id ON vulns
      WHEN
        (
          NEW.host_id IS NOT NULL
          AND NOT EXISTS (
            SELECT 1 FROM hosts
            WHERE hosts.id = NEW.host_id
              AND hosts.workspace_id = NEW.workspace_id
          )
        )
        OR (
          NEW.service_id IS NOT NULL
          AND NOT EXISTS (
            SELECT 1
            FROM services
            JOIN hosts ON hosts.id = services.host_id
            WHERE services.id = NEW.service_id
              AND hosts.workspace_id = NEW.workspace_id
          )
        )
        OR (
          NEW.host_id IS NOT NULL
          AND NEW.service_id IS NOT NULL
          AND NOT EXISTS (
            SELECT 1 FROM services
            WHERE services.id = NEW.service_id
              AND services.host_id = NEW.host_id
          )
        )
      BEGIN
        SELECT RAISE(ABORT, 'vuln host/service must belong to the vuln workspace');
      END;

      CREATE TRIGGER IF NOT EXISTS trg_loot_workspace_host_insert
      BEFORE INSERT ON loot
      WHEN NEW.host_id IS NOT NULL
        AND NOT EXISTS (
          SELECT 1 FROM hosts
          WHERE hosts.id = NEW.host_id
            AND hosts.workspace_id = NEW.workspace_id
        )
      BEGIN
        SELECT RAISE(ABORT, 'loot host must belong to the loot workspace');
      END;

      CREATE TRIGGER IF NOT EXISTS trg_loot_workspace_host_update
      BEFORE UPDATE OF workspace_id, host_id ON loot
      WHEN NEW.host_id IS NOT NULL
        AND NOT EXISTS (
          SELECT 1 FROM hosts
          WHERE hosts.id = NEW.host_id
            AND hosts.workspace_id = NEW.workspace_id
        )
      BEGIN
        SELECT RAISE(ABORT, 'loot host must belong to the loot workspace');
      END;

      CREATE TRIGGER IF NOT EXISTS trg_notes_workspace_links_insert
      BEFORE INSERT ON notes
      WHEN
        (
          NEW.host_id IS NOT NULL
          AND NOT EXISTS (
            SELECT 1 FROM hosts
            WHERE hosts.id = NEW.host_id
              AND hosts.workspace_id = NEW.workspace_id
          )
        )
        OR (
          NEW.service_id IS NOT NULL
          AND NOT EXISTS (
            SELECT 1
            FROM services
            JOIN hosts ON hosts.id = services.host_id
            WHERE services.id = NEW.service_id
              AND hosts.workspace_id = NEW.workspace_id
          )
        )
        OR (
          NEW.host_id IS NOT NULL
          AND NEW.service_id IS NOT NULL
          AND NOT EXISTS (
            SELECT 1 FROM services
            WHERE services.id = NEW.service_id
              AND services.host_id = NEW.host_id
          )
        )
      BEGIN
        SELECT RAISE(ABORT, 'note host/service must belong to the note workspace');
      END;

      CREATE TRIGGER IF NOT EXISTS trg_notes_workspace_links_update
      BEFORE UPDATE OF workspace_id, host_id, service_id ON notes
      WHEN
        (
          NEW.host_id IS NOT NULL
          AND NOT EXISTS (
            SELECT 1 FROM hosts
            WHERE hosts.id = NEW.host_id
              AND hosts.workspace_id = NEW.workspace_id
          )
        )
        OR (
          NEW.service_id IS NOT NULL
          AND NOT EXISTS (
            SELECT 1
            FROM services
            JOIN hosts ON hosts.id = services.host_id
            WHERE services.id = NEW.service_id
              AND hosts.workspace_id = NEW.workspace_id
          )
        )
        OR (
          NEW.host_id IS NOT NULL
          AND NEW.service_id IS NOT NULL
          AND NOT EXISTS (
            SELECT 1 FROM services
            WHERE services.id = NEW.service_id
              AND services.host_id = NEW.host_id
          )
        )
      BEGIN
        SELECT RAISE(ABORT, 'note host/service must belong to the note workspace');
      END;

      CREATE TRIGGER IF NOT EXISTS trg_cred_logins_workspace_insert
      BEFORE INSERT ON cred_logins
      WHEN NOT EXISTS (
        SELECT 1
        FROM creds
        JOIN services ON services.id = NEW.service_id
        JOIN hosts ON hosts.id = services.host_id
        WHERE creds.id = NEW.cred_id
          AND hosts.workspace_id = creds.workspace_id
      )
      BEGIN
        SELECT RAISE(ABORT, 'credential login must link a credential and service in the same workspace');
      END;

      CREATE TRIGGER IF NOT EXISTS trg_cred_logins_workspace_update
      BEFORE UPDATE OF cred_id, service_id ON cred_logins
      WHEN NOT EXISTS (
        SELECT 1
        FROM creds
        JOIN services ON services.id = NEW.service_id
        JOIN hosts ON hosts.id = services.host_id
        WHERE creds.id = NEW.cred_id
          AND hosts.workspace_id = creds.workspace_id
      )
      BEGIN
        SELECT RAISE(ABORT, 'credential login must link a credential and service in the same workspace');
      END;

      CREATE TRIGGER IF NOT EXISTS trg_sessions_workspace_links_insert
      BEFORE INSERT ON sessions
      WHEN
        (
          NEW.host_id IS NOT NULL
          AND NOT EXISTS (
            SELECT 1 FROM hosts
            WHERE hosts.id = NEW.host_id
              AND hosts.workspace_id = NEW.workspace_id
          )
        )
        OR (
          NEW.service_id IS NOT NULL
          AND NOT EXISTS (
            SELECT 1
            FROM services
            JOIN hosts ON hosts.id = services.host_id
            WHERE services.id = NEW.service_id
              AND hosts.workspace_id = NEW.workspace_id
          )
        )
        OR (
          NEW.host_id IS NOT NULL
          AND NEW.service_id IS NOT NULL
          AND NOT EXISTS (
            SELECT 1 FROM services
            WHERE services.id = NEW.service_id
              AND services.host_id = NEW.host_id
          )
        )
      BEGIN
        SELECT RAISE(ABORT, 'session host/service must belong to the session workspace');
      END;

      CREATE TRIGGER IF NOT EXISTS trg_sessions_workspace_links_update
      BEFORE UPDATE OF workspace_id, host_id, service_id ON sessions
      WHEN
        (
          NEW.host_id IS NOT NULL
          AND NOT EXISTS (
            SELECT 1 FROM hosts
            WHERE hosts.id = NEW.host_id
              AND hosts.workspace_id = NEW.workspace_id
          )
        )
        OR (
          NEW.service_id IS NOT NULL
          AND NOT EXISTS (
            SELECT 1
            FROM services
            JOIN hosts ON hosts.id = services.host_id
            WHERE services.id = NEW.service_id
              AND hosts.workspace_id = NEW.workspace_id
          )
        )
        OR (
          NEW.host_id IS NOT NULL
          AND NEW.service_id IS NOT NULL
          AND NOT EXISTS (
            SELECT 1 FROM services
            WHERE services.id = NEW.service_id
              AND services.host_id = NEW.host_id
          )
        )
      BEGIN
        SELECT RAISE(ABORT, 'session host/service must belong to the session workspace');
      END;

      ----------------------------------------------------------------------
      -- Persisted schedule shape.
      ----------------------------------------------------------------------
      CREATE TRIGGER IF NOT EXISTS trg_schedules_validate_insert
      BEFORE INSERT ON schedules
      WHEN NOT (
        ${validScheduleInterval}
        AND ${validScheduleTimes}
      )
      BEGIN
        SELECT RAISE(ABORT, 'invalid persisted schedule');
      END;

      CREATE TRIGGER IF NOT EXISTS trg_schedules_validate_update
      BEFORE UPDATE OF interval_spec, last_fired_at, next_fire_at ON schedules
      WHEN NOT (
        ${validScheduleInterval}
        AND ${validScheduleTimes}
      )
      BEGIN
        SELECT RAISE(ABORT, 'invalid persisted schedule');
      END;
    `);
  },
};
