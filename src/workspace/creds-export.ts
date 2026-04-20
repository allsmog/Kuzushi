/**
 * Credential export formatters — CSV, John the Ripper, Hashcat.
 *
 * Operators crack captured hashes with JtR or Hashcat; both want a
 * specific text layout. CSV is the default human-readable dump.
 */

import type { Cred } from "./entities.js";

export type CredsExportFormat = "csv" | "jtr" | "hcat";

export function exportCreds(rows: Cred[], format: CredsExportFormat): string {
  switch (format) {
    case "csv":
      return toCsv(rows);
    case "jtr":
      return toJtr(rows);
    case "hcat":
      return toHcat(rows);
  }
}

function csvEscape(value: string): string {
  if (value.includes(",") || value.includes('"') || value.includes("\n")) {
    return `"${value.replace(/"/g, '""')}"`;
  }
  return value;
}

function toCsv(rows: Cred[]): string {
  const header = [
    "id",
    "username",
    "private_type",
    "private_data",
    "realm_kind",
    "realm_value",
    "origin_type",
  ].join(",");
  const body = rows.map((r) =>
    [
      r.id.slice(0, 8),
      csvEscape(r.publicUsername ?? ""),
      r.privateType ?? "",
      csvEscape(r.privateData ?? ""),
      r.realmKind ?? "",
      csvEscape(r.realmValue ?? ""),
      r.originType ?? "",
    ].join(","),
  );
  return [header, ...body].join("\n") + "\n";
}

/**
 * John the Ripper `passwd`-style format: `user:hash`. Skips creds without
 * a private half or without a username (both would fail to crack).
 */
function toJtr(rows: Cred[]): string {
  const lines = rows
    .filter((r) => r.publicUsername && r.privateData)
    .map((r) => `${r.publicUsername}:${r.privateData}`);
  return lines.join("\n") + (lines.length ? "\n" : "");
}

/**
 * Hashcat `-m <mode>`-style format: just the hash, one per line.
 * Usernames are dropped because Hashcat expects raw hashes.
 */
function toHcat(rows: Cred[]): string {
  const lines = rows.filter((r) => r.privateData).map((r) => r.privateData as string);
  return lines.join("\n") + (lines.length ? "\n" : "");
}
