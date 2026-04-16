export function parseCsvRecords(content: string): string[][] {
  const normalized = content.startsWith("\uFEFF") ? content.slice(1) : content;
  const rows: string[][] = [];
  let row: string[] = [];
  let cell = "";
  let inQuotes = false;

  for (let idx = 0; idx < normalized.length; idx += 1) {
    const char = normalized[idx];

    if (inQuotes) {
      if (char === '"') {
        const next = normalized[idx + 1];
        if (next === '"') {
          cell += '"';
          idx += 1;
        } else {
          inQuotes = false;
        }
      } else {
        cell += char;
      }
      continue;
    }

    if (char === '"') {
      inQuotes = true;
      continue;
    }

    if (char === ",") {
      row.push(cell);
      cell = "";
      continue;
    }

    if (char === "\n") {
      row.push(cell);
      rows.push(row);
      row = [];
      cell = "";
      continue;
    }

    if (char === "\r") {
      row.push(cell);
      rows.push(row);
      row = [];
      cell = "";
      if (normalized[idx + 1] === "\n") {
        idx += 1;
      }
      continue;
    }

    cell += char;
  }

  if (cell.length > 0 || row.length > 0) {
    row.push(cell);
    rows.push(row);
  }

  return rows;
}

export function isCsvRecordBlank(record: string[]): boolean {
  return record.every((value) => value.trim().length === 0);
}

export function normalizeCandidateMarker(
  value: string | undefined,
): "source_candidate" | "sink_candidate" | null {
  const marker = value?.trim().toLowerCase();
  if (marker === "source_candidate" || marker === "sink_candidate") {
    return marker;
  }
  return null;
}

export function countCandidateCsvRecords(
  content: string,
  expectedKind: "source_candidate" | "sink_candidate",
): number {
  const rows = parseCsvRecords(content);
  let count = 0;

  for (const row of rows) {
    if (isCsvRecordBlank(row)) {
      continue;
    }
    const marker = normalizeCandidateMarker(row[1]);
    if (marker === expectedKind) {
      count += 1;
    }
  }

  return count;
}

export function toCsvRow(cells: string[]): string {
  return cells
    .map((cell) => {
      const value = cell ?? "";
      if (!/[",\r\n]/.test(value)) {
        return value;
      }
      return `"${value.replaceAll('"', '""')}"`;
    })
    .join(",");
}
