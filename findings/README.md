# findings/

Catalog of vulnerabilities kuzushi has surfaced against real software.
One subdirectory per target.

## Layout

```
findings/
├── README.md           ← this file
└── <target>/
    ├── README.md        ← target-specific index, status legend, promotion checklist
    ├── NN-short-slug.md ← VERIFIED finding (numbered, sorted by discovery order)
    └── UNVERIFIED.md    ← agent-surfaced hypotheses awaiting source-level verification
```

## Targets

- [`mariadb/`](./mariadb/) — `MariaDB/server` HEAD `96b3dd0c` (2026-05-07)

## Per-finding template

Each VERIFIED entry follows the template documented in
`<target>/README.md`. Standard fields: status, severity, file, line(s),
CWE, discovered-by (which kuzushi tool found it), disclosure status,
summary, source quote, verification notes, suggested fix.

## Adding a new target

1. `mkdir findings/<target>/`
2. Run kuzushi against the target: `kuzushi --target <repo> run systems-hunt:systems-hunt`
3. Copy `findings/mariadb/README.md` as a starting template; replace
   the target metadata in the header.
4. For each finding kuzushi surfaces, follow the promotion checklist
   in the target README (read source, confirm claim, decide severity).
   Promote VERIFIED findings to numbered files.

## Why catalogue this rather than rely on issue trackers / advisories

Issue trackers and CVE databases are downstream of disclosure. This
catalogue captures findings *as they're discovered*, before disclosure
decisions are made — including findings that turn out to be false
positives, that get bundled with other reports, or that are held back
because the target's status (private, embargo, dependent) makes
disclosure costly. The catalogue is the source of truth for which
findings exist; the disclosure documents under
`/home/user/mariadb-disclosures/` (or equivalent) are the formal
artifacts that get sent to vendors.
