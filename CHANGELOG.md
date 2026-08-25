# Changelog

Notable changes to the FLOD System, starting from this file's introduction at
1.1.1. Earlier releases are not backfilled here; see the git tags and
`docs/roadmap.md` for that history. Versioning and tagging follow the rules
in this repository's own contribution conventions: a patch bump is a fix, a
minor bump adds a feature, milestones are numbered separately from tags.

## 1.1.1, 2026-08-25

### Fixed

- The `0.0.0.0` sentinel Stage 1 writes for a window with no attributable
  dominant source was being logged into `logs.src_ip` as if it were a real
  address. It could account for a large share of an incident log's "sources"
  during idle or low-traffic periods. Stage 2 now skips the incident-log
  write entirely for a window with no attributable source, instead of
  logging a placeholder.
- The PDF incident report rendered in landscape with an unpainted page
  margin, which made every report look like a screenshot pasted onto a
  blank sheet. Switched to portrait and gave the page an explicit
  background matching the report's own theme.

## 1.1.0, 2026-08-23

### Changed

- PDF incident report generation moved to server side rendering.
  `report_data.py` and `report_pdf.py` build the report from the database
  and render it with WeasyPrint, replacing the client supplied chart data
  the dashboard used to hand the server for the same purpose.

The version strings in `stage1/Cargo.toml`, `stage1-common/Cargo.toml`,
`stage1-ebpf/Cargo.toml`, and `stage2/config.py` were not updated in the
commit this tag points to, and still read `1.0.2` there. Corrected as part
of the 1.1.1 bump; noted here since this entry is otherwise the only public
record that 1.1.0 exists.
