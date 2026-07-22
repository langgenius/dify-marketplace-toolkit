---
name: local-difypkg-validator
description: Validate a local Dify .difypkg file with bundled Marketplace package validators. Use when a user wants to check a downloaded or locally built plugin package before submitting a PR, including package contents, secrets, binaries, manifest/privacy, README, dependencies, Python safety warnings, and financial-activity review signals.
---

# Local DIFYPKG Validator

Use this skill when the user wants to validate a local `.difypkg` package without opening or reviewing a GitHub PR.

## Workflow

1. Get the local `.difypkg` path from the user.
2. Run the bundled validator CLI from this skill:
   ```bash
   python3 validator/validate-difypkg.py /path/to/plugin.difypkg
   ```
3. The wrapper script is also available for agent environments that prefer `scripts/` entrypoints:
   ```bash
   python3 scripts/validate_difypkg.py /path/to/plugin.difypkg
   ```
4. By default, the skill uses its bundled `validator/` directory. To force use of an external toolkit checkout, pass:
   ```bash
   python3 scripts/validate_difypkg.py /path/to/plugin.difypkg --toolkit-dir /path/to/dify-marketplace-toolkit
   ```
5. Report the summary table and the report directory path.
6. Treat exit code `0` as pass with possible warnings; exit code `1` means blocking errors or environment failures were found.

## Optional Inputs

- `--pr-body-file <path>`: run sensitive capability disclosure checks that need PR body text.
- `--keep-temp`: keep the unpacked package and reports in the temp directory.
- `--output-dir <path>`: write reports to a stable directory.

## Prerequisites

`python3` and `yq` must be available. The manifest validator uses `yq`; if it is missing, the manifest check is reported as a blocking environment failure.

## Coverage

Default local validation covers checks that can be evaluated from the `.difypkg` itself:

- package path and safe unzip
- package contents, size, and file count
- secret patterns
- executable binaries and platform daemon names
- manifest metadata and privacy policy
- README metadata
- dependency policy
- Python compile check
- Python safety warnings
- prohibited financial activity review warnings

The skill is self-contained for local package checks: copying or installing the `local-difypkg-validator` folder includes the validator scripts it calls. It does not submit GitHub reviews and does not run PR-only checks unless the required local input is provided. PR title/body language, PR template completeness, and Marketplace duplicate-version checks remain PR/CI workflow responsibilities.

## Expected Response

Summarize:

- whether the package passed blocking checks
- blocking categories and first few findings
- warning categories and first few findings
- skipped PR-only checks
- report directory path
