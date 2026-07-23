---
name: local-difypkg-validator
description: Validate a local Dify .difypkg file with bundled Marketplace package validators. Use when a user wants to check a downloaded or locally built plugin package before submitting a PR, including package contents, secrets, binaries, manifest/privacy, README, dependencies, Python safety warnings, and financial-activity review signals.
---

# Local DIFYPKG Validator

Use this skill when the user wants to validate a local `.difypkg` package without opening or reviewing a GitHub PR.

## Workflow

1. Get the local `.difypkg` path from the user.
2. Check prerequisites before running validation:
   ```bash
   command -v python3
   command -v yq
   ```
   If `python3` is missing, ask the user before installing or direct them to install Python. If `yq` is missing, ask whether to install it with Homebrew (`brew install yq`) before continuing. Do not install dependencies silently.
3. Run the bundled validator CLI from this skill:
   ```bash
   python3 validator/validate-difypkg.py /path/to/plugin.difypkg
   ```
4. The wrapper script is also available for agent environments that prefer `scripts/` entrypoints:
   ```bash
   python3 scripts/validate_difypkg.py /path/to/plugin.difypkg
   ```
5. By default, the skill uses its bundled `validator/` directory. To force use of an external toolkit checkout, pass:
   ```bash
   python3 scripts/validate_difypkg.py /path/to/plugin.difypkg --toolkit-dir /path/to/dify-marketplace-toolkit
   ```
6. Report the summary table and the report directory path.
7. Treat exit code `0` as pass with possible warnings; exit code `1` means blocking errors or environment failures were found.

## Optional Inputs

- `--pr-body-file <path>`: run sensitive capability disclosure checks that need PR body text.
- `--keep-temp`: keep the unpacked package and reports in the temp directory.
- `--output-dir <path>`: write reports to a stable directory.

## Prerequisites

`python3` and `yq` must be available. The manifest validator uses `yq`.

The bundled validator CLI checks for `yq` at startup. In an interactive terminal it prompts before running `brew install yq`; in non-interactive environments it prints the install command and exits with code `1`.

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
