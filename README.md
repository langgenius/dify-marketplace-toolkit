# dify-marketplace-toolkit

Toolkit for validating and uploading Dify Marketplace plugin packages.

## Local `.difypkg` validation

Use the local validator before submitting a plugin package PR. It checks a built
`.difypkg` package with the same package-level rules used by Marketplace review.

From the `dify-marketplace-toolkit` root:

```bash
python3 validator/validate-difypkg.py /path/to/plugin.difypkg \
  --output-dir /path/to/report-dir
```

If you also want to check sensitive capability disclosure against PR text, pass a
file containing the PR body:

```bash
python3 validator/validate-difypkg.py /path/to/plugin.difypkg \
  --pr-body-file /path/to/pr-body.md \
  --output-dir /path/to/report-dir
```

### Prerequisites

- `python3`
- `yq`, used by the manifest validator

If `yq` is missing, the validator checks for it at startup. In an interactive
terminal it asks before installing `yq` with Homebrew. In non-interactive
environments it prints the install command and exits with code `1`.

### Validation goals

The local validator covers checks that can be evaluated from the `.difypkg`
itself:

- safe unzip and package path validation
- package contents, blocked development artifacts, package size, unpacked size,
  and unpacked file count
- secret patterns, including OpenAI, AWS, GitHub, Slack, private keys, JWT, and
  secret assignments
- executable binaries, binary magic bytes, and platform daemon filenames
- `manifest.yaml` metadata, source repository URL, contact email, privacy field,
  and required `PRIVACY.md`
- README metadata, source repository URL, and English primary content
- dependency policy, including no bare requirements, no git/direct URL installs,
  and `dify-plugin >= 0.9.0`
- Python compile check
- Python safety warnings
- prohibited financial activity review warnings
- optional sensitive capability disclosure check when `--pr-body-file` is
  provided

The local validator does not cover checks that require PR or Marketplace
context, such as PR title/body language, PR template completeness, duplicate
published versions, GitHub review submission, plugin install tests, or
`upload-package.py --test`.

### Output

The command prints a summary table to the terminal and writes report files under
`--output-dir`:

- `summary.md`: overall Markdown report
- `*.errors.txt`: blocking findings by check
- `*.warnings.txt`: review warnings by check

Exit code `0` means no blocking errors were found. Exit code `1` means at least
one blocking error or environment error was found. Warnings alone do not make the
command fail.

If `--output-dir` is not provided, reports are written to a temporary directory
that is cleaned up when the command exits. Use `--keep-temp` only when you also
want to keep the unpacked package directory for debugging.

## Codex / Claude Code skill

The self-contained skill is available at:

```text
skill/local-difypkg-validator
```

Users can copy or install that folder into their agent skills directory and ask
the agent to validate a local package, for example:

```text
Please use local-difypkg-validator to validate /path/to/plugin.difypkg
```

The skill includes its own bundled validator scripts, so it can run without a
separate toolkit checkout.
