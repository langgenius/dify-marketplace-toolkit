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
- outbound access domains, and whether they match the optional
  `network.domains` node in `manifest.yaml`
- dependency vulnerabilities, looked up in the OSV database
- optional sensitive capability disclosure check when `--pr-body-file` is
  provided

The dependency vulnerability check is the only one that reaches the network.
Pass `--offline` to skip it; the run then reports the dependency set without a
verdict rather than reporting a clean one.

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

### Tests

```bash
make test     # offline unit tests
make check    # what CI runs: tests, stub wiring, skill sync
```

## Repository layout

```text
toolkit/            importable core -- no argparse, no sys.exit, unit-tested
  findings.py         the value every check returns
  cli.py              the one CLI shell all check scripts share
  registry.py         what the local validator runs, in what order
  walk.py  osv.py     shared file walk; OSV vulnerability client
  scan/               extracts facts: hosts, deps, capabilities, report
  checks/             turns those facts into errors and warnings
validator/          the CLI surface
  validate-difypkg.py   main entry point
  check-*.py            one six-line adapter per check -- paths other repos call
uploader/           publishing pipeline -- run it: python3 .scripts/uploader
  __main__.py         entry point
  cli.py              argparse and the upload -> scan report flow
  package_upload.py   POST /plugins/inner-upload; failures raise
  scan_report.py      scan + PUT /plugin-artifacts/{checksum}/scan-report; failures warn
  upload-package.py   deprecated alias for workflows not yet migrated
tools/sync-skill.py regenerates the bundled skill copy
```

Two rules keep this stable:

**Paths other repositories call are frozen until migrated.** `validator/check-pkg-paths.py`,
`validator/test-plugin-install.py` and the uploader entry are hardcoded in
`dify-plugins` and `dify-official-plugins` workflows, which clone this
repository at `HEAD` with no pinned SHA — moving one breaks every open plugin
PR in both repositories the moment it merges. The canonical uploader
invocation is the package directory itself, `python3 .scripts/uploader`;
`uploader/upload-package.py` stays as an alias until both repositories call
the package directly, then it goes.

**Category and severity live in `registry.py`, not in directory names.** A check
can be promoted from warning to blocking without a file move.

### Adding a check

1. Write `toolkit/checks/<name>.py` exposing `scan(args) -> Findings`.
2. Add a six-line adapter `validator/check-<name>.py`, copying any existing one.
3. Add a row to `CHECKS` in `toolkit/registry.py`.
4. `make check`.

## Scan report submitted after upload

`uploader/upload-package.py` publishes in two calls: the package is uploaded
first, then the packaged artifact is scanned and the result is submitted to
`PUT /api/v1/plugin-artifacts/{checksum}/scan-report`, addressed by the
checksum the upload response returned. It is what fills the "Access Domain"
and "Security" blocks on the plugin page.

The scan runs in `--test` mode too, so a pre-check run prints exactly what the
plugin page will say without uploading anything. Because the package is
already live when the report travels, a scan or submission failure can only
cost the page its scan data: it prints a `::warning::` annotation and never
fails the job. Server errors and timeouts are retried, a 4xx is not. Pass
`--no-vuln-scan` to collect dependencies without querying the vulnerability
database.

### Declaring outbound domains

A plugin may declare the domains it contacts in `manifest.yaml`:

```yaml
network:
  domains:
    - api.example-vendor.com
    - "*.cdn.example-vendor.com"
```

The node is optional and additive — every existing consumer ignores unknown
top-level manifest keys. It exists because static analysis can only read
hostnames that appear literally in the source: a URL assembled at runtime or
held inside a vendor SDK is invisible to the scanner, and across the current
plugin corpus that is the majority of outbound call sites. Declaring the
domains is how those become visible to users.

The check compares in one direction only. A domain the scan finds but the
manifest omits is reported. A domain the manifest declares but the scan cannot
find is accepted without comment — that gap is the reason the field exists.

## Publishing to more than one deployment

`--mirror-url URL --mirror-token TOKEN` (repeatable, paired positionally) sends
the same publish to a second Marketplace after the primary one succeeds. Its
purpose is staging: several backend scheduler tasks — `sync_latest_plugins` and
the rest of the upload-signal-driven set — only run when a new upload signals
them, so a staging deployment that never receives an upload cannot exercise
them at all.

Three properties make it safe to point production CI at staging:

* **A mirror cannot fail a publish.** The primary target uploads first and is
  the only one that raises; a mirror failure prints a `::warning::`, exactly
  like the scan report. A primary failure skips the mirrors entirely — a
  package production rejects has no business reaching staging.
* **The scan is built once.** It describes the local package bytes, so it is
  target-independent; building it per target would repeat dependency
  resolution and the OSV/PyPI queries for an identical answer.
* **Each target's report addresses its own checksum.** Every deployment
  re-signs the artifact with its own key, so the checksums differ, and a report
  is only ever submitted against the checksum that target returned.

A mirror upload is always forced, regardless of `-f`: a 409 from a version some
backfill already put there would hide whether the pipeline reached it. An empty
`--mirror-url` drops its pair, so a workflow can pass an unset repository secret
and simply get no mirror.

## Category changes

The Marketplace refuses an update that moves a plugin to another category
(for example an endpoint-only `extension` that adds tools and becomes a
`tool`). `--allow-category-change` lifts that for one upload, primary and
mirrors alike. Moves to or from `trigger` stay refused. It is separate from
`-f`, which only replaces an existing version: mirrors are always forced, and
that must not quietly change categories too.

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
