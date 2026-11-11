import os
import json
import sys

files: list[dict] = json.loads(os.environ['PR_FILES'])

def change_type(f: dict) -> str:
    # gh pr view --json files reports `changeType` (ADDED/DELETED/MODIFIED);
    # the raw API reports `status` (added/removed/modified). Support both.
    return str(f.get('changeType') or f.get('status') or '').upper()

# stdout is the answer and nothing else: both plugin repositories capture it
# with $(...) and write it straight into $GITHUB_ENV, so a single extra line --
# an "also removing ..." note, say -- turns the value into two lines and breaks
# the env file. Everything a human should read goes to stderr.

# Rule 1: every changed file must be a .difypkg package.
non_pkg = [f['path'] for f in files if not f['path'].endswith('.difypkg')]
if non_pkg:
    print('only .difypkg file changes are allowed in a single PR.', file=sys.stderr)
    print('non-package files: ' + ', '.join(non_pkg), file=sys.stderr)
    sys.exit(1)

# Rule 2: all packages must live in a single plugin directory (one plugin per PR).
dirs = sorted({os.path.dirname(f['path']) for f in files})
if len(dirs) != 1:
    print('only one plugin (directory) is allowed in a single PR.', file=sys.stderr)
    print('directories changed: ' + ', '.join(dirs), file=sys.stderr)
    sys.exit(1)

# Rule 3: within that directory exactly one package must be added or modified
# (the new version). Removals of older versions in the same directory are
# allowed — and encouraged by the packaging rules, which require keeping only
# the current version in the repository.
if all(not change_type(f) for f in files):
    # Path-only input (e.g. `git diff --name-only` in the upload workflow):
    # the working tree is checked out at the target commit, so a removed
    # package no longer exists on disk while the new/updated one does.
    for f in files:
        f['_exists'] = os.path.exists(f['path'])

    def _ct(f):
        if change_type(f):
            return change_type(f)
        return 'ADDED' if f.get('_exists') else 'REMOVED'
else:
    def _ct(f):
        return change_type(f)

primaries = [f for f in files if _ct(f) in ('ADDED', 'MODIFIED')]
removals = [f for f in files if _ct(f) in ('DELETED', 'REMOVED')]

if len(primaries) != 1:
    print('exactly one added or modified .difypkg is required in a single PR.', file=sys.stderr)
    print('candidates: ' + ', '.join(f['path'] for f in primaries), file=sys.stderr)
    sys.exit(1)

primary = primaries[0]['path']
if removals:
    print('also removing %d older version(s) in the same directory '
          '(allowed by the packaging rules): %s'
          % (len(removals), ', '.join(f['path'] for f in removals)), file=sys.stderr)
print(primary)
