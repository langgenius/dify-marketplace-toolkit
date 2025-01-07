import os
import json
import sys

files: list[str] = json.loads(os.environ['PR_FILES'])

if len(files) != 1:
    print("only one file change allowed in a single PR.")
    sys.exit(1)

if not files[0]['path'].endswith(".difypkg"):
    print("only .difypkg file allowed.")
    sys.exit(1)

print(files[0]['path'])