import os
import json

def get_prefix(file_path):
    return (file_path.split('/')[0] + '/' + file_path.split('/')[1]) if len(file_path.split('/')) > 1 else file_path

files = json.loads(os.environ['PR_FILES'])

# only tools/ models/ extensions/ agent-strategies/
files = [file for file in files if file['path'].startswith('tools/') or file['path'].startswith('models/') or file['path'].startswith('extensions/')]

previous_prefix = get_prefix(files[0]['path'])
for file in files:
    prefix = get_prefix(file['path'])
    if prefix != previous_prefix:
        print('not in same plugin directory')
        import sys
        sys.exit(1)

print(previous_prefix)