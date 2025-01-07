import argparse
import json
import sys
import os
import subprocess
import traceback
import requests

MARKETPLACE_BASE_URL = ""
PLUGIN_DAEMON_PATH = "./dify-plugin"
TESTING = False


def main():
    global MARKETPLACE_BASE_URL
    global PLUGIN_DAEMON_PATH
    parser = argparse.ArgumentParser(description="Upload a package or directory to the marketplace. Choose one of the following sources: -p(--package), -d(--directory), --batch-directory")
    # -p, --package
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-p", "--package", type=str, help="The package to upload")
    group.add_argument("-d", "--directory", type=str, help="The directory to package and upload")
    group.add_argument("--batch-directory", type=str, help="Batch upload all directories in the given directory")
    parser.add_argument("-t", "--token", type=str, required=True, help="The token to use for authentication")
    parser.add_argument("-u", "--base-url", type=str, help="The base url to use for the request")
    parser.add_argument("-f", "--force", action="store_true", help="Force upload the package, ignore version check")
    parser.add_argument("--with-changelog", action="store_true", help="Whether to read changelog from stdin")
    parser.add_argument("--plugin-daemon-path", type=str, help="The path to the plugin daemon")
    parser.add_argument("--test", action="store_true", help="Indicates that this is a testing")
    args = parser.parse_args()

    if args.plugin_daemon_path:
        PLUGIN_DAEMON_PATH = args.plugin_daemon_path

    global TESTING
    TESTING = args.test

    # if --with-changelog == true, read changelog from stdin
    if args.with_changelog:
        changelog = sys.stdin.read()
        args.changelog = changelog.strip()
    else:
        args.changelog = ""

    print(json.dumps(args.__dict__, indent=2))

    if args.base_url:
        MARKETPLACE_BASE_URL = args.base_url

    if args.package:
        upload_package(args.package, args.token, MARKETPLACE_BASE_URL, args.force, args.changelog)
    elif args.directory:
        upload_directory(args.directory, args.token, MARKETPLACE_BASE_URL, args.force, args.changelog)
    elif args.batch_directory:
        batch_upload_directory(args.batch_directory, args.token, MARKETPLACE_BASE_URL, args.force, args.changelog)
    else:
        print("No package or directory provided")


def upload_package(package: str, token: str, base_url: str, force: bool, changelog: str):
    global TESTING

    if TESTING:
        print("!!! Skip uploading package in testing")
        return

    url = f"{base_url}/api/v1/plugins/inner-upload"

    payload = {
        "changelog": changelog,
        "forcely": 'true' if force else 'false',
    }

    files = [
        ("file", (package, open(package, "rb"), "application/octet-stream"))
    ]

    headers = {
        "Authorization": f"Bearer {token}"
    }

    resp = requests.post(url, headers=headers, data=payload, files=files)
    print(resp.json())
    if resp.status_code != 200 or resp.json().get("code") != 0:
        raise Exception(f"Failed to upload package: {resp.json()}")


def upload_directory(directory: str, token: str, base_url: str, force: bool, changelog: str):
    check_plugin_daemon_command_exists()

    # delete temp.difypkg if exists
    if os.path.exists("temp.difypkg"):
        os.remove("temp.difypkg")

    # ./dify-plugin-daemon plugin package <directory> --out temp.difypkg
    result = subprocess.run([PLUGIN_DAEMON_PATH, "plugin", "package", directory, "-o", "temp.difypkg"], capture_output=True, text=True)
    print(result.stdout)
    print(result.stderr)
    if result.returncode != 0:
        raise Exception("Failed to package the directory")
    
    upload_package("temp.difypkg", token, base_url, force, changelog)


def batch_upload_directory(directory: str, token: str, base_url: str, force: bool, changelog: str):
    success_dirs = []
    failed_dirs = []
    for dir in os.listdir(directory):
        path = os.path.join(directory, dir)
        print(f"* Uploading directory: {path}")
        try:
            upload_directory(path, token, base_url, force, changelog)
            success_dirs.append(path)
        except Exception as e:
            print(f"** Failed to upload directory: {path}")
            print(traceback.format_exc())
            failed_dirs.append(path)

    if len(failed_dirs) > 0:
        success_dirs_str = "\n ".join(success_dirs)
        failed_dirs_str = "\n ".join(failed_dirs)
        raise Exception(f"!!! Done.\nFailed directories({len(failed_dirs)}):\n {failed_dirs_str}\n\nSuccess directories({len(success_dirs)}):\n {success_dirs_str}")
    else:
        print("!!! Done.")


def check_plugin_daemon_command_exists():
    # ./daemon version
    result = subprocess.run([PLUGIN_DAEMON_PATH, "version"], capture_output=True, text=True)
    print(result.stdout)
    if result.returncode != 0:
        raise Exception("Plugin daemon command not found")


if __name__ == "__main__":
    main()
