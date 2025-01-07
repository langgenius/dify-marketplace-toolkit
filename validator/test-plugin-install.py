import os
import sys
import argparse
import subprocess
import threading
import time

import requests


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-d", "--directory", type=str, required=True)
    args = parser.parse_args()

    if args.directory:
        print(f"Testing plugin in directory: {args.directory}")
    else:
        print("No directory provided")

    result = test_plugin_install(args.directory)
    print(f"!!! Plugin test result: {result}")
    if result != "success":
        sys.exit(1)

def test_plugin_install(directory: str) -> str:
    # workdir: <directory>, exec: python3 -m main
    result: str = "failed"
    env = os.environ.copy()
    try:
        process = subprocess.Popen(
            ["python3", "-m", "main"],
            cwd=directory,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )

        semaphore = threading.Semaphore(0)
        
        def check_output():
            nonlocal result
            while True:
                output = process.stdout.readline()
                if output == "" and process.poll() is not None:
                    print("!!! Process exited")
                    semaphore.release()
                    break
                if output:
                    print(output.strip())
                    if "Serving Flask app" in output:
                        print("!!! Detected 'Serving Flask app' in output, sending request to port 8080")
                        time.sleep(3)
                        response = requests.get("http://127.0.0.1:8080")
                        if response.status_code == 200 or response.status_code == 404:
                            print("!!! Request to port 8080 successful")
                            result = "success"
                            process.terminate()
                            semaphore.release()
                        else:
                            print("!!! Request to port 8080 failed")
                            result = "failed"
                            process.terminate()
                            semaphore.release()
                        break
        
        threading.Thread(target=check_output).start()

        def force_exit():
            time.sleep(20)
            print("!!! Force exit after 20 seconds")
            process.terminate()
            semaphore.release()

        threading.Thread(target=force_exit, daemon=True).start()

        semaphore.acquire()

        process.wait()

    except Exception as e:
        print(f"!!! An error occurred: {e}")
        result = "failed"

    return result

if __name__ == "__main__":
    main()
