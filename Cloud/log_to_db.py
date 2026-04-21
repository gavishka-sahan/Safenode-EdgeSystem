import os
import requests

API_BASE = "http://localhost:8000/api/v1"

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_FILE = os.path.join(BASE_DIR, "cloud_data_storage", "logs", "system_logs.log")


def insert_log(log_source, message):
    payload = {
        "log_level":  "INFO",
        "log_source": log_source,
        "message":    message,
    }
    try:
        r = requests.post(f"{API_BASE}/system-logs", json=payload, timeout=5)
        if r.status_code not in (200, 201):
            print(f"  ✗ Insert failed ({r.status_code}): {r.text}")
            return False
        return True
    except Exception as e:
        print(f"  ✗ Request error: {e}")
        return False


def main():
    if not os.path.isfile(LOG_FILE):
        print(f"Log file not found: {LOG_FILE}")
        return

    # Read-and-truncate under a lock-free swap:
    # rename to .processing so new writes from CloudSubscriber go to a fresh file,
    # then ingest from the snapshot. If any line fails, we re-append the remaining
    # lines back onto the live file so they retry on the next run.
    processing_path = LOG_FILE + ".processing"
    try:
        os.rename(LOG_FILE, processing_path)
    except FileNotFoundError:
        # Nothing to process
        return
    except OSError as e:
        print(f"Could not rotate log for processing: {e}")
        return

    with open(processing_path) as f:
        lines = f.readlines()

    if not lines:
        os.remove(processing_path)
        print("Log file empty")
        return

    print(f"Found {len(lines)} log lines\n")

    inserted = 0
    failed_lines = []

    for raw in lines:
        line = raw.rstrip("\n")
        if not line.strip():
            continue

        # CloudSubscriber writes each line as "<topic>\t<message>"
        if "\t" in line:
            log_source, message = line.split("\t", 1)
        else:
            log_source, message = "unknown", line

        if insert_log(log_source, message):
            inserted += 1
        else:
            failed_lines.append(raw)

    if failed_lines:
        # Re-queue failed lines at the front of the live log file
        with open(LOG_FILE, "a") as f:
            f.writelines(failed_lines)
        print(f"\n{len(failed_lines)} line(s) re-queued for next run")

    os.remove(processing_path)
    print(f"\nDone. Inserted: {inserted} | Failed: {len(failed_lines)}")


if __name__ == "__main__":
    main()
