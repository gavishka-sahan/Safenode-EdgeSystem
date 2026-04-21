"""
Shared utilities for batch loaders that consume JSONL files written by
CloudSubscriber.py.

The core pattern is atomic snapshot rotation:

    1. os.rename(live, snapshot)   # kernel-atomic on POSIX
    2. read lines from snapshot
    3. POST each line
    4. re-append failed / unpaired lines back to live
    5. delete snapshot

Because CloudSubscriber opens the live file in append mode per message
(not a persistent file handle), new writes after step 1 correctly land
in a fresh live file and are not affected by the snapshot.
"""

import os


def snapshot_file(live_path):
    """
    Atomically rename the live file to a .processing snapshot.
    Returns the snapshot path, or None if the live file is missing.
    """
    snapshot_path = live_path + ".processing"

    # If a previous run crashed mid-processing, resume from the stale snapshot.
    # This is safer than overwriting it or deleting unprocessed lines.
    if os.path.exists(snapshot_path):
        return snapshot_path

    if not os.path.exists(live_path):
        return None

    try:
        os.rename(live_path, snapshot_path)
    except OSError as e:
        print(f"Could not rotate {live_path}: {e}")
        return None

    return snapshot_path


def read_lines(snapshot_path):
    """Read all non-empty lines from a snapshot file."""
    if not snapshot_path or not os.path.exists(snapshot_path):
        return []
    with open(snapshot_path) as f:
        return [line for line in f.readlines() if line.strip()]


def requeue_lines(live_path, lines):
    """Append lines back to the live file (e.g. failed inserts for retry)."""
    if not lines:
        return
    with open(live_path, "a") as f:
        for line in lines:
            if not line.endswith("\n"):
                line = line + "\n"
            f.write(line)


def remove_snapshot(snapshot_path):
    """Remove the snapshot file once processing is complete."""
    if snapshot_path and os.path.exists(snapshot_path):
        try:
            os.remove(snapshot_path)
        except OSError as e:
            print(f"Could not remove {snapshot_path}: {e}")
