#!/usr/bin/env python3
"""
Logging Configuration for Edge ML System
Provides 5GB rotating log handlers with automatic cleanup
"""

import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path


class SizeBasedRotatingHandler(RotatingFileHandler):
    """
    Custom rotating file handler that maintains total size limit
    across all backup files
    """

    def __init__(self, filename, max_total_size=5 * 1024 * 1024 * 1024, max_single_file=100 * 1024 * 1024, backup_count=50):
        """
        Args:
            filename: Log file path
            max_total_size: Maximum total size for all logs (default: 5GB)
            max_single_file: Maximum size per file before rotation (default: 100MB)
            backup_count: Maximum number of backup files (default: 50)
        """
        self.max_total_size = max_total_size
        self.max_single_file = max_single_file

        # Calculate backup count to fit within total size
        # Reserve space for current file
        available_for_backups = max_total_size - max_single_file
        calculated_backup_count = max(1, int(available_for_backups / max_single_file))

        # Use the smaller of calculated or provided backup count
        final_backup_count = min(backup_count, calculated_backup_count)

        super().__init__(
            filename,
            maxBytes=max_single_file,
            backupCount=final_backup_count
        )

    def doRollover(self):
        """
        Override rollover to enforce total size limit
        """
        # Perform standard rotation
        super().doRollover()

        # Check total size and remove oldest if needed
        self.enforce_total_size_limit()

    def enforce_total_size_limit(self):
        """
        Ensure total size of all log files doesn't exceed limit
        Remove oldest files if needed
        """
        try:
            base_filename = Path(self.baseFilename)

            # Find all related log files
            log_files = []

            # Current file
            if base_filename.exists():
                log_files.append((base_filename, base_filename.stat().st_mtime))

            # Backup files (.1, .2, .3, etc.)
            for i in range(1, self.backupCount + 10):  # Check extra files
                backup_file = Path(f"{self.baseFilename}.{i}")
                if backup_file.exists():
                    log_files.append((backup_file, backup_file.stat().st_mtime))

            # Calculate total size
            total_size = sum(f[0].stat().st_size for f in log_files)

            # If over limit, remove oldest files
            if total_size > self.max_total_size:
                # Sort by modification time (oldest first)
                log_files.sort(key=lambda x: x[1])

                # Remove oldest until under limit
                for log_file, _ in log_files:
                    if total_size <= self.max_total_size:
                        break

                    # Don't remove the current log file
                    if log_file == base_filename:
                        continue

                    file_size = log_file.stat().st_size
                    log_file.unlink()
                    total_size -= file_size
                    print(f"Removed old log file: {log_file.name} ({file_size / 1024 / 1024:.2f} MB)")

        except Exception as e:
            print(f"Error enforcing size limit: {e}")


def setup_edge_ml_logger(log_file="edge_ml.log", max_total_size=5 * 1024 * 1024 * 1024):
    """
    Setup logger for Edge ML module with 5GB total size limit

    Args:
        log_file: Log file path
        max_total_size: Maximum total size (default: 5GB)

    Returns:
        Configured logger
    """
    logger = logging.getLogger("edge_ml")
    logger.setLevel(logging.DEBUG)

    # Remove existing handlers
    logger.handlers.clear()

    # Detailed format with thread info
    detailed_formatter = logging.Formatter(
        '%(asctime)s | %(levelname)-8s | %(name)s | %(funcName)s:%(lineno)d | %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )

    # Console format (simpler)
    console_formatter = logging.Formatter(
        '%(asctime)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )

    # File handler with 5GB total rotation
    file_handler = SizeBasedRotatingHandler(
        log_file,
        max_total_size=max_total_size,
        max_single_file=100 * 1024 * 1024,  # 100MB per file
        backup_count=50
    )
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(detailed_formatter)
    logger.addHandler(file_handler)

    # Console handler (less verbose)
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(console_formatter)
    logger.addHandler(console_handler)

    return logger


def setup_feature_log_receiver_logger(log_file="feature_extractor_received.log", max_total_size=5 * 1024 * 1024 * 1024):
    """
    Setup logger for Feature Extractor log receiver with 5GB limit

    Args:
        log_file: Log file path
        max_total_size: Maximum total size (default: 5GB)

    Returns:
        Configured logger
    """
    logger = logging.getLogger("feature_log_receiver")
    logger.setLevel(logging.DEBUG)

    # Remove existing handlers
    logger.handlers.clear()

    # Simple format for received logs (they already have timestamps)
    formatter = logging.Formatter('%(message)s')

    # File handler with 5GB total rotation
    file_handler = SizeBasedRotatingHandler(
        log_file,
        max_total_size=max_total_size,
        max_single_file=100 * 1024 * 1024,  # 100MB per file
        backup_count=50
    )
    file_handler.setLevel(logging.INFO)
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

    # Console handler for status
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(logging.Formatter(
        '%(asctime)s - %(levelname)s - %(message)s'
    ))
    logger.addHandler(console_handler)

    return logger


def get_log_directory_size(log_file):
    """
    Calculate total size of log file and its backups

    Args:
        log_file: Base log file path

    Returns:
        Total size in bytes
    """
    try:
        base_file = Path(log_file)
        total_size = 0

        # Current file
        if base_file.exists():
            total_size += base_file.stat().st_size

        # Backup files
        i = 1
        while True:
            backup_file = Path(f"{log_file}.{i}")
            if not backup_file.exists():
                break
            total_size += backup_file.stat().st_size
            i += 1

        return total_size

    except Exception as e:
        print(f"Error calculating log size: {e}")
        return 0


def get_log_stats(log_file):
    """
    Get statistics about log files

    Returns:
        Dict with file count, total size, oldest/newest timestamps
    """
    try:
        base_file = Path(log_file)
        files = []

        # Current file
        if base_file.exists():
            stat = base_file.stat()
            files.append({
                'name': base_file.name,
                'size': stat.st_size,
                'modified': stat.st_mtime
            })

        # Backup files
        i = 1
        while True:
            backup_file = Path(f"{log_file}.{i}")
            if not backup_file.exists():
                break
            stat = backup_file.stat()
            files.append({
                'name': backup_file.name,
                'size': stat.st_size,
                'modified': stat.st_mtime
            })
            i += 1

        if not files:
            return None

        total_size = sum(f['size'] for f in files)
        oldest = min(files, key=lambda x: x['modified'])
        newest = max(files, key=lambda x: x['modified'])

        return {
            'file_count': len(files),
            'total_size_bytes': total_size,
            'total_size_mb': total_size / 1024 / 1024,
            'total_size_gb': total_size / 1024 / 1024 / 1024,
            'oldest_file': oldest['name'],
            'newest_file': newest['name'],
            'oldest_timestamp': oldest['modified'],
            'newest_timestamp': newest['modified']
        }

    except Exception as e:
        print(f"Error getting log stats: {e}")
        return None


# Example usage
if __name__ == "__main__":
    # Test Edge ML logger
    print("Testing Edge ML Logger (5GB limit)...")
    logger = setup_edge_ml_logger("test_edge_ml.log", max_total_size=10 * 1024 * 1024)  # 10MB for testing

    logger.info("Edge ML system starting")
    logger.debug("Debug message with details")
    logger.warning("Warning message")
    logger.error("Error message")

    # Write some data to test rotation
    for i in range(100):
        logger.info(f"Test message {i}: " + "x" * 1000)

    # Get stats
    stats = get_log_stats("test_edge_ml.log")
    if stats:
        print("\nLog Statistics:")
        print(f"  Files: {stats['file_count']}")
        print(f"  Total Size: {stats['total_size_mb']:.2f} MB")
        print(f"  Oldest: {stats['oldest_file']}")
        print(f"  Newest: {stats['newest_file']}")

    # Test Feature Log Receiver logger
    print("\n\nTesting Feature Log Receiver Logger (5GB limit)...")
    feat_logger = setup_feature_log_receiver_logger("test_feature_received.log", max_total_size=10 * 1024 * 1024)

    for i in range(50):
        feat_logger.info(f"2026-02-11 10:30:{i:02d} | INFO | Feature Extractor | New flow created")

    stats = get_log_stats("test_feature_received.log")
    if stats:
        print("\nFeature Log Statistics:")
        print(f"  Files: {stats['file_count']}")
        print(f"  Total Size: {stats['total_size_mb']:.2f} MB")
