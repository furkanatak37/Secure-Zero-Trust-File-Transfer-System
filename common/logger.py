"""
Centralized security-aware logger for the Secure File Drop System.
Logs are written to a file AND printed to stdout.
Sensitive values (private keys, plaintext file contents) are NEVER logged.
"""

import logging
import os
import time


def get_logger(name: str, log_dir: str = None) -> logging.Logger:
    """
    Create a named logger that writes to:
      - stdout (INFO and above)
      - <log_dir>/<name>.log (DEBUG and above)
    """
    logger = logging.getLogger(name)
    if logger.handlers:
        return logger  # Already configured

    logger.setLevel(logging.DEBUG)
    fmt = logging.Formatter(
        fmt="%(asctime)s [%(levelname)s] [%(name)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )

    # Console handler
    ch = logging.StreamHandler()
    ch.setLevel(logging.INFO)
    ch.setFormatter(fmt)
    logger.addHandler(ch)

    # File handler
    if log_dir:
        os.makedirs(log_dir, exist_ok=True)
        log_path = os.path.join(log_dir, f"{name}.log")
        fh = logging.FileHandler(log_path)
        fh.setLevel(logging.DEBUG)
        fh.setFormatter(fmt)
        logger.addHandler(fh)

    return logger
