import logging
import sys
import os
from backend.config import settings

def setup_logging():
    log_level = getattr(logging, settings.LOG_LEVEL.upper(), logging.INFO)

    os.makedirs("logs", exist_ok=True)  # ✅ creates folder

    formatter = logging.Formatter(
        fmt="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )

    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)

    file_handler = logging.FileHandler("logs/app.log")  # ✅ THIS WAS MISSING
    file_handler.setFormatter(formatter)

    root_logger = logging.getLogger()
    root_logger.setLevel(log_level)

    if not root_logger.handlers:
        root_logger.addHandler(console_handler)
        root_logger.addHandler(file_handler)  # ✅ ADD THIS

# This file is responsible for logging configuration, used for setting up a consistent stdout logging format across all modules, and contains setup_logging function with formatter and stream handler initialization.