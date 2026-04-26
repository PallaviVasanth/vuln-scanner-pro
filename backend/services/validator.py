import re
import logging

logger = logging.getLogger(__name__)

DOMAIN_REGEX = re.compile(
    r"^(?:[a-zA-Z0-9]"
    r"(?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
    r"[a-zA-Z]{2,}$"
)
IP_REGEX = re.compile(
    r"^(\d{1,3}\.){3}\d{1,3}$"
)
URL_REGEX = re.compile(
    r"^(https?://)?"
    r"(([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}|(\d{1,3}\.){3}\d{1,3})"
    r"(:\d+)?(/.*)?$"
)

def validate_target(target: str) -> bool:
    target = target.strip()
    if not target:
        logger.warning("Empty target provided.")
        return False
    if URL_REGEX.match(target):
        logger.info(f"Target validated as URL: {target}")
        return True
    if DOMAIN_REGEX.match(target):
        logger.info(f"Target validated as domain: {target}")
        return True
    if IP_REGEX.match(target):
        parts = target.split(".")
        if all(0 <= int(p) <= 255 for p in parts):
            logger.info(f"Target validated as IP: {target}")
            return True
    logger.warning(f"Target validation failed: {target}")
    return False

def sanitize_target(target: str) -> str:
    return target.strip().rstrip("/")

# This file is responsible for input validation and sanitization, used for verifying that scan targets are valid domains, IPs, or URLs before processing, and contains validate_target and sanitize_target functions with regex-based checks.