# Illustrative examples for notes/part-3-processing-security/07-parameter-validation-schema.md
# Not for production use. Licensed under MIT (see LICENSE-CODE).

import json
import os
from typing import Protocol
from urllib.parse import urlparse

ALLOWED_HOSTS = {"api.example.com", "docs.example.com"}


# --- JSON schema через строгий decoder ---


def decode_strict(raw: str) -> dict:
    obj = json.loads(raw)
    if not isinstance(obj, dict):
        raise ValueError("expected a JSON object")
    return obj


def validate_fetch_url_args(obj: dict) -> tuple[str, int]:
    allowed_fields = {"url", "timeout_seconds"}
    extra = set(obj) - allowed_fields
    if extra:
        raise ValueError(f"unknown fields: {sorted(extra)}")

    url = obj.get("url", "")
    if not url:
        raise ValueError("url is required")

    parsed = urlparse(url)
    if parsed.scheme != "https":
        raise ValueError("only https scheme is allowed")

    host = (parsed.hostname or "").lower()
    if host not in ALLOWED_HOSTS:
        raise ValueError(f"host is not allowed: {host}")

    timeout = obj.get("timeout_seconds", 0)
    if not isinstance(timeout, int) or timeout <= 0 or timeout > 10:
        raise ValueError("timeout must be between 1 and 10 seconds")

    return url, timeout


# --- Безопасная проверка пути ---


def safe_join(base_dir: str, user_path: str) -> str:
    if not user_path:
        raise ValueError("path is required")

    clean = os.path.normpath(user_path)
    if os.path.isabs(clean):
        raise ValueError("absolute paths are not allowed")

    base_abs = os.path.abspath(base_dir)
    full_abs = os.path.abspath(os.path.join(base_abs, clean))

    if full_abs != base_abs and not full_abs.startswith(base_abs + os.sep):
        raise ValueError("path escapes base directory")

    return full_abs


# --- Ownership check ---


class ResourceAccessChecker(Protocol):
    def can_access_customer(self, user_id: str, customer_id: str) -> bool: ...


def validate_read_customer(
    user_id: str,
    customer_id: str,
    access: ResourceAccessChecker,
) -> None:
    if not customer_id:
        raise ValueError("customer_id is required")
    if not access.can_access_customer(user_id, customer_id):
        raise ValueError("customer does not belong to user")
