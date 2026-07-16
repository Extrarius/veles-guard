# Illustrative examples for notes/part-3-processing-security/10-secrets-management.md
# Not for production use. Licensed under MIT (see LICENSE-CODE).

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Protocol


@dataclass
class SecretScope:
    tool_name: str
    action: str
    user_id: str
    resource: str


class SecretProvider(Protocol):
    def get_scoped_token(self, scope: SecretScope) -> str: ...


class HTTPClient(Protocol):
    def post(self, url: str, bearer_token: str, body: bytes) -> bytes: ...


@dataclass
class SendRequestArgs:
    endpoint: str
    payload: str
    # Важно: здесь нет Token/APIKey.
    # LLM не должна формировать секрет в аргументах.


class ExternalAPIClient:
    def __init__(self, secrets: SecretProvider, http: HTTPClient) -> None:
        self.secrets = secrets
        self.http = http

    def send_request(self, user_id: str, args: SendRequestArgs) -> bytes:
        if not args.endpoint:
            raise ValueError("endpoint is required")

        token = self.secrets.get_scoped_token(
            SecretScope(
                tool_name="external_api.send_request",
                action="send",
                user_id=user_id,
                resource=args.endpoint,
            )
        )

        return self.http.post(args.endpoint, token, args.payload.encode("utf-8"))


# --- Redacted logger ---


class Redactor:
    def __init__(self) -> None:
        self.patterns = [
            re.compile(
                r"(?i)(api[_-]?key|token|password|secret)\s*[:=]\s*[^\s,]+",
            ),
            re.compile(
                r"-----BEGIN [A-Z ]+PRIVATE KEY-----[\s\S]+?-----END [A-Z ]+PRIVATE KEY-----",
            ),
            re.compile(r"(?i)bearer\s+[a-z0-9._\-]+"),
        ]

    def redact(self, text: str) -> str:
        out = text
        for pattern in self.patterns:
            out = pattern.sub("[REDACTED_SECRET]", out)
        return out


class SafeLogger:
    def __init__(self, redactor: Redactor) -> None:
        self.redactor = redactor

    def log(self, event: str, fields: dict[str, str]) -> None:
        safe: dict[str, str] = {}
        for key, value in fields.items():
            if _looks_sensitive_key(key):
                safe[key] = "[REDACTED_SECRET]"
            else:
                safe[key] = self.redactor.redact(value)

        # Здесь запись в реальный logger/tracing backend.
        _ = event
        _ = safe


def _looks_sensitive_key(key: str) -> bool:
    lower = key.lower()
    markers = ["token", "password", "secret", "api_key", "authorization"]
    return any(m in lower for m in markers)
