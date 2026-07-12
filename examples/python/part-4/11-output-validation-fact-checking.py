# Illustrative examples for notes/part-4-output-security/11-output-validation-fact-checking.md
# Not for production use. Licensed under MIT (see LICENSE-CODE).

from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Protocol


class OutputKind(str, Enum):
    FINAL_TEXT = "final_text"
    STRUCTURED_JSON = "structured_json"
    HTML = "html"
    CODE = "code"


@dataclass
class SourceRef:
    id: str
    title: str = ""
    url: str = ""


@dataclass
class Output:
    kind: OutputKind
    text: str
    meta: Dict[str, str] = field(default_factory=dict)
    sources: List[SourceRef] = field(default_factory=list)


@dataclass
class ValidationResult:
    allowed: bool = True
    reason: str = ""
    risk: str = ""  # High / Medium / Low


class Validator(Protocol):
    def validate(self, out: Output) -> ValidationResult: ...


@dataclass
class Pipeline:
    validators: List[Validator]

    def validate(self, out: Output) -> None:
        for validator in self.validators:
            result = validator.validate(out)
            if not result.allowed:
                raise ValueError(
                    f"output blocked: {result.reason} risk={result.risk}"
                )


class SecretLeakValidator:
    def validate(self, out: Output) -> ValidationResult:
        text = out.text.lower()
        markers = [
            "api_key",
            "authorization:",
            "bearer ",
            "password=",
            "secret=",
        ]
        for marker in markers:
            if marker in text:
                return ValidationResult(
                    allowed=False,
                    reason="possible secret leak",
                    risk="High",
                )
        return ValidationResult()


class HTMLPolicyValidator:
    def validate(self, out: Output) -> ValidationResult:
        if out.kind != OutputKind.HTML:
            return ValidationResult()

        lower = out.text.lower()
        disallowed = [
            "<script",
            "javascript:",
            "onerror=",
            "onclick=",
            "<iframe",
        ]
        for token in disallowed:
            if token in lower:
                return ValidationResult(
                    allowed=False,
                    reason="unsafe html output",
                    risk="High",
                )
        return ValidationResult()


class SourceRequiredValidator:
    def validate(self, out: Output) -> ValidationResult:
        if out.meta.get("requires_sources") != "true":
            return ValidationResult()
        if not out.sources:
            return ValidationResult(
                allowed=False,
                reason="answer requires sources but none provided",
                risk="Medium",
            )
        return ValidationResult()


def publish(pipeline: Pipeline, out: Output) -> None:
    if not out.text:
        raise ValueError("empty output")
    pipeline.validate(out)


@dataclass
class CustomerMessage:
    subject: str
    body: str
    tone: str


_ALLOWED_TONE = {"neutral", "formal", "friendly"}
_ALLOWED_FIELDS = {"subject", "body", "tone"}


def parse_customer_message(raw: bytes | str) -> CustomerMessage:
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8")

    data = json.loads(raw)
    if not isinstance(data, dict):
        raise ValueError("invalid structured output: expected object")

    unknown = set(data.keys()) - _ALLOWED_FIELDS
    if unknown:
        raise ValueError(f"invalid structured output: unknown fields {unknown}")

    subject = data.get("subject", "")
    body = data.get("body", "")
    tone = data.get("tone", "")

    if not subject or not body:
        raise ValueError("subject and body are required")

    if tone not in _ALLOWED_TONE:
        raise ValueError(f"unsupported tone: {tone!r}")

    if "password" in body.lower():
        raise ValueError("message may contain sensitive data")

    return CustomerMessage(subject=subject, body=body, tone=tone)


class SourceEvidenceStore(Protocol):
    def exists(self, source_id: str) -> bool: ...

    def allowed_for_user(self, user_id: str, source_id: str) -> bool: ...


def validate_sources(
    user_id: str, sources: List[SourceRef], store: SourceEvidenceStore
) -> None:
    for source in sources:
        if not source.id:
            raise ValueError("source id is required")
        if not store.exists(source.id):
            raise ValueError(f"unknown source: {source.id}")
        if not store.allowed_for_user(user_id, source.id):
            raise ValueError(f"source is not allowed for user: {source.id}")
