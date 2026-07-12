# Illustrative examples for notes/part-4-output-security/13-egress-control-data-exfiltration.md
# Not for production use. Licensed under MIT (see LICENSE-CODE).

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Protocol
from urllib.parse import urlparse


class DataClass(str, Enum):
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    SECRET = "secret"
    PERSONAL = "personal"


class EgressChannel(str, Enum):
    HTTP = "http"
    EMAIL = "email"
    BROWSER = "browser"
    LOG = "log"
    AGENT_MESSAGE = "agent_message"


@dataclass
class EgressRequest:
    user_id: str
    tenant_id: str
    channel: EgressChannel
    destination: str
    payload: str
    data_classes: List[DataClass] = field(default_factory=list)
    purpose: str = ""


@dataclass
class EgressDecision:
    allowed: bool = False
    needs_approval: bool = False
    reason: str = ""
    sanitized_body: str = ""


@dataclass
class EgressPolicy:
    allowed_http_domains: Dict[str, bool] = field(default_factory=dict)
    allowed_email_domains: Dict[str, bool] = field(default_factory=dict)

    def decide(self, req: EgressRequest) -> EgressDecision:
        if not req.destination:
            raise ValueError("destination is required")

        if _contains(req.data_classes, DataClass.SECRET):
            return EgressDecision(
                allowed=False,
                reason="secret data cannot leave runtime",
            )

        if _contains(req.data_classes, DataClass.PERSONAL) or _contains(
            req.data_classes, DataClass.CONFIDENTIAL
        ):
            return EgressDecision(
                allowed=False,
                needs_approval=True,
                reason="personal/confidential data requires approval",
            )

        if req.channel in (EgressChannel.HTTP, EgressChannel.BROWSER):
            if not self._allowed_url(req.destination):
                return EgressDecision(
                    allowed=False,
                    reason="destination domain is not allowed",
                )
        elif req.channel == EgressChannel.EMAIL:
            if not self._allowed_email(req.destination):
                return EgressDecision(
                    allowed=False,
                    reason="recipient domain is not allowed",
                )
        elif req.channel == EgressChannel.LOG:
            # Logs are internal, but still need redaction.
            pass
        else:
            return EgressDecision(
                allowed=False,
                reason="unsupported egress channel",
            )

        return EgressDecision(allowed=True, sanitized_body=_redact(req.payload))

    def _allowed_url(self, raw: str) -> bool:
        parsed = urlparse(raw)
        if not parsed.scheme or not parsed.hostname:
            return False
        if parsed.scheme != "https":
            return False
        return bool(self.allowed_http_domains.get(parsed.hostname.lower()))

    def _allowed_email(self, addr: str) -> bool:
        parts = addr.split("@")
        if len(parts) != 2:
            return False
        domain = parts[1].lower()
        return bool(self.allowed_email_domains.get(domain))


def _contains(classes: List[DataClass], target: DataClass) -> bool:
    return target in classes


def _redact(value: str) -> str:
    markers = ["api_key=", "password=", "token=", "secret="]
    out = value
    lower = out.lower()
    for marker in markers:
        idx = lower.find(marker)
        if idx >= 0:
            out = out[:idx] + marker + "[REDACTED]"
            lower = out.lower()
    return out


class Taint(str, Enum):
    NONE = "none"
    USER_INPUT = "user_input"
    SECRET_SOURCE = "secret_source"
    PERSONAL_DATA = "personal_data"
    TENANT_DATA = "tenant_data"


@dataclass
class AgentValue:
    value: str
    taints: List[Taint] = field(default_factory=list)

    def has_taint(self, taint: Taint) -> bool:
        return taint in self.taints


def build_egress_from_value(
    user_id: str, tenant_id: str, dest: str, val: AgentValue
) -> EgressRequest:
    classes: List[DataClass] = [DataClass.INTERNAL]

    if val.has_taint(Taint.SECRET_SOURCE):
        classes.append(DataClass.SECRET)
    if val.has_taint(Taint.PERSONAL_DATA):
        classes.append(DataClass.PERSONAL)
    if val.has_taint(Taint.TENANT_DATA):
        classes.append(DataClass.CONFIDENTIAL)

    return EgressRequest(
        user_id=user_id,
        tenant_id=tenant_id,
        channel=EgressChannel.HTTP,
        destination=dest,
        payload=val.value,
        data_classes=classes,
        purpose="agent_outbound_request",
    )


class HTTPSender(Protocol):
    def post(self, url: str, body: str, headers: Dict[str, str]) -> object: ...


@dataclass
class SafeHTTPClient:
    policy: EgressPolicy
    sender: HTTPSender

    def post(self, req: EgressRequest) -> object:
        decision = self.policy.decide(req)
        if decision.needs_approval:
            raise ValueError(f"egress requires approval: {decision.reason}")
        if not decision.allowed:
            raise ValueError(f"egress blocked: {decision.reason}")

        return self.sender.post(
            req.destination,
            decision.sanitized_body,
            {"Content-Type": "application/json"},
        )
