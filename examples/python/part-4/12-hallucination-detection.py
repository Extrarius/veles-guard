# Illustrative examples for notes/part-4-output-security/12-hallucination-detection.md
# Not for production use. Licensed under MIT (see LICENSE-CODE).

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import List, Protocol


class ClaimType(str, Enum):
    FACT = "fact"
    NUMBER = "number"
    CITATION = "citation"
    TOOL_RESULT = "tool_result"
    POLICY = "policy"
    OPINION = "opinion"


class ClaimStatus(str, Enum):
    SUPPORTED = "supported"
    UNSUPPORTED = "unsupported"
    CONTRADICTED = "contradicted"
    STALE = "stale"
    NOT_CHECKABLE = "not_checkable"


@dataclass
class Claim:
    id: str
    text: str
    type: ClaimType
    source_ids: List[str] = field(default_factory=list)
    created_at: datetime = field(default_factory=datetime.utcnow)


@dataclass
class ClaimResult:
    claim_id: str
    status: ClaimStatus
    evidence_id: str = ""
    reason: str = ""
    confidence: float = 0.0


@dataclass
class Evidence:
    id: str
    text: str
    fresh_at: str = ""
    acl: List[str] = field(default_factory=list)


class EvidenceStore(Protocol):
    def find(self, claim: Claim) -> List[Evidence]: ...


@dataclass
class ClaimVerifier:
    store: EvidenceStore

    def verify(self, claim: Claim) -> ClaimResult:
        if claim.type == ClaimType.OPINION:
            return ClaimResult(
                claim_id=claim.id,
                status=ClaimStatus.NOT_CHECKABLE,
                reason="opinion",
            )

        evidence = self.store.find(claim)
        if not evidence:
            return ClaimResult(
                claim_id=claim.id,
                status=ClaimStatus.UNSUPPORTED,
                reason="no evidence found",
            )

        for item in evidence:
            if supports(claim.text, item.text):
                return ClaimResult(
                    claim_id=claim.id,
                    status=ClaimStatus.SUPPORTED,
                    evidence_id=item.id,
                    reason="matched evidence",
                    confidence=0.8,
                )

        return ClaimResult(
            claim_id=claim.id,
            status=ClaimStatus.UNSUPPORTED,
            reason="evidence found but no support",
            confidence=0.4,
        )


def supports(claim_text: str, evidence_text: str) -> bool:
    # Упрощённый пример. В реальной системе здесь может быть:
    # - exact match для чисел/дат/id;
    # - semantic similarity;
    # - отдельный verifier model;
    # - проверка по БД/API.
    return claim_text.lower() in evidence_text.lower()


class PublishDecision(str, Enum):
    ALLOW = "allow"
    REWRITE = "rewrite"
    BLOCK = "block"
    REVIEW = "review"


@dataclass
class HallucinationPolicy:
    block_contradictions: bool = True
    review_high_impact: bool = True

    def decide(
        self, results: List[ClaimResult], high_impact: bool
    ) -> PublishDecision:
        for result in results:
            if result.status == ClaimStatus.CONTRADICTED and self.block_contradictions:
                raise ValueError(f"contradicted claim: {result.claim_id}")

        if high_impact and self.review_high_impact:
            for result in results:
                if result.status in (
                    ClaimStatus.UNSUPPORTED,
                    ClaimStatus.NOT_CHECKABLE,
                ):
                    raise ValueError(
                        f"high-impact answer contains unverified claim: {result.claim_id}"
                    )

        for result in results:
            if result.status in (ClaimStatus.UNSUPPORTED, ClaimStatus.STALE):
                return PublishDecision.REWRITE

        return PublishDecision.ALLOW


def rewrite_with_uncertainty(answer: str, results: List[ClaimResult]) -> str:
    needs_uncertainty = any(
        result.status
        in (
            ClaimStatus.UNSUPPORTED,
            ClaimStatus.STALE,
            ClaimStatus.NOT_CHECKABLE,
        )
        for result in results
    )

    if not needs_uncertainty:
        return answer

    prefix = "По доступным источникам это не подтверждено полностью. "
    if answer.startswith(prefix):
        return answer
    return prefix + answer
