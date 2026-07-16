// Illustrative examples for notes/part-4-output-security/12-hallucination-detection.md
// Not for production use. Licensed under MIT (see LICENSE-CODE).

enum ClaimType {
  Fact = "fact",
  Number = "number",
  Citation = "citation",
  ToolResult = "tool_result",
  Policy = "policy",
  Opinion = "opinion",
}

enum ClaimStatus {
  Supported = "supported",
  Unsupported = "unsupported",
  Contradicted = "contradicted",
  Stale = "stale",
  NotCheckable = "not_checkable",
}

interface Claim {
  id: string;
  text: string;
  type: ClaimType;
  sourceIds: string[];
  createdAt: Date;
}

interface ClaimResult {
  claimId: string;
  status: ClaimStatus;
  evidenceId: string;
  reason: string;
  confidence: number;
}

interface Evidence {
  id: string;
  text: string;
  freshAt: string;
  acl: string[];
}

interface EvidenceStore {
  find(claim: Claim): Evidence[];
}

class ClaimVerifier {
  store: EvidenceStore;

  constructor(store: EvidenceStore) {
    this.store = store;
  }

  verify(claim: Claim): ClaimResult {
    if (claim.type === ClaimType.Opinion) {
      return {
        claimId: claim.id,
        status: ClaimStatus.NotCheckable,
        evidenceId: "",
        reason: "opinion",
        confidence: 0,
      };
    }

    const evidence = this.store.find(claim);
    if (evidence.length === 0) {
      return {
        claimId: claim.id,
        status: ClaimStatus.Unsupported,
        evidenceId: "",
        reason: "no evidence found",
        confidence: 0,
      };
    }

    for (const item of evidence) {
      if (supports(claim.text, item.text)) {
        return {
          claimId: claim.id,
          status: ClaimStatus.Supported,
          evidenceId: item.id,
          reason: "matched evidence",
          confidence: 0.8,
        };
      }
    }

    return {
      claimId: claim.id,
      status: ClaimStatus.Unsupported,
      evidenceId: "",
      reason: "evidence found but no support",
      confidence: 0.4,
    };
  }
}

function supports(claimText: string, evidenceText: string): boolean {
  // Упрощённый пример. В реальной системе здесь может быть:
  // - exact match для чисел/дат/id;
  // - semantic similarity;
  // - отдельный verifier model;
  // - проверка по БД/API.
  return evidenceText.toLowerCase().includes(claimText.toLowerCase());
}

enum PublishDecision {
  Allow = "allow",
  Rewrite = "rewrite",
  Block = "block",
  Review = "review",
}

class HallucinationPolicy {
  blockContradictions: boolean;
  reviewHighImpact: boolean;

  constructor(blockContradictions = true, reviewHighImpact = true) {
    this.blockContradictions = blockContradictions;
    this.reviewHighImpact = reviewHighImpact;
  }

  decide(results: ClaimResult[], highImpact: boolean): PublishDecision {
    for (const result of results) {
      if (result.status === ClaimStatus.Contradicted && this.blockContradictions) {
        throw new Error(`contradicted claim: ${result.claimId}`);
      }
    }

    if (highImpact && this.reviewHighImpact) {
      for (const result of results) {
        if (
          result.status === ClaimStatus.Unsupported ||
          result.status === ClaimStatus.NotCheckable
        ) {
          throw new Error(
            `high-impact answer contains unverified claim: ${result.claimId}`,
          );
        }
      }
    }

    for (const result of results) {
      if (
        result.status === ClaimStatus.Unsupported ||
        result.status === ClaimStatus.Stale
      ) {
        return PublishDecision.Rewrite;
      }
    }

    return PublishDecision.Allow;
  }
}

function rewriteWithUncertainty(answer: string, results: ClaimResult[]): string {
  const needsUncertainty = results.some(
    (result) =>
      result.status === ClaimStatus.Unsupported ||
      result.status === ClaimStatus.Stale ||
      result.status === ClaimStatus.NotCheckable,
  );

  if (!needsUncertainty) {
    return answer;
  }

  const prefix = "По доступным источникам это не подтверждено полностью. ";
  if (answer.startsWith(prefix)) {
    return answer;
  }
  return prefix + answer;
}
