from __future__ import annotations

from dataclasses import dataclass

from app.config import settings

SEVERITY = {"critical": 100.0, "high": 80.0, "medium": 55.0, "low": 25.0, "info": 5.0}


@dataclass(frozen=True)
class RiskFactors:
    exposure: float = 0.5
    confidence: float = 0.9
    blast_radius: float = 0.5
    exploitability: float = 0.5


@dataclass(frozen=True)
class RiskConfig:
    severity: float = settings.risk_severity_weight
    exposure: float = settings.risk_exposure_weight
    confidence: float = settings.risk_confidence_weight
    blast_radius: float = settings.risk_blast_radius_weight
    exploitability: float = settings.risk_exploitability_weight

    def normalized(self) -> "RiskConfig":
        values = [self.severity, self.exposure, self.confidence, self.blast_radius, self.exploitability]
        if any(value < 0 for value in values) or sum(values) <= 0:
            raise ValueError("Risk weights must be non-negative and have a positive sum")
        total = sum(values)
        return RiskConfig(*(value / total for value in values))


def finding_risk(severity: str, factors: RiskFactors | None = None, config: RiskConfig | None = None) -> float:
    """Return a deterministic 0-100 finding risk score."""
    factors = factors or RiskFactors()
    weights = (config or RiskConfig()).normalized()
    bounded = [max(0.0, min(1.0, value)) for value in (
        factors.exposure, factors.confidence, factors.blast_radius, factors.exploitability
    )]
    score = (
        SEVERITY.get(severity.lower(), 50.0) * weights.severity
        + bounded[0] * 100 * weights.exposure
        + bounded[1] * 100 * weights.confidence
        + bounded[2] * 100 * weights.blast_radius
        + bounded[3] * 100 * weights.exploitability
    )
    return round(max(0.0, min(100.0, score)), 1)


def infer_factors(evidence: dict, *, scope: str = "resource") -> RiskFactors:
    """Infer explainable factors from static evidence without randomness."""
    rendered = str(evidence).lower()
    public = any(marker in rendered for marker in ("0.0.0.0/0", "::/0", "public", "wildcard"))
    credential = any(marker in rendered for marker in ("secret", "access_key", "token", "password"))
    return RiskFactors(
        exposure=1.0 if public else 0.5,
        confidence=0.95,
        blast_radius=0.8 if scope == "scan" else 0.5,
        exploitability=0.8 if public or credential else 0.5,
    )

