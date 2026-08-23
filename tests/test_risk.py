from app.services.risk import RiskConfig, RiskFactors, finding_risk


def test_risk_is_deterministic_bounded_and_explainable():
    factors = RiskFactors(exposure=1, confidence=.9, blast_radius=.8, exploitability=.7)
    first = finding_risk("high", factors)
    assert first == finding_risk("high", factors)
    assert 0 <= first <= 100
    assert first > finding_risk("low", factors)


def test_risk_weights_are_normalized_and_validated():
    assert finding_risk("high", config=RiskConfig(2, 0, 0, 0, 0)) == 80
    try:
        RiskConfig(0, 0, 0, 0, 0).normalized()
    except ValueError as exc:
        assert "positive sum" in str(exc)
    else:
        raise AssertionError("invalid weights should be rejected")
