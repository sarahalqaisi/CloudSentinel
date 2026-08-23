# Risk scoring model

CloudSentinel produces deterministic prioritization scores for static-analysis findings. A score is an explainable estimate, not an exploitability guarantee or a measurement of production impact.

## Finding score

Each component is normalized to `0..100` and combined as:

```text
risk = severity × 0.50
     + exposure × 0.20
     + confidence × 0.10
     + blast radius × 0.10
     + exploitability × 0.10
```

Severity bases are critical 100, high 80, medium 55, low 25, and informational 5. Exposure and exploitability increase for evidence containing deterministic public-access, wildcard, or credential indicators. Scan-wide controls receive a higher blast-radius factor. Confidence is 0.95 for a matched deterministic policy. Scores are rounded to one decimal place and clamped to `0..100`.

Weights are configurable with the `RISK_*_WEIGHT` environment variables documented in `.env.example`. They are normalized at runtime so proportional configurations behave consistently. Negative weights and an all-zero configuration are rejected.

## Scan security score

The existing scan posture score remains backward compatible. It starts at 100 and subtracts severity-weighted finding penalties normalized by the number of resources. Its severity penalties are critical 20, high 12, medium 6, low 2, and informational 0.5. The result is clamped at zero and mapped to grades A through F.

## Assumptions and limitations

- Static Terraform input may differ from deployed state.
- Dynamic expressions and provider defaults may be unresolved by the lightweight parser.
- A high score means fewer detected policy violations, not proof of security.
- Risk factors do not use randomness, cloud telemetry, threat intelligence, or live exploit validation.
- Policy changes, scoring configuration, and input changes can affect scores; record those alongside results when comparing runs.
