# Defender Robustness Benchmark

- Generated: `2026-03-30T07:55:42+00:00`
- Risk threshold: `0.55`
- Composite score (heuristic): `100.00`
- Ablations: `policy=False`, `substrate=False`, `privacy=False`

## Attack Recall

- Overall recall: `1.0` (42 perturbed samples)

| Category | Recall |
| --- | ---: |
| `indirect_injection` | `1.0` |
| `jailbreak` | `1.0` |
| `insecure_output` | `1.0` |
| `pii_leak` | `1.0` |
| `supply_chain` | `1.0` |
| `prompt_extraction` | `1.0` |

## Benign False Positives

- False positive rate: `0.0` (0/4)

## Sanitizer Effectiveness

- Blocked rate: `1.0` (4/4)

## Multi-round Replay

- Replayed rounds: `35`
- High suspicion rate: `0.0`
- Semantic privacy leak rate: `0.0`
- Recommendation surface leak rate: `0.0`
- Evidence misalignment rate: `0.0`

## Notes

- Recall measures category prediction OR high-risk detection with expected flag coverage.
- False positives approximate over-refusal pressure in benign workflows.
- Replay metrics score defender behavior over existing multi-round transcripts.
- Composite score is a quick trend metric, not a competition ground-truth score.

