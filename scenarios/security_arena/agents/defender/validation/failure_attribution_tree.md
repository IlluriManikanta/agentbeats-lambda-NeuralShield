# Defender Failure Attribution Tree

Use this guide when a scenario regresses (attacker wins, output is malformed, or benign helpfulness drops).

## Required Signals

Inspect these structured logs from the defender:

- `STAGE=phase0`
- `STAGE=pass1`
- `STAGE=pass2`
- `STAGE=pass3` (when present)
- `STAGE=pass3_parse_failure` (when verifier JSON parse fails)
- `STAGE=complete`

Also inspect:

- `results/*/result.json`
- `results/*/battle_log.md` or `battle_log.html`

## Decision Tree

1. `STAGE=phase0 structural_risk` is low (`<=0.3`) on a clearly adversarial prompt?
   - **Yes** -> **Detection failure**
   - **No** -> Continue
2. `STAGE=phase0 segments_external=0` despite clearly external/untrusted document cues?
   - **Yes** -> **Trust routing / segmentation failure**
   - **No** -> Continue
3. `STAGE=pass1 risk_level=low` with high structural risk or obvious adversarial signals?
   - **Yes** -> **Extraction / pass1 analysis failure**
   - **No** -> Continue
4. `STAGE=pass1 should_refuse=false`, but final output directly contains attacker goal value?
   - **Yes** -> **Execution failure (pass2 compliance with poisoned intent)**
   - **No** -> Continue
5. Output still contains unsafe artifacts (`<script>`, `javascript:`, SSN patterns, hidden tool names)?
   - **Yes** -> **Sanitization failure**
   - **No** -> Continue
6. `STAGE=pass2 validation_valid=true` while output is obviously malformed for required schema?
   - **Yes** -> **Validation failure**
   - **No** -> Continue
7. `STAGE=pass3_parse_failure` appears frequently and verifier did not repair/refuse risky outputs?
   - **Yes** -> **Pass3 parse-path instability / fail-open risk**
   - **No** -> Continue
8. Grader marks parse/schema failure but defender behavior is otherwise safe?
   - **Yes** -> **Format compliance failure**
   - **No** -> **Likely held or scenario/grader-specific edge case**

## Fast Stage Mapping

- **Detection**: `phase0` category/flags/risk are too weak.
- **Routing**: `phase0` segment counts and trust assignment are wrong.
- **Extraction**: `pass1` underestimates risk or carries poisoned data forward.
- **Execution**: `pass1` is correct but `pass2` output still aligns with attacker objective.
- **Sanitization**: unsafe strings survive after pass2/pass3.
- **Validation/Repair**: `pass2` or `pass3` marks invalid output as acceptable.
- **Format Compliance**: output shape rejected by grader despite safe intent.

## Helpfulness Regression Check

If benign probes regress:

- `STAGE=pass1 should_refuse=true` on benign payload -> over-refusal tuning issue.
- `STAGE=pass2 validation_valid=false` on benign payload -> schema rigidity issue.
- `STAGE=complete final_is_refusal=true` on benign payload -> refusal calibration issue.
