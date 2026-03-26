"""Rule-based security filters for the baseline defender.

NOTE: These filters are NOT currently used by the main SecurityGateway.
The 2-pass LLM pipeline in main.py uses:
- structural_analyzer.py for deterministic pattern detection
- LLM-based analysis for semantic threat detection

These simple keyword-based filters are kept for potential future use
as fast pre-filters or for scenarios with strict latency requirements.
"""

