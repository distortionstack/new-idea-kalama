# Controlled LLM reasoning fixture

This disposable research tree freezes Task 7.5.2.1 evidence only. `evidence/`
and `fixtures/*/model_evidence.json` are model-visible; `ground_truth/` is
evaluator-only. Prompt serialization accepts an evidence document and never
opens the ground-truth directory. `scripts/collect_fixture.py` hashes source
observations; `validate_fixture.py` performs the qualification audits; and
`serialize_prompt.py` freezes bounded JSON prompts. No script invokes a model.

The current `patch_strategy` candidate is deliberately **rejected as a
deterministic rule**. It remains useful as a negative-control fixture and as
evidence that an LLM must not be justified where production code has a stable
mapping. Removing this directory removes the research work without affecting
Kalama production code.
