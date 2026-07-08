# Evaluation

The evaluation harness is intentionally local and deterministic. It scans labeled Python and Java fixtures in `evaluation/corpus/` with semantic analysis disabled, then compares detected rule IDs and line numbers with `evaluation/labels.json`.

Run:

```powershell
python evaluation/run_evaluation.py
```

Metrics:

- precision
- recall
- F1 score
- false-positive rate
- false-negative rate
- evidence-validity rate
- line-accuracy rate
- rule coverage
- severity accuracy
- files scanned/sec
- LOC scanned/sec
- total scan time
- semantic call count
- token estimate per scan
- average findings per KLOC

Release targets:

- precision >= 0.80
- recall >= 0.70
- evidence_validity >= 0.95
- line_accuracy >= 0.90
- rule_test_coverage = 100%
