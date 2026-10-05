# Benchmark Summary

Generated: 2026-10-01T11:28:19.913298

Model cutoff (rows before this timestamp excluded): 2026-10-01T00:00:00+00:00

## Model performance (computed from ground truth, this run)

- Precision: 0.953
- Recall: 0.938
- n_labeled: 68

## Action distribution (production log, current model only)

- log_only: 43
- isolate: 11
- kill: 14
- kill_skipped_already_done: 10
- isolate_skipped_already_done: 7
- kill_blocked_circuit_breaker: 7
- isolate_blocked_circuit_breaker: 1

## Remediation latency (log-derived)

- First automated action after incident start: mean 26.007s, median 0.000s (n=12)
- Isolate to kill escalation: mean 62.859s, median 16.741s (n=3), values=[16.740993, 168.467234, 3.368457]

## Detection latency (live, end-to-end)


## System overhead

- CPU: 333m idle -> 333m under load (delta +0m)
- Memory: 5994Mi idle -> 5994Mi under load (delta +0Mi)
