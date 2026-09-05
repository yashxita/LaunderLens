# Artifact Map — LaunderLens

Every table and figure in the paper maps to the exact experiment(s) and script(s)
that regenerate it. Reviewers: everything below can be rerun from a clean checkout.

## Tables

| Table | Content | Source data | Generator script |
|-------|---------|-------------|------------------|
| Table 1 | Full Attack × Defence matrix (ASR, SER, LIS, LIS+D) | `experiments/results/phase4_*.json` | `python analysis/build_tables.py` |
| Table 2 | Utility / over-blocking rates per defence | `experiments/results/utility_*.json` | `python analysis/build_tables.py` |
| Table 3 | Cross-domain consistency (banking vs slack) | `experiments/results/phase4_*.json` | `python analysis/build_tables.py` |
| Table 4 | Oracle reliability (κ, n, agreement %) | `analysis/kappa_ratings.json` | `python analysis/build_tables.py` |

## Figures

| Figure | Content | Source data | Generator script |
|--------|---------|-------------|------------------|
| Fig 1 | AuthGraph mechanism (verbatim-match shortcut) | Conceptual (no data) | `python analysis/build_figures.py` |
| Fig 2 | ASR vs LIS scatter, per defence | `experiments/results/phase4_*.json` | `python analysis/build_figures.py` |
| Fig 3 | Security/utility trade-off scatter | `experiments/results/phase4_*.json` + `utility_*.json` | `python analysis/build_figures.py` |
| Fig 4 | Cross-domain grouped bars | `experiments/results/phase4_*.json` | `python analysis/build_figures.py` |
| Fig 5 | Oracle reliability breakdown | `analysis/kappa_ratings.json` | `python analysis/build_figures.py` |

## Headline Numbers

| Metric | Script | Command |
|--------|--------|---------|
| LIS-with-defence (per cell) | `analysis/rescore_phase4.py` | `python analysis/rescore_phase4.py experiments/results/phase4_*.json` |
| 95% bootstrap CIs | `analysis/stats.py` | `python analysis/stats.py experiments/results/phase4_*.json` |
| Cohen's κ | `analysis/kappa_rate.py` | `python analysis/kappa_rate.py --report-only` |
| Over-blocking / FPR | `experiments/run_utility.py` | `python experiments/run_utility.py` |

## Experiment Runners

| Experiment | Script | Example command |
|------------|--------|-----------------|
| Phase 4 (single variant) | `experiments/run_phase4.py` | `python experiments/run_phase4.py --attack attribution_forgery --variant priority_billing --defense authgraph --seeds 3` |
| Phase 4 (full matrix) | `experiments/run_matrix.py` | `python experiments/run_matrix.py --seeds 3 --suites banking slack` |
| Utility measurement | `experiments/run_utility.py` | `python experiments/run_utility.py --model-id qwen2.5:14b` |
| Oracle rating | `analysis/kappa_rate.py` | `python analysis/kappa_rate.py experiments/results/phase4_*.json` |

## Full Regeneration (from scratch)

```bash
# 1. Run experiments (requires Ollama + agentdojo)
python experiments/run_matrix.py --seeds 3 --suites banking slack

# 2. Measure utility
python experiments/run_utility.py

# 3. Rate oracle (interactive — requires human input)
python analysis/kappa_rate.py experiments/results/phase4_*.json

# 4. Generate stats, tables, figures
python analysis/stats.py experiments/results/phase4_*.json
python analysis/build_tables.py
python analysis/build_figures.py
```
