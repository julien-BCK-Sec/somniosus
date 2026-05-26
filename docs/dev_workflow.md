# Development Workflow (Early Stage)

Somniosus is under active architectural development. Git history is not yet considered stable, so development emphasizes reproducible runs and lightweight snapshots.

---

## Repository status

The repository is evolving quickly:
- architecture still shifting
- reporting pipeline stabilizing
- plugin system expanding

Commits may begin once schemas and reporting stabilize.

---

## Lightweight safety strategy

### Results directory as historical record
Every run produces:

results/<target>/<timestamp>/

These runs provide behavioral history even when code changes.

Do not overwrite previous runs.

---

### Manual snapshots (recommended)
Occasionally snapshot the working directory:

Example:

    cp -r Somniosus Somniosus_snapshot_YYYYMMDD

or:

    tar czf snapshot_YYYYMMDD.tgz Somniosus/

Recommended after:
- successful pipeline run
- reporting changes
- new tool integration
- major refactor

---

## Known-good smoke targets

Maintain a list of targets for regression checks:

Example:

scanme.nmap.org — baseline pipeline test  
example.com — HTTP enumeration sanity check  

When behavior changes unexpectedly, rerun these targets.

---

## When git becomes mandatory

Begin committing once:
- Hybrid v1 reporting is stable
- schemas stop changing
- tool integrations stabilize
- regressions become costly

---

## Philosophy

Current priority:

architecture > correctness > repeatability > polish

Optimization and cleanup come later.
