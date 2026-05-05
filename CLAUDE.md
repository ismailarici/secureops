# SecureOps — Project Instructions

## Git identity

All commits and pushes must be authored and pushed as **ismailarici**.
Never use Claude as an author, committer, or co-author.
Never add `Co-Authored-By` lines to any commit message.

## Scope

SecureOps does NOT run security scans. It only consumes outputs from SecurePipe and SecureInfra.
Do not add any scanning logic to this repository.

## Architecture rules

- Everything must be portable across AWS, GCP, and Azure — no hardcoded cloud or org specifics
- All behaviour is config-driven via `config/config.yaml` (never committed — see `.gitignore`)
- All inputs are normalised to the shared event schema before any routing or alerting
- Keep modules loosely coupled — each integration is independent
- No Kafka, no heavy pipelines — keep it simple Python

## Commit style

- Short imperative subject line (under 72 characters)
- No trailing summaries or change lists in the body — the diff speaks for itself
- No `Co-Authored-By` lines
