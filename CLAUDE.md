# CLAUDE.md — aegis-core

## Project
The AEGIS enforcement engine — risk scoring models, mediation layer, and policy runtime.

## Org Context
- GitHub Org: github.com/aegis-initiative
- IP Owner: Finnoybu IP LLC
- Parent Ecosystem: Finnoybu Holdings LLC
- Domain: aegissystems.app

## This Repo's Role
aegis-core is the computational heart of AEGIS. It implements the risk scoring algorithms, the mediation layer that arbitrates policy conflicts, and the policy runtime that evaluates governance rules against AI system behavior. It is consumed by aegis-platform as a library and is independently testable.

## Related Repos
- aegis — Architectural specs and schemas this engine implements
- aegis-platform — Production platform that consumes this engine
- aegis-sdk — SDK that exposes a subset of this engine's capabilities
- aegis-labs — Experimental versions and research spikes for new scoring models

## Stack
TBD — Python (primary), with potential TypeScript bindings via aegis-sdk

## Key Conventions
- All public APIs must have corresponding JSON Schema definitions in aegis
- Unit tests required for all scoring functions (pytest)
- Branch: main is protected; all changes via PR with 1 required review
- Commit style: conventional commits

## Current Focus
Initial architecture setup — defining module structure and core interfaces
