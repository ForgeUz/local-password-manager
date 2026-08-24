# ADR 002: V6.5 Files Require Reconciliation

**Status:** Proposed  
**Date:** 2026-08-24

## Context
V6.5 added files that may duplicate existing modules in lib/src/{sync,totp,security}.

## Decision
- Run `flutter analyze` to detect duplicates
- Merge logic where existing modules are more complete
- Delete redundant files

## Consequences
- No dead code
- Single source of truth per module
