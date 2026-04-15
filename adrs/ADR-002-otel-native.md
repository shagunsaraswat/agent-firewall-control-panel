# ADR-002 — OpenTelemetry-native Telemetry

## Status
Accepted

## Context
Observability products already exist and interoperability matters.

## Decision
Use OpenTelemetry traces/spans and semantic attributes as the default telemetry backbone.

## Consequences
- Positive: better ecosystem compatibility and easier integration with enterprise tooling.
- Positive: shared data model across runtime governance, analytics, and later vault modules.
- Negative: semantic conventions may evolve and require compatibility work.
