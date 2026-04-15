# ADR-001 — MCP-first Interoperability

## Status
Accepted

## Context
The product must govern agent tool access across a fragmented ecosystem.

## Decision
Adopt MCP as the primary tool interoperability standard and support raw wrapper adapters for non-MCP frameworks.

## Consequences
- Positive: aligns with ecosystem momentum and enterprise integration patterns.
- Positive: reduces need to invent a custom tool protocol.
- Negative: must track MCP spec changes and transport/auth updates.
