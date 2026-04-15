# ADR-003 — Enforcement Wedge Before Full Control Plane

## Status
Accepted

## Context
A broad control-plane launch risks being too diffuse and hard to sell.

## Decision
Ship AgentFirewall first as the runtime governance wedge, while designing all internals to be reusable for AgentFirewall.

## Consequences
- Positive: strongest urgency and shortest path to adoption.
- Positive: avoids overbuilding before market validation.
- Negative: requires careful product messaging so customers understand the broader roadmap without expecting unfinished modules.
