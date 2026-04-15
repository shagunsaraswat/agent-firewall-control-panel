# Gemini Image Generation Prompts for Agent FirewallKit README

Use these prompts with Google Gemini (or Imagen) to generate visuals for the README.
After generation, place images in `docs/assets/` and update the README `<img>` tags accordingly.

Total: **12 images** across logo, hero, architecture, features, workflows, scenarios, and social.

---

## 1. Logo — `logo.png`

**Placement**: Top of README, centered
**README tag**: `<img src="docs/assets/logo.png" alt="Agent FirewallKit" width="120" />`

```
Create a modern, minimal logo for an open-source project called "Agent FirewallKit".

The concept: a shield or vault door that protects AI agents. Combine a stylized vault/safe
door icon with a subtle AI neural network pattern or circuit trace integrated into the shield shape.

Style requirements:
- Flat design, no gradients, no 3D effects
- Two colors maximum: deep indigo (#4338CA) as primary, warm amber (#F59E0B) as accent
- Clean geometric shapes, no organic curves
- The vault element should feel protective and secure
- The AI element should be subtle — a few connected nodes or circuit lines woven into the vault shape
- No text in the image — just the icon mark
- Square aspect ratio (1:1)
- Must look sharp at 120px and at 512px
- White or transparent background
- Similar in spirit to logos from Hashicorp, Datadog, or Grafana — technical but approachable
```

---

## 2. Hero Banner — `hero-banner.png`

**Placement**: Below badges, above "The Problem" section
**README tag**: `<img src="docs/assets/hero-banner.png" alt="Agent FirewallKit Hero" width="100%" />`

```
Create a hero banner image for an open-source project called "Agent FirewallKit" — a runtime
safety layer for autonomous AI agents.

The image should convey: protection, control, and safety for AI systems.

Visual concept: An abstract scene showing a series of translucent AI agent silhouettes (humanoid
or robotic shapes, very minimal and geometric) moving through a transparent security checkpoint
or vault gateway. The gateway has subtle scan lines and a green approval glow. One agent on the
left side is being held back with a red/amber indicator, showing the blocking/approval concept.

Style:
- Dark gradient background (deep navy #0F172A to midnight blue #1E1B4B)
- Glowing elements in indigo (#6366F1) and amber/gold (#F59E0B)
- Subtle grid pattern in the background suggesting a digital environment
- Very minimal, almost abstract — not literal or cartoonish
- Tech-forward aesthetic similar to Linear, Vercel, or Raycast marketing imagery
- Aspect ratio 3:1 (e.g., 2400x800px) for a wide README banner
- Include subtle text "Agent FirewallKit" in a clean sans-serif font, positioned left-center
- Tagline "Runtime safety for autonomous agents" in smaller text below
```

---

## 3. "The Problem" Illustration — `problem-scenario.png`

**Placement**: "The Problem" section — visualizes the chaos Agent FirewallKit prevents
**README tag**: `![The Problem](docs/assets/problem-scenario.png)`

```
Create an illustration showing the problems that occur when autonomous AI agents run
without guardrails. This is for a technical open-source project README.

The image shows a split-screen concept. Both sides show the same AI agent icon (a simple
geometric robot/agent shape).

LEFT SIDE — labeled "Without guardrails" (red-tinted):
- Agent icon surrounded by warning signs and red indicators
- Visual elements showing (as small, clear icons with labels):
  - A circular arrow (looping) — "Infinite loop"
  - A dollar sign burning — "Budget blown"
  - A file being modified with a red X — "Unauthorized write"
  - A terminal icon with skull — "Dangerous command"
  - A clock with exclamation — "Stale approval executed"
- Overall feel: chaotic, uncontrolled, red/orange tones

RIGHT SIDE — labeled "With Agent FirewallKit" (green-tinted):
- Same agent icon, but now passing through a shield/checkpoint
- Visual elements showing (as small, clear icons with labels):
  - A radar with checkmark — "Progress tracked"
  - A shield with rules — "Policy enforced"
  - A person reviewing — "Human approval"
  - A hash comparison — "State verified"
  - A brain with lightbulb — "Learning from behavior"
- Overall feel: controlled, safe, green/indigo tones

Style:
- Light background (#F8FAFC) for README readability
- Clean flat icons, no 3D
- Left side uses red (#EF4444) and amber (#F59E0B) accents
- Right side uses green (#22C55E) and indigo (#6366F1) accents
- Dividing line in the center
- Aspect ratio 2:1 (e.g., 1600x800px)
- Clean sans-serif labels (Inter or similar)
- Similar to comparison diagrams in Vercel, Supabase, or Linear documentation
```

---

## 4. Architecture Diagram — `architecture-overview.png`

**Placement**: "How It Connects to Your Agent" section — replaces the ASCII diagram
**README tag**: `![Architecture](docs/assets/architecture-overview.png)`

```
Create a clean technical architecture diagram for a software system called "Agent FirewallKit".
This diagram should show exactly how an AI agent connects to the control plane.

The diagram has THREE horizontal layers:

TOP LAYER — "Your Agent / Host Process" (amber border):
- Inside: three boxes in a row representing in-process SDK components:
  - "Policy Evaluator" — icon: shield with checklist — label below: "Allow / Deny / Require Approval"
  - "Sentinel Tracker" — icon: radar/signal — label below: "Detect loops & stalls"
  - "Witness Guard" — icon: fingerprint/hash — label below: "Hash state for revalidation"
- A fourth box to the right: "Learner Client" — icon: outgoing arrow — label: "→ NATS spans"
- Below all four boxes, a label: "All run in-process • No network latency for policy/sentinel/witness"

MIDDLE — Connection arrows:
- Three arrows going down from the SDK zone to the server zone, labeled:
  - "HTTP / gRPC" for control plane calls
  - "NATS" for learner telemetry (going to the right, into the NATS box in the server)

BOTTOM LAYER — "Agent FirewallKit Control Plane" (indigo border):
- Top row: five service boxes:
  - "Policy Service" — "Store & version rules"
  - "Run Service" — "Track agent runs"
  - "Approval Service" — "Human-in-the-loop"
  - "Incident Service" — "Security events"
  - "Learner Service" — "Baselines & candidates"
- Middle row: "Span Ingest" and "Baseline Aggregator" (spanning the width)
- Bottom row: four database boxes:
  - "PostgreSQL" — "Primary data" (elephant icon)
  - "ClickHouse" — "Analytics" (column icon)
  - "NATS" — "Events" (message icon)
  - "Redis" — "Cache" (lightning icon)

Style:
- Dark background (#0F172A slate-900) with white text
- Agent zone boxes in amber (#F59E0B) with dark text
- Service boxes in indigo (#6366F1) with white text
- Database boxes in teal (#14B8A6) with white text
- Connection arrows as thin white/gray lines with labels
- Clean sans-serif font (Inter or similar)
- Aspect ratio 16:9 (1920x1080px)
- No decorative elements — purely functional
- Each box has a small icon and a one-line description
- Similar to architecture diagrams from Supabase, PlanetScale, or Vercel docs
```

---

## 5. Feature Cards — three individual images

**Placement**: "Why Agent FirewallKit?" section, displayed in a 3-column grid
**README tag**: Grid of three `<img>` tags with `width="30%"`

### 5a. Sentinel Card — `feature-sentinel.png`

```
Create a feature illustration card for a capability called "Sentinel" — goal-aware
progress tracking for AI agents.

Concept: Show an abstract radar or sonar display with concentric rings. A bright dot
represents an AI agent's trajectory plotted over time (like a path through the rings).
The trajectory shows three phases:
1. Clean forward progress (green line, moving outward toward the goal at the center)
2. Stalling (amber line, circling at the same radius — not making progress)
3. Regression (red line, moving backward / inward — losing progress)

At the regression point, a clear "ALERT" indicator or warning badge appears, showing
that Sentinel has detected the problem.

Style:
- Dark background (#1E1B4B)
- Concentric rings in subtle gray (#374151, 20% opacity)
- Progress line: green (#22C55E) → amber (#F59E0B) → red (#EF4444)
- Alert badge: bright red with white exclamation
- Goal point at center: bright indigo (#6366F1) star or target
- Clean geometric lines, no organic shapes
- Aspect ratio 4:3 (800x600px)
- Small label at bottom: "Sentinel — Progress Tracking"
- Minimalist, technical, dashboard-inspired aesthetic
```

### 5b. Witness Card — `feature-witness.png`

```
Create a feature illustration card for a capability called "Witness" — state
revalidation at execution time for AI agent approvals.

Concept: Show a timeline with two moments:

LEFT — "Approval Time (T1)":
- A document/file icon representing state
- A hash value displayed below it (like "SHA-256: a1b2c3...")
- A green checkmark and label "Approved"

RIGHT — "Execution Time (T2)":
- The same document icon, but subtly different (indicating change)
- A different hash value below it
- The two hashes have a comparison line between them with a red X
- A shield icon above with "BLOCKED" label
- Label: "State changed → Approval invalid"

Between T1 and T2:
- A subtle timeline arrow
- A small lightning bolt or warning icon where the state changed

Style:
- Dark background (#1E1B4B)
- T1 elements in green (#22C55E) — approved, valid
- T2 elements in red (#EF4444) — changed, blocked
- Hash text in monospace, light gray
- Timeline in white/gray
- Clean geometric style
- Aspect ratio 4:3 (800x600px)
- Small label at bottom: "Witness — State Revalidation"
- Similar aesthetic to Git diff or blockchain verification visuals
```

### 5c. Learner Card — `feature-learner.png`

```
Create a feature illustration card for a capability called "Learner" — behavioral
baseline learning that generates enforceable security policies for AI agents.

Concept: A three-phase visual flowing left to right:

PHASE 1 — "Observe" (left third):
- Multiple thin translucent lines (like time-series traces) representing individual
  agent actions over time (tool calls, costs, etc.)
- Lines are in soft blue (#93C5FD, 30% opacity)
- Label: "Agent behavior spans"

PHASE 2 — "Learn" (middle third):
- A bold envelope/confidence-band line forms around the traces, showing the
  "learned normal range" — the statistical baseline
- Envelope in bright indigo (#6366F1)
- Outlier dots above/below the envelope in amber (#F59E0B)
- Label: "Behavioral baseline"

PHASE 3 — "Enforce" (right third):
- An arrow from the envelope pointing to a stylized policy document icon
- The policy shows 2-3 rule lines (like "ALLOW read_file", "DENY shell")
- Document icon in amber (#F59E0B)
- Label: "Generated policy"

Style:
- Dark background (#1E1B4B)
- Clean, data-visualization aesthetic
- Left-to-right flow with subtle connecting arrows
- Aspect ratio 4:3 (800x600px)
- Small label at bottom: "Learner — Observe → Learn → Enforce"
- Similar to observability dashboards from Datadog or Grafana
```

---

## 6. End-to-End Workflow Diagram — `workflow-approval.png`

**Placement**: "How It Works: End-to-End Scenario" section
**README tag**: `![Approval Workflow](docs/assets/workflow-approval.png)`

```
Create a horizontal workflow diagram showing the complete Agent FirewallKit approval lifecycle
for an AI agent attempting a write operation.

The flow reads left to right with numbered steps:

1. "Agent wants to write file" (icon: robot + pencil, blue box)
   → arrow →
2. "Policy evaluator checks rules" (icon: shield with magnifying glass, indigo box)
   → splits into TWO paths:

   PATH A (top, green):
   → "ALLOWED" (green checkmark) → "Action executes immediately"

   PATH B (bottom, amber):
   → "REQUIRES_APPROVAL" (amber warning) →
3. "Witness captures state hash" (icon: fingerprint/hash, amber box)
   → arrow →
4. "Human reviews request" (icon: person with document, gray box)
   → splits into two:
   → "REJECTED" (red X) → end
   → "APPROVED" (green check) →
5. "Witness re-validates state" (icon: eye scanning hash, indigo box)
   → splits into two:
   → "State unchanged" (green) → "Execute action" (green checkmark)
   → "State CHANGED" (red) → "BLOCKED — stale approval" (red X, with text "WITNESS_HASH_MISMATCH")

At the very bottom, a separate lane:
6. "If policy returns DENY → Incident created automatically" (red box with severity badge)

Style:
- Light background (#F8FAFC) for README readability
- Boxes with rounded corners, subtle drop shadows
- Each box has a small icon and bold label
- Arrows are clean lines with small labels
- Color coding: green (#22C55E) for allow, amber (#F59E0B) for review, red (#EF4444) for block/deny
- Indigo (#6366F1) for system actions (witness, policy)
- Font: clean sans-serif (Inter)
- Step numbers in small circles at top-left of each box
- Aspect ratio approximately 3:1 (2400x800px) — wide horizontal flow
- Similar to flowcharts in Stripe, GitHub, or Vercel documentation
```

---

## 7. SDK Integration Diagram — `sdk-integration.png`

**Placement**: "How It Connects to Your Agent" section, next to the integration code
**README tag**: `![SDK Integration](docs/assets/sdk-integration.png)`

```
Create a diagram showing how Agent FirewallKit SDK integrates into an AI agent's execution loop.

The diagram shows a vertical flow representing a single agent "step" (one iteration of
the agent's main loop), with Agent FirewallKit checkpoints at each stage:

┌─────────────────────────────────────┐
│         Agent Main Loop              │
│                                      │
│  1. Receive task / pick next action  │
│         │                            │
│         ▼                            │
│  ┌─────────────────────┐            │
│  │ POLICY CHECK        │ ← Agent FirewallKit SDK
│  │ evaluate(action)    │            │
│  │ → Allow? Continue   │            │
│  │ → Deny? Skip + log  │            │
│  │ → Approval? Request │            │
│  └─────────────────────┘            │
│         │                            │
│         ▼                            │
│  ┌─────────────────────┐            │
│  │ SENTINEL CHECK      │ ← Agent FirewallKit SDK
│  │ evaluate_step(state)│            │
│  │ → Progress OK?      │            │
│  │ → Stalling? Warn    │            │
│  │ → Regressing? Block │            │
│  └─────────────────────┘            │
│         │                            │
│         ▼                            │
│  ┌─────────────────────┐            │
│  │ EXECUTE ACTION       │            │
│  │ (if approved)        │            │
│  └─────────────────────┘            │
│         │                            │
│         ▼                            │
│  ┌─────────────────────┐            │
│  │ EMIT TELEMETRY      │ ← Agent FirewallKit SDK
│  │ learner.emit_span() │            │
│  │ → tool, cost, model │            │
│  └─────────────────────┘            │
│         │                            │
│         ▼                            │
│     Next iteration                   │
└─────────────────────────────────────┘

Show this as a clean, styled diagram — NOT as ASCII art.

Each "Agent FirewallKit SDK" checkpoint should be in a different color (indigo for policy,
amber for sentinel, green for execute, teal for telemetry) with a small icon.

The main loop box should be in a neutral gray.
An arrow from "EMIT TELEMETRY" goes off to the right, labeled "→ NATS → Control Plane",
showing the server connection.

Style:
- Light background (#F8FAFC) for README readability
- Main loop container in light gray (#F1F5F9) with rounded corners
- SDK checkpoints as colored boxes: indigo, amber, green, teal
- Small icons in each checkpoint box
- Clean sans-serif font
- Aspect ratio 3:4 (600x800px, vertical)
- Similar to execution-flow diagrams in LangChain or CrewAI documentation
```

---

## 8. Security Model Diagram — `security-model.png`

**Placement**: "Security Model" section
**README tag**: `![Security Model](docs/assets/security-model.png)`

```
Create a layered security diagram for "Agent FirewallKit" showing how multiple security
mechanisms protect tenant data.

The diagram shows concentric rectangles (like an onion), each layer labeled:

OUTERMOST — "TLS / Network Encryption" (dark gray border)
  NEXT — "API Key Authentication" (indigo border)
    - Shows: "SHA-256 hashed at rest" • "Bearer or x-api-key header"
    NEXT — "RBAC Permissions" (amber border)
      - Shows a grid of permission badges: PolicyRead, PolicyWrite, RunRead, RunWrite,
        ApprovalRead, ApprovalWrite, IncidentRead, IncidentWrite, LearnerRead, LearnerWrite, Admin
      NEXT — "Tenant Isolation" (teal border)
        - Shows: "Every query scoped by tenant_id" • "Cross-tenant access impossible"
        CENTER — "Your Data" (green, protected)
          - Small icons: policies, runs, approvals, incidents

Outside the layers, three arrows pointing at the outer boundary, labeled:
- "Unauthenticated request → 401"
- "Wrong tenant → empty results"
- "Missing permission → 403"

Bottom section: "Audit Log" spanning the full width — "Append-only • Time-partitioned •
Immutable (no UPDATE/DELETE triggers)"

Style:
- Light background for README readability
- Each layer as a clearly labeled rectangle with its own color
- Center is the most protected (green)
- Outer layers in progressively darker/cooler colors
- Rejection arrows in red
- Clean, geometric, no 3D effects
- Aspect ratio 4:3 (800x600px)
- Similar to security architecture diagrams from AWS or HashiCorp
```

---

## 9. Database Schema Diagram — `database-schema.png`

**Placement**: "Database Schema" section — visual companion to the table
**README tag**: `![Database Schema](docs/assets/database-schema.png)`

```
Create an entity-relationship diagram for the Agent FirewallKit database schema.

Tables and their relationships:

- policies (1) → (many) policy_versions
- policy_versions (1) → (many) policy_rules
- runs (1) → (many) run_steps (partitioned)
- runs (1) → (many) approvals
- runs (1) → (many) incidents (optional FK)
- approvals (1) → (0..1) incidents (optional FK)
- policy_candidates — standalone, links to proposed policy
- api_keys — standalone, tenant-scoped
- idempotency_keys — standalone, tenant-scoped
- audit_log — append-only, partitioned

Each table shows 3-5 key columns (not all columns):
- policies: id, tenant_id, name, slug
- policy_versions: id, policy_id, version, status, default_action
- policy_rules: id, policy_version_id, rule_key, priority, action
- runs: id, tenant_id, agent_id, status, mode, goal
- run_steps: id, run_id, step_index, action_type, decision (partitioned)
- approvals: id, tenant_id, run_id, status, witness_hash, expires_at
- incidents: id, tenant_id, severity, status, reason_code
- api_keys: id, tenant_id, key_hash, permissions[]
- idempotency_keys: id, tenant_id, operation, status
- audit_log: id, tenant_id, action, resource_type (append-only, partitioned)

Style:
- Light background (#F8FAFC)
- Tables as boxes with header row (table name in bold, indigo background)
- Column rows in white with light borders
- FK relationships as lines with crow's foot notation
- Partitioned tables (run_steps, audit_log) have a special icon or subtle repeating pattern
- Append-only tables have a lock icon
- Group related tables visually (policy group, run group, security group)
- Clean sans-serif font
- Aspect ratio 16:9 (1600x900px)
- Similar to ERD diagrams from dbdiagram.io or DrawSQL
```

---

## 10. Metrics Dashboard Mockup — `metrics-dashboard.png`

**Placement**: "Observability" section
**README tag**: `![Metrics](docs/assets/metrics-dashboard.png)`

```
Create a mockup of a Grafana-style metrics dashboard showing Agent FirewallKit observability.

The dashboard has a dark background (#1a1a2e) with 6 panels arranged in a 3x2 grid:

Panel 1 (top-left): "Request Rate" — line chart showing requests/second over time,
  with separate colored lines for each endpoint group (policies, runs, approvals, incidents)
  
Panel 2 (top-center): "Request Latency p95" — line chart showing p95 latency in ms,
  with a horizontal threshold line at 100ms

Panel 3 (top-right): "Active Runs" — single big number "24" with a small sparkline below

Panel 4 (bottom-left): "Policy Decisions" — stacked bar chart showing Allow (green),
  Deny (red), Require Approval (amber) counts per hour

Panel 5 (bottom-center): "Incidents by Severity" — donut chart with segments:
  CRITICAL (red), HIGH (orange), MEDIUM (amber), LOW (gray)

Panel 6 (bottom-right): "DB Pool" — gauge showing 8/20 connections used, healthy green

Top bar: "Agent FirewallKit — Production" with time range selector "Last 6 hours"

Style:
- Grafana-dark aesthetic (#1a1a2e background, #2a2a3e panel backgrounds)
- Chart colors: green (#22C55E), amber (#F59E0B), red (#EF4444), indigo (#6366F1)
- Clean chart axes with subtle grid lines
- Each panel has a title in the top-left
- Aspect ratio 16:9 (1600x900px)
- Should look like an actual Grafana screenshot, realistic and functional
```

---

## 11. Social Preview / OG Image — `social-preview.png`

**Placement**: Repository settings → Social preview image (GitHub)

```
Create a social preview image for a GitHub repository called "Agent FirewallKit".

Content:
- Left side: The Agent FirewallKit logo icon (a vault/shield with subtle circuit traces, in amber)
- Center-right: Title "Agent FirewallKit" in bold sans-serif, white, large
- Below title: "Runtime safety layer for autonomous AI agents" in lighter weight, light gray
- Below tagline, three small feature badges in a row:
  - "Sentinel" with radar icon
  - "Witness" with hash/fingerprint icon
  - "Learner" with brain icon
- Bottom-right corner: "MIT License" • "Rust" • "Open Source" in small text

Style:
- Background: deep indigo gradient (#1E1B4B to #312E81)
- Text in white and light gray (#94A3B8)
- Logo and feature icons in amber (#F59E0B)
- Feature badges have subtle indigo (#4338CA) backgrounds
- Clean, professional, open-source project aesthetic
- Exact dimensions: 1280x640px (GitHub OG image requirement)
- Similar to social previews from Deno, Turbo, or SWC repositories
```

---

## 12. CLI Screenshot — `cli-screenshot.png`

**Placement**: "CLI" section, showing what the CLI looks like in practice
**README tag**: `![CLI](docs/assets/cli-screenshot.png)`

```
Create a realistic terminal screenshot showing the Agent FirewallKit CLI in action.

The terminal shows a dark background (#1E1B2E) with the following commands and outputs:

$ agentfirewall policy list
┌──────────────────────────────────────┬─────────────────────────┬────────┬──────────┐
│ ID                                   │ Name                    │ Status │ Rules    │
├──────────────────────────────────────┼─────────────────────────┼────────┼──────────┤
│ 2174a212-5d2a-45b2-a9f0-6d429404bd2d│ code-agent-guardrails   │ ACTIVE │ 4        │
│ 898fd0fa-9b47-4b87-a498-c32909e5ea38│ test-safety-policy      │ ARCHIVED│ 1       │
└──────────────────────────────────────┴─────────────────────────┴────────┴──────────┘

$ agentfirewall incident list --severity 3
┌──────────────────────────────────────┬──────────┬──────────────┬───────────────────────────────┐
│ ID                                   │ Severity │ Status       │ Title                         │
├──────────────────────────────────────┼──────────┼──────────────┼───────────────────────────────┤
│ 019d5e0f-733c-7d81-9933-1ad45e0a501a│ HIGH     │ OPEN         │ Agent attempted execute_shell  │
└──────────────────────────────────────┴──────────┴──────────────┴───────────────────────────────┘

$ agentfirewall server health
✓ HTTP API: healthy (http://localhost:8080)
✓ Database: connected (PostgreSQL 16)
✓ Redis: connected
✓ NATS: connected (JetStream enabled)

The terminal should show:
- A modern terminal emulator look (iTerm2 or Warp style)
- Colored output: green for status, amber for warnings, red for errors
- Table borders using Unicode box-drawing characters
- The prompt in green/white
- Command text in white, output in appropriate colors
- Aspect ratio 16:9 (1200x675px)
- Terminal title bar: "agentfirewall — bash"
```

---

## Image Placement Map

| # | Image | README Section | Tag |
|---|-------|---------------|-----|
| 1 | `logo.png` | Top (centered) | `<img>` |
| 2 | `hero-banner.png` | Below badges | `<img width="100%">` |
| 3 | `problem-scenario.png` | "The Problem" | `![The Problem](...)` |
| 4 | `architecture-overview.png` | "How It Connects" | `![Architecture](...)` |
| 5a | `feature-sentinel.png` | "Why Agent FirewallKit?" | `<img width="30%">` |
| 5b | `feature-witness.png` | "Why Agent FirewallKit?" | `<img width="30%">` |
| 5c | `feature-learner.png` | "Why Agent FirewallKit?" | `<img width="30%">` |
| 6 | `workflow-approval.png` | "How It Works" | `![Workflow](...)` |
| 7 | `sdk-integration.png` | "How It Connects" | `![SDK Integration](...)` |
| 8 | `security-model.png` | "Security Model" | `![Security](...)` |
| 9 | `database-schema.png` | "Database Schema" | `![Schema](...)` |
| 10 | `metrics-dashboard.png` | "Observability" | `![Metrics](...)` |
| 11 | `social-preview.png` | GitHub settings | Repo social preview |
| 12 | `cli-screenshot.png` | "CLI" | `![CLI](...)` |

## Generation Order

Generate in this order for best results (later images can reference earlier ones):

1. Logo (used in social preview)
2. Feature cards (3 images — can batch)
3. Problem scenario
4. Architecture diagram
5. SDK integration diagram
6. Workflow diagram
7. Security model
8. Database schema
9. Metrics dashboard
10. CLI screenshot
11. Hero banner
12. Social preview (uses logo)
