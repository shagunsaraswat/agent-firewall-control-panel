/**
 * TypeScript definitions for `@agentfirewall/sdk` (NAPI-RS native addon).
 *
 * `context` / span payloads use **snake_case** field names matching Rust `serde` on the core types.
 */

/** Result of policy evaluation (flattened for JS). */
export interface PolicyDecision {
  decision:
    | 'allow'
    | 'deny'
    | 'downgrade'
    | 'pause'
    | 'require_approval'
    | string
  reasonCode?: string
  detail?: Record<string, unknown> | null
}

/** Budget figures for the current run (USD). */
export interface BudgetSnapshot {
  /** Same as `limitUsd` — total budget ceiling. */
  totalUsd: number
  spentUsd: number
  remainingUsd: number
  reservedUsd: number
  estimatedUsd: number
  limitUsd: number
  updatedAt: string
}

/** Witness snapshot (includes preimage required for revalidation). */
export interface StateSnapshot {
  hash: string
  resourceUri: string
  capturedAt: string
  formatVersion: number
  sizeBytes: number
  preimage: Uint8Array
}

export interface RevalidationOutcome {
  result: 'valid' | 'state_changed' | string
  originalHash: string
  currentHash: string
}

export interface LearnerClientConfig {
  natsUrl: string
  tenantId: string
  subjectPrefix?: string
  sampleRate?: number
  publishQueueCapacity?: number
  maxSpanBytes?: number
}

/** Sentinel settings mirror `agentfirewall_sentinel::SentinelConfig` (config-only in Node). */
export interface SentinelConfigView {
  enabled: boolean
  modelId: string
  stallThreshold: number
  stallWindow: number
  regressionThreshold: number
  maxIntervention: 'warn' | 'downgrade' | 'pause' | 'deny' | string
  maxEmbedInputBytes: number
  emaAlpha: number
}

export class PolicyEvaluator {
  constructor()
  loadRulesJson(rules: string): void
  addRuleJson(ruleJson: string): void
  evaluate(
    actionType: string,
    resource: string,
    context: Record<string, unknown>
  ): PolicyDecision
}

export class RunContextManager {
  constructor(runId: string, tenantId: string, goal: string)
  start(): void
  recordCost(amount: number, unit: string): void
  recordStep(stepId: string, tool: string): void
  getBudget(): BudgetSnapshot
  getContext(): Record<string, unknown>
}

export class ReasonCodeRegistry {
  constructor()
  register(code: string, description: string): void
  lookup(code: string): string | undefined
}

export class WitnessGuard {
  constructor()
  captureJson(value: string, uri: string): StateSnapshot
  verifyJson(snapshot: StateSnapshot, current: string): RevalidationOutcome
}

export class LearnerClient {
  constructor(config: LearnerClientConfig)
  connect(): Promise<void>
  emitSpan(span: Record<string, unknown>): void
  getMode(): string
  setMode(mode: string): string
  shutdown(): Promise<void>
}

/** Holds validated Sentinel configuration without loading embeddings in Node. */
export class SentinelConfigHolder {
  constructor(config: SentinelConfigView)
  validate(): void
  toObject(): SentinelConfigView
}

/** Default `SentinelConfig` (Rust defaults). */
export function sentinelDefaultConfig(): SentinelConfigView

/** Default embedding model id string from `agentfirewall-embed`. */
export function defaultEmbeddingModelId(): string
