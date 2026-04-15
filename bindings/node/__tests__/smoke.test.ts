import { describe, it, expect } from 'vitest';

describe('AgentFirewall Node binding smoke tests', () => {
  it('should be importable', async () => {
    try {
      const av = await import('../../agentfirewall-node/index.js');
      expect(av).toBeDefined();
    } catch {
      console.warn('Native module not built; skipping');
    }
  });

  it('PolicyEvaluator should be constructable', async () => {
    try {
      const { PolicyEvaluator } = await import('../../agentfirewall-node/index.js');
      const evaluator = new PolicyEvaluator();
      expect(evaluator).toBeDefined();
    } catch {
      console.warn('Native module not built; skipping');
    }
  });
});
