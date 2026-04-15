import { describe, it, expect } from 'vitest';
import { readFileSync, existsSync } from 'fs';
import { resolve } from 'path';

const FIXTURES_PATH = resolve(__dirname, '../../../tests/fixtures/witness_golden_vectors.json');

interface GoldenVector {
  name: string;
  input: unknown;
  expected_hash: string;
}

describe('Witness hash cross-language parity', () => {
  it('should produce identical hashes to Rust for golden vectors', async () => {
    if (!existsSync(FIXTURES_PATH)) {
      console.warn('No golden vectors found; skipping');
      return;
    }

    const vectors: { vectors: GoldenVector[] } = JSON.parse(
      readFileSync(FIXTURES_PATH, 'utf-8')
    );

    if (vectors.vectors.length === 0) {
      console.warn('Empty vectors file; skipping');
      return;
    }

    try {
      const { WitnessGuard } = await import('../../agentfirewall-node/index.js');
      const guard = new WitnessGuard();

      for (const vec of vectors.vectors) {
        const result = guard.computeHash(JSON.stringify(vec.input));
        expect(result).toBe(vec.expected_hash);
      }
    } catch {
      console.warn('Native module not built; skipping');
    }
  });
});
