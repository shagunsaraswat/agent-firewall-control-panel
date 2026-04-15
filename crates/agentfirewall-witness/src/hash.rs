use agentfirewall_core::types::WitnessHash;
use sha2::{Digest, Sha256};

pub fn compute_witness_hash(preimage: &[u8]) -> WitnessHash {
    let mut hasher = Sha256::new();
    hasher.update(preimage);
    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    WitnessHash(hash)
}

pub fn constant_time_compare(a: &WitnessHash, b: &WitnessHash) -> bool {
    let a_bytes = a.as_bytes();
    let b_bytes = b.as_bytes();
    let mut diff = 0u8;
    for i in 0..32 {
        diff |= a_bytes[i] ^ b_bytes[i];
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_hash() {
        let h1 = compute_witness_hash(b"hello world");
        let h2 = compute_witness_hash(b"hello world");
        assert!(constant_time_compare(&h1, &h2));
    }

    #[test]
    fn different_inputs_different_hashes() {
        let h1 = compute_witness_hash(b"hello");
        let h2 = compute_witness_hash(b"world");
        assert!(!constant_time_compare(&h1, &h2));
    }

    #[test]
    fn empty_input() {
        let h = compute_witness_hash(b"");
        assert_eq!(h.as_bytes().len(), 32);
    }
}
