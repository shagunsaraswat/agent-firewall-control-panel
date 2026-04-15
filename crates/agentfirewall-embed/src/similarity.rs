//! Cosine similarity and vector helpers for embedding-based scoring.

/// Cosine similarity of two vectors: `dot(a, b) / (||a|| * ||b||)`.
///
/// Returns `0.0` when vectors differ in length, are empty, either has zero norm,
/// or any element is non-finite (NaN/±Inf). Non-finite results are clamped to `0.0`.
pub fn cosine_similarity(a: &[f32], b: &[f32]) -> f32 {
    if a.len() != b.len() || a.is_empty() {
        return 0.0;
    }
    let mut dot = 0f64;
    let mut na = 0f64;
    let mut nb = 0f64;
    for (&x, &y) in a.iter().zip(b.iter()) {
        let xf = x as f64;
        let yf = y as f64;
        if !xf.is_finite() || !yf.is_finite() {
            return 0.0;
        }
        dot += xf * yf;
        na += xf * xf;
        nb += yf * yf;
    }
    if na == 0.0 || nb == 0.0 {
        return 0.0;
    }
    let denom = na.sqrt() * nb.sqrt();
    if denom == 0.0 {
        return 0.0;
    }
    let sim = dot / denom;
    if sim.is_finite() {
        sim as f32
    } else {
        0.0
    }
}

/// Euclidean (L2) distance between `a` and `b`.
///
/// Returns `f32::NAN` if lengths differ. Returns `0.0` for two empty slices.
/// Non-finite components yield `f32::NAN`.
pub fn euclidean_distance(a: &[f32], b: &[f32]) -> f32 {
    if a.len() != b.len() {
        return f32::NAN;
    }
    if a.is_empty() {
        return 0.0;
    }
    let mut acc = 0f64;
    for (&x, &y) in a.iter().zip(b.iter()) {
        let xf = x as f64;
        let yf = y as f64;
        if !xf.is_finite() || !yf.is_finite() {
            return f32::NAN;
        }
        let d = xf - yf;
        acc += d * d;
    }
    let out = acc.sqrt();
    if out.is_finite() {
        out as f32
    } else {
        f32::NAN
    }
}

/// Dot product of `a` and `b`.
///
/// Returns `0.0` on length mismatch or empty vectors. Non-finite values yield `0.0`.
pub fn dot_product(a: &[f32], b: &[f32]) -> f32 {
    if a.len() != b.len() || a.is_empty() {
        return 0.0;
    }
    let mut acc = 0f64;
    for (&x, &y) in a.iter().zip(b.iter()) {
        let xf = x as f64;
        let yf = y as f64;
        if !xf.is_finite() || !yf.is_finite() {
            return 0.0;
        }
        acc += xf * yf;
    }
    if acc.is_finite() {
        acc as f32
    } else {
        0.0
    }
}

/// L2 norm `sqrt(sum_i x_i^2)`.
///
/// Returns `0.0` for an empty vector. Returns `f32::NAN` if any element is non-finite
/// or the accumulated norm is non-finite.
pub fn l2_norm(v: &[f32]) -> f32 {
    if v.is_empty() {
        return 0.0;
    }
    let mut acc = 0f64;
    for &x in v {
        let xf = x as f64;
        if !xf.is_finite() {
            return f32::NAN;
        }
        acc += xf * xf;
    }
    let out = acc.sqrt();
    if out.is_finite() {
        out as f32
    } else {
        f32::NAN
    }
}

/// Unit vector in the direction of `v`, or a zero vector of the same length if `v` is zero
/// or non-finite.
pub fn normalize(v: &[f32]) -> Vec<f32> {
    if v.is_empty() {
        return Vec::new();
    }
    let n = l2_norm(v);
    if !n.is_finite() || n == 0.0 {
        return vec![0.0; v.len()];
    }
    let inv = 1.0 / n as f64;
    v.iter().map(|&x| (x as f64 * inv) as f32).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const EPS: f32 = 1e-5;

    #[test]
    fn cosine_identical_is_one() {
        let a = [1.0_f32, 2.0, 3.0];
        let s = cosine_similarity(&a, &a);
        assert!((s - 1.0).abs() < EPS);
    }

    #[test]
    fn cosine_orthogonal_is_zero() {
        let a = [1.0_f32, 0.0];
        let b = [0.0_f32, 1.0];
        let s = cosine_similarity(&a, &b);
        assert!(s.abs() < EPS);
    }

    #[test]
    fn cosine_opposite_is_negative_one() {
        let a = [1.0_f32, 0.0, 0.0];
        let b = [-3.0_f32, 0.0, 0.0];
        let s = cosine_similarity(&a, &b);
        assert!((s + 1.0).abs() < EPS);
    }

    #[test]
    fn cosine_scaled_direction_unchanged() {
        let a = [1.0_f32, 2.0, 3.0];
        let b = [2.0_f32, 4.0, 6.0];
        let s = cosine_similarity(&a, &b);
        assert!((s - 1.0).abs() < EPS);
    }

    #[test]
    fn cosine_zero_vector() {
        let a = [0.0_f32; 4];
        let b = [1.0_f32, 0.0, 0.0, 0.0];
        assert_eq!(cosine_similarity(&a, &b), 0.0);
        assert_eq!(cosine_similarity(&a, &a), 0.0);
    }

    #[test]
    fn cosine_single_element() {
        assert_eq!(cosine_similarity(&[5.0], &[5.0]), 1.0);
        assert_eq!(cosine_similarity(&[5.0], &[-5.0]), -1.0);
        assert_eq!(cosine_similarity(&[3.0], &[4.0]), 1.0);
    }

    #[test]
    fn cosine_length_mismatch() {
        assert_eq!(cosine_similarity(&[1.0, 2.0], &[1.0]), 0.0);
    }

    #[test]
    fn cosine_nan_inputs() {
        let a = [1.0_f32, f32::NAN];
        let b = [1.0_f32, 0.0];
        assert_eq!(cosine_similarity(&a, &b), 0.0);
    }

    #[test]
    fn cosine_inf_inputs() {
        let a = [1.0_f32, f32::INFINITY];
        let b = [1.0_f32, 0.0];
        assert_eq!(cosine_similarity(&a, &b), 0.0);
    }

    #[test]
    fn dot_product_basic() {
        let a = [1.0_f32, 2.0, 3.0];
        let b = [4.0_f32, 5.0, 6.0];
        assert!((dot_product(&a, &b) - 32.0).abs() < EPS);
    }

    #[test]
    fn euclidean_known() {
        let a = [0.0_f32, 0.0];
        let b = [3.0_f32, 4.0];
        assert!((euclidean_distance(&a, &b) - 5.0).abs() < EPS);
    }

    #[test]
    fn euclidean_mismatch_nan() {
        assert!(euclidean_distance(&[1.0], &[1.0, 2.0]).is_nan());
    }

    #[test]
    fn l2_norm_unit() {
        assert!((l2_norm(&[1.0_f32, 0.0, 0.0]) - 1.0).abs() < EPS);
        let v = [3.0_f32, 4.0];
        assert!((l2_norm(&v) - 5.0).abs() < EPS);
    }

    #[test]
    fn normalize_unit_and_zero() {
        let v = [3.0_f32, 0.0, 4.0];
        let u = normalize(&v);
        assert!((l2_norm(&u) - 1.0).abs() < EPS);
        assert!((u[0] - 0.6).abs() < 1e-4);
        assert!((u[2] - 0.8).abs() < 1e-4);
        let z = normalize(&[0.0_f32; 3]);
        assert_eq!(z, vec![0.0_f32; 3]);
    }

    #[test]
    fn very_large_vector_cosine_self_one() {
        let n = 10_000usize;
        let v: Vec<f32> = (0..n).map(|i| (i as f32) * 0.001).collect();
        let s = cosine_similarity(&v, &v);
        assert!((s - 1.0).abs() < 1e-4);
    }

    #[test]
    fn numerical_stability_tiny_values() {
        let a = [1e-30_f32, 0.0];
        let b = [1e-30_f32, 0.0];
        let s = cosine_similarity(&a, &b);
        assert!((s - 1.0).abs() < 1e-4);
    }

    #[test]
    fn numerical_stability_large_values() {
        let a = [1e20_f32, 0.0];
        let b = [1e20_f32, 0.0];
        let s = cosine_similarity(&a, &b);
        assert!((s - 1.0).abs() < 1e-4);
    }

    #[test]
    fn property_self_similarity_high_dimensional() {
        for dim in [2usize, 16, 127, 384] {
            let v: Vec<f32> = (0..dim)
                .map(|i| ((i * 17 + 3) % 100) as f32 * 0.1 - 0.5)
                .collect();
            let s = cosine_similarity(&v, &v);
            assert!((s - 1.0).abs() < 1e-3, "dim {dim}: expected ~1, got {s}");
        }
    }

    #[test]
    fn normalize_preserves_direction_property() {
        let v = [0.1_f32, -0.3, 0.7];
        let u = normalize(&v);
        if l2_norm(&v) > 0.0 {
            let s = cosine_similarity(&v, &u);
            assert!((s - 1.0).abs() < 1e-4);
        }
    }
}
