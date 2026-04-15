use serde_json::Value;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CanonicalError {
    #[error("serialization failed: {0}")]
    Serialization(String),
    #[error("input contains non-finite float: {0}")]
    NonFiniteFloat(f64),
    #[error("input exceeds maximum size: {size} > {max}")]
    InputTooLarge { size: usize, max: usize },
}

const MAX_CANONICAL_SIZE: usize = 10 * 1024 * 1024; // 10 MiB

pub fn canonicalize(value: &Value) -> Result<Vec<u8>, CanonicalError> {
    validate_value(value)?;
    let sorted = sort_keys(value);
    let bytes =
        serde_json::to_vec(&sorted).map_err(|e| CanonicalError::Serialization(e.to_string()))?;
    if bytes.len() > MAX_CANONICAL_SIZE {
        return Err(CanonicalError::InputTooLarge {
            size: bytes.len(),
            max: MAX_CANONICAL_SIZE,
        });
    }
    Ok(bytes)
}

fn validate_value(value: &Value) -> Result<(), CanonicalError> {
    match value {
        Value::Number(n) => {
            if let Some(f) = n.as_f64() {
                if f.is_nan() || f.is_infinite() {
                    return Err(CanonicalError::NonFiniteFloat(f));
                }
            }
            Ok(())
        }
        Value::Array(arr) => {
            for item in arr {
                validate_value(item)?;
            }
            Ok(())
        }
        Value::Object(map) => {
            for v in map.values() {
                validate_value(v)?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

fn sort_keys(value: &Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut sorted: Vec<_> = map.iter().collect();
            sorted.sort_by(|(a, _), (b, _)| a.cmp(b));
            let sorted_map: serde_json::Map<String, Value> = sorted
                .into_iter()
                .map(|(k, v)| (k.clone(), sort_keys(v)))
                .collect();
            Value::Object(sorted_map)
        }
        Value::Array(arr) => Value::Array(arr.iter().map(sort_keys).collect()),
        other => other.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn sorted_keys() {
        let input = json!({"z": 1, "a": 2, "m": 3});
        let bytes = canonicalize(&input).unwrap();
        let s = String::from_utf8(bytes).unwrap();
        assert_eq!(s, r#"{"a":2,"m":3,"z":1}"#);
    }

    #[test]
    fn nested_sorting() {
        let input = json!({"b": {"z": 1, "a": 2}, "a": 3});
        let bytes = canonicalize(&input).unwrap();
        let s = String::from_utf8(bytes).unwrap();
        assert_eq!(s, r#"{"a":3,"b":{"a":2,"z":1}}"#);
    }

    #[test]
    fn deterministic() {
        let input = json!({"foo": "bar", "baz": [1, 2, 3]});
        let b1 = canonicalize(&input).unwrap();
        let b2 = canonicalize(&input).unwrap();
        assert_eq!(b1, b2);
    }
}
