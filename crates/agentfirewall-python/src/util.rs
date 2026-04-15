use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use serde_json::Value;

pub fn py_to_json_value(py: Python<'_>, obj: &Bound<'_, PyAny>) -> PyResult<Value> {
    if obj.is_none() {
        return Ok(Value::Null);
    }
    let json = py.import("json")?;
    let dumped: String = json.call_method1("dumps", (obj,))?.extract()?;
    serde_json::from_str(&dumped).map_err(|e| PyValueError::new_err(e.to_string()))
}

pub fn json_value_to_py(py: Python<'_>, v: &Value) -> PyResult<PyObject> {
    let s = serde_json::to_string(v).map_err(|e| PyValueError::new_err(e.to_string()))?;
    let json = py.import("json")?;
    let obj = json.call_method1("loads", (s.as_str(),))?;
    Ok(obj.into())
}

pub fn json_str_to_value(s: &str) -> PyResult<Value> {
    serde_json::from_str(s).map_err(|e| PyValueError::new_err(e.to_string()))
}
