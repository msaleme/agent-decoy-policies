// Copyright (c) 2026 msaleme. Licensed under the MIT License.
use crate::{generated::config::Config, json::NoDuplicateMembers};
use serde_json::{Map, Value};
pub const LIMIT: usize = 64 * 1024;
pub struct Engine(pub Config);
pub struct RequestPlan {
    pub blocked: bool,
    pub sentinel_hit: bool,
    pub honey_hit: bool,
    pub breadcrumb_hit: bool,
    pub body: Vec<u8>,
    pub list_id: Option<Value>,
}

fn parse(body: &[u8]) -> Option<Value> {
    if body.len() > LIMIT {
        return None;
    }
    serde_json::from_slice::<NoDuplicateMembers>(body).ok()?;
    serde_json::from_slice(body).ok()
}

fn envelope(value: &Value) -> bool {
    let Some(obj) = value.as_object() else {
        return false;
    };
    if obj.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
        return false;
    }
    if obj
        .get("id")
        .is_some_and(|id| !matches!(id, Value::Null | Value::String(_) | Value::Number(_)))
    {
        return false;
    }
    if let Some(method) = obj.get("method") {
        let Some(method) = method.as_str() else {
            return false;
        };
        if obj.contains_key("result")
            || obj.contains_key("error")
            || obj
                .get("params")
                .is_some_and(|v| !v.is_object() && !v.is_array())
        {
            return false;
        }
        if method == "tools/call" {
            let Some(params) = obj.get("params").and_then(Value::as_object) else {
                return false;
            };
            if params.get("name").and_then(Value::as_str).is_none()
                || params.get("arguments").is_some_and(|v| !v.is_object())
            {
                return false;
            }
        }
    } else {
        if !obj.contains_key("id")
            || obj.contains_key("params")
            || obj.contains_key("result") == obj.contains_key("error")
        {
            return false;
        }
        if let Some(error) = obj.get("error") {
            let Some(error) = error.as_object() else {
                return false;
            };
            if !error.get("code").is_some_and(|n| n.is_i64() || n.is_u64())
                || error.get("message").and_then(Value::as_str).is_none()
            {
                return false;
            }
        }
    }
    true
}

fn contains(value: &Value, needle: &str, fold: bool) -> bool {
    let matches = |s: &str| {
        if fold {
            s.to_ascii_lowercase()
                .contains(&needle.to_ascii_lowercase())
        } else {
            s.contains(needle)
        }
    };
    match value {
        Value::String(s) => matches(s),
        Value::Array(items) => items.iter().any(|v| contains(v, needle, fold)),
        Value::Object(map) => map
            .iter()
            .any(|(k, v)| matches(k) || contains(v, needle, fold)),
        _ => matches(&value.to_string()),
    }
}

fn remove(text: &str, needle: &str, fold: bool) -> String {
    if !fold {
        return text.replace(needle, "");
    }
    let lower = text.to_ascii_lowercase();
    let search = needle.to_ascii_lowercase();
    let mut out = String::new();
    let mut offset = 0;
    while let Some(found) = lower[offset..].find(&search) {
        let start = offset + found;
        out.push_str(&text[offset..start]);
        offset = start + search.len();
    }
    out.push_str(&text[offset..]);
    out
}

// Reject key collisions; never silently discard an object member while rewriting.
fn rewrite(value: &Value, needles: &[String], fold: bool) -> Option<Value> {
    let clean = |s: &str| {
        needles
            .iter()
            .fold(s.to_owned(), |s, n| remove(&s, n, fold))
    };
    Some(match value {
        Value::String(s) => Value::String(clean(s)),
        Value::Array(items) => Value::Array(
            items
                .iter()
                .map(|v| rewrite(v, needles, fold))
                .collect::<Option<_>>()?,
        ),
        Value::Object(map) => {
            let mut result = Map::new();
            for (k, v) in map {
                if result
                    .insert(clean(k), rewrite(v, needles, fold)?)
                    .is_some()
                {
                    return None;
                }
            }
            Value::Object(result)
        }
        _ => value.clone(),
    })
}

impl Engine {
    pub fn response_hit(&self, body: &[u8]) -> bool {
        if let Some(value) = parse(body) {
            return self.honey(body, &value);
        }
        let text = String::from_utf8_lossy(body);
        self.0.honeytokens.iter().any(|n| {
            if self.0.case_sensitive {
                text.contains(n)
            } else {
                text.to_ascii_lowercase().contains(&n.to_ascii_lowercase())
            }
        })
    }
    pub fn validate(&self) -> bool {
        ["monitor", "block"].contains(&self.0.honeytoken_mode.as_str())
            && ["monitor", "block"].contains(&self.0.sentinel_mode.as_str())
            && ["observe", "sanitize", "block"].contains(&self.0.breadcrumb_mode.as_str())
            && ["disabled", "enabled"].contains(&self.0.seeding.as_str())
            && self
                .0
                .honeytokens
                .iter()
                .chain(self.0.decoy_tools.iter())
                .all(|s| !s.trim().is_empty())
    }
    pub fn response_enforced(&self) -> bool {
        self.0.honeytoken_mode == "block" && !self.0.honeytokens.is_empty()
    }
    fn honey(&self, body: &[u8], value: &Value) -> bool {
        let raw = String::from_utf8_lossy(body);
        self.0.honeytokens.iter().any(|n| {
            contains(value, n, !self.0.case_sensitive)
                || if self.0.case_sensitive {
                    raw.contains(n)
                } else {
                    raw.to_ascii_lowercase().contains(&n.to_ascii_lowercase())
                }
        })
    }
    fn sentinel(&self, value: &Value) -> bool {
        value["method"] == "tools/call"
            && value["params"]["name"]
                .as_str()
                .is_some_and(|name| self.0.decoy_tools.iter().any(|n| n == name))
    }
    pub fn request(&self, body: &[u8]) -> Result<RequestPlan, &'static str> {
        let original = parse(body).filter(envelope).ok_or("unsupported-jsonrpc")?;
        // All initial decisions use the same immutable original representation.
        let honey = self.honey(body, &original);
        let mut sentinel_hit = self.sentinel(&original);
        let breadcrumb =
            !self.0.breadcrumb.is_empty() && contains(&original, &self.0.breadcrumb, false);
        let mut blocked = (honey && self.response_enforced())
            || (sentinel_hit && self.0.sentinel_mode == "block")
            || (breadcrumb && self.0.breadcrumb_mode == "block");
        let mut output = body.to_vec();
        let original_id = original.get("id").cloned();
        let original_method = original.get("method").cloned();
        let mut final_value = original;
        if !blocked && breadcrumb && self.0.breadcrumb_mode == "sanitize" {
            final_value = rewrite(
                &final_value,
                std::slice::from_ref(&self.0.breadcrumb),
                false,
            )
            .ok_or("ambiguous-sanitization")?;
            output = serde_json::to_vec(&final_value).map_err(|_| "serialization")?;
            if output.len() > body.len()
                || final_value.get("id").cloned() != original_id
                || final_value.get("method").cloned() != original_method
                || !envelope(&final_value)
                || contains(&final_value, &self.0.breadcrumb, false)
            {
                return Err("unsafe-sanitization");
            }
            // Mutation must not introduce a new terminal decision either.
            sentinel_hit |= self.sentinel(&final_value);
            blocked = (self.response_enforced() && self.honey(&output, &final_value))
                || (sentinel_hit && self.0.sentinel_mode == "block");
        }
        let list_id = if !blocked && final_value["method"] == "tools/list" {
            final_value
                .get("id")
                .filter(|id| id.is_string() || id.is_number())
                .cloned()
        } else {
            None
        };
        Ok(RequestPlan {
            blocked,
            sentinel_hit,
            honey_hit: honey,
            breadcrumb_hit: breadcrumb,
            body: output,
            list_id,
        })
    }
    pub fn response(&self, body: &[u8], id: Option<&Value>) -> Vec<u8> {
        let Some(mut value) = parse(body) else {
            return if self.response_enforced() {
                Vec::new()
            } else {
                body.to_vec()
            };
        };
        let original_id = value.get("id").cloned();
        let original_method = value.get("method").cloned();
        let originally_valid = envelope(&value);
        let mut required = body.to_vec();
        if self.response_enforced() && self.honey(body, &value) {
            let Some(clean) = rewrite(&value, &self.0.honeytokens, !self.0.case_sensitive) else {
                return Vec::new();
            };
            value = clean;
            let Ok(bytes) = serde_json::to_vec(&value) else {
                return Vec::new();
            };
            if bytes.len() > body.len() || self.honey(&bytes, &value) {
                return Vec::new();
            }
            if originally_valid
                && (!envelope(&value)
                    || value.get("id").cloned() != original_id
                    || value.get("method").cloned() != original_method)
            {
                return Vec::new();
            }
            required = bytes;
        }
        if self.0.seeding == "enabled"
            && !self.0.breadcrumb.is_empty()
            && envelope(&value)
            && value.get("method").is_none()
            && value.get("error").is_none()
            && id.is_some()
            && value.get("id") == id
        {
            if let Some(tools) = value
                .get_mut("result")
                .and_then(|v| v.get_mut("tools"))
                .and_then(Value::as_array_mut)
            {
                for tool in tools {
                    if let Some(tool) = tool.as_object_mut() {
                        let current = tool
                            .get("description")
                            .and_then(Value::as_str)
                            .unwrap_or_default();
                        if !current.contains(&self.0.breadcrumb) {
                            let text = if current.is_empty() {
                                self.0.breadcrumb.clone()
                            } else {
                                format!("{current} {}", self.0.breadcrumb)
                            };
                            tool.insert("description".into(), Value::String(text));
                        }
                    }
                }
                if let Ok(candidate) = serde_json::to_vec(&value) {
                    // Withhold rather than forward a seed-created protected value.
                    if self.response_enforced() && self.honey(&candidate, &value) {
                        return Vec::new();
                    }
                    // Optional growth is skipped; mandatory clean bytes survive.
                    if candidate.len() <= body.len() && candidate.len() <= LIMIT {
                        return candidate;
                    }
                }
            }
        }
        required
    }
}
#[cfg(test)]
#[path = "engine_tests.rs"]
mod tests;
