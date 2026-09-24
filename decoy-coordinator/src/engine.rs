// Copyright (c) 2026 msaleme. Licensed under the MIT License.
use crate::{generated::config::Config, json::NoDuplicateMembers};
use serde_json::{Map, Value};
pub const LIMIT: usize = 64 * 1024;
// Conservative configuration bounds. A bounded request body is worthless if a
// hostile or mistaken configuration can still drive unbounded per-request scan
// work, so detector count, individual detector length, breadcrumb length and the
// aggregate detector byte budget are all capped and rejected at startup (#40).
pub const MAX_DETECTORS: usize = 64;
pub const MAX_DETECTOR_LEN: usize = 256;
pub const MAX_BREADCRUMB_LEN: usize = 256;
pub const MAX_CONFIG_BYTES: usize = 8 * 1024;
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

// When `fold` is set, `needle` MUST already be ASCII-lowercased by the caller.
// Only the haystack is folded here; folding the needle once at the call site
// avoids re-lowercasing it at every visited JSON node (#40).
fn contains(value: &Value, needle: &str, fold: bool) -> bool {
    let matches = |s: &str| {
        if fold {
            s.to_ascii_lowercase().contains(needle)
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

// Neutralize a lure only in inert string VALUES. Object keys are structural
// identifiers: they are preserved byte-for-byte, and a marker embedded in a key
// fails closed (None) because deleting key bytes would rename a field and change
// message semantics rather than remove a decoy — e.g. `{"decoy_role":"admin"}`
// must never become `{"role":"admin"}` (#39).
fn rewrite(value: &Value, needles: &[String], fold: bool) -> Option<Value> {
    let hit = |s: &str| {
        needles.iter().any(|n| {
            if fold {
                s.to_ascii_lowercase().contains(&n.to_ascii_lowercase())
            } else {
                s.contains(n)
            }
        })
    };
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
                if hit(k) {
                    return None;
                }
                // Keys are preserved verbatim, so collisions are impossible; the
                // guard remains as a defensive invariant.
                if result
                    .insert(k.clone(), rewrite(v, needles, fold)?)
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
    pub fn breadcrumb_enforced(&self) -> bool {
        self.0.breadcrumb_mode == "block" && !self.0.breadcrumb.is_empty()
    }
    // Any active block mode makes the policy an enforcing filter: uninspectable
    // traffic then fails closed rather than passing through (#38).
    pub fn enforcing(&self) -> bool {
        self.response_enforced()
            || (self.0.sentinel_mode == "block" && !self.0.decoy_tools.is_empty())
            || self.breadcrumb_enforced()
    }
    // Configuration must not turn a bounded request into unbounded scan work.
    pub fn within_limits(&self) -> bool {
        let detectors_ok = |v: &[String]| {
            v.len() <= MAX_DETECTORS && v.iter().all(|s| s.len() <= MAX_DETECTOR_LEN)
        };
        let aggregate: usize = self
            .0
            .honeytokens
            .iter()
            .chain(self.0.decoy_tools.iter())
            .map(String::len)
            .sum::<usize>()
            + self.0.breadcrumb.len();
        detectors_ok(&self.0.honeytokens)
            && detectors_ok(&self.0.decoy_tools)
            && self.0.breadcrumb.len() <= MAX_BREADCRUMB_LEN
            && aggregate <= MAX_CONFIG_BYTES
    }
    // A locally-generated denial must never reflect a planted lure back to the
    // caller. Inspect the DECODED candidate so an escaped marker in a reflected
    // `id` (e.g. a newline serialized as `\n`) is still caught, and withhold if
    // the candidate cannot be parsed to prove safe reflection (#44).
    pub fn echoes_protected(&self, denial: &[u8]) -> bool {
        match parse(denial) {
            Some(value) => {
                self.honey(denial, &value)
                    || (!self.0.breadcrumb.is_empty()
                        && contains(&value, &self.0.breadcrumb, false))
            }
            None => true,
        }
    }
    // True when seeding is enabled and would attempt to plant the breadcrumb into
    // this correlated tools/list response. Used only to emit an explicit
    // skip event when the non-expanding edit cannot fit (#41).
    pub fn seed_applicable(&self, body: &[u8], id: Option<&Value>) -> bool {
        if self.0.seeding != "enabled" || self.0.breadcrumb.is_empty() {
            return false;
        }
        let Some(value) = parse(body).filter(envelope) else {
            return false;
        };
        if value.get("method").is_some()
            || value.get("error").is_some()
            || id.is_none()
            || value.get("id") != id
        {
            return false;
        }
        value
            .get("result")
            .and_then(|v| v.get("tools"))
            .and_then(Value::as_array)
            .is_some_and(|tools| {
                tools.iter().any(|t| {
                    !t.get("description")
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .contains(&self.0.breadcrumb)
                })
            })
    }
    fn honey(&self, body: &[u8], value: &Value) -> bool {
        let fold = !self.0.case_sensitive;
        let raw = String::from_utf8_lossy(body);
        let raw_folded = if fold {
            Some(raw.to_ascii_lowercase())
        } else {
            None
        };
        self.0.honeytokens.iter().any(|n| {
            // Fold each needle once per call, not at every visited JSON node.
            let folded = if fold {
                n.to_ascii_lowercase()
            } else {
                n.clone()
            };
            contains(value, &folded, fold)
                || match &raw_folded {
                    Some(r) => r.contains(&folded),
                    None => raw.contains(n),
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
            // Arguments to tools/call are semantically load-bearing: stripping a
            // marker there could synthesize or alter a privileged argument, so we
            // fail closed instead of rewriting them (#39). Sanitization is limited
            // to inert string values outside tool-call parameters.
            if final_value.get("method").and_then(Value::as_str) == Some("tools/call")
                && final_value
                    .get("params")
                    .is_some_and(|p| contains(p, &self.0.breadcrumb, false))
            {
                return Err("unsafe-sanitization-argument");
            }
            final_value = rewrite(
                &final_value,
                std::slice::from_ref(&self.0.breadcrumb),
                false,
            )
            .ok_or("unsafe-sanitization-key")?;
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
