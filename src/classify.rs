//! Decides whether a request changes state, without looking inside the emulator.
//!
//! RPC protocols (awsJson / awsQuery / Smithy RPCv2) are judged by the operation name prefix, REST protocols by the
//! HTTP method. When in doubt, it treats the request as a write. Recording a read only makes replay a little slower,
//! but dropping a write loses state.

use std::collections::HashSet;

use crate::http::{header, Headers};

/// Prefixes of operations that do not change state. The following are left out because, despite their names, they
/// change state: Verify* (SES VerifyEmailIdentity creates an identity), Detect* (DetectStackDrift keeps a result),
/// Export* (a DynamoDB export becomes a resource), Check* (CheckoutLicense), Sign* (SignUp).
const READ_PREFIXES: &[&str] = &[
    "Describe",
    "List",
    "Get",
    "Head",
    "BatchGet",
    "Scan",
    "Query",
    "Search",
    "Lookup",
    "Select",
    "Validate",
    "Estimate",
    "Preview",
    "Simulate",
    "Decrypt",
    "ReEncrypt",
    "GenerateDataKey",
    "GenerateRandom",
    "GenerateMac",
    "Count",
];

/// Operations treated as reads only on an exact match, because as prefixes they would also catch write operations.
/// With `Sign` as a prefix, Cognito `SignUp` would not be recorded, and with `Check` as a prefix, License Manager
/// `CheckoutLicense` would not be recorded (user sign-ups would disappear on restart).
const READ_EXACT: &[&str] =
    &["Sign", "Encrypt", "VerifyMac", "CheckDomainAvailability", "CheckIfPhoneNumberIsOptedOut"];

/// Operations whose prefix looks like a read but which issue credentials or IDs.
const WRITE_OVERRIDES: &[&str] = &[
    "GetSessionToken",
    "GetFederationToken",
    "GetId",
    "GetCredentialsForIdentity",
    "GetOpenIdToken",
    "GetOpenIdTokenForDeveloperIdentity",
];

fn query_param(query: &str, name: &str) -> Option<String> {
    query.split('&').find_map(|kv| {
        let (k, v) = kv.split_once('=')?;
        (k == name).then(|| v.replace('+', " "))
    })
}

/// Returns the operation name for RPC protocols. Returns None for REST protocols (which have no operation name).
pub fn operation_name(method: &str, target: &str, headers: &Headers, body: &[u8]) -> Option<String> {
    if let Some(t) = header(headers, "x-amz-target") {
        return Some(t.rsplit('.').next().unwrap_or(t).to_string());
    }
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    let parts: Vec<&str> = path.split('/').collect();
    if parts.len() >= 5 && parts[1] == "service" && parts[3] == "operation" {
        return Some(parts[4].to_string()); // Smithy RPCv2 CBOR
    }
    if let Some(a) = query_param(query, "Action") {
        return Some(a);
    }
    let form = header(headers, "content-type").is_some_and(|c| c.starts_with("application/x-www-form-urlencoded"));
    if method == "POST" && form {
        return query_param(&String::from_utf8_lossy(body), "Action");
    }
    None
}

pub fn is_mutating(
    method: &str,
    op: Option<&str>,
    extra_writes: &HashSet<String>,
    extra_reads: &HashSet<String>,
) -> bool {
    match op {
        Some(op) => {
            if extra_writes.contains(op) || WRITE_OVERRIDES.contains(&op) {
                return true;
            }
            if extra_reads.contains(op) {
                return false;
            }
            !(READ_EXACT.contains(&op) || READ_PREFIXES.iter().any(|p| op.starts_with(p)))
        }
        None => !matches!(method.to_ascii_uppercase().as_str(), "GET" | "HEAD" | "OPTIONS"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(pairs: &[(&str, &str)]) -> Headers {
        pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    #[test]
    fn names() {
        assert_eq!(
            operation_name("POST", "/", &h(&[("X-Amz-Target", "DynamoDB_20120810.PutItem")]), b"").as_deref(),
            Some("PutItem")
        );
        let form = h(&[("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")]);
        assert_eq!(
            operation_name("POST", "/", &form, b"Action=CreateVpc&Version=2016-11-15").as_deref(),
            Some("CreateVpc")
        );
        assert_eq!(operation_name("GET", "/?Action=DescribeVpcs", &h(&[]), b"").as_deref(), Some("DescribeVpcs"));
        assert_eq!(
            operation_name("POST", "/service/X/operation/PutMetricData", &h(&[]), b"").as_deref(),
            Some("PutMetricData")
        );
        assert_eq!(operation_name("PUT", "/bucket/key", &h(&[]), b"x"), None);
    }

    #[test]
    fn mutating() {
        let none = HashSet::new();
        for op in
            ["DescribeVpcs", "ListQueues", "GetItem", "Query", "Scan", "BatchGetItem", "Decrypt", "Sign", "Encrypt"]
        {
            assert!(!is_mutating("POST", Some(op), &none, &none), "{op}");
        }
        for op in [
            "PutItem",
            "CreateQueue",
            "ReceiveMessage",
            "VerifyEmailIdentity",
            "DetectStackDrift",
            "ExportTableToPointInTime",
            "SignUp",
            "CheckoutLicense",
            "CheckInLicense",
            "GetSessionToken",
        ] {
            assert!(is_mutating("POST", Some(op), &none, &none), "{op}");
        }
        assert!(!is_mutating("HEAD", None, &none, &none));
        assert!(is_mutating("DELETE", None, &none, &none));
        let w: HashSet<String> = ["GetThing".to_string()].into();
        assert!(is_mutating("POST", Some("GetThing"), &w, &none));
    }
}
