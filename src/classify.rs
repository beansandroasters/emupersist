//! リクエストが状態を変えるかどうかを、エミュレータの中を見ずに判定する。
//!
//! RPC 系(awsJson / awsQuery / Smithy RPCv2)は操作名の接頭辞で、REST 系は HTTP メソッドで判断する。
//! 迷ったら「書き込み」に倒す。読み取りを記録してもリプレイが少し遅くなるだけだが、
//! 書き込みを落とすと状態が欠ける。

use std::collections::HashSet;

use crate::http::{header, Headers};

/// 状態を変えない操作の接頭辞。次のものは、名前に反して状態を変えるので入れていない。
/// Verify*(SES の VerifyEmailIdentity は ID を作る)、Detect*(DetectStackDrift は結果を残す)、
/// Export*(DynamoDB のエクスポートはリソースになる)、Check*(CheckoutLicense)、Sign*(SignUp)。
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

/// 接頭辞にすると書き込み操作まで巻き込むので、完全一致で読み取りとみなす操作。
/// `Sign` を接頭辞にすると Cognito の `SignUp` が、`Check` を接頭辞にすると License Manager の
/// `CheckoutLicense` が記録されなくなる(ユーザー登録が再起動で消える)。
const READ_EXACT: &[&str] =
    &["Sign", "Encrypt", "VerifyMac", "CheckDomainAvailability", "CheckIfPhoneNumberIsOptedOut"];

/// 接頭辞は読み取り系に見えるが、資格情報や ID を発行する操作。
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

/// RPC 系なら操作名を返す。REST 系(操作名がない)なら None。
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
