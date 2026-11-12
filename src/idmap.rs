//! リプレイで変わってしまう ID を、クライアントから見て変わらないように見せる。
//!
//! 記録には応答も残しておき、リプレイで得た応答と構造を揃えて比べる。同じ位置にあって値だけが違う文字列を
//! 「記録時の ID → 今の ID」の対応として覚える。以後は、エミュレータへ送る要求を今の ID に書き換え、
//! 応答を記録時の ID に書き戻す。ジャーナルにはクライアント側の ID で書くので、再起動を何回またいでも
//! クライアントにとっての ID は最初に見たものから変わらない。
//!
//! 書き換えるのは、パス・ヘッダ・テキスト系の本文(JSON / XML / フォーム)だけ。S3 のオブジェクト本文には、
//! content-type が JSON でも触らない(利用者のデータであり、チェックサムで守られているため)。
//! 本文を書き換えたときは、本文に結びついた整合性ヘッダ(x-amz-crc32、Content-MD5、x-amz-checksum-*、
//! x-amz-content-sha256)を計算し直す。
//!
//! 何を ID とみなすかは推測で、外れるのは避けられない。状態値(`PENDING` → `RUNNING`)のように毎回
//! 変わるのが正しい値を覚えると、無関係な要求まで書き換えてしまう。そこで次のものは覚えない。
//! - 時刻・数値・真偽値・HTTP 日付・6文字未満の値
//! - 数字も `:` `/` も含まず、大文字と小文字が語の途中で混ざってもいない値(英単語や列挙値)
//! - 名前が RequestId・Token・Status・State・Message などで終わる項目

use std::collections::{BTreeMap, HashMap};
use std::sync::RwLock;

use serde_json::Value;

use ring::digest;

use crate::http::{header, Headers};
use crate::util::{b64encode, crc32, crc32c, crc64nvme, hex, md5, quote};

const TEXT_TYPES: &[&str] = &["json", "xml", "x-www-form-urlencoded", "text/plain"];
const SKIP_HEADERS: &[&str] = &[
    "date",
    "content-length",
    "x-amzn-requestid",
    "x-amz-request-id",
    "x-amz-id-2",
    "x-amz-crc32",
    "x-amz-cf-id",
    "connection",
    "keep-alive",
    "transfer-encoding",
    "last-modified",
    "expires",
];
const MIN_LEN: usize = 6;
/// 項目名がこれで終わるものは、値が変わっても ID ではない(大文字小文字は区別しない)
const NOT_ID_KEYS: &[&str] = &[
    "requestid",
    "token",
    "status",
    "state",
    "message",
    "reason",
    "date",
    "time",
    "timestamp",
    "etag",
    "checksum",
    "md5",
    "marker",
    "signature",
];
/// S3 の設定系サブリソース。この付いた要求・応答の本文はバケットの設定(XML / JSON)で、ID が載りうる。
/// これが付かない S3 の要求・応答の本文はオブジェクトのデータなので、書き換えない
const S3_CONFIG_SUBRESOURCES: &[&str] = &[
    "accelerate",
    "acl",
    "analytics",
    "cors",
    "encryption",
    "intelligent-tiering",
    "inventory",
    "lifecycle",
    "logging",
    "metrics",
    "notification",
    "object-lock",
    "ownershipControls",
    "policy",
    "publicAccessBlock",
    "replication",
    "requestPayment",
    "tagging",
    "versioning",
    "website",
];

pub fn is_text(content_type: Option<&str>) -> bool {
    content_type.is_some_and(|c| {
        let c = c.to_ascii_lowercase();
        TEXT_TYPES.iter().any(|t| c.contains(t))
    })
}

/// 署名の資格情報スコープ(`<akid>/<日付>/<リージョン>/<サービス>/aws4_request`)からサービス名を取る。
fn signing_service(target: &str, headers: &Headers) -> Option<String> {
    let scope = header(headers, "authorization")
        .and_then(|a| a.split("Credential=").nth(1))
        .map(|c| c.split([',', ' ']).next().unwrap_or("").to_string())
        .or_else(|| {
            let q = target.split_once('?')?.1;
            let v = q.split('&').find_map(|kv| kv.strip_prefix("X-Amz-Credential="))?;
            Some(crate::stores::percent_decode(v))
        })?;
    scope.split('/').nth(3).map(str::to_string)
}

/// この要求(とその応答)の本文が、S3 のオブジェクトのデータか。
fn is_s3_object_body(target: &str, headers: &Headers) -> bool {
    let s3 = signing_service(target, headers).is_some_and(|s| s.starts_with("s3"));
    if !s3 {
        return false;
    }
    let query = target.split_once('?').map_or("", |(_, q)| q);
    !query.split('&').any(|kv| S3_CONFIG_SUBRESOURCES.contains(&kv.split('=').next().unwrap_or("")))
}

fn has_mid_word_case_mix(s: &str) -> bool {
    let mut chars = s.chars();
    chars.next();
    chars.any(|c| c.is_ascii_uppercase()) && s.chars().any(|c| c.is_ascii_lowercase())
}

/// ID らしい値か。次のどれかに当たるものを ID とみなす。
/// - 数字・`:`・`/` のどれかを含む
/// - 大文字と小文字が語の途中で混ざっている(`gZHOzH`)
/// - 16 文字以上の英数字だけでできている(IAM のアクセスキー。乱数次第で数字を含まないことがある)
///
/// `PENDING`・`available`・`Running`・`CREATE_IN_PROGRESS` のような英単語や列挙値は外れる。
fn looks_like_id(s: &str) -> bool {
    s.chars().any(|c| c.is_ascii_digit() || c == ':' || c == '/')
        || has_mid_word_case_mix(s)
        || (s.len() >= 16 && s.chars().all(|c| c.is_ascii_alphanumeric()))
}

fn key_is_not_id(path: &str) -> bool {
    // パスの最後の要素(`/A/B[0]` の `B`、XML の名前空間接頭辞は外す)
    let last = path.rsplit('/').next().unwrap_or("");
    let name = last.split('[').next().unwrap_or("").rsplit(':').next().unwrap_or("").to_ascii_lowercase();
    NOT_ID_KEYS.iter().any(|k| name.ends_with(k))
}

/// 値が違っても ID ではないもの(時刻・数値・真偽値・HTTP 日付)。毎回変わるのが正しい。
fn not_id(s: &str) -> bool {
    let b = s.as_bytes();
    let d = |i: usize| b.get(i).is_some_and(u8::is_ascii_digit);
    if b.len() >= 11
        && (0..4).all(d)
        && b[4] == b'-'
        && d(5)
        && d(6)
        && b[7] == b'-'
        && d(8)
        && d(9)
        && (b[10] == b'T' || b[10] == b' ')
    {
        return true;
    }
    if s.eq_ignore_ascii_case("true") || s.eq_ignore_ascii_case("false") {
        return true;
    }
    // \d+(\.\d+)?([eE][+-]?\d+)?
    let mut i = 0;
    while d(i) {
        i += 1;
    }
    if i > 0 {
        if b.get(i) == Some(&b'.') && d(i + 1) {
            i += 1;
            while d(i) {
                i += 1;
            }
        }
        if matches!(b.get(i), Some(b'e' | b'E')) {
            let mut j = i + 1;
            if matches!(b.get(j), Some(b'+' | b'-')) {
                j += 1;
            }
            if d(j) {
                i = j;
                while d(i) {
                    i += 1;
                }
            }
        }
        if i == b.len() {
            return true;
        }
    }
    ["Mon, ", "Tue, ", "Wed, ", "Thu, ", "Fri, ", "Sat, ", "Sun, "]
        .iter()
        .any(|w| s.len() > 5 && s[..5].eq_ignore_ascii_case(w))
        && s.to_ascii_uppercase().ends_with("GMT")
}

fn json_leaves(v: &Value, path: String, out: &mut BTreeMap<String, String>) {
    match v {
        Value::Object(m) => m.iter().for_each(|(k, x)| json_leaves(x, format!("{path}/{k}"), out)),
        Value::Array(a) => a.iter().enumerate().for_each(|(i, x)| json_leaves(x, format!("{path}[{i}]"), out)),
        Value::String(s) => {
            out.insert(path, s.clone());
        }
        _ => {}
    }
}

/// XML を「要素の位置 → 葉要素の文字列」に平らにする。宣言・コメントは飛ばし、CDATA は文字列として読む。
fn xml_leaves(text: &str) -> Option<BTreeMap<String, String>> {
    struct Frame {
        path: String,
        seen: HashMap<String, usize>,
        text: String,
        children: usize,
    }
    let mut out = BTreeMap::new();
    let mut stack = vec![Frame { path: String::new(), seen: HashMap::new(), text: String::new(), children: 0 }];
    let mut rest = text;
    while !rest.is_empty() {
        let Some(lt) = rest.find('<') else {
            stack.last_mut()?.text.push_str(&crate::aws::xml_unescape(rest));
            break;
        };
        stack.last_mut()?.text.push_str(&crate::aws::xml_unescape(&rest[..lt]));
        rest = &rest[lt..];
        if let Some(r) = rest.strip_prefix("<![CDATA[") {
            let end = r.find("]]>")?;
            stack.last_mut()?.text.push_str(&r[..end]);
            rest = &r[end + 3..];
            continue;
        }
        if rest.starts_with("<?") || rest.starts_with("<!--") || rest.starts_with("<!") {
            let close = if rest.starts_with("<!--") { "-->" } else { ">" };
            rest = &rest[rest.find(close)? + close.len()..];
            continue;
        }
        let gt = rest.find('>')?;
        let tag = &rest[1..gt];
        rest = &rest[gt + 1..];
        if let Some(name) = tag.strip_prefix('/') {
            let f = stack.pop()?;
            let _ = name;
            let t = f.text.trim();
            if f.children == 0 && !t.is_empty() {
                out.insert(f.path, t.to_string());
            }
            if stack.is_empty() {
                return None;
            }
            continue;
        }
        let self_close = tag.ends_with('/');
        let name = tag.trim_end_matches('/').split_whitespace().next()?.to_string();
        let parent = stack.last_mut()?;
        parent.children += 1;
        let n = parent.seen.entry(name.clone()).and_modify(|n| *n += 1).or_insert(0);
        let path = format!("{}/{}[{}]", parent.path, name, n);
        if !self_close {
            stack.push(Frame { path, seen: HashMap::new(), text: String::new(), children: 0 });
        }
    }
    (stack.len() == 1).then_some(out)
}

fn leaves(body: &[u8], content_type: &str) -> Option<BTreeMap<String, String>> {
    let ct = content_type.to_ascii_lowercase();
    if ct.contains("json") {
        let v: Value = serde_json::from_slice(body).ok()?;
        let mut out = BTreeMap::new();
        json_leaves(&v, String::new(), &mut out);
        Some(out)
    } else if ct.contains("xml") {
        xml_leaves(std::str::from_utf8(body).ok()?)
    } else {
        None
    }
}

/// 一方向の置換表。長いキーから順に当てる(ARN の中のキー ID より ARN 全体を先に当てる)。
#[derive(Default)]
struct Table {
    map: HashMap<String, String>,
    /// 先頭バイト → (キー, 置換後) を長い順に。URL エンコードした形も入れる。足すたびに差分で更新する
    index: HashMap<u8, Vec<(String, String)>>,
}

impl Table {
    fn index_one(&mut self, k: String, v: String) {
        let Some(&first) = k.as_bytes().first() else { return };
        let bucket = self.index.entry(first).or_default();
        bucket.retain(|(x, _)| *x != k);
        let pos = bucket.partition_point(|(x, _)| x.len() > k.len() || (x.len() == k.len() && *x < k));
        bucket.insert(pos, (k, v));
    }

    fn insert(&mut self, from: String, to: String) {
        let (ek, ev) = (quote(&from, ""), quote(&to, ""));
        if ek != from {
            self.index_one(ek, ev);
        }
        self.index_one(from.clone(), to.clone());
        self.map.insert(from, to);
    }

    fn apply(&self, text: &str) -> String {
        if self.map.is_empty() {
            return text.to_string();
        }
        let b = text.as_bytes();
        let mut out = String::with_capacity(text.len());
        let (mut i, mut copied) = (0, 0);
        while i < b.len() {
            if let Some(cands) = self.index.get(&b[i]) {
                if let Some((k, v)) = cands.iter().find(|(k, _)| b[i..].starts_with(k.as_bytes())) {
                    out.push_str(&text[copied..i]);
                    out.push_str(v);
                    i += k.len();
                    copied = i;
                    continue;
                }
            }
            i += 1;
        }
        out.push_str(&text[copied..]);
        out
    }
}

/// 本文を書き換えたあと、本文に結びついた整合性ヘッダを付け直す。知らない形式のチェックサムは外す。
fn refresh_integrity(headers: &mut Headers, body: &[u8]) {
    let sha = |alg: &'static digest::Algorithm| digest::digest(alg, body).as_ref().to_vec();
    headers.retain_mut(|(k, v)| {
        let lk = k.to_ascii_lowercase();
        match lk.as_str() {
            "x-amz-crc32" => *v = crc32(body).to_string(), // DynamoDB の応答。SDK が照合する
            "content-md5" => *v = b64encode(&md5(body)),
            "x-amz-content-sha256" if v.len() == 64 => *v = hex(&sha(&digest::SHA256)),
            "x-amz-checksum-crc32" => *v = b64encode(&crc32(body).to_be_bytes()),
            "x-amz-checksum-crc32c" => *v = b64encode(&crc32c(body).to_be_bytes()),
            "x-amz-checksum-crc64nvme" => *v = b64encode(&crc64nvme(body).to_be_bytes()),
            "x-amz-checksum-sha1" => *v = b64encode(&sha(&digest::SHA1_FOR_LEGACY_USE_ONLY)),
            "x-amz-checksum-sha256" => *v = b64encode(&sha(&digest::SHA256)),
            other if other.starts_with("x-amz-checksum-") && other != "x-amz-checksum-type" => return false,
            _ => {}
        }
        true
    });
}

#[derive(Default)]
pub struct IdMap {
    inner: RwLock<(Table, Table)>, // (記録時 → 今, 今 → 記録時)
}

impl IdMap {
    pub fn len(&self) -> usize {
        self.inner.read().unwrap_or_else(|e| e.into_inner()).0.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// 記録時の応答と今の応答を比べて対応を足す。足した数を返す。
    pub fn learn(&self, old_headers: &Headers, old_body: &[u8], new_headers: &Headers, new_body: &[u8]) -> usize {
        let mut pairs: Vec<(String, String)> = Vec::new();
        for (k, v) in old_headers {
            if SKIP_HEADERS.iter().any(|s| k.eq_ignore_ascii_case(s)) || key_is_not_id(k) {
                continue;
            }
            if let Some(nv) = header(new_headers, k) {
                pairs.push((v.clone(), nv.to_string()));
            }
        }
        let ct = header(old_headers, "content-type").unwrap_or("");
        if is_text(Some(ct)) && !old_body.is_empty() && !new_body.is_empty() {
            let nct = header(new_headers, "content-type").unwrap_or(ct);
            if let (Some(a), Some(b)) = (leaves(old_body, ct), leaves(new_body, nct)) {
                pairs.extend(
                    a.into_iter().filter(|(p, _)| !key_is_not_id(p)).filter_map(|(p, v)| Some((v, b.get(&p)?.clone()))),
                );
            }
        }
        // 短い値から学ぶ。キー ID を先に覚えれば、それを含む ARN は「説明できる」ので足さずに済む。
        // 本文の並び順に頼ると、ARN が先に来たときに冗長な対応が増える
        pairs.sort_by_key(|(old, _)| old.len());
        let mut g = self.inner.write().unwrap_or_else(|e| e.into_inner());
        let mut added = 0;
        for (old, now) in pairs {
            if old == now || old.chars().count() < MIN_LEN || not_id(&old) || not_id(&now) || !looks_like_id(&old) {
                continue;
            }
            // すでに覚えている対応で説明できるなら足さない(ARN の中のキー ID など)
            if g.0.apply(&old) == now {
                continue;
            }
            g.0.insert(old.clone(), now.clone());
            g.1.insert(now, old);
            added += 1;
        }
        added
    }

    fn rewrite(table: &Table, headers: &Headers, body: &[u8], body_is_data: bool) -> (Headers, Vec<u8>) {
        if table.map.is_empty() {
            return (headers.clone(), body.to_vec());
        }
        let mut hs: Headers = headers.iter().map(|(k, v)| (k.clone(), table.apply(v))).collect();
        if !body_is_data && is_text(header(headers, "content-type")) && !body.is_empty() {
            if let Ok(text) = std::str::from_utf8(body) {
                let nb = table.apply(text).into_bytes();
                if nb != body {
                    refresh_integrity(&mut hs, &nb);
                    return (hs, nb);
                }
            }
        }
        (hs, body.to_vec())
    }

    /// クライアントの要求を、エミュレータへ送る形に書き換える(記録時の ID → 今の ID)。
    pub fn to_emulator(
        &self,
        _method: &str,
        target: &str,
        headers: &Headers,
        body: &[u8],
    ) -> (String, Headers, Vec<u8>) {
        let g = self.inner.read().unwrap_or_else(|e| e.into_inner());
        let (h, b) = Self::rewrite(&g.0, headers, body, is_s3_object_body(target, headers));
        (g.0.apply(target), h, b)
    }

    /// エミュレータの応答を、クライアントに返す形に書き戻す(今の ID → 記録時の ID)。
    /// `target` と `req_headers` は元の要求のもの(S3 のオブジェクト本文かどうかを決めるのに使う)。
    pub fn to_client(
        &self,
        _method: &str,
        target: &str,
        req_headers: &Headers,
        headers: &Headers,
        body: &[u8],
    ) -> (Headers, Vec<u8>) {
        let g = self.inner.read().unwrap_or_else(|e| e.into_inner());
        Self::rewrite(&g.1, headers, body, is_s3_object_body(target, req_headers))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(ct: &str) -> Headers {
        vec![("Content-Type".into(), ct.into())]
    }

    #[test]
    fn learns_json_and_rewrites_both_ways() {
        let m = IdMap::default();
        let j = h("application/x-amz-json-1.1");
        let old = br#"{"KeyMetadata":{"KeyId":"aaaa-1111","Arn":"arn:aws:kms:us-east-1:0:key/aaaa-1111","CreationDate":1700000000.1}}"#;
        let new = br#"{"KeyMetadata":{"KeyId":"bbbb-2222","Arn":"arn:aws:kms:us-east-1:0:key/bbbb-2222","CreationDate":1800000000.2}}"#;
        assert_eq!(m.learn(&j, old, &j, new), 1);
        let (p, _, b) = m.to_emulator("POST", "/x/aaaa-1111", &j, br#"{"KeyId":"aaaa-1111"}"#);
        assert_eq!((p.as_str(), b.as_slice()), ("/x/bbbb-2222", &br#"{"KeyId":"bbbb-2222"}"#[..]));
        let (_, b) = m.to_client("POST", "/", &j, &j, br#"{"Arn":"arn:aws:kms:us-east-1:0:key/bbbb-2222"}"#);
        assert_eq!(b, br#"{"Arn":"arn:aws:kms:us-east-1:0:key/aaaa-1111"}"#);
    }

    #[test]
    fn learning_does_not_depend_on_field_order() {
        let m = IdMap::default();
        let j = h("application/json");
        assert_eq!(
            m.learn(
                &j,
                br#"{"Arn":"arn:aws:kms:us-east-1:0:key/aaaa-1111","KeyId":"aaaa-1111"}"#,
                &j,
                br#"{"Arn":"arn:aws:kms:us-east-1:0:key/bbbb-2222","KeyId":"bbbb-2222"}"#
            ),
            1
        );
    }

    #[test]
    fn ignores_non_ids() {
        let m = IdMap::default();
        let j = h("application/json");
        assert_eq!(
            m.learn(
                &j,
                br#"{"a":"2026-01-01T00:00:00Z","b":"12345678","c":"abc","d":"1.5E+3"}"#,
                &j,
                br#"{"a":"2026-02-02T00:00:00Z","b":"87654321","c":"xyz","d":"2.5E+3"}"#
            ),
            0
        );
    }

    #[test]
    fn xml_and_form() {
        let m = IdMap::default();
        let x = h("text/xml");
        m.learn(
            &x,
            b"<?xml version=\"1.0\"?><R xmlns=\"n\"><Arn>arn:aws:secretsmanager:r:0:secret:s-AAAAAA</Arn><Empty/></R>",
            &x,
            b"<?xml version=\"1.0\"?><R xmlns=\"n\"><Arn>arn:aws:secretsmanager:r:0:secret:s-BBBBBB</Arn><Empty/></R>",
        );
        let f = h("application/x-www-form-urlencoded");
        let (_, _, b) =
            m.to_emulator("POST", "/", &f, b"SecretId=arn%3Aaws%3Asecretsmanager%3Ar%3A0%3Asecret%3As-AAAAAA");
        assert_eq!(b, b"SecretId=arn%3Aaws%3Asecretsmanager%3Ar%3A0%3Asecret%3As-BBBBBB");
    }

    #[test]
    fn binary_untouched_and_crc_refreshed() {
        let m = IdMap::default();
        let j = h("application/x-amz-json-1.0");
        m.learn(&j, br#"{"Id":"old-id-123"}"#, &j, br#"{"Id":"new-id-456"}"#);
        assert_eq!(m.to_emulator("PUT", "/", &h("application/octet-stream"), b"old-id-123").2, b"old-id-123");
        let mut hs = j.clone();
        hs.push(("x-amz-crc32".into(), "0".into()));
        let (hs, b) = m.to_client("POST", "/", &j, &hs, br#"{"Id":"new-id-456"}"#);
        assert_eq!(b, br#"{"Id":"old-id-123"}"#);
        assert_eq!(header(&hs, "x-amz-crc32"), Some(crc32(&b).to_string().as_str()));
    }

    #[test]
    fn enum_values_and_request_ids_are_not_learned() {
        let m = IdMap::default();
        let j = h("application/json");
        let x = h("text/xml");
        assert_eq!(
            m.learn(
                &j,
                br#"{"State":"PENDING","Phase":"available"}"#,
                &j,
                br#"{"State":"RUNNING","Phase":"deleting"}"#
            ),
            0
        );
        assert_eq!(
            m.learn(&j, br#"{"Code":"PENDING"}"#, &j, br#"{"Code":"RUNNING"}"#),
            0,
            "列挙値は項目名に関係なく外す"
        );
        assert_eq!(
            m.learn(
                &x,
                b"<R><ResponseMetadata><RequestId>aaaa-1111-2222</RequestId></ResponseMetadata></R>",
                &x,
                b"<R><ResponseMetadata><RequestId>bbbb-3333-4444</RequestId></ResponseMetadata></R>"
            ),
            0
        );
        assert_eq!(m.learn(&j, br#"{"Suffix":"gZHOzH"}"#, &j, br#"{"Suffix":"PzyfKV"}"#), 1, "大小が混ざった乱数は ID");
        assert_eq!(
            m.learn(&j, br#"{"AccessKeyId":"EMULATORAKABCDEFGHIJ"}"#, &j, br#"{"AccessKeyId":"EMULATORAKZYXWVUTSRQ"}"#),
            1
        );
        assert_eq!(m.learn(&j, br#"{"Phase":"CREATE_IN_PROGRESS"}"#, &j, br#"{"Phase":"CREATE_COMPLETE_NOW"}"#), 0);
    }

    #[test]
    fn s3_object_bodies_are_data_but_bucket_config_is_rewritten() {
        let m = IdMap::default();
        let j = h("application/json");
        m.learn(&j, br#"{"KeyId":"key-1111"}"#, &j, br#"{"KeyId":"key-2222"}"#);
        let s3 = |ct: &str| {
            vec![
                ("Content-Type".to_string(), ct.to_string()),
                ("Authorization".into(), "AWS4-HMAC-SHA256 Credential=AKIA/20261112/us-east-1/s3/aws4_request, SignedHeaders=host, Signature=0".into()),
                ("Content-MD5".into(), "x".into()),
            ]
        };
        let (_, hs, b) = m.to_emulator("PUT", "/bkt/user.json", &s3("application/json"), br#"{"k":"key-1111"}"#);
        assert_eq!(b, br#"{"k":"key-1111"}"#, "オブジェクトのデータには触らない");
        assert_eq!(header(&hs, "content-md5"), Some("x"));
        let body = b"<ServerSideEncryptionConfiguration><KMSMasterKeyID>key-1111</KMSMasterKeyID></ServerSideEncryptionConfiguration>";
        let (_, hs, b) = m.to_emulator("PUT", "/bkt?encryption", &s3("application/xml"), body);
        assert!(String::from_utf8(b.clone()).unwrap().contains("key-2222"), "設定の本文は書き換える");
        assert_eq!(header(&hs, "content-md5"), Some(b64encode(&md5(&b)).as_str()), "Content-MD5 を付け直す");
        // 署名つき URL(クエリの X-Amz-Credential)でも S3 と見分ける
        let q = "/bkt/a.json?X-Amz-Credential=AKIA%2F20261112%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Signature=0";
        assert_eq!(m.to_emulator("PUT", q, &j, br#"{"k":"key-1111"}"#).2, br#"{"k":"key-1111"}"#);
    }

    #[test]
    fn index_stays_longest_first_when_built_incrementally() {
        let m = IdMap::default();
        let j = h("application/json");
        m.learn(&j, br#"{"Id":"id-0001"}"#, &j, br#"{"Id":"id-9999"}"#);
        m.learn(&j, br#"{"Id":"id-0001-long"}"#, &j, br#"{"Id":"zz-7777-long"}"#);
        assert_eq!(
            m.to_emulator("POST", "/", &j, br#"["id-0001-long","id-0001"]"#).2,
            br#"["zz-7777-long","id-9999"]"#
        );
    }
}
