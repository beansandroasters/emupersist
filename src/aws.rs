//! AWS 上の保存先(DynamoDB / S3)。AWS SDK を使わず、SigV4 を自前で署名する(HMAC-SHA256 は ring)。
//!
//! aws-sdk-dynamodb と aws-sdk-s3 を入れると、tokio・hyper・aws-smithy-* で依存が百を超える。
//! このツールが AWS に投げるのは PutItem / DeleteItem / Query / BatchWriteItem / CreateTable /
//! DescribeTable と S3 の Put / Get / List / Delete だけなので、署名は自前で持つ。
//!
//! 資格情報の探し方: 環境変数 → 共有設定ファイルの静的キー → credential_process。
//! SSO や AssumeRole(role_arn)の連鎖は扱わない。

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ring::{digest, hmac};
use serde_json::{json, Value};

use crate::http::{Client, Headers};
use crate::stores::{seq_of, Store, StoreError, StoreResult};
use crate::util::{b64decode, b64encode, civil, hex, quote, zlib_compress, zlib_decompress};

/// DynamoDB の項目上限は 400KB。名前やキーの分を引いて、レコード本体はこの大きさで分割する。
const DDB_CHUNK: usize = 350_000;

// --- 資格情報 -------------------------------------------------------------

#[derive(Clone)]
pub struct Creds {
    pub akid: String,
    pub secret: String,
    pub token: Option<String>,
}

pub struct Credentials {
    profile: Option<String>,
    cached: Mutex<Option<(Creds, Option<i64>)>>,
}

fn home() -> String {
    std::env::var("HOME").unwrap_or_default()
}

fn expand(path: &str) -> String {
    path.strip_prefix("~/").map(|p| format!("{}/{p}", home())).unwrap_or_else(|| path.to_string())
}

/// 共有設定ファイルの INI。字下げされた継続行(`s3 =` の下など)は読み飛ばす。
fn read_ini(path: &str) -> HashMap<String, HashMap<String, String>> {
    let mut out: HashMap<String, HashMap<String, String>> = HashMap::new();
    let Ok(text) = std::fs::read_to_string(expand(path)) else { return out };
    let mut section = None;
    for line in text.lines() {
        if line.starts_with([' ', '\t']) {
            continue;
        }
        let t = line.trim();
        if t.is_empty() || t.starts_with(['#', ';']) {
            continue;
        }
        if let Some(name) = t.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
            section = Some(name.trim().to_string());
            out.entry(name.trim().to_string()).or_default();
        } else if let (Some(sec), Some((k, v))) = (&section, t.split_once('=')) {
            out.entry(sec.clone()).or_default().insert(k.trim().to_lowercase(), v.trim().to_string());
        }
    }
    out
}

fn config_file() -> String {
    std::env::var("AWS_CONFIG_FILE").unwrap_or_else(|_| "~/.aws/config".into())
}

fn profile_section(conf: &HashMap<String, HashMap<String, String>>, name: &str) -> Option<HashMap<String, String>> {
    conf.get(&if name == "default" { name.to_string() } else { format!("profile {name}") }).cloned()
}

pub fn default_region(profile: Option<&str>) -> Option<String> {
    for v in ["AWS_REGION", "AWS_DEFAULT_REGION"] {
        if let Ok(r) = std::env::var(v) {
            if !r.is_empty() {
                return Some(r);
            }
        }
    }
    let name = profile.map(str::to_string).or_else(|| std::env::var("AWS_PROFILE").ok()).unwrap_or("default".into());
    profile_section(&read_ini(&config_file()), &name)?.get("region").cloned()
}

impl Credentials {
    pub fn new(profile: Option<String>) -> Self {
        Credentials { profile, cached: Mutex::new(None) }
    }

    pub fn fixed(c: Creds) -> Self {
        Credentials { profile: None, cached: Mutex::new(Some((c, None))) }
    }

    pub fn get(&self) -> Result<Creds, String> {
        let mut cached = self.cached.lock().unwrap_or_else(|e| e.into_inner());
        let now = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0);
        let fresh = matches!(&*cached, Some((_, None))) || matches!(&*cached, Some((_, Some(exp))) if exp - now >= 300);
        if !fresh {
            *cached = Some(self.resolve()?);
        }
        Ok(cached.as_ref().map(|(c, _)| c.clone()).expect("直前に入れた"))
    }

    fn resolve(&self) -> Result<(Creds, Option<i64>), String> {
        if self.profile.is_none() {
            if let (Ok(akid), Ok(secret)) = (std::env::var("AWS_ACCESS_KEY_ID"), std::env::var("AWS_SECRET_ACCESS_KEY"))
            {
                return Ok((Creds { akid, secret, token: std::env::var("AWS_SESSION_TOKEN").ok() }, None));
            }
        }
        let name = self.profile.clone().or_else(|| std::env::var("AWS_PROFILE").ok()).unwrap_or("default".into());
        let static_key = |s: &HashMap<String, String>| {
            Some(Creds {
                akid: s.get("aws_access_key_id")?.clone(),
                secret: s.get("aws_secret_access_key")?.clone(),
                token: s.get("aws_session_token").cloned(),
            })
        };
        let creds = read_ini(&std::env::var("AWS_SHARED_CREDENTIALS_FILE").unwrap_or("~/.aws/credentials".into()));
        if let Some(c) = creds.get(&name).and_then(static_key) {
            return Ok((c, None));
        }
        let sec = profile_section(&read_ini(&config_file()), &name).ok_or_else(|| {
            format!("AWS プロファイル {name:?} が見つからない(AWS_PROFILE が実在しない値になっていないか確認)")
        })?;
        if let Some(c) = static_key(&sec) {
            return Ok((c, None));
        }
        if let Some(cmd) = sec.get("credential_process") {
            let out = std::process::Command::new("sh")
                .arg("-c")
                .arg(cmd)
                .output()
                .map_err(|e| format!("credential_process を起動できない: {e}"))?;
            if !out.status.success() {
                return Err(format!("credential_process が失敗した: {}", String::from_utf8_lossy(&out.stderr).trim()));
            }
            let v: Value = serde_json::from_slice(&out.stdout)
                .map_err(|e| format!("credential_process の出力が JSON でない: {e}"))?;
            let s = |k: &str| v.get(k).and_then(Value::as_str).map(str::to_string);
            let exp = s("Expiration").map(|e| {
                crate::util::parse_iso8601(&e).unwrap_or_else(|| {
                    // 読めない期限を「期限なし」として抱え続けると、切れたあとも使い続けてしまう。
                    // 15 分後に切れるものとして扱い、10 分後(期限の 5 分前)に取り直す
                    crate::log!("credential_process の Expiration {e:?} を読めない。10 分ごとに取り直す");
                    now_secs() + 900
                })
            });
            return Ok((
                Creds {
                    akid: s("AccessKeyId").ok_or("credential_process に AccessKeyId がない")?,
                    secret: s("SecretAccessKey").ok_or("credential_process に SecretAccessKey がない")?,
                    token: s("SessionToken"),
                },
                exp,
            ));
        }
        Err(format!(
            "プロファイル {name:?} の資格情報の形式に対応していない(SSO / role_arn など)。\
                     `aws configure export-credentials --profile <名前> --format env` の結果を環境変数に入れて使う"
        ))
    }
}

fn now_secs() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

// --- SigV4 ---------------------------------------------------------------

fn hmac_sha256(key: &[u8], msg: &str) -> Vec<u8> {
    hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, key), msg.as_bytes()).as_ref().to_vec()
}

/// 署名ヘッダを足したヘッダ一覧を返す。path は URI エンコード済みのものを渡す。
#[allow(clippy::too_many_arguments)]
pub fn sign(
    method: &str,
    host: &str,
    path: &str,
    query: &[(String, String)],
    headers: &[(String, String)],
    body: &[u8],
    region: &str,
    service: &str,
    creds: &Creds,
) -> Headers {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0);
    let (y, mo, d, h, mi, s) = civil(now);
    let day = format!("{y:04}{mo:02}{d:02}");
    let amz_date = format!("{day}T{h:02}{mi:02}{s:02}Z");
    let payload_hash = hex(digest::digest(&digest::SHA256, body).as_ref());
    let mut hs: Vec<(String, String)> = headers.iter().map(|(k, v)| (k.to_lowercase(), v.trim().to_string())).collect();
    hs.retain(|(k, _)| {
        !matches!(k.as_str(), "host" | "x-amz-date" | "x-amz-content-sha256" | "x-amz-security-token" | "authorization")
    });
    hs.push(("host".into(), host.into()));
    hs.push(("x-amz-date".into(), amz_date.clone()));
    hs.push(("x-amz-content-sha256".into(), payload_hash.clone()));
    if let Some(t) = &creds.token {
        hs.push(("x-amz-security-token".into(), t.clone()));
    }
    hs.sort();
    let signed: Vec<&str> = hs.iter().map(|(k, _)| k.as_str()).collect();
    let mut q: Vec<(String, String)> = query.iter().map(|(k, v)| (quote(k, "~"), quote(v, "~"))).collect();
    q.sort();
    let canonical_query = q.iter().map(|(k, v)| format!("{k}={v}")).collect::<Vec<_>>().join("&");
    let canonical_headers: String = hs.iter().map(|(k, v)| format!("{k}:{v}\n")).collect();
    let canonical = [method, path, &canonical_query, &canonical_headers, &signed.join(";"), &payload_hash].join("\n");
    let scope = format!("{day}/{region}/{service}/aws4_request");
    let to_sign = format!(
        "AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{}",
        hex(digest::digest(&digest::SHA256, canonical.as_bytes()).as_ref())
    );
    let mut key = hmac_sha256(format!("AWS4{}", creds.secret).as_bytes(), &day);
    for part in [region, service, "aws4_request"] {
        key = hmac_sha256(&key, part);
    }
    let signature = hex(&hmac_sha256(&key, &to_sign));
    hs.push((
        "authorization".into(),
        format!(
            "AWS4-HMAC-SHA256 Credential={}/{scope}, SignedHeaders={}, Signature={signature}",
            creds.akid,
            signed.join(";")
        ),
    ));
    hs
}

/// 署名つき HTTPS クライアント。
pub struct AwsHttp {
    client: Client,
    region: String,
    service: String,
    creds: Credentials,
}

impl AwsHttp {
    pub fn new(
        endpoint: &str,
        region: &str,
        service: &str,
        creds: Credentials,
        ca: Option<&str>,
    ) -> Result<Self, String> {
        Ok(AwsHttp {
            client: Client::new(endpoint, ca, false, Duration::from_secs(30))?,
            region: region.into(),
            service: service.into(),
            creds,
        })
    }

    pub fn request(
        &self,
        method: &str,
        path: &str,
        query: &[(String, String)],
        headers: &[(String, String)],
        body: &[u8],
    ) -> Result<(u16, Headers, Vec<u8>), String> {
        let full = format!("{}{}", self.client.base_path, path);
        let qs =
            query.iter().map(|(k, v)| format!("{}={}", quote(k, "~"), quote(v, "~"))).collect::<Vec<_>>().join("&");
        let target = if qs.is_empty() { path.to_string() } else { format!("{path}?{qs}") };
        // 届かなかったとき・5xx・スロットリングは、間隔を伸ばしながら最大 RETRIES 回やり直す。
        // やり直した書き込みが実は届いていた場合の扱いは、呼び出し側(条件付き書き込みの照合)が持つ
        let mut wait = Duration::from_millis(100);
        for attempt in 0..=RETRIES {
            let creds = self.creds.get()?;
            let hs =
                sign(method, &self.client.authority, &full, query, headers, body, &self.region, &self.service, &creds);
            let result = self.client.send(method, &target, &hs, body);
            let retryable = match &result {
                Err(_) => true,
                Ok(r) => r.status >= 500 || (r.status == 400 && is_throttle(&r.body)),
            };
            if !retryable || attempt == RETRIES {
                let r = result.map_err(|e| format!("{} に届かない: {e}", self.client.url))?;
                return Ok((r.status, r.headers, r.body));
            }
            std::thread::sleep(wait + jitter(wait));
            wait *= 2;
        }
        unreachable!("ループの最後の回で必ず返る")
    }
}

/// AWS へのやり直しの回数(初回を除く)。間隔は 100ms から倍々で、最後は 1.6 秒前後。
const RETRIES: u32 = 4;

fn is_throttle(body: &[u8]) -> bool {
    let text = String::from_utf8_lossy(body);
    ["ThrottlingException", "ProvisionedThroughputExceeded", "RequestLimitExceeded", "TooManyRequests", "SlowDown"]
        .iter()
        .any(|c| text.contains(c))
}

/// 0〜wait/2 のゆらぎ。複数のプロセスが同じ間隔でやり直して、また同時にぶつかるのを避ける。
fn jitter(wait: Duration) -> Duration {
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.subsec_nanos()).unwrap_or(0) as u64;
    Duration::from_nanos(nanos % (wait.as_nanos() as u64 / 2 + 1))
}

fn pack(record: &Value) -> Vec<u8> {
    zlib_compress(serde_json::to_string(record).unwrap_or_default().as_bytes())
}

fn unpack(blob: &[u8]) -> StoreResult<Value> {
    let raw = zlib_decompress(blob)?;
    Ok(serde_json::from_slice(&raw).map_err(|e| e.to_string())?)
}

fn opt<'a>(opts: &'a HashMap<String, String>, k: &str) -> Option<&'a str> {
    opts.get(k).map(String::as_str)
}

fn region_of(opts: &HashMap<String, String>, scheme: &str) -> Result<String, String> {
    opt(opts, "region")
        .map(str::to_string)
        .or_else(|| default_region(opt(opts, "profile")))
        .ok_or_else(|| format!("{scheme}:// には region が必要(?region= か AWS_REGION)"))
}

// --- DynamoDB ------------------------------------------------------------

/// パーティションキー ns(S)、ソートキー sk(S) のテーブルに、1レコードを1〜n項目で書く。
///
/// sk は "<seq 12桁>.<part 4桁>"。400KB を超えるレコードは分割する。各項目は attribute_not_exists
/// 条件つきで書くので、同じ名前空間に2つのプロキシが書き込むと、後から来た方が Conflict で止まる。
/// ただし条件に当たった項目が自分の書こうとした内容と同じなら、それは自分の前回の試み(応答だけ
/// 失われてやり直したもの)なので、成功として扱う。
pub struct DynamoDbStore {
    table: String,
    ns: String,
    http: AwsHttp,
}

impl DynamoDbStore {
    pub fn new(table: &str, ns: &str, opts: &HashMap<String, String>) -> Result<Self, String> {
        let region = region_of(opts, "dynamodb")?;
        let endpoint =
            opt(opts, "endpoint").map(str::to_string).unwrap_or(format!("https://dynamodb.{region}.amazonaws.com"));
        let creds = Credentials::new(opt(opts, "profile").map(str::to_string));
        Ok(DynamoDbStore {
            table: table.into(),
            ns: ns.into(),
            http: AwsHttp::new(&endpoint, &region, "dynamodb", creds, opt(opts, "ca"))?,
        })
    }

    fn call(&self, op: &str, payload: Value) -> StoreResult<Value> {
        let headers = vec![
            ("content-type".to_string(), "application/x-amz-json-1.0".to_string()),
            ("x-amz-target".to_string(), format!("DynamoDB_20120810.{op}")),
        ];
        let (status, _, data) = self.http.request("POST", "/", &[], &headers, payload.to_string().as_bytes())?;
        let out: Value =
            if data.is_empty() { json!({}) } else { serde_json::from_slice(&data).map_err(|e| e.to_string())? };
        if status != 200 {
            let err =
                out.get("__type").and_then(Value::as_str).unwrap_or("").rsplit('#').next().unwrap_or("").to_string();
            if err == "ConditionalCheckFailedException" {
                return Err(StoreError::Conflict(format!("{} の {} に別の書き手がいる", self.table, self.ns)));
            }
            let msg = out.get("message").or(out.get("Message")).and_then(Value::as_str).unwrap_or("");
            return Err(format!("DynamoDB {op} が失敗した: {status} {err} {msg}").into());
        }
        Ok(out)
    }

    fn items(&self, projection: Option<&str>) -> StoreResult<Vec<Value>> {
        let mut req = json!({"TableName": self.table, "ConsistentRead": true, "KeyConditionExpression": "ns = :ns",
                             "ExpressionAttributeValues": {":ns": {"S": self.ns}}});
        if let Some(p) = projection {
            req["ProjectionExpression"] = json!(p);
        }
        let mut out = Vec::new();
        loop {
            let resp = self.call("Query", req.clone())?;
            out.extend(resp["Items"].as_array().cloned().unwrap_or_default());
            match resp.get("LastEvaluatedKey") {
                Some(k) => req["ExclusiveStartKey"] = k.clone(),
                None => return Ok(out),
            }
        }
    }
}

fn s_attr<'a>(item: &'a Value, k: &str) -> &'a str {
    item[k]["S"].as_str().or(item[k]["N"].as_str()).or(item[k]["B"].as_str()).unwrap_or("")
}

impl Store for DynamoDbStore {
    fn append(&self, record: &Value) -> StoreResult<()> {
        let blob = pack(record);
        let chunks: Vec<&[u8]> = if blob.is_empty() { vec![&[][..]] } else { blob.chunks(DDB_CHUNK).collect() };
        // 後ろの断片から書き、最後に part 0 を書く。読む側は全断片が揃ったレコードだけを使う。
        for part in (0..chunks.len()).rev() {
            let sk = format!("{:012}.{:04}", seq_of(record), part);
            let rec = b64encode(chunks[part]);
            let put = self.call(
                "PutItem",
                json!({
                "TableName": self.table,
                "Item": {"ns": {"S": self.ns}, "sk": {"S": sk}, "parts": {"N": chunks.len().to_string()}, "rec": {"B": rec}},
                "ConditionExpression": "attribute_not_exists(sk)"}),
            );
            if let Err(StoreError::Conflict(msg)) = put {
                let existing = self.call(
                    "GetItem",
                    json!({"TableName": self.table, "ConsistentRead": true, "Key": {"ns": {"S": self.ns}, "sk": {"S": sk}}}),
                )?;
                if existing["Item"]["rec"]["B"].as_str() != Some(rec.as_str()) {
                    return Err(StoreError::Conflict(msg));
                }
            } else {
                put?;
            }
        }
        Ok(())
    }

    /// 全断片が揃ったレコードだけを返す。揃っていない断片は分割レコードを書いている途中で落ちた跡なので消す
    /// (残すと、次の書き込みが同じ sk にぶつかって Conflict が出続ける)。
    fn read_all(&self) -> StoreResult<Vec<Value>> {
        let mut groups: Vec<(String, Vec<Value>)> = Vec::new();
        for item in self.items(None)? {
            let seq = s_attr(&item, "sk").split('.').next().unwrap_or("").to_string();
            match groups.last_mut() {
                Some((s, v)) if *s == seq => v.push(item),
                _ => groups.push((seq, vec![item])), // Query はソートキー順に返す
            }
        }
        let mut out = Vec::new();
        for (seq, items) in groups {
            let parts: usize = s_attr(&items[0], "parts").parse().unwrap_or(0);
            if items.len() == parts {
                let mut blob = Vec::new();
                for i in &items {
                    blob.extend(b64decode(s_attr(i, "rec"))?);
                }
                out.push(unpack(&blob)?);
                continue;
            }
            crate::log!(
                "seq {} は書きかけ({}/{} 断片)なので消した",
                seq.parse::<u64>().unwrap_or(0),
                items.len(),
                parts
            );
            for i in &items {
                self.call("DeleteItem", json!({"TableName": self.table, "Key": {"ns": i["ns"], "sk": i["sk"]}}))?;
            }
        }
        Ok(out)
    }

    fn clear(&self) -> StoreResult<()> {
        let keys: Vec<Value> =
            self.items(Some("ns, sk"))?.into_iter().map(|i| json!({"ns": i["ns"], "sk": i["sk"]})).collect();
        for chunk in keys.chunks(25) {
            let reqs: Vec<Value> = chunk.iter().map(|k| json!({"DeleteRequest": {"Key": k}})).collect();
            let mut pending = json!({ self.table.clone(): reqs });
            let mut wait = Duration::from_millis(50);
            while pending.as_object().is_some_and(|o| !o.is_empty()) {
                if wait > Duration::from_millis(50) {
                    std::thread::sleep(wait); // UnprocessedItems はスロットリングで返る。間を空けて送り直す
                }
                wait = (wait * 2).min(Duration::from_secs(2));
                pending = self
                    .call("BatchWriteItem", json!({"RequestItems": pending}))?
                    .get("UnprocessedItems")
                    .cloned()
                    .unwrap_or(json!({}));
            }
        }
        Ok(())
    }

    fn describe(&self) -> String {
        format!("dynamodb://{}#{}", self.table, self.ns)
    }

    fn ensure(&self) -> StoreResult<Option<bool>> {
        match self.call("DescribeTable", json!({"TableName": self.table})) {
            Ok(_) => return Ok(Some(false)),
            Err(StoreError::Other(m)) if m.contains("ResourceNotFoundException") => {}
            Err(e) => return Err(e),
        }
        self.call("CreateTable", json!({
            "TableName": self.table, "BillingMode": "PAY_PER_REQUEST",
            "AttributeDefinitions": [{"AttributeName": "ns", "AttributeType": "S"}, {"AttributeName": "sk", "AttributeType": "S"}],
            "KeySchema": [{"AttributeName": "ns", "KeyType": "HASH"}, {"AttributeName": "sk", "KeyType": "RANGE"}]}))?;
        for _ in 0..60 {
            if self.call("DescribeTable", json!({"TableName": self.table}))?["Table"]["TableStatus"] == "ACTIVE" {
                return Ok(Some(true));
            }
            std::thread::sleep(Duration::from_secs(1));
        }
        Err(format!("テーブル {} が ACTIVE にならない", self.table).into())
    }
}

// --- S3 ------------------------------------------------------------------

/// `<prefix>/<ns>/<seq 12桁>.json.z` に、1レコードを1オブジェクトで書く。
///
/// PutObject に If-None-Match: * を付ける。同じ連番に2つ目の書き手が来ると 412 になり Conflict で止まる
/// (既にあるオブジェクトが自分の書こうとした内容と同じなら、自分の前回の試みなので成功として扱う)。
/// 接頭辞の下にあるジャーナル以外のオブジェクト(名前が `<12桁>.json.z` でないもの)は読み飛ばす。
/// 起動時の読み込みはレコード数ぶん GET を投げるので、レコードが数千を超えると起動が遅くなる。
pub struct S3Store {
    bucket: String,
    prefix: String,
    http: AwsHttp,
}

/// `<tag>...</tag>` の中身を順に取り出す。ListObjectsV2 の応答を読むのに足りる分だけの XML 読み。
pub fn xml_texts(body: &str, tag: &str) -> Vec<String> {
    let (open, close) = (format!("<{tag}>"), format!("</{tag}>"));
    let mut out = Vec::new();
    let mut rest = body;
    while let Some(i) = rest.find(&open) {
        let after = &rest[i + open.len()..];
        let Some(j) = after.find(&close) else { break };
        out.push(xml_unescape(&after[..j]));
        rest = &after[j + close.len()..];
    }
    out
}

pub fn xml_unescape(s: &str) -> String {
    s.replace("&lt;", "<").replace("&gt;", ">").replace("&quot;", "\"").replace("&apos;", "'").replace("&amp;", "&")
}

impl S3Store {
    pub fn new(bucket: &str, prefix: &str, ns: &str, opts: &HashMap<String, String>) -> Result<Self, String> {
        let region = region_of(opts, "s3")?;
        let creds = Credentials::new(opt(opts, "profile").map(str::to_string));
        let endpoint = match opt(opts, "endpoint") {
            Some(e) => format!("{}/{bucket}", e.trim_end_matches('/')), // エミュレータなど: パス形式
            None => format!("https://{bucket}.s3.{region}.amazonaws.com"),
        };
        let prefix = [prefix, ns].iter().filter(|p| !p.is_empty()).cloned().collect::<Vec<_>>().join("/") + "/";
        Ok(S3Store {
            bucket: bucket.into(),
            prefix,
            http: AwsHttp::new(&endpoint, &region, "s3", creds, opt(opts, "ca"))?,
        })
    }

    fn key_path(key: &str) -> String {
        format!("/{}", quote(key, "/~"))
    }

    fn keys(&self) -> StoreResult<Vec<String>> {
        let (mut keys, mut token) = (Vec::new(), None::<String>);
        loop {
            let mut q = vec![("list-type".to_string(), "2".to_string()), ("prefix".to_string(), self.prefix.clone())];
            if let Some(t) = &token {
                q.push(("continuation-token".into(), t.clone()));
            }
            let (status, _, data) = self.http.request("GET", "/", &q, &[], b"")?;
            let text = String::from_utf8_lossy(&data);
            if status != 200 {
                return Err(format!("S3 ListObjectsV2 が失敗した: {status} {}", &text[..text.len().min(300)]).into());
            }
            for key in xml_texts(&text, "Key") {
                let name = &key[self.prefix.len().min(key.len())..];
                let is_record =
                    name.len() == 19 && name.ends_with(".json.z") && name[..12].bytes().all(|b| b.is_ascii_digit());
                if is_record {
                    keys.push(key);
                } else {
                    crate::log!("ジャーナルではないオブジェクトを読み飛ばした: s3://{}/{key}", self.bucket);
                }
            }
            token = xml_texts(&text, "NextContinuationToken").into_iter().next();
            if token.is_none() {
                keys.sort();
                return Ok(keys);
            }
        }
    }
}

impl Store for S3Store {
    fn append(&self, record: &Value) -> StoreResult<()> {
        let key = format!("{}{:012}.json.z", self.prefix, seq_of(record));
        let blob = pack(record);
        let (status, _, data) =
            self.http.request("PUT", &Self::key_path(&key), &[], &[("if-none-match".into(), "*".into())], &blob)?;
        match status {
            200 => Ok(()),
            412 => {
                let (st, _, existing) = self.http.request("GET", &Self::key_path(&key), &[], &[], b"")?;
                if st == 200 && existing == blob {
                    return Ok(()); // 応答だけ失われた自分の前回の試み
                }
                Err(StoreError::Conflict(format!("s3://{}/{key} は既にある(別の書き手がいる?)", self.bucket)))
            }
            _ => Err(format!(
                "S3 PutObject が失敗した: {status} {}",
                String::from_utf8_lossy(&data[..data.len().min(300)])
            )
            .into()),
        }
    }

    fn read_all(&self) -> StoreResult<Vec<Value>> {
        let mut out = Vec::new();
        for key in self.keys()? {
            let (status, _, data) = self.http.request("GET", &Self::key_path(&key), &[], &[], b"")?;
            if status != 200 {
                return Err(format!("S3 GetObject {key} が失敗した: {status}").into());
            }
            out.push(unpack(&data)?);
        }
        Ok(out)
    }

    fn clear(&self) -> StoreResult<()> {
        for key in self.keys()? {
            let (status, _, data) = self.http.request("DELETE", &Self::key_path(&key), &[], &[], b"")?;
            if !matches!(status, 200 | 204) {
                return Err(format!(
                    "S3 DeleteObject {key} が失敗した: {status} {}",
                    String::from_utf8_lossy(&data[..data.len().min(300)])
                )
                .into());
            }
        }
        Ok(())
    }

    fn describe(&self) -> String {
        format!("s3://{}/{}", self.bucket, self.prefix)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xml_keys() {
        let body = "<ListBucketResult xmlns=\"x\"><Contents><Key>a/1&amp;2</Key></Contents><Contents><Key>a/3</Key></Contents>\
                    <NextContinuationToken>tok</NextContinuationToken></ListBucketResult>";
        assert_eq!(xml_texts(body, "Key"), vec!["a/1&2", "a/3"]);
        assert_eq!(xml_texts(body, "NextContinuationToken"), vec!["tok"]);
    }

    /// AWS の SigV4 テストスイート(get-vanilla)と同じ鍵導出・署名になることを、既知の値で確かめる。
    #[test]
    fn signing_key_derivation() {
        let mut key = hmac_sha256(b"AWS4wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY", "20150830");
        for part in ["us-east-1", "iam", "aws4_request"] {
            key = hmac_sha256(&key, part);
        }
        // 期待値は、AWS のドキュメントが例示に使うキー(…EXAMPLEKEY)から導いた署名鍵で、どのアカウントの鍵でもない
        let expected = "c4afb1cc5771d871763a393e44b703571b55cc28424d1a5e86da6ed3c154a4b9"; // pragma: allowlist secret
        assert_eq!(hex(&key), expected);
    }
}
