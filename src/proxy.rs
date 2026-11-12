//! クライアントとエミュレータのあいだに立つ HTTP プロキシ。
//!
//! 状態を変える要求のうち 2xx で終わったものを、受け取った形のままジャーナルに追記する。
//! 起動時にジャーナルを先頭から同じ順で流し直すと、エミュレータの状態が戻る(イベントソーシング)。
//!
//! エミュレータは `-a off`(署名検証なし)で動かす前提。資格情報は起動のたびに変わるので、
//! 記録した署名は再起動後には通らない。`-a off` ならリージョンとアカウントは Authorization ヘッダの
//! 資格情報スコープから読まれ、署名そのものは見られない。だから記録には署名を伏せた Authorization を残す。

use std::collections::HashSet;
use std::io::{BufReader, BufWriter};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use serde_json::{json, Value};

use crate::classify;
use crate::http::{self, header, is_hop_by_hop, Client, Headers, ReadError, Request, Response};
use crate::idmap::{is_text, IdMap};
use crate::stores::{seq_of, Store};
use crate::util::{b64decode, b64encode, now_f64};

pub const ADMIN_PREFIX: &str = "/__persist/";
/// 応答はこの大きさまで記録する(ID の対応づけに使う)。大きい応答に ID が載ることはまずない。
const MAX_RECORDED_RESPONSE: usize = 1 << 20;

/// Authorization の `Signature=<16進>` を伏せる。
fn redact_signature(v: &str) -> String {
    match v.find("Signature=") {
        Some(i) => {
            let start = i + "Signature=".len();
            let end = v[start..].find(|c: char| !c.is_ascii_hexdigit()).map_or(v.len(), |n| start + n);
            if end == start {
                v.to_string()
            } else {
                format!("{}redacted{}", &v[..start], &v[end..])
            }
        }
        None => v.to_string(),
    }
}

/// クエリの X-Amz-Signature / X-Amz-Security-Token(署名つき URL)を伏せる。
fn redact_query(path: &str) -> String {
    let Some((p, q)) = path.split_once('?') else { return path.to_string() };
    let q: Vec<String> = q
        .split('&')
        .map(|kv| match kv.split_once('=') {
            Some((k, _))
                if k.eq_ignore_ascii_case("X-Amz-Signature") || k.eq_ignore_ascii_case("X-Amz-Security-Token") =>
            {
                format!("{k}=redacted")
            }
            _ => kv.to_string(),
        })
        .collect();
    format!("{p}?{}", q.join("&"))
}

fn headers_to_json(h: &Headers) -> Value {
    Value::Array(h.iter().map(|(k, v)| json!([k, v])).collect())
}

fn headers_from_json(v: &Value) -> Headers {
    v.as_array()
        .map(|a| {
            a.iter().filter_map(|p| Some((p.get(0)?.as_str()?.to_string(), p.get(1)?.as_str()?.to_string()))).collect()
        })
        .unwrap_or_default()
}

fn summary(rec: &Value) -> Value {
    let mut m = serde_json::Map::new();
    for k in ["seq", "ts", "op", "method", "path", "status"] {
        m.insert(k.into(), rec.get(k).cloned().unwrap_or(Value::Null));
    }
    Value::Object(m)
}

pub struct Journal {
    pub store: Box<dyn Store>,
    inner: Mutex<(u64, Vec<Value>)>, // (次の連番, 一覧表示用の要約)
    pub emulator_version: Option<String>,
}

impl Journal {
    /// 保存先を読み、本文つきの全レコード(リプレイ用)と一緒に返す。
    pub fn open(store: Box<dyn Store>) -> Result<(Self, Vec<Value>), String> {
        let loaded = store.read_all().map_err(|e| e.to_string())?;
        let next = loaded.last().map_or(1, |r| seq_of(r) + 1);
        let summaries = loaded.iter().map(summary).collect();
        Ok((Journal { store, inner: Mutex::new((next, summaries)), emulator_version: None }, loaded))
    }

    pub fn len(&self) -> usize {
        self.inner.lock().unwrap_or_else(|e| e.into_inner()).1.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn next_seq(&self) -> u64 {
        self.inner.lock().unwrap_or_else(|e| e.into_inner()).0
    }

    pub fn summaries(&self) -> Vec<Value> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner()).1.clone()
    }

    #[allow(clippy::too_many_arguments)]
    pub fn append(
        &self,
        method: &str,
        path: &str,
        headers: &Headers,
        body: &[u8],
        op: Option<&str>,
        status: u16,
        rheaders: &Headers,
        rbody: &[u8],
    ) -> Result<u64, String> {
        let kept: Headers = headers
            .iter()
            .filter(|(k, _)| !is_hop_by_hop(k) && !k.eq_ignore_ascii_case("x-amz-security-token"))
            .map(|(k, v)| {
                (k.clone(), if k.eq_ignore_ascii_case("authorization") { redact_signature(v) } else { v.clone() })
            })
            .collect();
        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let seq = g.0;
        let mut rec = json!({
            "v": 1, "seq": seq, "ts": now_f64(), "emu": self.emulator_version, "op": op, "status": status,
            "method": method, "path": redact_query(path), "headers": headers_to_json(&kept), "body": b64encode(body),
        });
        if is_text(header(rheaders, "content-type")) && rbody.len() <= MAX_RECORDED_RESPONSE {
            let rh: Headers = rheaders.iter().filter(|(k, _)| !is_hop_by_hop(k)).cloned().collect();
            rec["rheaders"] = headers_to_json(&rh);
            rec["rbody"] = json!(b64encode(rbody));
        }
        // 失敗しても連番は進める。保存先によっては、失敗に見えても一部が書けていることがある
        // (DynamoDB の分割レコードの一部、応答だけ失われた S3 の PUT)。同じ連番に書き直すと、
        // それに当たって Conflict が出続ける。飛んだ連番は読み込み時に問題にならない
        g.0 = seq + 1;
        self.store.append(&rec).map_err(|e| e.to_string())?;
        g.1.push(summary(&rec));
        Ok(seq)
    }

    pub fn clear(&self) -> Result<(), String> {
        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        self.store.clear().map_err(|e| e.to_string())?;
        *g = (1, Vec::new());
        Ok(())
    }
}

fn op_label(rec: &Value) -> String {
    match rec["op"].as_str() {
        Some(op) => op.to_string(),
        None => format!("{} {}", rec["method"].as_str().unwrap_or(""), rec["path"].as_str().unwrap_or("")),
    }
}

/// SIGTERM / SIGINT を受けたら立つ。リプレイの途中でも止まり、子のエミュレータを片付けてから終わるため。
pub static STOP: AtomicBool = AtomicBool::new(false);

/// 記録を順に流す。最後まで 2xx にならなかった件数を返す。
///
/// エミュレータは非同期の状態遷移も再現する(DynamoDB の CreateTable 直後は CREATING で、続く PutItem は
/// ResourceNotFoundException になる)。リプレイは間を詰めて流すので、同じ遷移の途中に当たる。そこで、
/// 記録時に成功していて今回失敗したものは、間隔を伸ばしながら送り直す。失敗した要求は状態を変えていない
/// ので、二重には適用されない。送り直しに使う時間は、リプレイ全体の合計で `retry_budget` まで
/// (版が変わって大量に食い違うときに、1件ごとに待って起動が何十分も止まらないため)。
/// 成功したら、記録時と今回の応答を比べて ID の対応を覚える。
pub fn replay(upstream: &Client, records: &[Value], idmap: &IdMap, retry_budget: Duration) -> Result<usize, String> {
    let (mut failed, mut retried) = (0, 0);
    let t0 = Instant::now();
    let mut spent = Duration::ZERO;
    for rec in records {
        if STOP.load(Ordering::SeqCst) {
            return Err("シグナルを受けたのでリプレイを中断した".into());
        }
        let method = rec["method"].as_str().unwrap_or("GET");
        let body = b64decode(rec["body"].as_str().unwrap_or(""))?;
        let headers = headers_from_json(&rec["headers"]);
        let mut wait = Duration::from_millis(50);
        let resp = loop {
            // 対応表は前のレコードで育つので、送るたびに書き換え直す
            let (path, h, b) = idmap.to_emulator(method, rec["path"].as_str().unwrap_or("/"), &headers, &body);
            let resp = upstream.send(method, &path, &h, &b).map_err(|e| format!("エミュレータに届かない: {e}"))?;
            if (200..300).contains(&resp.status) || spent + wait > retry_budget || STOP.load(Ordering::SeqCst) {
                break resp;
            }
            retried += 1;
            std::thread::sleep(wait);
            spent += wait;
            wait = (wait * 2).min(Duration::from_secs(2));
        };
        if (200..300).contains(&resp.status) {
            if let Some(rb) = rec["rbody"].as_str() {
                idmap.learn(&headers_from_json(&rec["rheaders"]), &b64decode(rb)?, &resp.headers, &resp.body);
            }
        } else {
            failed += 1;
            let text = String::from_utf8_lossy(&resp.body[..resp.body.len().min(200)]).into_owned();
            crate::log!(
                "リプレイで食い違い seq={} op={} 記録時={} 今回={} {text:?}",
                seq_of(rec),
                op_label(rec),
                rec["status"],
                resp.status
            );
        }
    }
    crate::log!(
        "{} 件をリプレイした({:.1} 秒、送り直し {retried} 回、食い違い {failed} 件、ID の対応 {} 件)",
        records.len(),
        t0.elapsed().as_secs_f64(),
        idmap.len()
    );
    Ok(failed)
}

pub type ResetFn = Box<dyn Fn() -> Result<Client, String> + Send + Sync>;

/// ブラウザ経由の攻撃を防ぐための規則。
///
/// 後段は署名を検証しない(`-a off`)。127.0.0.1 で待ち受けていても、利用者のブラウザが悪意あるページを
/// 開けば、そのページから http://127.0.0.1:4566 にフォームを POST できる(CSRF)。DNS を差し替えて
/// 同一オリジンに見せかけることもできる(DNS rebinding)。そこで次の2つを断る。
/// - `Origin` ヘッダつきの要求(ブラウザは別オリジンへの POST や fetch に必ず付ける)。`--allow-origin` で許す
/// - `Host` がループバック(127.0.0.1 / localhost / ::1)でも待ち受けアドレスでもない要求(DNS rebinding)。
///   0.0.0.0 などで待ち受けているときは、どの名前で届くか決められないので見ない
pub struct BrowserGuard {
    pub allow_origins: Vec<String>,
    /// None なら Host を見ない
    pub allowed_hosts: Option<Vec<String>>,
}

impl BrowserGuard {
    pub fn new(bind: &str, allow_origins: Vec<String>) -> Self {
        let unspecified = bind.parse::<std::net::IpAddr>().is_ok_and(|ip| ip.is_unspecified());
        let mut hosts = vec!["127.0.0.1".to_string(), "localhost".into(), "::1".into()];
        hosts.push(bind.trim_matches(['[', ']']).to_ascii_lowercase());
        BrowserGuard { allow_origins, allowed_hosts: (!unspecified).then_some(hosts) }
    }

    fn check(&self, headers: &Headers) -> Result<(), String> {
        if let Some(origin) = header(headers, "origin") {
            if !self.allow_origins.iter().any(|o| o == "*" || o.eq_ignore_ascii_case(origin)) {
                return Err(format!(
                    "ブラウザからの要求(Origin: {origin})は断っている。許すなら --allow-origin {origin}"
                ));
            }
        }
        if let Some(allowed) = &self.allowed_hosts {
            let host = header(headers, "host").unwrap_or("");
            let name = match host.strip_prefix('[') {
                Some(v6) => v6.split(']').next().unwrap_or(""),
                None => host.rsplit_once(':').map_or(host, |(h, _)| h),
            };
            if !allowed.iter().any(|a| a.eq_ignore_ascii_case(name)) {
                return Err(format!("Host {host:?} はこのプロキシの名前ではない(DNS rebinding を防ぐため断っている)"));
            }
        }
        Ok(())
    }
}

pub struct Proxy {
    pub journal: Journal,
    /// エミュレータと対応表は reset で丸ごと差し替える
    pub state: RwLock<(Arc<Client>, Arc<IdMap>)>,
    /// 要求の処理(エミュレータへの送信から記録まで)は read、reset は write で取る。
    /// reset の途中に古いエミュレータで成功した書き込みが、消したばかりのジャーナルに混ざらないため
    pub gate: RwLock<()>,
    /// 書き込み系のリクエストは、エミュレータへの送信から記録までをこのロックの中で1本ずつ行う。
    /// 並行に通すと、記録の順(レスポンスが返った順)がエミュレータの適用した順とずれ、同じ項目を同時に
    /// 書き換えたときに、リプレイで最後に残る値が入れ替わる(実測: 8 クライアントで 20 回中 14 回)
    pub write_lock: Mutex<()>,
    pub extra_writes: HashSet<String>,
    pub extra_reads: HashSet<String>,
    pub on_reset: Option<ResetFn>,
    pub degraded: Mutex<Option<String>>,
    pub started: Instant,
    pub guard: BrowserGuard,
    pub max_body: usize,
    pub connections: AtomicUsize,
}

/// 同時接続の上限。1接続1スレッドなので、外に開いたときにスレッドを使い切られないようにする
const MAX_CONNECTIONS: usize = 512;
/// クライアントが何も送らずに接続を保っていられる時間
const CLIENT_IDLE: Duration = Duration::from_secs(300);

fn json_response(status: u16, v: &Value) -> Response {
    Response {
        status,
        headers: vec![("Content-Type".into(), "application/json".into())],
        body: v.to_string().into_bytes(),
    }
}

impl Proxy {
    fn set_degraded(&self, msg: String) {
        *self.degraded.lock().unwrap_or_else(|e| e.into_inner()) = Some(msg);
    }

    fn reset(&self) -> Response {
        let Some(reset) = &self.on_reset else {
            return json_response(
                409,
                &json!({"error": "接続モードでは reset できない。エミュレータを自分で再起動してから、保存先を消す"}),
            );
        };
        let _g = self.gate.write().unwrap_or_else(|e| e.into_inner());
        // 先にエミュレータを作り直す。失敗したらジャーナルは消さない(次の起動で元に戻せるように)
        let client = match reset() {
            Ok(c) => c,
            Err(e) => {
                self.set_degraded(format!("reset でエミュレータを起動し直せなかった: {e}"));
                return json_response(500, &json!({"error": e}));
            }
        };
        let url = client.url.clone();
        *self.state.write().unwrap_or_else(|e| e.into_inner()) = (Arc::new(client), Arc::new(IdMap::default()));
        if let Err(e) = self.journal.clear() {
            self.set_degraded(format!("reset で記録を消せなかった(エミュレータは空になった): {e}"));
            return json_response(500, &json!({"error": e}));
        }
        *self.degraded.lock().unwrap_or_else(|e| e.into_inner()) = None;
        json_response(200, &json!({"reset": true, "upstream": url}))
    }

    fn admin(&self, req: &Request) -> Response {
        let name = &req.target[ADMIN_PREFIX.len()..];
        let (upstream, idmap) = self.state.read().unwrap_or_else(|e| e.into_inner()).clone();
        match (req.method.as_str(), name) {
            ("GET", "status") => json_response(
                200,
                &json!({
                    "store": self.journal.store.describe(), "records": self.journal.len(), "next_seq": self.journal.next_seq(),
                    "upstream": upstream.url, "degraded": *self.degraded.lock().unwrap_or_else(|e| e.into_inner()),
                    "id_mappings": idmap.len(), "uptime_seconds": self.started.elapsed().as_secs(),
                }),
            ),
            ("GET", "journal") => json_response(200, &Value::Array(self.journal.summaries())),
            ("POST", "reset") => self.reset(),
            _ => json_response(404, &json!({"error": format!("不明な管理操作: {} {}", req.method, req.target)})),
        }
    }

    pub fn handle(&self, req: &Request) -> Response {
        if let Err(e) = self.guard.check(&req.headers) {
            return json_response(403, &json!({"__type": "AccessDenied", "message": e}));
        }
        if req.target.starts_with(ADMIN_PREFIX) {
            return self.admin(req);
        }
        let _g = self.gate.read().unwrap_or_else(|e| e.into_inner());
        let op = classify::operation_name(&req.method, &req.target, &req.headers, &req.body);
        let mut mutating = classify::is_mutating(&req.method, op.as_deref(), &self.extra_writes, &self.extra_reads);
        // SQS の ReceiveMessage はロングポーリングで最大 20 秒待つので、順番待ちに入れるとほかの書き込みが
        // 止まる。受信どうし・受信と送信の順は、リプレイ後の状態への影響が小さいので外す
        let _w = (mutating && op.as_deref() != Some("ReceiveMessage"))
            .then(|| self.write_lock.lock().unwrap_or_else(|e| e.into_inner()));
        let (upstream, idmap) = self.state.read().unwrap_or_else(|e| e.into_inner()).clone();
        let (path, fh, fb) = idmap.to_emulator(&req.method, &req.target, &req.headers, &req.body);
        let resp = match upstream.send(&req.method, &path, &fh, &fb) {
            Ok(r) => r,
            Err(e) => return json_response(502, &json!({"error": format!("エミュレータに届かない: {e}")})),
        };
        let (rh, rb) = idmap.to_client(&req.method, &req.target, &req.headers, &resp.headers, &resp.body);
        if mutating && op.as_deref() == Some("ReceiveMessage") && !rb.windows(13).any(|w| w == b"ReceiptHandle") {
            mutating = false; // 空振りの受信は状態を変えない。ポーリングでジャーナルが伸びるのを防ぐ
        }
        if mutating && (200..300).contains(&resp.status) {
            // クライアントが送ったまま・受け取ったままの形で書く(ID は記録時の側に揃う)
            if let Err(e) = self.journal.append(
                &req.method,
                &req.target,
                &req.headers,
                &req.body,
                op.as_deref(),
                resp.status,
                &rh,
                &rb,
            ) {
                // エミュレータの状態は変わったのに記録できなかった。成功を返すと、再起動後に黙って状態が欠ける。
                // だから失敗として返し、状態にも残す
                crate::log!("記録に失敗した({}): {e}", op.as_deref().unwrap_or(&req.method));
                self.set_degraded(e.clone());
                return json_response(
                    500,
                    &json!({"__type": "PersistenceFailure",
                            "message": format!("エミュレータには適用されたが、記録に失敗した: {e}")}),
                );
            }
        }
        Response { status: resp.status, headers: rh, body: rb }
    }

    fn serve_conn(&self, stream: TcpStream) {
        let _ = stream.set_nodelay(true);
        let _ = stream.set_read_timeout(Some(CLIENT_IDLE));
        let Ok(w) = stream.try_clone() else { return };
        let mut reader = BufReader::with_capacity(64 * 1024, stream);
        let mut writer = BufWriter::new(w);
        loop {
            let (req, close) = match http::read_request(&mut reader, &mut writer, self.max_body) {
                Ok(Some(r)) => r,
                Ok(None) | Err(ReadError::Io(_)) => return,
                Err(ReadError::Reject(status, msg)) => {
                    // 本文を読み切っていないので、この接続はもう使えない。理由を返して閉じる
                    let resp = json_response(status, &json!({"error": msg}));
                    let _ = http::write_response(&mut writer, &resp, false, true);
                    return;
                }
            };
            let resp = self.handle(&req);
            if http::write_response(&mut writer, &resp, req.method == "HEAD", close).is_err() || close {
                return;
            }
        }
    }

    /// 1接続1スレッドで待ち受ける。開発用の道具なので、同時接続はスレッドで足りる(上限 MAX_CONNECTIONS)。
    pub fn serve(self: Arc<Self>, listener: TcpListener) {
        for mut stream in listener.incoming().flatten() {
            if self.connections.fetch_add(1, Ordering::SeqCst) >= MAX_CONNECTIONS {
                self.connections.fetch_sub(1, Ordering::SeqCst);
                let resp = json_response(503, &json!({"error": "同時接続が多すぎる"}));
                let _ = http::write_response(&mut stream, &resp, false, true);
                continue;
            }
            let me = self.clone();
            std::thread::spawn(move || {
                me.serve_conn(stream);
                me.connections.fetch_sub(1, Ordering::SeqCst);
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redaction() {
        assert_eq!(
            redact_signature("AWS4-HMAC-SHA256 Credential=A/x, SignedHeaders=host, Signature=abc123"),
            "AWS4-HMAC-SHA256 Credential=A/x, SignedHeaders=host, Signature=redacted"
        );
        assert_eq!(
            redact_query("/b/k?X-Amz-Signature=ff&x=1&X-Amz-Security-Token=t"),
            "/b/k?X-Amz-Signature=redacted&x=1&X-Amz-Security-Token=redacted"
        );
    }

    fn hs(pairs: &[(&str, &str)]) -> Headers {
        pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    #[test]
    fn browser_guard() {
        let g = BrowserGuard::new("127.0.0.1", vec![]);
        assert!(g.check(&hs(&[("Host", "127.0.0.1:4566")])).is_ok());
        assert!(g.check(&hs(&[("Host", "localhost:4566")])).is_ok());
        assert!(g.check(&hs(&[("Host", "[::1]:4566")])).is_ok());
        assert!(g.check(&hs(&[("Host", "evil.example:4566")])).is_err(), "DNS rebinding");
        assert!(g.check(&hs(&[("Host", "127.0.0.1:4566"), ("Origin", "https://evil.example")])).is_err(), "CSRF");
        let g = BrowserGuard::new("0.0.0.0", vec!["http://localhost:3000".into()]);
        assert!(g.check(&hs(&[("Host", "dev-box:4566"), ("Origin", "http://localhost:3000")])).is_ok());
        assert!(g.check(&hs(&[("Host", "dev-box:4566"), ("Origin", "http://other")])).is_err());
    }
}
