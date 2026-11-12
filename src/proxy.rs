//! An HTTP proxy that sits between the client and the emulator.
//!
//! State-changing requests that finish with 2xx are appended to the journal exactly as received.
//! Replaying the journal from the start in the same order at startup restores the emulator state (event sourcing).
//!
//! The emulator is assumed to run with `-a off` (no signature verification). Credentials change on every start, so
//! recorded signatures do not pass after a restart. With `-a off`, the region and account are read from the
//! credential scope in the Authorization header and the signature itself is not checked. So records keep the
//! Authorization header with the signature redacted.

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
/// Responses up to this size are recorded (used for ID mapping). Large responses rarely carry IDs.
const MAX_RECORDED_RESPONSE: usize = 1 << 20;

/// Redacts `Signature=<hex>` in Authorization.
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

/// Redacts X-Amz-Signature / X-Amz-Security-Token in the query (presigned URLs).
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
    inner: Mutex<(u64, Vec<Value>)>, // (next sequence number, summaries for listing)
    pub emulator_version: Option<String>,
}

impl Journal {
    /// Reads the store and returns the journal together with all records including bodies (for replay).
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
        // Advance the sequence number even on failure. Depending on the store, part of a write may have landed even
        // when it looks failed (part of a split DynamoDB record, an S3 PUT whose response alone was lost). Rewriting
        // the same sequence number would hit it and keep failing with Conflict. Skipped sequence numbers cause no
        // problem when loading
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

/// Set on SIGTERM / SIGINT, so the proxy stops even in the middle of replay and exits after cleaning up the child
/// emulator.
pub static STOP: AtomicBool = AtomicBool::new(false);

/// Replays the records in order. Returns the number that never reached 2xx.
///
/// The emulator also reproduces asynchronous state transitions (right after DynamoDB CreateTable the table is
/// CREATING, and a following PutItem gets ResourceNotFoundException). Replay sends requests back to back, so it
/// lands in the middle of such transitions. So requests that succeeded when recorded but fail now are resent with
/// growing intervals. A failed request did not change state, so nothing is applied twice. The time spent on resends
/// is capped at `retry_budget` in total for the whole replay (so that when a version change causes many mismatches,
/// waiting on each one does not stall startup for tens of minutes).
/// On success, the recorded and current responses are compared to learn ID mappings.
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
            // The mapping table grows with earlier records, so rewrite again on every send
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

/// Rules that block attacks through a browser.
///
/// The backend does not verify signatures (`-a off`). Even when listening on 127.0.0.1, if the user's browser opens
/// a malicious page, that page can POST a form to http://127.0.0.1:4566 (CSRF). It can also swap DNS to look
/// same-origin (DNS rebinding). So the following two are rejected:
/// - Requests with an `Origin` header (browsers always send it on cross-origin POST and fetch). Allowed with
///   `--allow-origin`
/// - Requests whose `Host` is neither loopback (127.0.0.1 / localhost / ::1) nor the listen address (DNS rebinding).
///   When listening on 0.0.0.0 or similar, the name requests arrive under cannot be determined, so Host is not
///   checked
pub struct BrowserGuard {
    pub allow_origins: Vec<String>,
    /// If None, Host is not checked
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
    /// The emulator and the mapping table are replaced as a whole on reset
    pub state: RwLock<(Arc<Client>, Arc<IdMap>)>,
    /// Request handling (from sending to the emulator through recording) takes it for read, and reset takes it for
    /// write. This keeps writes that succeeded on the old emulator during a reset out of the journal just cleared
    pub gate: RwLock<()>,
    /// Write requests go one at a time inside this lock, from sending to the emulator through recording.
    /// If they ran concurrently, the recording order (the order responses came back) would drift from the order the
    /// emulator applied them, and when the same item is updated concurrently, the value left last after replay would
    /// be swapped (measured: 14 of 20 trials with 8 clients)
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

/// The limit on concurrent connections. Each connection gets one thread, so this keeps threads from being exhausted
/// when the proxy is exposed externally
const MAX_CONNECTIONS: usize = 512;
/// How long a client can keep a connection open without sending anything
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
        // Recreate the emulator first. If that fails, do not clear the journal (so the next start can restore it)
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
        // SQS ReceiveMessage waits up to 20 seconds with long polling, so queuing it would block other writes. The
        // order among receives, and between receives and sends, has little effect on the state after replay, so it
        // is left out
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
            mutating = false; // An empty receive does not change state. Keeps polling from growing the journal
        }
        if mutating && (200..300).contains(&resp.status) {
            // Write exactly what the client sent and received (IDs stay on the recorded side)
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
                // The emulator state changed but could not be recorded. Returning success would silently lose state
                // after a restart. So return a failure and also record it in the degraded status
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
                    // The body was not fully read, so this connection is no longer usable. Send the reason and close
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

    /// Listens with one thread per connection. This is a development tool, so threads are enough for concurrent
    /// connections (up to MAX_CONNECTIONS).
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
