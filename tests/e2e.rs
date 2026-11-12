//! Round-trip tests against a real aws-emulator. They run only when EMUPERSIST_TEST_EMULATOR is set to the path of
//! the executable.
//! The client is built from this crate's SigV4 signer and HTTP client (no dependency on the aws CLI or an SDK).

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use emupersist::aws::{sign, Creds};
use emupersist::http::{header, Client, Headers, Response};
use serde_json::{json, Value};

fn emulator() -> Option<String> {
    let e = std::env::var("EMUPERSIST_TEST_EMULATOR").ok();
    if e.is_none() {
        eprintln!("EMUPERSIST_TEST_EMULATOR が未設定なので飛ばす");
    }
    e
}

/// A running emupersist. Stopped in Drop so that a failed test does not leave the process behind.
struct Running {
    child: Option<Child>,
    client: Client,
    host: String,
    log: Arc<Mutex<String>>,
}

impl Running {
    fn start(emu: &str, store: &str, extra: &[&str]) -> Running {
        let mut child = Command::new(env!("CARGO_BIN_EXE_emupersist"))
            .args(["run", "--store", store, "--port", "0", "--emulator", emu])
            .args(extra)
            .args(["--", "-t", "off"])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("起動できない");
        // Drain stderr on a separate thread. Left unread, the pipe fills up and emupersist's writes block
        let log = Arc::new(Mutex::new(String::new()));
        let (sink, mut stderr) = (log.clone(), child.stderr.take().unwrap());
        std::thread::spawn(move || {
            let mut buf = [0u8; 8192];
            while let Ok(n) = stderr.read(&mut buf) {
                if n == 0 {
                    break;
                }
                sink.lock().unwrap().push_str(&String::from_utf8_lossy(&buf[..n]));
            }
        });
        let mut line = String::new();
        BufReader::new(child.stdout.as_mut().unwrap()).read_line(&mut line).unwrap();
        let v: Value =
            serde_json::from_str(&line).unwrap_or_else(|_| panic!("起動に失敗: {line}\n{}", log.lock().unwrap()));
        let url = v["endpoint_url"].as_str().unwrap().to_string();
        let host = url.trim_start_matches("http://").to_string();
        let client = Client::new(&url, None, false, Duration::from_secs(60)).unwrap();
        Running { child: Some(child), client, host, log }
    }

    fn call(&self, method: &str, path: &str, service: &str, headers: &[(&str, &str)], body: &[u8]) -> Response {
        let h: Vec<(String, String)> = headers.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
        // A dummy for sending to an emulator with signature verification off (-a off). Not valid credentials anywhere
        let creds = Creds { akid: "AKIATESTCLIENT".into(), secret: "secret".into(), token: None }; // pragma: allowlist secret
        let path_only = path.split('?').next().unwrap();
        let signed: Headers = sign(method, &self.host, path_only, &[], &h, body, "us-east-1", service, &creds);
        self.client.send(method, path, &signed, body).unwrap()
    }

    fn json(&self, service: &str, target: &str, payload: Value) -> (u16, Value) {
        let ct = if service == "dynamodb" { "application/x-amz-json-1.0" } else { "application/x-amz-json-1.1" };
        let headers = [("content-type", ct), ("x-amz-target", target)];
        let r = self.call("POST", "/", service, &headers, payload.to_string().as_bytes());
        (r.status, serde_json::from_slice(&r.body).unwrap_or(json!({})))
    }

    fn admin(&self, method: &str, name: &str) -> Response {
        self.client.send(method, &format!("/__persist/{name}"), &vec![], b"").unwrap()
    }

    fn pid(&self) -> u32 {
        self.child.as_ref().unwrap().id()
    }

    /// Stops with SIGTERM and returns stderr (the log).
    fn stop(mut self) -> String {
        let mut child = self.child.take().unwrap();
        // SAFETY: only sends SIGTERM to a child this process started and has not reaped yet
        unsafe { libc::kill(child.id() as libc::pid_t, libc::SIGTERM) };
        child.wait().unwrap();
        std::thread::sleep(Duration::from_millis(100)); // Wait for the drain thread to read to the end
        let log = self.log.lock().unwrap().clone();
        log
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        if let Some(mut c) = self.child.take() {
            // SAFETY: only sends SIGTERM to a child this process started and has not reaped yet
            unsafe { libc::kill(c.id() as libc::pid_t, libc::SIGTERM) };
            let _ = c.wait();
        }
    }
}

fn tmpdir(name: &str) -> String {
    let d = std::env::temp_dir().join(format!("emupersist-e2e-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d.to_string_lossy().into_owned()
}

fn wait_active(e: &Running, table: &str) {
    for _ in 0..100 {
        if e.json("dynamodb", "DynamoDB_20120810.DescribeTable", json!({"TableName": table})).1["Table"]["TableStatus"]
            == "ACTIVE"
        {
            return;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    panic!("{table} が ACTIVE にならない");
}

fn blob() -> Vec<u8> {
    // Also checks that ID-like strings in the body are not rewritten (pseudo-random data is enough)
    let mut x: u64 = 0x9E37_79B9_7F4A_7C15;
    (0..50_000)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x as u8
        })
        .collect()
}

/// First run: creates a table, a KMS key, and an S3 object. Returns the randomly assigned key ID.
fn write_phase(e: &Running, blob: &[u8]) -> String {
    let (st, out) = e.json(
        "dynamodb",
        "DynamoDB_20120810.CreateTable",
        json!({"TableName": "users", "BillingMode": "PAY_PER_REQUEST",
               "AttributeDefinitions": [{"AttributeName": "id", "AttributeType": "S"}],
               "KeySchema": [{"AttributeName": "id", "KeyType": "HASH"}]}),
    );
    assert_eq!(st, 200, "{out}");
    wait_active(e, "users");
    let (st, out) = e.json(
        "dynamodb",
        "DynamoDB_20120810.PutItem",
        json!({"TableName": "users", "Item": {"id": {"S": "u1"}, "name": {"S": "フリーレン"}}}),
    );
    assert_eq!(st, 200, "{out}");
    let (_, key) = e.json("kms", "TrentService.CreateKey", json!({}));
    let key_id = key["KeyMetadata"]["KeyId"].as_str().unwrap().to_string();
    let (st, _) = e.json("kms", "TrentService.CreateAlias", json!({"AliasName": "alias/app", "TargetKeyId": key_id}));
    assert_eq!(st, 200);
    assert_eq!(e.call("PUT", "/bkt", "s3", &[], b"").status, 200);
    let octet = [("content-type", "application/octet-stream")];
    assert_eq!(e.call("PUT", "/bkt/data.bin", "s3", &octet, blob).status, 200);
    let head = e.call("HEAD", "/bkt/data.bin", "s3", &[], b"");
    assert_eq!((head.status, header(&head.headers, "content-length")), (200, Some(blob.len().to_string().as_str())));
    e.json("sqs", "AmazonSQS.CreateQueue", json!({"QueueName": "q"}));
    let (st, _) =
        e.json("sqs", "AmazonSQS.ReceiveMessage", json!({"QueueUrl": format!("http://{}/000000000000/q", e.host)}));
    assert_eq!(st, 200);
    key_id
}

/// Second run: checks that state and IDs are restored after the restart.
fn read_phase(e: &Running, key_id: &str, blob: &[u8]) {
    let (_, out) =
        e.json("dynamodb", "DynamoDB_20120810.GetItem", json!({"TableName": "users", "Key": {"id": {"S": "u1"}}}));
    assert_eq!(out["Item"]["name"]["S"], "フリーレン");
    let (st, out) = e.json("kms", "TrentService.DescribeKey", json!({"KeyId": key_id}));
    assert_eq!((st, out["KeyMetadata"]["KeyId"].as_str()), (200, Some(key_id)), "{out}");
    let (_, out) = e.json("kms", "TrentService.ListAliases", json!({}));
    let aliases = out["Aliases"].as_array().unwrap();
    assert!(aliases.iter().any(|a| a["AliasName"] == "alias/app" && a["TargetKeyId"] == key_id));
    let r = e.call("GET", "/bkt/data.bin", "s3", &[], b"");
    assert_eq!((r.status, r.body.as_slice()), (200, blob));
}

#[test]
fn state_survives_restart() {
    let Some(emu) = emulator() else { return };
    let store = format!("sqlite:{}/j.db", tmpdir("restart"));
    let blob = blob();
    let e = Running::start(&emu, &store, &[]);
    let key_id = write_phase(&e, &blob);
    e.stop();

    let e = Running::start(&emu, &store, &[]);
    read_phase(&e, &key_id, &blob);
    let journal: Value = serde_json::from_slice(&e.admin("GET", "journal").body).unwrap();
    let ops: Vec<&str> = journal.as_array().unwrap().iter().filter_map(|r| r["op"].as_str()).collect();
    assert!(!ops.contains(&"ReceiveMessage"), "空振りの受信は記録しない: {ops:?}");
    assert!(!ops.contains(&"DescribeTable"));

    // With the ID mapping table active, JSON content stored in S3 is not rewritten (it is the user's data)
    let doc = format!(r#"{{"kms_key":"{key_id}"}}"#);
    let put = e.call("PUT", "/bkt/config.json", "s3", &[("content-type", "application/json")], doc.as_bytes());
    assert_eq!(put.status, 200);
    let get = e.call("GET", "/bkt/config.json", "s3", &[], b"");
    assert_eq!((get.status, get.body.as_slice()), (200, doc.as_bytes()));

    assert_eq!(e.admin("POST", "reset").status, 200);
    let (st, _) =
        e.json("dynamodb", "DynamoDB_20120810.GetItem", json!({"TableName": "users", "Key": {"id": {"S": "u1"}}}));
    assert_eq!(st, 400, "作り直したエミュレータにはテーブルがない");
    // After reset, and even after the connection closes, the emulator is still alive (PDEATHSIG is not set up on a
    // connection thread)
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(e.json("sqs", "AmazonSQS.ListQueues", json!({})).0, 200);
    let log = e.stop();
    assert!(log.contains("食い違い 0 件"), "{log}");
}

/// Even when several clients update the same item concurrently, the last value is not swapped after a restart.
/// In the version that let writes through concurrently, it was swapped in 14 of 20 trials with 8 clients.
#[test]
fn concurrent_writes_to_one_item_survive_restart_in_order() {
    let Some(emu) = emulator() else { return };
    for round in 0..5 {
        let store = format!("file:{}/j.jsonl", tmpdir(&format!("concurrent-{round}")));
        let e = Running::start(&emu, &store, &[]);
        let (st, out) = e.json(
            "dynamodb",
            "DynamoDB_20120810.CreateTable",
            json!({"TableName": "tbl", "BillingMode": "PAY_PER_REQUEST",
                   "AttributeDefinitions": [{"AttributeName": "k", "AttributeType": "S"}],
                   "KeySchema": [{"AttributeName": "k", "KeyType": "HASH"}]}),
        );
        assert_eq!(st, 200, "{out}");
        wait_active(&e, "tbl");
        let barrier = std::sync::Barrier::new(8);
        std::thread::scope(|s| {
            for i in 0..8 {
                let (e, barrier) = (&e, &barrier);
                s.spawn(move || {
                    barrier.wait();
                    let item =
                        json!({"TableName": "tbl", "Item": {"k": {"S": "same"}, "v": {"S": format!("client-{i}")}}});
                    assert_eq!(e.json("dynamodb", "DynamoDB_20120810.PutItem", item).0, 200);
                });
            }
        });
        let get = |e: &Running| {
            let key = json!({"TableName": "tbl", "Key": {"k": {"S": "same"}}});
            e.json("dynamodb", "DynamoDB_20120810.GetItem", key).1["Item"]["v"]["S"].as_str().map(str::to_string)
        };
        let before = get(&e);
        e.stop();
        let e = Running::start(&emu, &store, &[]);
        assert_eq!(get(&e), before, "round {round}");
        e.stop();
    }
}

/// A format v1 journal (a sample recorded by the other implementation) can be read as is to restore state. Confirms
/// that the storage format has not changed.
#[test]
fn replays_v1_journal_fixture() {
    let Some(emu) = emulator() else { return };
    let dir = tmpdir("fixture");
    let path = format!("{dir}/j.jsonl");
    std::fs::copy(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/journal-v1.jsonl"), &path).unwrap();
    let records: Vec<Value> =
        std::fs::read_to_string(&path).unwrap().lines().map(|l| serde_json::from_str(l).unwrap()).collect();
    let create_key = records.iter().find(|r| r["op"] == "CreateKey").unwrap();
    let rbody = emupersist::util::b64decode(create_key["rbody"].as_str().unwrap()).unwrap();
    let key_id = serde_json::from_slice::<Value>(&rbody).unwrap()["KeyMetadata"]["KeyId"].as_str().unwrap().to_string();

    let e = Running::start(&emu, &format!("file:{path}"), &[]);
    let (_, out) =
        e.json("dynamodb", "DynamoDB_20120810.GetItem", json!({"TableName": "users", "Key": {"id": {"S": "u1"}}}));
    assert_eq!(out["Item"]["name"]["S"], "フリーレン");
    let (st, out) = e.json("kms", "TrentService.DescribeKey", json!({"KeyId": key_id}));
    assert_eq!((st, out["KeyMetadata"]["KeyId"].as_str()), (200, Some(key_id.as_str())), "{out}");
    let r = e.call("GET", "/bkt/hello.txt", "s3", &[], b"");
    assert_eq!((r.status, r.body.as_slice()), (200, "千年の記録".as_bytes()));
    let log = e.stop();
    assert!(log.contains("食い違い 0 件"), "{log}");
}

/// Behavior against the attacks and malformed inputs found in review.
#[test]
fn rejects_hostile_requests_and_survives() {
    let Some(emu) = emulator() else { return };
    let e = Running::start(&emu, &format!("file:{}/j.jsonl", tmpdir("hostile")), &["--max-body-bytes", "1048576"]);
    let raw = |req: &[u8]| {
        let mut s = TcpStream::connect(&e.host).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        s.write_all(req).unwrap();
        let mut out = Vec::new();
        let _ = s.read_to_end(&mut out);
        String::from_utf8_lossy(&out).into_owned()
    };
    let host = e.host.clone();
    // A huge Content-Length does not crash the process; it returns 413
    let r = raw(format!("POST / HTTP/1.1\r\nHost: {host}\r\nContent-Length: 999999999999999\r\n\r\n").as_bytes());
    assert!(r.starts_with("HTTP/1.1 413"), "{r}");
    // A reset from a cross-origin browser page (CSRF) and a DNS rebinding Host are rejected
    let r = raw(format!("POST /__persist/reset HTTP/1.1\r\nHost: {host}\r\nOrigin: https://evil.example\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").as_bytes());
    assert!(r.starts_with("HTTP/1.1 403"), "{r}");
    let r = raw(b"GET /__persist/status HTTP/1.1\r\nHost: evil.example:4566\r\nConnection: close\r\n\r\n");
    assert!(r.starts_with("HTTP/1.1 403"), "{r}");
    // A truncated chunked body is neither forwarded to the emulator nor recorded
    let r =
        raw(format!("PUT /bkt HTTP/1.1\r\nHost: {host}\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n").as_bytes());
    assert!(r.is_empty() || !r.starts_with("HTTP/1.1 200"), "{r}");
    // After all this it is still alive and has recorded nothing
    let status: Value = serde_json::from_slice(&e.admin("GET", "status").body).unwrap();
    assert_eq!(status["records"], 0, "{status}");
    e.stop();
}

/// Even if emupersist dies from SIGKILL, the child emulator is not left behind as an orphan (Linux PDEATHSIG).
#[cfg(target_os = "linux")]
#[test]
fn emulator_does_not_outlive_a_killed_proxy() {
    let Some(emu) = emulator() else { return };
    let mut e = Running::start(&emu, &format!("file:{}/j.jsonl", tmpdir("orphan")), &[]);
    let upstream: Value = serde_json::from_slice(&e.admin("GET", "status").body).unwrap();
    let port: u16 = upstream["upstream"].as_str().unwrap().rsplit(':').next().unwrap().parse().unwrap();
    // SAFETY: only sends SIGKILL to a child this process started and has not reaped yet (it is reaped right below)
    unsafe { libc::kill(e.pid() as libc::pid_t, libc::SIGKILL) };
    e.child.take().unwrap().wait().unwrap();
    for _ in 0..50 {
        if TcpStream::connect(("127.0.0.1", port)).is_err() {
            return;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    panic!("エミュレータ(ポート {port})が残っている");
}
