//! 本物の aws-emulator を相手にした往復テスト。EMUPERSIST_TEST_EMULATOR に実行ファイルの場所を入れたときだけ動く。
//! クライアントはこのクレートの SigV4 署名器と HTTP クライアントで組む(aws CLI や SDK に依存しない)。

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

/// 起動した emupersist。落ちたテストでもプロセスを残さないよう、Drop で止める。
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
        // 標準エラーは別スレッドで吸い出す。読まずにいるとパイプが埋まり、emupersist の書き込みが詰まる
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
        // 署名検証を外したエミュレータ(-a off)に送るためのダミーで、どこでも有効な資格情報ではない
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

    /// SIGTERM で止めて、標準エラー(ログ)を返す。
    fn stop(mut self) -> String {
        let mut child = self.child.take().unwrap();
        // SAFETY: 自分が起動して、まだ回収していない子プロセスに SIGTERM を送るだけ
        unsafe { libc::kill(child.id() as libc::pid_t, libc::SIGTERM) };
        child.wait().unwrap();
        std::thread::sleep(Duration::from_millis(100)); // 吸い出しスレッドが最後まで読むのを待つ
        let log = self.log.lock().unwrap().clone();
        log
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        if let Some(mut c) = self.child.take() {
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
    // 本文に ID らしい文字列が混ざっても書き換えないことも見る(擬似乱数で十分)
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

/// 1回目: テーブル・KMS キー・S3 オブジェクトを作る。乱数で振られるキー ID を返す。
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

/// 2回目: 再起動後に、状態と ID が戻っているか。
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

    // ID の対応表が効いている状態で、S3 に置いた JSON の中身は書き換えない(利用者のデータなので)
    let doc = format!(r#"{{"kms_key":"{key_id}"}}"#);
    let put = e.call("PUT", "/bkt/config.json", "s3", &[("content-type", "application/json")], doc.as_bytes());
    assert_eq!(put.status, 200);
    let get = e.call("GET", "/bkt/config.json", "s3", &[], b"");
    assert_eq!((get.status, get.body.as_slice()), (200, doc.as_bytes()));

    assert_eq!(e.admin("POST", "reset").status, 200);
    let (st, _) =
        e.json("dynamodb", "DynamoDB_20120810.GetItem", json!({"TableName": "users", "Key": {"id": {"S": "u1"}}}));
    assert_eq!(st, 400, "作り直したエミュレータにはテーブルがない");
    // reset の後も、接続を閉じたあとでもエミュレータが生きている(PDEATHSIG を接続スレッドで仕掛けていない)
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(e.json("sqs", "AmazonSQS.ListQueues", json!({})).0, 200);
    let log = e.stop();
    assert!(log.contains("食い違い 0 件"), "{log}");
}

/// 複数のクライアントが同じ項目を同時に書き換えても、再起動の後に最後の値が入れ替わらない。
/// 書き込みを並行に通していた版では、8 クライアントで 20 回中 14 回入れ替わった。
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
                    let item = json!({"TableName": "tbl", "Item": {"k": {"S": "same"}, "v": {"S": format!("client-{i}")}}});
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

/// 形式 v1 のジャーナル(別の実装で記録した見本)を、そのまま読んで状態を戻せる。保存形式を変えていないことの確認。
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

/// レビューで見つかった攻撃と壊れた入力に対する振る舞い。
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
    // 巨大な Content-Length でもプロセスは落ちず、413 を返す
    let r = raw(format!("POST / HTTP/1.1\r\nHost: {host}\r\nContent-Length: 999999999999999\r\n\r\n").as_bytes());
    assert!(r.starts_with("HTTP/1.1 413"), "{r}");
    // ブラウザの別オリジンからの reset(CSRF)と、DNS rebinding の Host は断る
    let r = raw(format!("POST /__persist/reset HTTP/1.1\r\nHost: {host}\r\nOrigin: https://evil.example\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").as_bytes());
    assert!(r.starts_with("HTTP/1.1 403"), "{r}");
    let r = raw(b"GET /__persist/status HTTP/1.1\r\nHost: evil.example:4566\r\nConnection: close\r\n\r\n");
    assert!(r.starts_with("HTTP/1.1 403"), "{r}");
    // 途中で切れた chunked 本文は、エミュレータに届けず記録もしない
    let r =
        raw(format!("PUT /bkt HTTP/1.1\r\nHost: {host}\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n").as_bytes());
    assert!(r.is_empty() || !r.starts_with("HTTP/1.1 200"), "{r}");
    // ここまで来ても生きていて、何も記録していない
    let status: Value = serde_json::from_slice(&e.admin("GET", "status").body).unwrap();
    assert_eq!(status["records"], 0, "{status}");
    e.stop();
}

/// emupersist が SIGKILL で死んでも、子のエミュレータが孤児として残らない(Linux の PDEATHSIG)。
#[cfg(target_os = "linux")]
#[test]
fn emulator_does_not_outlive_a_killed_proxy() {
    let Some(emu) = emulator() else { return };
    let mut e = Running::start(&emu, &format!("file:{}/j.jsonl", tmpdir("orphan")), &[]);
    let upstream: Value = serde_json::from_slice(&e.admin("GET", "status").body).unwrap();
    let port: u16 = upstream["upstream"].as_str().unwrap().rsplit(':').next().unwrap().parse().unwrap();
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
