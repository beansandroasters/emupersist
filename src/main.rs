//! The emupersist command line.

use std::collections::HashSet;
use std::net::TcpListener;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use emupersist::emulator::EmulatorProcess;
use emupersist::http::Client;
use emupersist::idmap::IdMap;
use emupersist::log;
use emupersist::proxy::{replay, BrowserGuard, Journal, Proxy, ResetFn, STOP};
use emupersist::stores::open_store;

const DEFAULT_STORE: &str = "file:.emupersist/journal.jsonl";
/// The default limit on accepted request bodies. Requests are held entirely in memory, so there is always a limit
const DEFAULT_MAX_BODY: usize = 512 * 1024 * 1024;

const USAGE: &str = "\
使い方: emupersist <コマンド> [オプション] [-- エミュレータへの追加引数]

コマンド:
  run         aws-emulator を子プロセスで起動し、ジャーナルをリプレイしてから前段で待ち受ける
  proxy       起動済みのエミュレータ(-a off・空の状態)の前段に立つ
  inspect     記録の一覧を表示する
  reset       記録を全部消す
  init-store  保存先を用意する(DynamoDB テーブルの作成)

共通オプション:
  --store URL               保存先(既定 file:.emupersist/journal.jsonl、環境変数 EMUPERSIST_STORE)
                            file:PATH / sqlite:PATH / dynamodb://TABLE?region=.. / s3://BUCKET/PREFIX?region=..
  --namespace NAME          sqlite / dynamodb / s3 で1つの保存先に複数の状態を持つときの名前
                            (既定 default、英数字と . _ - のみ、環境変数 EMUPERSIST_NAMESPACE)
  -h, --help                この説明を表示する
  --version                 版を表示する

run / proxy のオプション:
  --bind ADDR               待ち受けアドレス(既定 127.0.0.1)。後段は署名を検証せず、管理用の reset にも
                            認証がない。外に開くと、届く人は誰でも状態を変えたり消したりできる
  --port N                  待ち受けポート(既定 4566、0 で空きポート、環境変数 EMUPERSIST_PORT)
  --allow-origin ORIGIN     ブラウザからの要求を許すオリジン(繰り返し可、* ですべて)。既定では
                            Origin ヘッダつきの要求を断る(悪意あるページからの書き換えを防ぐため)
  --max-body-bytes N        受け付ける要求本文の上限(既定 536870912 = 512 MiB)
  --write-op OP             読み取り系に見えるが記録したい操作名(繰り返し可)
  --read-op OP              記録しなくてよい操作名(繰り返し可)
  --replay-retry-seconds S  リプレイで失敗した要求の送り直しに使う時間の合計の上限(既定 30)
  --strict                  リプレイで1件でも食い違ったら起動をやめる
  --emulator PATH           (run) aws-emulator 実行ファイル(既定 aws-emulator、環境変数 EMUPERSIST_EMULATOR)
  --upstream URL            (proxy) エミュレータの URL(例 https://127.0.0.1:9297)
  --ca FILE                 (proxy) エミュレータの CA(例 ~/.aws/emulator/9297/ca.pem)
  --insecure                (proxy) エミュレータの証明書を検証しない
";

extern "C" fn on_signal(_: libc::c_int) {
    STOP.store(true, Ordering::SeqCst);
}

struct Args {
    cmd: String,
    store: String,
    namespace: String,
    bind: String,
    port: u16,
    allow_origins: Vec<String>,
    max_body: usize,
    write_ops: HashSet<String>,
    read_ops: HashSet<String>,
    retry: f64,
    strict: bool,
    emulator: Option<String>,
    upstream: Option<String>,
    ca: Option<String>,
    insecure: bool,
    emu_args: Vec<String>,
}

fn env_or(name: &str, default: &str) -> String {
    std::env::var(name).ok().filter(|v| !v.is_empty()).unwrap_or_else(|| default.to_string())
}

fn parse_args(argv: Vec<String>) -> Result<Args, String> {
    let (argv, emu_args) = match argv.iter().position(|a| a == "--") {
        Some(i) => (argv[..i].to_vec(), argv[i + 1..].to_vec()),
        None => (argv, Vec::new()),
    };
    if argv.iter().any(|a| a == "-h" || a == "--help") {
        print!("{USAGE}");
        std::process::exit(0);
    }
    if argv.iter().any(|a| a == "--version" || a == "-V") {
        println!("emupersist {}", env!("CARGO_PKG_VERSION"));
        std::process::exit(0);
    }
    let mut it = argv.into_iter();
    let cmd = it.next().ok_or("コマンドがない")?;
    if !["run", "proxy", "inspect", "reset", "init-store"].contains(&cmd.as_str()) {
        return Err(format!("知らないコマンド: {cmd}"));
    }
    let mut a = Args {
        cmd,
        store: env_or("EMUPERSIST_STORE", DEFAULT_STORE),
        namespace: env_or("EMUPERSIST_NAMESPACE", "default"),
        bind: "127.0.0.1".into(),
        port: env_or("EMUPERSIST_PORT", "4566").parse().map_err(|_| "EMUPERSIST_PORT が数でない")?,
        allow_origins: Vec::new(),
        max_body: DEFAULT_MAX_BODY,
        write_ops: HashSet::new(),
        read_ops: HashSet::new(),
        retry: 30.0,
        strict: false,
        emulator: std::env::var("EMUPERSIST_EMULATOR").ok().filter(|v| !v.is_empty()),
        upstream: None,
        ca: None,
        insecure: false,
        emu_args,
    };
    let mut emulator_flag = false;
    while let Some(flag) = it.next() {
        let mut val = || it.next().ok_or(format!("{flag} に値がない"));
        match flag.as_str() {
            "--store" => a.store = val()?,
            "--namespace" => a.namespace = val()?,
            "--bind" => a.bind = val()?,
            "--port" => a.port = val()?.parse().map_err(|_| "--port が数でない")?,
            "--allow-origin" => a.allow_origins.push(val()?),
            "--max-body-bytes" => {
                a.max_body = val()?.parse().ok().filter(|n| *n > 0).ok_or("--max-body-bytes は正の整数")?;
            }
            "--write-op" => {
                a.write_ops.insert(val()?);
            }
            "--read-op" => {
                a.read_ops.insert(val()?);
            }
            "--replay-retry-seconds" => {
                a.retry = val()?
                    .parse::<f64>()
                    .ok()
                    .filter(|s| s.is_finite() && *s >= 0.0 && *s <= 86_400.0)
                    .ok_or("--replay-retry-seconds は 0〜86400 の数")?;
            }
            "--strict" => a.strict = true,
            "--emulator" => {
                a.emulator = Some(val()?);
                emulator_flag = true;
            }
            "--upstream" => a.upstream = Some(val()?),
            "--ca" => a.ca = Some(val()?),
            "--insecure" => a.insecure = true,
            _ => return Err(format!("知らないオプション: {flag}")),
        }
    }
    let serving = a.cmd == "run" || a.cmd == "proxy";
    if !serving && (a.upstream.is_some() || emulator_flag || !a.emu_args.is_empty()) {
        return Err(format!("{} に --upstream / --emulator / -- 以降の引数は使えない", a.cmd));
    }
    if a.cmd == "proxy" {
        if a.upstream.is_none() {
            return Err("proxy には --upstream が必要".into());
        }
        if emulator_flag || !a.emu_args.is_empty() {
            return Err("proxy はエミュレータを起動しないので、--emulator と -- 以降の引数は使えない".into());
        }
    }
    if a.cmd == "run" && (a.upstream.is_some() || a.ca.is_some() || a.insecure) {
        return Err("--upstream / --ca / --insecure は proxy で使う".into());
    }
    Ok(a)
}

fn fmt_ts(ts: f64) -> String {
    let (y, mo, d, h, mi, s) = emupersist::util::civil(ts as i64);
    format!("{y:04}-{mo:02}-{d:02} {h:02}:{mi:02}:{s:02}Z")
}

fn run(a: Args) -> Result<i32, String> {
    let store = open_store(&a.store, &a.namespace).map_err(|e| e.to_string())?;
    match a.cmd.as_str() {
        "inspect" => {
            for r in store.read_all().map_err(|e| e.to_string())? {
                let label = r["op"].as_str().map(str::to_string).unwrap_or_else(|| {
                    let path = r["path"].as_str().unwrap_or("").split('?').next().unwrap_or("");
                    format!("{} {path}", r["method"].as_str().unwrap_or(""))
                });
                println!("{:>6}  {}  {}  {label}", r["seq"], fmt_ts(r["ts"].as_f64().unwrap_or(0.0)), r["status"]);
            }
            return Ok(0);
        }
        "reset" => {
            store.clear().map_err(|e| e.to_string())?;
            log!("消した: {}", store.describe());
            return Ok(0);
        }
        "init-store" => {
            match store.ensure().map_err(|e| e.to_string())? {
                Some(true) => log!("テーブルを作った"),
                Some(false) => log!("テーブルは既にある"),
                None => log!("{} は準備不要", store.describe()),
            }
            return Ok(0);
        }
        _ => {}
    }

    // Install before starting the emulator, so that even a SIGTERM during replay exits after cleaning up the child
    // SAFETY: the signal handler only writes an atomic variable (async-signal-safe)
    unsafe {
        libc::signal(libc::SIGTERM, on_signal as *const () as libc::sighandler_t);
        libc::signal(libc::SIGINT, on_signal as *const () as libc::sighandler_t);
    }

    let (mut journal, loaded) = Journal::open(store)?;
    log!("保存先 {}: {} 件", journal.store.describe(), loaded.len());
    let mut emu_holder: Option<Arc<Mutex<EmulatorProcess>>> = None;
    let (upstream, on_reset): (Client, Option<ResetFn>) = if a.cmd == "run" {
        let mut emu = EmulatorProcess::new(a.emulator.as_deref().unwrap_or("aws-emulator"), a.emu_args.clone());
        emu.start(Duration::from_secs(60))?;
        let client = emu.client()?;
        let others: Vec<String> = loaded
            .iter()
            .filter_map(|r| r["emu"].as_str().map(str::to_string))
            .filter(|v| *v != emu.version)
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect();
        if !others.is_empty() {
            log!("注意: 記録時と版が違う({} → {})。結果が変わることがある", others.join(", "), emu.version);
        }
        journal.emulator_version = Some(emu.version.clone());
        let emu = Arc::new(Mutex::new(emu));
        emu_holder = Some(emu.clone());
        let reset: ResetFn = Box::new(move || {
            let mut e = emu.lock().unwrap_or_else(|e| e.into_inner());
            e.stop();
            e.start(Duration::from_secs(60))?;
            e.client()
        });
        (client, Some(reset))
    } else {
        let url = a.upstream.as_deref().expect("parse_args で確かめた");
        (Client::new(url, a.ca.as_deref(), a.insecure, Duration::from_secs(900))?, None)
    };
    let stop_emulator = || {
        if let Some(e) = &emu_holder {
            e.lock().unwrap_or_else(|e| e.into_inner()).stop();
        }
    };

    let idmap = IdMap::default();
    let failed = match replay(&upstream, &loaded, &idmap, Duration::from_secs_f64(a.retry)) {
        Ok(f) => f,
        Err(e) => {
            stop_emulator();
            return Err(e);
        }
    };
    drop(loaded); // The bodies are no longer needed
    if failed > 0 && a.strict {
        stop_emulator();
        return Ok(1);
    }

    let listener = match TcpListener::bind((a.bind.as_str(), a.port)) {
        Ok(l) => l,
        Err(e) => {
            stop_emulator();
            return Err(format!("{}:{} で待ち受けられない: {e}", a.bind, a.port));
        }
    };
    let addr = listener.local_addr().map_err(|e| e.to_string())?;
    log!("待ち受け開始 http://{addr}  → {}", upstream.url);
    println!("{}", serde_json::json!({"endpoint_url": format!("http://{addr}")}));

    let proxy = Arc::new(Proxy {
        journal,
        state: RwLock::new((Arc::new(upstream), Arc::new(idmap))),
        gate: RwLock::new(()),
        write_lock: Mutex::new(()),
        extra_writes: a.write_ops,
        extra_reads: a.read_ops,
        on_reset,
        degraded: Mutex::new(None),
        started: Instant::now(),
        guard: BrowserGuard::new(&a.bind, a.allow_origins),
        max_body: a.max_body,
        connections: AtomicUsize::new(0),
    });
    std::thread::spawn(move || proxy.serve(listener));
    while !STOP.load(Ordering::SeqCst) {
        std::thread::sleep(Duration::from_millis(100));
    }
    stop_emulator();
    Ok(0)
}

fn main() {
    let args = match parse_args(std::env::args().skip(1).collect()) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("emupersist: {e}\n\n{USAGE}");
            std::process::exit(2);
        }
    };
    match run(args) {
        Ok(code) => std::process::exit(code),
        Err(e) => {
            log!("{e}");
            std::process::exit(1);
        }
    }
}
