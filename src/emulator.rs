//! aws-emulator を子プロセスとして起動・停止する(監督モード)。
//!
//! ポートは `-p 0` で OS に選ばせる。実際のエンドポイントと CA ファイルの場所は、
//! エミュレータが起動時に出す JSON ログの "emulator server information" 行から読む。

use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use serde_json::Value;

use crate::http::Client;

type SpawnJob = (Command, mpsc::Sender<std::io::Result<Child>>);

/// 子プロセスを、プロセスが終わるまで生き続ける専用スレッドで起動する。
/// reset は接続ごとのスレッドから呼ばれるので、そこで fork すると、接続が閉じた時点で
/// PDEATHSIG が子に届いてしまう。
fn spawn_on_keeper(cmd: Command) -> std::io::Result<Child> {
    static KEEPER: std::sync::OnceLock<std::sync::Mutex<mpsc::Sender<SpawnJob>>> = std::sync::OnceLock::new();
    let tx = KEEPER.get_or_init(|| {
        let (tx, rx) = mpsc::channel::<SpawnJob>();
        std::thread::spawn(move || {
            for (mut cmd, reply) in rx {
                let _ = reply.send(cmd.spawn());
            }
        });
        std::sync::Mutex::new(tx)
    });
    let (reply_tx, reply_rx) = mpsc::channel();
    tx.lock().unwrap_or_else(|e| e.into_inner()).send((cmd, reply_tx)).map_err(std::io::Error::other)?;
    reply_rx.recv().map_err(std::io::Error::other)?
}

pub struct EmulatorProcess {
    binary: String,
    extra_args: Vec<String>,
    child: Option<Child>,
    pub endpoint: String,
    pub ca_file: String,
    pub version: String,
}

impl EmulatorProcess {
    pub fn new(binary: &str, extra_args: Vec<String>) -> Self {
        EmulatorProcess {
            binary: binary.into(),
            extra_args,
            child: None,
            endpoint: String::new(),
            ca_file: String::new(),
            version: String::new(),
        }
    }

    pub fn start(&mut self, timeout: Duration) -> Result<(), String> {
        let v = Command::new(&self.binary)
            .arg("--version")
            .output()
            .map_err(|e| format!("aws-emulator を起動できない({}): {e}。--emulator で場所を指定する", self.binary))?;
        self.version = String::from_utf8_lossy(&v.stdout).lines().next().unwrap_or("").to_string();
        // -a off: 記録した署名は再起動後の資格情報では通らないので、検証を外す(proxy.rs の冒頭を参照)
        let mut cmd = Command::new(&self.binary);
        cmd.args(["-b", "127.0.0.1", "-p", "0", "-a", "off"]).args(&self.extra_args);
        #[cfg(target_os = "linux")]
        {
            use std::os::unix::process::CommandExt;
            // 親(このプロキシ)がどう終わっても(abort や SIGKILL で Drop が走らなくても)、子に SIGTERM が届くようにする。
            // PDEATHSIG は親の「プロセス」ではなく fork した「スレッド」が終わると発火するので、起動は spawn_on_keeper
            // (プロセスと同じだけ生きるスレッド)で行う。macOS には同じ仕組みがないので、シグナルで止めたときにだけ片付く
            // SAFETY: fork と exec のあいだで呼ぶのは、async-signal-safe な prctl だけ
            unsafe {
                cmd.pre_exec(|| {
                    if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGTERM) != 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                    Ok(())
                });
            }
        }
        cmd.stdout(Stdio::piped()).stderr(Stdio::inherit());
        let mut child = spawn_on_keeper(cmd).map_err(|e| format!("aws-emulator を起動できない: {e}"))?;
        let stdout = child.stdout.take().expect("piped");
        self.child = Some(child);
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines().map_while(Result::ok) {
                if let Ok(v) = serde_json::from_str::<Value>(&line) {
                    let f = &v["fields"];
                    if f["message"] == "emulator server information" {
                        let _ = tx.send((
                            f["endpoint_url"].as_str().unwrap_or("").to_string(),
                            f["ca_file"].as_str().unwrap_or("").to_string(),
                        ));
                    }
                }
                eprintln!("[aws-emulator] {line}");
            }
        });
        let Ok((endpoint, ca)) = rx.recv_timeout(timeout) else {
            self.stop();
            return Err("aws-emulator が起動しなかった(上のログを確認)".into());
        };
        self.endpoint = endpoint;
        self.ca_file = ca;
        let client = self.client()?;
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            if client.send("GET", "/__admin/health", &vec![], b"").is_ok_and(|r| r.status == 200) {
                return Ok(());
            }
            std::thread::sleep(Duration::from_millis(200));
        }
        self.stop();
        Err("aws-emulator のヘルスチェックが通らない".into())
    }

    pub fn client(&self) -> Result<Client, String> {
        Client::new(&self.endpoint, Some(&self.ca_file), false, Duration::from_secs(900))
    }

    pub fn stop(&mut self) {
        if let Some(mut c) = self.child.take() {
            // std の Child::kill は SIGKILL。エミュレータが自分の一時ファイルを片付けられるよう SIGTERM を送る
            // SAFETY: 自分が起動して、まだ回収していない子プロセスの pid に送るだけ
            unsafe { libc::kill(c.id() as libc::pid_t, libc::SIGTERM) };
            let deadline = Instant::now() + Duration::from_secs(10);
            while Instant::now() < deadline {
                if let Ok(Some(_)) = c.try_wait() {
                    return;
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            let _ = c.kill();
            let _ = c.wait();
        }
    }
}

impl Drop for EmulatorProcess {
    fn drop(&mut self) {
        self.stop();
    }
}
