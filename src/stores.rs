//! Journal stores. Every implementation has only three operations: append to the end, read in order from the
//! start, and delete everything. The store is chosen by a URL.
//!
//! ```text
//! file:./state.jsonl            JSON Lines, one record per line (default)
//! sqlite:./state.db             feature "sqlite" (enabled by default). Multiple namespaces in one file
//! dynamodb://TABLE?region=..    Shared, conditional writes (aws.rs)
//! s3://BUCKET/PREFIX?region=..  One object per record (aws.rs)
//! ```

use std::collections::HashMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::sync::Mutex;

use serde_json::Value;

#[derive(Debug)]
pub enum StoreError {
    /// Another writer is using the same namespace and the sequence numbers collided.
    Conflict(String),
    Other(String),
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StoreError::Conflict(m) => write!(f, "ConflictError: {m}"),
            StoreError::Other(m) => write!(f, "{m}"),
        }
    }
}

impl From<String> for StoreError {
    fn from(s: String) -> Self {
        StoreError::Other(s)
    }
}

pub type StoreResult<T> = Result<T, StoreError>;

pub trait Store: Send + Sync {
    fn append(&self, record: &Value) -> StoreResult<()>;
    fn read_all(&self) -> StoreResult<Vec<Value>>;
    fn clear(&self) -> StoreResult<()>;
    fn describe(&self) -> String;
    /// Prepares the store (creates the DynamoDB table). Returns true if it created something.
    fn ensure(&self) -> StoreResult<Option<bool>> {
        Ok(None)
    }
}

pub fn seq_of(record: &Value) -> u64 {
    record.get("seq").and_then(Value::as_u64).unwrap_or(0)
}

/// JSON Lines. The file itself is one namespace.
///
/// Calls fsync after every record. Records that were fully written survive a process crash.
/// A partially written last line is truncated from the file when reading. Only that one record is lost, and later
/// appends are not corrupted (if it were kept, the next append would be joined onto it, leaving a broken line in the
/// middle that makes the file unreadable).
/// The file is created with mode 0600 (because it contains request bodies verbatim).
pub struct FileStore {
    path: PathBuf,
    lock: Mutex<()>,
}

impl FileStore {
    pub fn new(path: &str) -> StoreResult<Self> {
        let path = std::path::absolute(path).map_err(|e| format!("パスを解決できない {path}: {e}"))?;
        if let Some(dir) = path.parent() {
            fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
        }
        Ok(FileStore { path, lock: Mutex::new(()) })
    }
}

/// Opens with mode 0600 (creating the file if missing). If `append` is false, it only creates the file and does not
/// touch the contents.
fn private_file(path: &std::path::Path, append: bool) -> std::io::Result<fs::File> {
    let mut o = OpenOptions::new();
    o.create(true).read(true);
    if append {
        o.append(true);
    } else {
        o.write(true); // Create only (do not erase the contents)
    }
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut o, 0o600);
    o.open(path)
}

impl Store for FileStore {
    fn append(&self, record: &Value) -> StoreResult<()> {
        let mut line = serde_json::to_string(record).map_err(|e| e.to_string())?;
        line.push('\n');
        let err = |e: std::io::Error| format!("{}: {e}", self.path.display());
        let _g = self.lock.lock().unwrap_or_else(|e| e.into_inner());
        let mut f = private_file(&self.path, true).map_err(err)?;
        let before = f.metadata().map_err(err)?.len();
        if let Err(e) = f.write_all(line.as_bytes()).and_then(|_| f.sync_all()) {
            // A partial line left behind would be joined with the next append and corrupt it. Restore the length
            // from before the write
            let _ = f.set_len(before);
            return Err(err(e).into());
        }
        Ok(())
    }

    fn read_all(&self) -> StoreResult<Vec<Value>> {
        let err = |e: std::io::Error| format!("{}: {e}", self.path.display());
        let _g = self.lock.lock().unwrap_or_else(|e| e.into_inner());
        let bytes = match fs::read(&self.path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(err(e).into()),
        };
        let mut out = Vec::new();
        let mut offset = 0usize;
        let lines: Vec<&[u8]> = bytes.split_inclusive(|&b| b == b'\n').collect();
        for (i, line) in lines.iter().enumerate() {
            let last = i == lines.len() - 1;
            let terminated = line.ends_with(b"\n");
            let text = std::str::from_utf8(line).map(str::trim).unwrap_or("\u{FFFD}");
            if !text.is_empty() {
                match serde_json::from_str::<Value>(text) {
                    Ok(v) => out.push(v),
                    Err(_) if last && !terminated => {
                        crate::log!("書きかけの最終行を切り詰めた: {}:{}", self.path.display(), i + 1);
                        let f = OpenOptions::new().write(true).open(&self.path).map_err(err)?;
                        f.set_len(offset as u64).and_then(|_| f.sync_all()).map_err(err)?;
                        return Ok(out);
                    }
                    Err(e) => return Err(format!("{}:{}: {e}", self.path.display(), i + 1).into()),
                }
            }
            if last && !terminated && !text.is_empty() {
                // A line whose newline was not written before a crash. It parsed, so keep it and add the newline
                // so the next append is not joined onto it
                let mut f = private_file(&self.path, true).map_err(err)?;
                f.write_all(b"\n").and_then(|_| f.sync_all()).map_err(err)?;
            }
            offset += line.len();
        }
        Ok(out)
    }

    fn clear(&self) -> StoreResult<()> {
        let _g = self.lock.lock().unwrap_or_else(|e| e.into_inner());
        match fs::remove_file(&self.path) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(format!("{}: {e}", self.path.display()).into()),
            _ => Ok(()),
        }
    }

    fn describe(&self) -> String {
        format!("file:{}", self.path.display())
    }
}

#[cfg(feature = "sqlite")]
pub struct SqliteStore {
    path: PathBuf,
    ns: String,
    db: Mutex<rusqlite::Connection>,
}

#[cfg(feature = "sqlite")]
impl SqliteStore {
    pub fn new(path: &str, ns: &str) -> StoreResult<Self> {
        let path = std::path::absolute(path).map_err(|e| format!("パスを解決できない {path}: {e}"))?;
        // The file contains request bodies verbatim, so create it with mode 0600 first so other users cannot read it
        private_file(&path, false).map_err(|e| format!("{}: {e}", path.display()))?;
        let db = rusqlite::Connection::open(&path).map_err(|e| format!("{}: {e}", path.display()))?;
        // journal_mode returns a result row, so run it with a query instead of execute
        db.query_row("PRAGMA journal_mode=WAL", [], |_| Ok(())).map_err(|e| e.to_string())?;
        db.execute(
            "CREATE TABLE IF NOT EXISTS journal (ns TEXT NOT NULL, seq INTEGER NOT NULL, rec TEXT NOT NULL, PRIMARY KEY (ns, seq))",
            [],
        ).map_err(|e| e.to_string())?;
        Ok(SqliteStore { path, ns: ns.to_string(), db: Mutex::new(db) })
    }
}

#[cfg(feature = "sqlite")]
impl Store for SqliteStore {
    fn append(&self, record: &Value) -> StoreResult<()> {
        let rec = serde_json::to_string(record).map_err(|e| e.to_string())?;
        let seq = seq_of(record);
        let db = self.db.lock().unwrap_or_else(|e| e.into_inner());
        match db.execute("INSERT INTO journal VALUES (?1, ?2, ?3)", rusqlite::params![self.ns, seq as i64, rec]) {
            Ok(_) => Ok(()),
            Err(rusqlite::Error::SqliteFailure(e, _)) if e.code == rusqlite::ErrorCode::ConstraintViolation => {
                Err(StoreError::Conflict(format!("seq {seq} は既に書かれている(別の書き手がいる?)")))
            }
            Err(e) => Err(e.to_string().into()),
        }
    }

    fn read_all(&self) -> StoreResult<Vec<Value>> {
        let db = self.db.lock().unwrap_or_else(|e| e.into_inner());
        let mut stmt = db.prepare("SELECT rec FROM journal WHERE ns = ?1 ORDER BY seq").map_err(|e| e.to_string())?;
        let rows = stmt.query_map([&self.ns], |r| r.get::<_, String>(0)).map_err(|e| e.to_string())?;
        let mut out = Vec::new();
        for row in rows {
            let text = row.map_err(|e| e.to_string())?;
            out.push(serde_json::from_str(&text).map_err(|e| e.to_string())?);
        }
        Ok(out)
    }

    fn clear(&self) -> StoreResult<()> {
        let db = self.db.lock().unwrap_or_else(|e| e.into_inner());
        db.execute("DELETE FROM journal WHERE ns = ?1", [&self.ns]).map_err(|e| e.to_string())?;
        Ok(())
    }

    fn describe(&self) -> String {
        format!("sqlite:{}#{}", self.path.display(), self.ns)
    }
}

pub fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'%' if i + 2 < b.len() => {
                let hex = std::str::from_utf8(&b[i + 1..i + 3]).ok().and_then(|h| u8::from_str_radix(h, 16).ok());
                match hex {
                    Some(v) => {
                        out.push(v);
                        i += 3;
                        continue;
                    }
                    None => out.push(b'%'),
                }
            }
            b'+' => out.push(b' '),
            c => out.push(c),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Splits `scheme://netloc/path?k=v&...` into its parts.
pub fn split_url(url: &str) -> (String, String, HashMap<String, String>) {
    let rest = url.split_once("://").map(|(_, r)| r).unwrap_or(url);
    let (main, query) = rest.split_once('?').unwrap_or((rest, ""));
    let (netloc, path) = main.split_once('/').unwrap_or((main, ""));
    let opts = query
        .split('&')
        .filter(|s| !s.is_empty())
        .filter_map(|kv| {
            let (k, v) = kv.split_once('=')?;
            Some((percent_decode(k), percent_decode(v)))
        })
        .collect();
    (netloc.to_string(), path.trim_matches('/').to_string(), opts)
}

/// Characters allowed in a namespace. In S3 the namespace becomes a key prefix, so allowing `/` would mix `a/b` into
/// the listing of `a`.
pub fn validate_namespace(ns: &str) -> StoreResult<()> {
    let ok = !ns.is_empty() && ns.len() <= 128 && ns.bytes().all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b));
    if ok {
        Ok(())
    } else {
        Err(format!("名前空間 {ns:?} には英数字と . _ - だけを使う(1〜128 文字)").into())
    }
}

pub fn open_store(url: &str, namespace: &str) -> StoreResult<Box<dyn Store>> {
    validate_namespace(namespace)?;
    let (scheme, rest) = url.split_once(':').unwrap_or((url, ""));
    match scheme {
        "file" => Ok(Box::new(FileStore::new(rest)?)),
        #[cfg(feature = "sqlite")]
        "sqlite" => Ok(Box::new(SqliteStore::new(rest, namespace)?)),
        #[cfg(not(feature = "sqlite"))]
        "sqlite" => Err("この版は sqlite なしでビルドされている(cargo build --features sqlite)".to_string().into()),
        "dynamodb" => {
            let (table, _, opts) = split_url(url);
            Ok(Box::new(crate::aws::DynamoDbStore::new(&table, namespace, &opts)?))
        }
        "s3" => {
            let (bucket, prefix, opts) = split_url(url);
            Ok(Box::new(crate::aws::S3Store::new(&bucket, &prefix, namespace, &opts)?))
        }
        _ => Err(format!("保存先の形式がわからない: {url}(file: / sqlite: / dynamodb:// / s3://)").into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn tmp(name: &str) -> String {
        let d = std::env::temp_dir().join(format!("emupersist-test-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        d.join("sub").join(name).to_string_lossy().into_owned()
    }

    #[test]
    fn file_roundtrip_and_truncated_tail() {
        let s = FileStore::new(&tmp("j.jsonl")).unwrap();
        s.append(&json!({"seq": 1, "body": "フリーレン"})).unwrap();
        s.append(&json!({"seq": 2})).unwrap();
        OpenOptions::new().append(true).open(&s.path).unwrap().write_all(b"{\"seq\": 3, \"bo").unwrap();
        let all = s.read_all().unwrap();
        assert_eq!(all.iter().map(seq_of).collect::<Vec<_>>(), vec![1, 2]);
        assert_eq!(all[0]["body"], "フリーレン");
        // The partial line was truncated, so later appends are not corrupted (regression test for a bug reproduced in
        // review)
        s.append(&json!({"seq": 3})).unwrap();
        s.append(&json!({"seq": 4})).unwrap();
        assert_eq!(s.read_all().unwrap().iter().map(seq_of).collect::<Vec<_>>(), vec![1, 2, 3, 4]);
        // A last line missing only its newline is kept, and the newline is added
        OpenOptions::new().append(true).open(&s.path).unwrap().write_all(b"{\"seq\": 5}").unwrap();
        assert_eq!(s.read_all().unwrap().len(), 5);
        s.append(&json!({"seq": 6})).unwrap();
        assert_eq!(s.read_all().unwrap().len(), 6);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(fs::metadata(&s.path).unwrap().permissions().mode() & 0o777, 0o600);
        }
        s.clear().unwrap();
        assert!(s.read_all().unwrap().is_empty());
    }

    #[cfg(feature = "sqlite")]
    #[test]
    fn sqlite_namespaces_and_conflict() {
        let p = tmp("j.db");
        fs::create_dir_all(std::path::Path::new(&p).parent().unwrap()).unwrap();
        let a = SqliteStore::new(&p, "a").unwrap();
        let b = SqliteStore::new(&p, "b").unwrap();
        a.append(&json!({"seq": 1})).unwrap();
        b.append(&json!({"seq": 1})).unwrap();
        assert!(matches!(a.append(&json!({"seq": 1})), Err(StoreError::Conflict(_))));
        a.clear().unwrap();
        assert!(a.read_all().unwrap().is_empty());
        assert_eq!(b.read_all().unwrap().len(), 1);
    }

    #[test]
    fn url_parts() {
        let (n, p, o) = split_url("s3://bkt/a/b?region=us-east-1&endpoint=https%3A%2F%2F127.0.0.1%3A9500");
        assert_eq!((n.as_str(), p.as_str()), ("bkt", "a/b"));
        assert_eq!(o["endpoint"], "https://127.0.0.1:9500");
        assert!(open_store("redis://x", "default").is_err());
        for bad in ["", "a/b", "../x", "名前"] {
            assert!(validate_namespace(bad).is_err(), "{bad}");
        }
        assert!(validate_namespace("feature-x.v2_1").is_ok());
    }
}
