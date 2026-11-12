//! std の TcpStream の上に書いた最小限の HTTP/1.1。
//!
//! 扱うのは、Content-Length と chunked の本文、keep-alive、`Expect: 100-continue`、
//! HEAD / 204 / 304 の本文なし応答だけ。これで AWS SDK と aws-emulator のあいだに立てる。
//! hyper と tokio を入れれば短く書けるが、依存が数十クレート増える。

use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rustls::pki_types::{CertificateDer, ServerName};

pub type Headers = Vec<(String, String)>;

/// 転送の単位を決めるヘッダ。プロキシは中継せず、自分で付け直す。
pub const HOP_BY_HOP: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
    "expect",
    "content-length",
];

pub fn is_hop_by_hop(name: &str) -> bool {
    HOP_BY_HOP.iter().any(|h| name.eq_ignore_ascii_case(h))
}

pub fn header<'a>(headers: &'a Headers, name: &str) -> Option<&'a str> {
    headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
}

#[derive(Debug)]
pub struct Request {
    pub method: String,
    pub target: String,
    pub headers: Headers,
    pub body: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct Response {
    pub status: u16,
    pub headers: Headers,
    pub body: Vec<u8>,
}

fn bad(msg: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.into())
}

/// ヘッダ1行の上限。AWS の署名ヘッダでも数 KB に収まる。
const MAX_LINE: usize = 16 * 1024;
/// ヘッダ部全体の上限と、ヘッダの個数の上限。
const MAX_HEAD: usize = 256 * 1024;
const MAX_HEADERS: usize = 256;

/// 要求を読めなかった理由。`Reject` はクライアントに状態コードで返し、`Io` は接続を閉じる。
#[derive(Debug)]
pub enum ReadError {
    Io(io::Error),
    Reject(u16, String),
}

impl From<io::Error> for ReadError {
    fn from(e: io::Error) -> Self {
        ReadError::Io(e)
    }
}

impl std::fmt::Display for ReadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReadError::Io(e) => write!(f, "{e}"),
            ReadError::Reject(s, m) => write!(f, "{s} {m}"),
        }
    }
}

/// 1行読む(改行込み)。`max` を超える行は 431 で断る。接続が閉じていれば None。
fn read_line_limited<R: BufRead>(r: &mut R, max: usize) -> Result<Option<String>, ReadError> {
    let mut line = Vec::new();
    loop {
        let buf = r.fill_buf()?;
        if buf.is_empty() {
            return if line.is_empty() {
                Ok(None)
            } else {
                Err(io::Error::new(io::ErrorKind::UnexpectedEof, "行の途中で接続が閉じた").into())
            };
        }
        let (take, done) = match buf.iter().position(|&b| b == b'\n') {
            Some(i) => (i + 1, true),
            None => (buf.len(), false),
        };
        if line.len() + take > max {
            return Err(ReadError::Reject(431, format!("1行が {max} バイトを超えた")));
        }
        line.extend_from_slice(&buf[..take]);
        r.consume(take);
        if done {
            return String::from_utf8(line)
                .map(Some)
                .map_err(|_| ReadError::Reject(400, "ヘッダが UTF-8 でない".into()));
        }
    }
}

/// 空行までのヘッダ部を読む。接続が閉じていたら None。
fn read_head<R: BufRead>(r: &mut R) -> Result<Option<(String, Headers)>, ReadError> {
    let first = loop {
        match read_line_limited(r, MAX_LINE)? {
            None => return Ok(None),
            Some(l) if l.trim().is_empty() => continue, // 要求のあいだの空行は読み飛ばす(RFC 9112 2.2)
            Some(l) => break l,
        }
    };
    let mut headers = Vec::new();
    let mut total = first.len();
    loop {
        let line = read_line_limited(r, MAX_LINE)?
            .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "ヘッダの途中で接続が閉じた"))?;
        total += line.len();
        if total > MAX_HEAD || headers.len() >= MAX_HEADERS {
            return Err(ReadError::Reject(431, "ヘッダが大きすぎる".into()));
        }
        let line = line.trim_end_matches(['\r', '\n']);
        if line.is_empty() {
            break;
        }
        let (k, v) = line.split_once(':').ok_or_else(|| ReadError::Reject(400, format!("壊れたヘッダ行: {line}")))?;
        headers.push((k.trim().to_string(), v.trim().to_string()));
    }
    Ok(Some((first.trim_end().to_string(), headers)))
}

/// ちょうど n バイト読む。先に n バイト確保せず、届いた分だけ伸ばす(巨大な宣言値で確保に失敗しないため)。
fn read_exactly<R: Read>(r: &mut R, n: u64, out: &mut Vec<u8>) -> io::Result<()> {
    let before = out.len();
    r.take(n).read_to_end(out)?;
    if (out.len() - before) as u64 != n {
        return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "本文の途中で接続が閉じた"));
    }
    Ok(())
}

fn too_large(max: usize) -> ReadError {
    ReadError::Reject(413, format!("本文が上限 {max} バイトを超えた(--max-body-bytes)"))
}

fn read_chunked<R: BufRead>(r: &mut R, max: usize) -> Result<Vec<u8>, ReadError> {
    let mut out = Vec::new();
    let eof = || io::Error::new(io::ErrorKind::UnexpectedEof, "chunked 本文の途中で接続が閉じた");
    loop {
        let line = read_line_limited(r, MAX_LINE)?.ok_or_else(eof)?;
        let size_hex = line.split(';').next().unwrap_or("").trim();
        let size = u64::from_str_radix(size_hex, 16)
            .map_err(|_| ReadError::Reject(400, format!("chunk の大きさが読めない: {line:?}")))?;
        if size == 0 {
            loop {
                // trailer は読み捨てる
                let t = read_line_limited(r, MAX_LINE)?.ok_or_else(eof)?;
                if t == "\r\n" || t == "\n" {
                    return Ok(out);
                }
            }
        }
        if (out.len() as u64).checked_add(size).is_none_or(|n| n > max as u64) {
            return Err(too_large(max));
        }
        read_exactly(r, size, &mut out)?;
        match read_line_limited(r, MAX_LINE)?.as_deref() {
            Some("\r\n") | Some("\n") => {}
            Some(_) => return Err(ReadError::Reject(400, "chunk の後ろに CRLF がない".into())),
            None => return Err(eof().into()),
        }
    }
}

fn is_chunked(headers: &Headers) -> bool {
    header(headers, "transfer-encoding").is_some_and(|v| v.to_ascii_lowercase().contains("chunked"))
}

fn read_body<R: BufRead>(r: &mut R, headers: &Headers, until_eof: bool, max: usize) -> Result<Vec<u8>, ReadError> {
    if is_chunked(headers) {
        return read_chunked(r, max);
    }
    if let Some(len) = header(headers, "content-length") {
        let n: u64 = len.parse().map_err(|_| ReadError::Reject(400, "Content-Length が数でない".into()))?;
        if n > max as u64 {
            return Err(too_large(max));
        }
        let mut body = Vec::new();
        read_exactly(r, n, &mut body)?;
        return Ok(body);
    }
    let mut body = Vec::new();
    if until_eof {
        r.take(max as u64 + 1).read_to_end(&mut body)?;
        if body.len() > max {
            return Err(too_large(max));
        }
    }
    Ok(body)
}

/// `Connection` ヘッダ(カンマ区切りのトークン)と HTTP の版から、この応答の後に接続を閉じるべきかを決める。
pub fn wants_close(version: &str, headers: &Headers) -> bool {
    let has = |token: &str| {
        headers
            .iter()
            .filter(|(k, _)| k.eq_ignore_ascii_case("connection"))
            .any(|(_, v)| v.split(',').any(|t| t.trim().eq_ignore_ascii_case(token)))
    };
    if version.eq_ignore_ascii_case("HTTP/1.0") {
        !has("keep-alive")
    } else {
        has("close")
    }
}

/// サーバ側: 要求を1つ読む。`Expect: 100-continue` には本文を読む前に 100 を返す。
/// 戻り値の2つ目は、応答の後に接続を閉じるべきか。
pub fn read_request<R: BufRead, W: Write>(
    r: &mut R,
    w: &mut W,
    max_body: usize,
) -> Result<Option<(Request, bool)>, ReadError> {
    let Some((line, headers)) = read_head(r)? else { return Ok(None) };
    let mut parts = line.splitn(3, ' ');
    let (method, target, version) = match (parts.next(), parts.next(), parts.next()) {
        (Some(m), Some(t), v) => (m.to_string(), t.to_string(), v.unwrap_or("HTTP/1.0").to_string()),
        _ => return Err(ReadError::Reject(400, format!("壊れた要求行: {line}"))),
    };
    // 両方あると、前後の機器で本文の切れ目の解釈が割れる(要求の密輸)。RFC 9112 6.1 に従って断る
    if header(&headers, "transfer-encoding").is_some() && header(&headers, "content-length").is_some() {
        return Err(ReadError::Reject(400, "Transfer-Encoding と Content-Length が両方ある".into()));
    }
    if header(&headers, "transfer-encoding").is_some() && !is_chunked(&headers) {
        return Err(ReadError::Reject(501, "chunked 以外の Transfer-Encoding には対応していない".into()));
    }
    if header(&headers, "expect").is_some_and(|v| v.eq_ignore_ascii_case("100-continue")) {
        let declared = header(&headers, "content-length").and_then(|v| v.parse::<u64>().ok()).unwrap_or(0);
        if declared > max_body as u64 {
            return Err(too_large(max_body)); // 100 を返す前に断れば、クライアントは本文を送らない
        }
        w.write_all(b"HTTP/1.1 100 Continue\r\n\r\n")?;
        w.flush()?;
    }
    let close = wants_close(&version, &headers);
    let body = read_body(r, &headers, false, max_body)?;
    Ok(Some((Request { method, target, headers, body }, close)))
}

pub fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        201 => "Created",
        202 => "Accepted",
        204 => "No Content",
        206 => "Partial Content",
        301 => "Moved Permanently",
        302 => "Found",
        304 => "Not Modified",
        307 => "Temporary Redirect",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        409 => "Conflict",
        412 => "Precondition Failed",
        413 => "Content Too Large",
        421 => "Misdirected Request",
        431 => "Request Header Fields Too Large",
        500 => "Internal Server Error",
        501 => "Not Implemented",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        _ => "",
    }
}

/// サーバ側: 応答を1回の write で書く(ヘッダと本文を分けて書くと Nagle と遅延 ACK で待たされる)。
///
/// 204 と 304 には Content-Length を付けない(RFC 9110 8.6)。HEAD のときは本文を書かず、
/// Content-Length は上流が伝えた値をそのまま返す(上流が付けていなければ付けない)。
pub fn write_response<W: Write>(w: &mut W, resp: &Response, head: bool, close: bool) -> io::Result<()> {
    let mut out = format!("HTTP/1.1 {} {}\r\n", resp.status, reason(resp.status)).into_bytes();
    let mut length = None;
    for (k, v) in &resp.headers {
        if k.eq_ignore_ascii_case("content-length") {
            length = Some(v.clone());
        }
        if !is_hop_by_hop(k) {
            out.extend_from_slice(format!("{k}: {v}\r\n").as_bytes());
        }
    }
    let len = match (resp.status, head) {
        (204 | 304, _) => None,
        (_, true) => length,
        (_, false) => Some(resp.body.len().to_string()),
    };
    if let Some(len) = len {
        out.extend_from_slice(format!("Content-Length: {len}\r\n").as_bytes());
    }
    if close {
        out.extend_from_slice(b"Connection: close\r\n");
    }
    out.extend_from_slice(b"\r\n");
    if !head && !matches!(resp.status, 204 | 304) {
        out.extend_from_slice(&resp.body);
    }
    w.write_all(&out)?;
    w.flush()
}

// --- クライアント ---------------------------------------------------------

enum Stream {
    Plain(TcpStream),
    Tls(Box<rustls::StreamOwned<rustls::ClientConnection, TcpStream>>),
}

impl Read for Stream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Stream::Plain(s) => s.read(buf),
            Stream::Tls(s) => s.read(buf),
        }
    }
}

impl Write for Stream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            Stream::Plain(s) => s.write(buf),
            Stream::Tls(s) => s.write(buf),
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        match self {
            Stream::Plain(s) => s.flush(),
            Stream::Tls(s) => s.flush(),
        }
    }
}

/// 1つの宛先への keep-alive 接続のプール。スレッドをまたいで使い回す。
pub struct Client {
    pub url: String,
    pub scheme: String,
    pub authority: String,
    host: String,
    port: u16,
    pub base_path: String,
    tls: Option<Arc<rustls::ClientConfig>>,
    pool: Mutex<Vec<BufReader<Stream>>>,
    timeout: Duration,
}

impl Client {
    /// `ca` があればその CA だけを信頼する(エミュレータの自己署名 CA)。なければ webpki-roots。
    pub fn new(url: &str, ca: Option<&str>, insecure: bool, timeout: Duration) -> Result<Self, String> {
        let (scheme, rest) = url.split_once("://").ok_or_else(|| format!("URL ではない: {url}"))?;
        let (authority, path) = match rest.find('/') {
            Some(i) => (&rest[..i], rest[i..].trim_end_matches('/')),
            None => (rest, ""),
        };
        let default_port = if scheme == "https" { 443 } else { 80 };
        let (host, port) = if let Some(v6) = authority.strip_prefix('[') {
            let (h, rest) = v6.split_once(']').ok_or_else(|| format!("壊れた IPv6 アドレス: {url}"))?;
            let port = match rest.strip_prefix(':') {
                Some(p) => p.parse().map_err(|_| format!("ポートが読めない: {url}"))?,
                None if rest.is_empty() => default_port,
                None => return Err(format!("壊れた IPv6 アドレス: {url}")),
            };
            (h.to_string(), port)
        } else {
            match authority.rsplit_once(':') {
                Some((h, p)) => (h.to_string(), p.parse().map_err(|_| format!("ポートが読めない: {url}"))?),
                None => (authority.to_string(), default_port),
            }
        };
        let tls = if scheme == "https" { Some(Arc::new(tls_config(ca, insecure)?)) } else { None };
        Ok(Client {
            url: url.to_string(),
            scheme: scheme.to_string(),
            authority: authority.to_string(),
            host,
            port,
            base_path: path.to_string(),
            tls,
            pool: Mutex::new(Vec::new()),
            timeout,
        })
    }

    fn connect(&self) -> io::Result<BufReader<Stream>> {
        let tcp = TcpStream::connect((self.host.as_str(), self.port))?;
        tcp.set_nodelay(true)?;
        tcp.set_read_timeout(Some(self.timeout))?;
        tcp.set_write_timeout(Some(self.timeout))?;
        let stream = match &self.tls {
            None => Stream::Plain(tcp),
            Some(cfg) => {
                let name = ServerName::try_from(self.host.clone()).map_err(|e| bad(format!("{e}")))?;
                let conn = rustls::ClientConnection::new(cfg.clone(), name).map_err(|e| bad(format!("{e}")))?;
                Stream::Tls(Box::new(rustls::StreamOwned::new(conn, tcp)))
            }
        };
        Ok(BufReader::with_capacity(64 * 1024, stream))
    }

    /// 要求を送って応答を読む。`path` は base_path の後ろに付く(クエリ込み)。
    ///
    /// 使い回した接続がすでに閉じられていたときは、新しい接続で1回だけやり直す。やり直すのは、
    /// 応答を1バイトも受け取る前に接続が切れていた場合だけ(エミュレータが要求を処理していないので、
    /// 書き込み系でも二重適用にならない)。応答の途中で切れた場合はやり直さず、エラーにする。
    pub fn send(&self, method: &str, path: &str, headers: &Headers, body: &[u8]) -> io::Result<Response> {
        let full = format!("{}{}", self.base_path, path);
        let mut req = format!("{method} {full} HTTP/1.1\r\n").into_bytes();
        let mut has_host = false;
        for (k, v) in headers {
            if is_hop_by_hop(k) {
                continue;
            }
            has_host |= k.eq_ignore_ascii_case("host");
            req.extend_from_slice(format!("{k}: {v}\r\n").as_bytes());
        }
        if !has_host {
            req.extend_from_slice(format!("Host: {}\r\n", self.authority).as_bytes());
        }
        if !body.is_empty() || matches!(method, "POST" | "PUT" | "PATCH") {
            req.extend_from_slice(format!("Content-Length: {}\r\n", body.len()).as_bytes());
        }
        req.extend_from_slice(b"\r\n");
        req.extend_from_slice(body);

        let pooled = self.pool.lock().unwrap_or_else(|e| e.into_inner()).pop();
        let reused = pooled.is_some();
        let mut conn = match pooled {
            Some(c) => c,
            None => self.connect()?,
        };
        let result = match self.exchange(&mut conn, &req, method == "HEAD") {
            Err(Exchange::BeforeResponse(_)) if reused => {
                conn = self.connect()?;
                self.exchange(&mut conn, &req, method == "HEAD")
            }
            other => other,
        };
        match result {
            Ok((resp, keep)) => {
                if keep {
                    self.pool.lock().unwrap_or_else(|e| e.into_inner()).push(conn);
                }
                Ok(resp)
            }
            Err(Exchange::BeforeResponse(e) | Exchange::After(e)) => Err(e),
        }
    }

    fn exchange(&self, conn: &mut BufReader<Stream>, req: &[u8], head: bool) -> Result<(Response, bool), Exchange> {
        let stale = |e: io::Error| {
            if matches!(
                e.kind(),
                io::ErrorKind::BrokenPipe | io::ErrorKind::ConnectionReset | io::ErrorKind::ConnectionAborted
            ) {
                Exchange::BeforeResponse(e)
            } else {
                Exchange::After(e)
            }
        };
        conn.get_mut().write_all(req).map_err(stale)?;
        conn.get_mut().flush().map_err(stale)?;
        // 応答の最初のバイトが来るまでに切れたかどうかで、やり直してよいかが決まる
        match conn.fill_buf() {
            Ok([]) => {
                return Err(Exchange::BeforeResponse(io::Error::new(
                    io::ErrorKind::ConnectionAborted,
                    "応答の前に接続が閉じた",
                )))
            }
            Ok(_) => {}
            Err(e) => return Err(stale(e)),
        }
        let after = |e: ReadError| {
            Exchange::After(match e {
                ReadError::Io(e) => e,
                ReadError::Reject(s, m) => bad(format!("上流の応答が壊れている: {s} {m}")),
            })
        };
        loop {
            let (line, headers) = read_head(conn).map_err(after)?.ok_or_else(|| {
                Exchange::After(io::Error::new(io::ErrorKind::UnexpectedEof, "応答の途中で接続が閉じた"))
            })?;
            let mut parts = line.split(' ');
            let version = parts.next().unwrap_or("HTTP/1.1").to_string();
            let status: u16 = parts
                .next()
                .and_then(|s| s.parse().ok())
                .ok_or_else(|| Exchange::After(bad(format!("壊れた状態行: {line}"))))?;
            if (100..200).contains(&status) {
                continue; // 100 Continue などの中間応答
            }
            let close = wants_close(&version, &headers);
            let no_body = head || status == 204 || status == 304;
            let has_len = header(&headers, "content-length").is_some() || is_chunked(&headers);
            // 上流(エミュレータ・AWS)の応答は信頼する相手なので、大きさの上限は掛けない。
            // 宣言された大きさを先に確保しないので、壊れた値でも確保の失敗では落ちない
            let body = if no_body { Vec::new() } else { read_body(conn, &headers, true, usize::MAX).map_err(after)? };
            return Ok((Response { status, headers, body }, !close && (no_body || has_len)));
        }
    }
}

enum Exchange {
    /// 応答を1バイトも受け取る前に切れた(使い回した接続が向こうで閉じられていた)
    BeforeResponse(io::Error),
    After(io::Error),
}

fn tls_config(ca: Option<&str>, insecure: bool) -> Result<rustls::ClientConfig, String> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .map_err(|e| e.to_string())?;
    if insecure {
        return Ok(builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerify(provider)))
            .with_no_client_auth());
    }
    let mut roots = rustls::RootCertStore::empty();
    match ca {
        Some(path) => {
            use rustls::pki_types::pem::PemObject;
            let certs: Vec<CertificateDer> = CertificateDer::pem_file_iter(path)
                .map_err(|e| format!("CA を読めない {path}: {e}"))?
                .collect::<Result<_, _>>()
                .map_err(|e| format!("CA を読めない {path}: {e}"))?;
            for c in certs {
                roots.add(c).map_err(|e| format!("CA を登録できない {path}: {e}"))?;
            }
        }
        None => roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned()),
    }
    Ok(builder.with_root_certificates(roots).with_no_client_auth())
}

/// `--insecure` を明示したときだけ使う。証明書を検証しない。
#[derive(Debug)]
struct NoVerify(Arc<rustls::crypto::CryptoProvider>);

impl rustls::client::danger::ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        m: &[u8],
        c: &CertificateDer<'_>,
        d: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(m, c, d, &self.0.signature_verification_algorithms)
    }
    fn verify_tls13_signature(
        &self,
        m: &[u8],
        c: &CertificateDer<'_>,
        d: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(m, c, d, &self.0.signature_verification_algorithms)
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn read(raw: &[u8], max: usize) -> Result<Option<(Request, bool)>, ReadError> {
        read_request(&mut Cursor::new(raw), &mut Vec::new(), max)
    }

    #[test]
    fn reads_chunked_request_and_sends_100_continue() {
        let raw = b"PUT /b/k HTTP/1.1\r\nHost: x\r\nExpect: 100-continue\r\nTransfer-Encoding: chunked\r\n\r\n\
                    3\r\nabc\r\n2;ext=1\r\nde\r\n0\r\nx-trailer: 1\r\n\r\n";
        let mut out = Vec::new();
        let (req, close) = read_request(&mut Cursor::new(&raw[..]), &mut out, 1 << 20).unwrap().unwrap();
        assert_eq!((req.method.as_str(), req.target.as_str(), req.body.as_slice()), ("PUT", "/b/k", &b"abcde"[..]));
        assert_eq!(out, b"HTTP/1.1 100 Continue\r\n\r\n");
        assert!(!close);
    }

    #[test]
    fn huge_content_length_is_rejected_without_allocating() {
        let raw = b"POST / HTTP/1.1\r\nContent-Length: 999999999999999\r\n\r\nabc";
        assert!(matches!(read(raw, 1 << 20), Err(ReadError::Reject(413, _))));
        // 上限内でも、宣言より短く切れたら EOF(先に確保しないので落ちない)
        let raw = b"POST / HTTP/1.1\r\nContent-Length: 100\r\n\r\nabc";
        assert!(matches!(read(raw, 1 << 20), Err(ReadError::Io(e)) if e.kind() == io::ErrorKind::UnexpectedEof));
    }

    #[test]
    fn oversized_headers_are_rejected() {
        let mut raw = b"GET / HTTP/1.1\r\nX: ".to_vec();
        raw.extend(std::iter::repeat_n(b'a', MAX_LINE + 1));
        assert!(matches!(read(&raw, 1 << 20), Err(ReadError::Reject(431, _))));
        let mut raw = b"GET / HTTP/1.1\r\n".to_vec();
        for i in 0..=MAX_HEADERS {
            raw.extend(format!("X-{i}: 1\r\n").as_bytes());
        }
        assert!(matches!(read(&raw, 1 << 20), Err(ReadError::Reject(431, _))));
    }

    #[test]
    fn truncated_or_malformed_chunked_is_an_error() {
        let base = b"PUT / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec();
        for tail in [&b"3\r\nabc\r\n"[..], b"3\r\nabc", b"3\r\nabcXX0\r\n\r\n", b"ffffffffffffffff\r\n"] {
            let mut raw = base.clone();
            raw.extend_from_slice(tail);
            assert!(read(&raw, 1 << 20).is_err(), "{:?}", String::from_utf8_lossy(tail));
        }
        let mut raw = base.clone();
        raw.extend_from_slice(b"10\r\n0123456789abcdef\r\n0\r\n\r\n");
        assert!(matches!(read(&raw, 8), Err(ReadError::Reject(413, _))));
    }

    #[test]
    fn smuggling_shapes_are_rejected() {
        let raw = b"POST / HTTP/1.1\r\nContent-Length: 3\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n";
        assert!(matches!(read(raw, 1 << 20), Err(ReadError::Reject(400, _))));
        let raw = b"POST / HTTP/1.1\r\nTransfer-Encoding: gzip\r\n\r\n";
        assert!(matches!(read(raw, 1 << 20), Err(ReadError::Reject(501, _))));
    }

    #[test]
    fn connection_tokens_and_http10() {
        let h = |v: &str| vec![("Connection".to_string(), v.to_string())];
        assert!(wants_close("HTTP/1.1", &h("keep-alive, close")));
        assert!(!wants_close("HTTP/1.1", &h("keep-alive")));
        assert!(wants_close("HTTP/1.0", &vec![]));
        assert!(!wants_close("HTTP/1.0", &h("Keep-Alive")));
    }

    #[test]
    fn content_length_rules_on_write() {
        let write = |status, headers: Headers, head| {
            let mut out = Vec::new();
            write_response(&mut out, &Response { status, headers, body: vec![] }, head, false).unwrap();
            String::from_utf8(out).unwrap()
        };
        assert!(write(200, vec![("Content-Length".into(), "42".into())], true).ends_with("Content-Length: 42\r\n\r\n"));
        assert!(!write(200, vec![("Transfer-Encoding".into(), "chunked".into())], true).contains("Content-Length"));
        assert!(!write(204, vec![], false).contains("Content-Length"));
        assert!(write(200, vec![], false).contains("Content-Length: 0"));
    }

    #[test]
    fn ipv6_port_errors() {
        assert!(Client::new("http://[::1]:x/", None, false, Duration::from_secs(1)).is_err());
        assert!(Client::new("http://[::1]:8080/", None, false, Duration::from_secs(1)).is_ok());
    }
}
