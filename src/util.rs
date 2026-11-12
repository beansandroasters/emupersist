//! 小さな道具: base64、URI エンコード、UTC 日時、CRC32、zlib。
//! どれも数十行で書けるので、そのためだけにクレートを足さない。

use std::time::{SystemTime, UNIX_EPOCH};

#[macro_export]
macro_rules! log {
    ($($t:tt)*) => { eprintln!("[emupersist] {}", format!($($t)*)) };
}

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

pub fn b64encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
        let n = (b[0] as u32) << 16 | (b[1] as u32) << 8 | b[2] as u32;
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(B64[(n >> (18 - 6 * i) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

pub fn b64decode(s: &str) -> Result<Vec<u8>, String> {
    let mut out = Vec::with_capacity(s.len() / 4 * 3);
    let (mut acc, mut bits) = (0u32, 0);
    for c in s.bytes() {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            b'=' | b'\n' | b'\r' => continue,
            _ => return Err(format!("base64 に使えない文字: {:?}", c as char)),
        };
        acc = acc << 6 | v as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    Ok(out)
}

/// RFC 3986 の非予約文字(と `safe` に含めた文字)以外を %XX にする。
pub fn quote(s: &str, safe: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b"-_.~".contains(&b) || safe.as_bytes().contains(&b) {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

pub fn now_f64() -> f64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs_f64()).unwrap_or(0.0)
}

/// UNIX 秒から (年, 月, 日, 時, 分, 秒)。Howard Hinnant の civil_from_days。
pub fn civil(secs: i64) -> (i64, u32, u32, u32, u32, u32) {
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400) as u32;
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = yoe + era * 400 + if m <= 2 { 1 } else { 0 };
    (y, m, d, rem / 3600, rem / 60 % 60, rem % 60)
}

/// ISO 8601(`2026-11-12T00:00:00Z` や `+00:00` 付き)を UNIX 秒に。credential_process の Expiration 用。
pub fn parse_iso8601(s: &str) -> Option<i64> {
    let b = s.as_bytes();
    if b.len() < 19 {
        return None;
    }
    let num = |r: std::ops::Range<usize>| s.get(r)?.parse::<i64>().ok();
    let (y, mo, d, h, mi, se) = (num(0..4)?, num(5..7)?, num(8..10)?, num(11..13)?, num(14..16)?, num(17..19)?);
    let (yy, mm) = if mo <= 2 { (y - 1, mo + 9) } else { (y, mo - 3) };
    let era = yy.div_euclid(400);
    let yoe = yy - era * 400;
    let doy = (153 * mm + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    let mut t = days * 86_400 + h * 3600 + mi * 60 + se;
    // 小数秒を飛ばしてからタイムゾーン
    let mut i = 19;
    if b.get(i) == Some(&b'.') {
        i += 1;
        while b.get(i).is_some_and(|c| c.is_ascii_digit()) {
            i += 1;
        }
    }
    match b.get(i) {
        Some(b'+') | Some(b'-') => {
            let sign = if b[i] == b'+' { 1 } else { -1 };
            let oh = num(i + 1..i + 3)?;
            let om = num(i + 4..i + 6).unwrap_or(0);
            t -= sign * (oh * 3600 + om * 60);
        }
        _ => {}
    }
    Some(t)
}

static CRC_TABLE: std::sync::OnceLock<[u32; 256]> = std::sync::OnceLock::new();

/// zlib.crc32 と同じ値(DynamoDB の x-amz-crc32)。
pub fn crc32(data: &[u8]) -> u32 {
    let table = CRC_TABLE.get_or_init(|| {
        let mut t = [0u32; 256];
        for (i, slot) in t.iter_mut().enumerate() {
            let mut c = i as u32;
            for _ in 0..8 {
                c = if c & 1 != 0 { 0xEDB8_8320 ^ (c >> 1) } else { c >> 1 };
            }
            *slot = c;
        }
        t
    });
    let mut c = !0u32;
    for &b in data {
        c = table[((c ^ b as u32) & 0xFF) as usize] ^ (c >> 8);
    }
    !c
}

fn crc_table(poly: u32) -> [u32; 256] {
    let mut t = [0u32; 256];
    for (i, slot) in t.iter_mut().enumerate() {
        let mut c = i as u32;
        for _ in 0..8 {
            c = if c & 1 != 0 { poly ^ (c >> 1) } else { c >> 1 };
        }
        *slot = c;
    }
    t
}

static CRC32C_TABLE: std::sync::OnceLock<[u32; 256]> = std::sync::OnceLock::new();

/// CRC32C(Castagnoli)。S3 の x-amz-checksum-crc32c。
pub fn crc32c(data: &[u8]) -> u32 {
    let table = CRC32C_TABLE.get_or_init(|| crc_table(0x82F6_3B78));
    let mut c = !0u32;
    for &b in data {
        c = table[((c ^ b as u32) & 0xFF) as usize] ^ (c >> 8);
    }
    !c
}

static CRC64_TABLE: std::sync::OnceLock<[u64; 256]> = std::sync::OnceLock::new();

/// CRC64/NVME。S3 の x-amz-checksum-crc64nvme。
pub fn crc64nvme(data: &[u8]) -> u64 {
    let table = CRC64_TABLE.get_or_init(|| {
        let mut t = [0u64; 256];
        for (i, slot) in t.iter_mut().enumerate() {
            let mut c = i as u64;
            for _ in 0..8 {
                c = if c & 1 != 0 { 0x9A6C_9329_AC4B_C9B5 ^ (c >> 1) } else { c >> 1 };
            }
            *slot = c;
        }
        t
    });
    let mut c = !0u64;
    for &b in data {
        c = table[((c ^ b as u64) & 0xFF) as usize] ^ (c >> 8);
    }
    !c
}

/// MD5(RFC 1321)。S3 の Content-MD5 を付け直すためだけに使う。ring は MD5 を持たない。
pub fn md5(data: &[u8]) -> [u8; 16] {
    const S: [u32; 64] = [
        7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14,
        20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6,
        10, 15, 21,
    ];
    let k: Vec<u32> = (0..64).map(|i| ((i as f64 + 1.0).sin().abs() * 4_294_967_296.0) as u32).collect();
    let mut msg = data.to_vec();
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&((data.len() as u64).wrapping_mul(8)).to_le_bytes());
    let (mut a0, mut b0, mut c0, mut d0) = (0x6745_2301u32, 0xEFCD_AB89u32, 0x98BA_DCFEu32, 0x1032_5476u32);
    for chunk in msg.chunks(64) {
        let m: Vec<u32> = chunk.chunks(4).map(|w| u32::from_le_bytes([w[0], w[1], w[2], w[3]])).collect();
        let (mut a, mut b, mut c, mut d) = (a0, b0, c0, d0);
        for i in 0..64 {
            let (f, g) = match i / 16 {
                0 => ((b & c) | (!b & d), i),
                1 => ((d & b) | (!d & c), (5 * i + 1) % 16),
                2 => (b ^ c ^ d, (3 * i + 5) % 16),
                _ => (c ^ (b | !d), (7 * i) % 16),
            };
            let f = f.wrapping_add(a).wrapping_add(k[i]).wrapping_add(m[g]);
            a = d;
            d = c;
            c = b;
            b = b.wrapping_add(f.rotate_left(S[i]));
        }
        a0 = a0.wrapping_add(a);
        b0 = b0.wrapping_add(b);
        c0 = c0.wrapping_add(c);
        d0 = d0.wrapping_add(d);
    }
    let mut out = [0u8; 16];
    for (i, v) in [a0, b0, c0, d0].iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&v.to_le_bytes());
    }
    out
}

/// zlib(ヘッダつき)で圧縮する。DynamoDB / S3 に置くレコードの形式。
pub fn zlib_compress(data: &[u8]) -> Vec<u8> {
    miniz_oxide::deflate::compress_to_vec_zlib(data, 6)
}

pub fn zlib_decompress(data: &[u8]) -> Result<Vec<u8>, String> {
    miniz_oxide::inflate::decompress_to_vec_zlib(data).map_err(|e| format!("zlib の展開に失敗: {e:?}"))
}

pub fn hex(data: &[u8]) -> String {
    data.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_roundtrip() {
        for s in [&b""[..], b"f", b"fo", b"foo", b"foob", "千年".as_bytes()] {
            assert_eq!(b64decode(&b64encode(s)).unwrap(), s);
        }
        assert_eq!(b64encode(b"foob"), "Zm9vYg==");
    }

    #[test]
    fn quote_reserved() {
        assert_eq!(quote("arn:aws:kms/a b", ""), "arn%3Aaws%3Akms%2Fa%20b");
        assert_eq!(quote("/a b/~c", "/~"), "/a%20b/~c");
    }

    #[test]
    fn dates() {
        assert_eq!(civil(0), (1970, 1, 1, 0, 0, 0));
        assert_eq!(civil(1_762_905_600), (2025, 11, 12, 0, 0, 0));
        assert_eq!(parse_iso8601("2025-11-12T00:00:00Z"), Some(1_762_905_600));
        assert_eq!(parse_iso8601("2025-11-12T09:00:00.123+09:00"), Some(1_762_905_600));
    }

    #[test]
    fn crc_and_zlib() {
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
        assert_eq!(crc32c(b"123456789"), 0xE306_9283);
        assert_eq!(crc64nvme(b"123456789"), 0xAE8B_1486_0A79_9888);
        // 次の3行は MD5 の公開されたテストベクタ(RFC 1321 などに載っている既知のハッシュ値)で、秘密ではない。
        // detect-secrets は16進の高エントロピー文字列という形だけで反応するので、行ごとに抑止する
        assert_eq!(hex(&md5(b"")), "d41d8cd98f00b204e9800998ecf8427e"); // pragma: allowlist secret
        assert_eq!(hex(&md5(b"The quick brown fox jumps over the lazy dog")), "9e107d9d372bb6826bd81d3542a419d6"); // pragma: allowlist secret
        assert_eq!(hex(&md5(&[b'a'; 100])), "36a92cc94a9e0fa21f625f8bfb007adf"); // pragma: allowlist secret
        assert_eq!(zlib_decompress(&zlib_compress(b"hello")).unwrap(), b"hello");
    }
}
