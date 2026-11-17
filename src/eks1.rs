//! Format file terenkripsi EKS1: header, lalu chunk AES-256-GCM berurutan.
//!
//! ```text
//! header = "EKS1" || format(1) || LP16(content_alg) || LP16(document_id)
//!          || version(4) || chunk_size(4) || nonce_prefix(8)
//! chunk  = AES-256-GCM(DEK, nonce = nonce_prefix || index(4),
//!                      AAD = SHA-256(header) || index(4) || final(1))
//! ```
//!
//! AAD mengikat setiap chunk ke header, posisinya, dan penanda chunk terakhir,
//! sehingga chunk yang ditukar, dihapus, ditambah, atau file yang dipotong
//! terdeteksi. Setiap DEK hanya boleh dipakai untuk satu file (satu versi dokumen).

use std::io::{self, BufRead, BufReader, Read, Write};

use aws_lc_rs::aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};
use aws_lc_rs::{digest, rand};
use thiserror::Error;
use zeroize::Zeroizing;

pub const CONTENT_ALG: &str = "AES256GCM-CHUNK-v1";
pub const DEFAULT_CHUNK_SIZE: u32 = 1 << 20;

const MAGIC: &[u8; 4] = b"EKS1";
const FORMAT_VERSION: u8 = 1;
const TAG_LEN: usize = 16;
const PREFIX_LEN: usize = 8;
const MIN_CHUNK: u32 = 4 << 10;
const MAX_CHUNK: u32 = 16 << 20;
const MAX_FIELD: usize = 1024;

#[derive(Debug, Error)]
pub enum Eks1Error {
    #[error("format EKS1 tidak valid")]
    Format,
    #[error("autentikasi EKS1 gagal")]
    Auth,
    #[error("DEK harus 32 byte")]
    BadKey,
    #[error("I/O: {0}")]
    Io(#[from] io::Error),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    pub document_id: String,
    pub version: u32,
    pub chunk_size: u32,
    pub content_alg: String,
    prefix: [u8; PREFIX_LEN],
}

impl Header {
    fn marshal(&self) -> Result<Vec<u8>, Eks1Error> {
        if self.document_id.is_empty()
            || self.document_id.len() > MAX_FIELD
            || self.version == 0
            || !(MIN_CHUNK..=MAX_CHUNK).contains(&self.chunk_size)
        {
            return Err(Eks1Error::Format);
        }
        let mut b = Vec::with_capacity(64 + self.document_id.len());
        b.extend_from_slice(MAGIC);
        b.push(FORMAT_VERSION);
        push_lp16(&mut b, self.content_alg.as_bytes());
        push_lp16(&mut b, self.document_id.as_bytes());
        b.extend_from_slice(&self.version.to_be_bytes());
        b.extend_from_slice(&self.chunk_size.to_be_bytes());
        b.extend_from_slice(&self.prefix);
        Ok(b)
    }
}

fn push_lp16(b: &mut Vec<u8>, v: &[u8]) {
    b.extend_from_slice(&(v.len() as u16).to_be_bytes());
    b.extend_from_slice(v);
}

/// Membaca dan memvalidasi header. Mengembalikan header dan byte mentahnya.
pub fn read_header<R: Read>(r: &mut R) -> Result<(Header, Vec<u8>), Eks1Error> {
    let mut raw = Vec::with_capacity(128);
    let mut fixed = [0u8; 5];
    r.read_exact(&mut fixed).map_err(|_| Eks1Error::Format)?;
    if &fixed[..4] != MAGIC || fixed[4] != FORMAT_VERSION {
        return Err(Eks1Error::Format);
    }
    raw.extend_from_slice(&fixed);

    let read_lp = |r: &mut R, raw: &mut Vec<u8>| -> Result<String, Eks1Error> {
        let mut l = [0u8; 2];
        r.read_exact(&mut l).map_err(|_| Eks1Error::Format)?;
        let n = u16::from_be_bytes(l) as usize;
        if n == 0 || n > MAX_FIELD {
            return Err(Eks1Error::Format);
        }
        let mut v = vec![0u8; n];
        r.read_exact(&mut v).map_err(|_| Eks1Error::Format)?;
        raw.extend_from_slice(&l);
        raw.extend_from_slice(&v);
        String::from_utf8(v).map_err(|_| Eks1Error::Format)
    };
    let content_alg = read_lp(r, &mut raw)?;
    if content_alg != CONTENT_ALG {
        return Err(Eks1Error::Format);
    }
    let document_id = read_lp(r, &mut raw)?;

    let mut tail = [0u8; 8 + PREFIX_LEN];
    r.read_exact(&mut tail).map_err(|_| Eks1Error::Format)?;
    raw.extend_from_slice(&tail);
    let version = u32::from_be_bytes(tail[0..4].try_into().unwrap());
    let chunk_size = u32::from_be_bytes(tail[4..8].try_into().unwrap());
    let mut prefix = [0u8; PREFIX_LEN];
    prefix.copy_from_slice(&tail[8..]);
    if version == 0 || !(MIN_CHUNK..=MAX_CHUNK).contains(&chunk_size) {
        return Err(Eks1Error::Format);
    }
    Ok((
        Header {
            document_id,
            version,
            chunk_size,
            content_alg,
            prefix,
        },
        raw,
    ))
}

fn chunk_aad(header_hash: &[u8], index: u32, last: bool) -> Vec<u8> {
    let mut aad = Vec::with_capacity(32 + 4 + 1);
    aad.extend_from_slice(header_hash);
    aad.extend_from_slice(&index.to_be_bytes());
    aad.push(u8::from(last));
    aad
}

fn chunk_nonce(prefix: &[u8; PREFIX_LEN], index: u32) -> Nonce {
    let mut n = [0u8; 12];
    n[..PREFIX_LEN].copy_from_slice(prefix);
    n[PREFIX_LEN..].copy_from_slice(&index.to_be_bytes());
    Nonce::assume_unique_for_key(n)
}

fn aead_key(dek: &[u8]) -> Result<LessSafeKey, Eks1Error> {
    if dek.len() != 32 {
        return Err(Eks1Error::BadKey);
    }
    Ok(LessSafeKey::new(
        UnboundKey::new(&AES_256_GCM, dek).map_err(|_| Eks1Error::BadKey)?,
    ))
}

/// Membaca sampai `buf` penuh atau EOF; mengembalikan jumlah byte terbaca.
fn read_full<R: Read>(r: &mut R, buf: &mut [u8]) -> io::Result<usize> {
    let mut n = 0;
    while n < buf.len() {
        match r.read(&mut buf[n..]) {
            Ok(0) => break,
            Ok(k) => n += k,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(n)
}

fn at_eof<R: BufRead>(r: &mut R) -> io::Result<bool> {
    Ok(r.fill_buf()?.is_empty())
}

/// Mengenkripsi `src` ke `dst` dalam format EKS1. Prefix nonce selalu acak.
/// `chunk_size` 0 berarti 1 MiB.
pub fn encrypt<R: Read, W: Write>(
    dst: &mut W,
    src: R,
    dek: &[u8],
    document_id: &str,
    version: u32,
    chunk_size: u32,
) -> Result<(), Eks1Error> {
    let key = aead_key(dek)?;
    let chunk_size = if chunk_size == 0 {
        DEFAULT_CHUNK_SIZE
    } else {
        chunk_size
    };
    let mut h = Header {
        document_id: document_id.to_string(),
        version,
        chunk_size,
        content_alg: CONTENT_ALG.to_string(),
        prefix: [0u8; PREFIX_LEN],
    };
    rand::fill(&mut h.prefix).map_err(|_| Eks1Error::Format)?;
    let hdr = h.marshal()?;
    dst.write_all(&hdr)?;
    let hh = digest::digest(&digest::SHA256, &hdr);

    let mut src = BufReader::with_capacity(chunk_size as usize + 1, src);
    let mut buf = Zeroizing::new(vec![0u8; chunk_size as usize + TAG_LEN]);
    let mut index: u32 = 0;
    loop {
        let n = read_full(&mut src, &mut buf[..chunk_size as usize])?;
        let last = n < chunk_size as usize || at_eof(&mut src)?;
        let mut chunk = buf[..n].to_vec();
        key.seal_in_place_append_tag(
            chunk_nonce(&h.prefix, index),
            Aad::from(chunk_aad(hh.as_ref(), index, last).as_slice()),
            &mut chunk,
        )
        .map_err(|_| Eks1Error::Format)?;
        dst.write_all(&chunk)?;
        if last {
            return Ok(());
        }
        index = index.checked_add(1).ok_or(Eks1Error::Format)?;
    }
}

/// Mendekripsi file EKS1 dari `src` ke `dst`.
///
/// Setiap chunk ditulis hanya setelah tag-nya terverifikasi, tetapi kegagalan
/// bisa muncul di chunk berikutnya: pemanggil WAJIB membuang seluruh keluaran
/// bila fungsi ini mengembalikan error.
pub fn decrypt<R: Read, W: Write>(dst: &mut W, src: R, dek: &[u8]) -> Result<Header, Eks1Error> {
    let key = aead_key(dek)?;
    let mut src = BufReader::new(src);
    let (h, raw) = read_header(&mut src)?;
    let hh = digest::digest(&digest::SHA256, &raw);

    let sealed_len = h.chunk_size as usize + TAG_LEN;
    let mut src = BufReader::with_capacity(sealed_len + 1, src);
    let mut buf = Zeroizing::new(vec![0u8; sealed_len]);
    let mut index: u32 = 0;
    loop {
        let n = read_full(&mut src, &mut buf)?;
        if n < TAG_LEN {
            return Err(Eks1Error::Auth);
        }
        let last = n < sealed_len || at_eof(&mut src)?;
        let plain = key
            .open_in_place(
                chunk_nonce(&h.prefix, index),
                Aad::from(chunk_aad(hh.as_ref(), index, last).as_slice()),
                &mut buf[..n],
            )
            .map_err(|_| Eks1Error::Auth)?;
        dst.write_all(plain)?;
        if last {
            return Ok(h);
        }
        index = index.checked_add(1).ok_or(Eks1Error::Format)?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CS: u32 = 4096;

    fn dek() -> Vec<u8> {
        let mut k = vec![0u8; 32];
        rand::fill(&mut k).unwrap();
        k
    }

    fn seal(key: &[u8], plain: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        encrypt(&mut out, plain, key, "ND-2026-0001", 3, CS).unwrap();
        out
    }

    fn open(key: &[u8], ct: &[u8]) -> Result<(Vec<u8>, Header), Eks1Error> {
        let mut out = Vec::new();
        let h = decrypt(&mut out, ct, key)?;
        Ok((out, h))
    }

    fn header_len(ct: &[u8]) -> usize {
        let mut r = ct;
        read_header(&mut r).unwrap().1.len()
    }

    fn random(n: usize) -> Vec<u8> {
        let mut v = vec![0u8; n];
        rand::fill(&mut v).unwrap();
        v
    }

    #[test]
    fn round_trip_sizes() {
        let key = dek();
        for n in [0usize, 1, 4095, 4096, 4097, 8192, 3 * 4096 + 17] {
            let plain = random(n);
            let (got, h) = open(&key, &seal(&key, &plain)).unwrap();
            assert_eq!(got, plain, "n={n}");
            assert_eq!(
                (h.document_id.as_str(), h.version, h.chunk_size),
                ("ND-2026-0001", 3, CS)
            );
        }
    }

    #[test]
    fn nonce_prefix_random() {
        let key = dek();
        assert_ne!(seal(&key, b"x"), seal(&key, b"x"));
    }

    #[test]
    fn tamper_detection() {
        let key = dek();
        let ct = seal(&key, &random(3 * 4096 + 10)); // 4 chunk
        let hl = header_len(&ct);
        let sc = CS as usize + TAG_LEN;
        let chunk = |i: usize| ct[hl + i * sc..(hl + (i + 1) * sc).min(ct.len())].to_vec();
        let cat = |parts: &[Vec<u8>]| parts.concat();
        let flip = |i: usize| {
            let mut c = ct.clone();
            c[i] ^= 1;
            c
        };
        let head = ct[..hl].to_vec();
        let cases: Vec<(&str, Vec<u8>)> = vec![
            ("terpotong di batas chunk", ct[..hl + 2 * sc].to_vec()),
            ("terpotong di tengah chunk", ct[..hl + sc + 100].to_vec()),
            ("hanya header", head.clone()),
            (
                "chunk ditukar",
                cat(&[head.clone(), chunk(1), chunk(0), chunk(2), chunk(3)]),
            ),
            (
                "chunk dihapus",
                cat(&[head.clone(), chunk(0), chunk(2), chunk(3)]),
            ),
            (
                "chunk diduplikasi",
                cat(&[
                    head.clone(),
                    chunk(0),
                    chunk(0),
                    chunk(1),
                    chunk(2),
                    chunk(3),
                ]),
            ),
            ("sampah di akhir", cat(&[ct.clone(), vec![0]])),
            ("bit isi diubah", flip(hl + 2000)),
            ("bit tag diubah", flip(ct.len() - 1)),
            ("prefix nonce diubah", flip(hl - 1)),
            ("versi di header diubah", flip(hl - PREFIX_LEN - 5)),
        ];
        for (name, bad) in cases {
            assert!(open(&key, &bad).is_err(), "{name}: seharusnya gagal");
        }
        assert!(matches!(open(&dek(), &ct), Err(Eks1Error::Auth)));
    }

    #[test]
    fn header_swap_between_documents() {
        let key = dek();
        let (mut a, mut b) = (Vec::new(), Vec::new());
        encrypt(&mut a, &b"isi A"[..], &key, "DOC-A", 1, CS).unwrap();
        encrypt(&mut b, &b"isi B"[..], &key, "DOC-B", 1, CS).unwrap();
        let mixed = [&a[..header_len(&a)], &b[header_len(&b)..]].concat();
        assert!(open(&key, &mixed).is_err());
    }

    #[test]
    fn rejects_bad_params() {
        let mut out = Vec::new();
        assert!(encrypt(&mut out, &b""[..], &[0u8; 16], "D", 1, CS).is_err());
        assert!(encrypt(&mut out, &b""[..], &dek(), "", 1, CS).is_err());
        assert!(encrypt(&mut out, &b""[..], &dek(), "D", 1, 100).is_err());
    }
}
