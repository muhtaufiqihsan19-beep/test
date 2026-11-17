//! Pembungkus kunci privat jabatan dengan KEK yang tidak pernah keluar dari
//! OpenBao (secrets engine Transit), plus sealer khusus pengembangan lokal.

use std::path::PathBuf;
use std::time::Duration;

use aws_lc_rs::aead::{AES_256_GCM, Aad, LessSafeKey, NONCE_LEN, Nonce, UnboundKey};
use aws_lc_rs::rand;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use serde::Deserialize;
use thiserror::Error;
use zeroize::Zeroizing;

#[derive(Debug, Error)]
pub enum KekError {
    #[error("token OpenBao tidak terbaca")]
    Token,
    #[error("OpenBao tidak bisa dihubungi: {0}")]
    Transport(String),
    #[error("OpenBao menolak (HTTP {status}): {errors:?}")]
    Rejected { status: u16, errors: Vec<String> },
    #[error("respons OpenBao tidak valid")]
    BadResponse,
    #[error("blob tidak valid")]
    BadBlob,
    #[error("konfigurasi klien OpenBao: {0}")]
    Config(String),
}

/// Sealer yang dipakai layanan. Enum (bukan trait object) agar method async sederhana.
pub enum Sealer {
    Transit(Transit),
    Dev(InsecureDevSealer),
}

impl Sealer {
    pub async fn seal(&self, plaintext: &[u8]) -> Result<String, KekError> {
        match self {
            Sealer::Transit(t) => t.seal(plaintext).await,
            Sealer::Dev(d) => d.seal(plaintext),
        }
    }

    pub async fn unseal(&self, blob: &str) -> Result<Zeroizing<Vec<u8>>, KekError> {
        match self {
            Sealer::Transit(t) => t.unseal(blob).await,
            Sealer::Dev(d) => d.unseal(blob),
        }
    }
}

/// Klien Transit OpenBao. Token dibaca dari file yang ditulis OpenBao Agent
/// (auth Kubernetes) pada setiap panggilan, sehingga rotasi token tidak perlu restart.
pub struct Transit {
    pub addr: String,
    pub mount: String,
    pub key_name: String,
    pub namespace: Option<String>,
    pub token_file: PathBuf,
    pub http: reqwest::Client,
}

#[derive(Deserialize, Default)]
struct TransitData {
    #[serde(default)]
    ciphertext: String,
    #[serde(default)]
    plaintext: String,
}

#[derive(Deserialize, Default)]
struct TransitResp {
    #[serde(default)]
    data: Option<TransitData>,
    #[serde(default)]
    errors: Vec<String>,
}

impl Transit {
    /// Klien HTTPS dengan TLS 1.3 dan CA OpenBao yang ditentukan.
    pub fn http_client(ca_pem_file: Option<&std::path::Path>) -> Result<reqwest::Client, KekError> {
        let mut roots = rustls::RootCertStore::empty();
        if let Some(path) = ca_pem_file {
            use rustls::pki_types::CertificateDer;
            use rustls::pki_types::pem::PemObject;
            let certs = CertificateDer::pem_file_iter(path)
                .map_err(|e| KekError::Config(format!("CA OpenBao: {e}")))?;
            for c in certs {
                let c = c.map_err(|e| KekError::Config(format!("CA OpenBao: {e}")))?;
                roots
                    .add(c)
                    .map_err(|e| KekError::Config(format!("CA OpenBao: {e}")))?;
            }
        }
        let tls = rustls::ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .with_root_certificates(roots)
            .with_no_client_auth();
        reqwest::Client::builder()
            .use_preconfigured_tls(tls)
            .timeout(Duration::from_secs(5))
            .build()
            .map_err(|e| KekError::Config(e.to_string()))
    }

    async fn call(&self, op: &str, body: serde_json::Value) -> Result<TransitData, KekError> {
        let token = tokio::fs::read_to_string(&self.token_file)
            .await
            .map_err(|_| KekError::Token)?;
        let url = format!(
            "{}/v1/{}/{}/{}",
            self.addr.trim_end_matches('/'),
            self.mount,
            op,
            self.key_name
        );
        let mut req = self
            .http
            .post(url)
            .header("X-Vault-Token", token.trim())
            .json(&body);
        if let Some(ns) = &self.namespace {
            req = req.header("X-Vault-Namespace", ns);
        }
        let resp = req
            .send()
            .await
            .map_err(|e| KekError::Transport(e.to_string()))?;
        let status = resp.status().as_u16();
        let parsed: TransitResp = resp.json().await.map_err(|_| KekError::BadResponse)?;
        if status != 200 {
            return Err(KekError::Rejected {
                status,
                errors: parsed.errors,
            });
        }
        parsed.data.ok_or(KekError::BadResponse)
    }

    pub async fn seal(&self, plaintext: &[u8]) -> Result<String, KekError> {
        let pt = Zeroizing::new(B64.encode(plaintext));
        let data = self
            .call("encrypt", serde_json::json!({ "plaintext": pt.as_str() }))
            .await?;
        if data.ciphertext.is_empty() {
            return Err(KekError::BadResponse);
        }
        Ok(data.ciphertext)
    }

    pub async fn unseal(&self, blob: &str) -> Result<Zeroizing<Vec<u8>>, KekError> {
        let data = self
            .call("decrypt", serde_json::json!({ "ciphertext": blob }))
            .await?;
        let pt = Zeroizing::new(data.plaintext);
        B64.decode(pt.as_bytes())
            .map(Zeroizing::new)
            .map_err(|_| KekError::BadResponse)
    }
}

/// HANYA untuk pengembangan lokal dan pengujian: KEK disimpan di memori proses.
/// Jangan pernah dipakai di staging atau produksi.
pub struct InsecureDevSealer {
    key: LessSafeKey,
}

const DEV_PREFIX: &str = "dev:v1:";

impl InsecureDevSealer {
    pub fn new() -> Result<Self, KekError> {
        let mut k = Zeroizing::new([0u8; 32]);
        rand::fill(&mut k[..]).map_err(|_| KekError::Config("RNG".into()))?;
        let key = LessSafeKey::new(
            UnboundKey::new(&AES_256_GCM, &k[..]).map_err(|_| KekError::Config("KEK".into()))?,
        );
        Ok(Self { key })
    }

    pub fn seal(&self, plaintext: &[u8]) -> Result<String, KekError> {
        let mut nonce = [0u8; NONCE_LEN];
        rand::fill(&mut nonce).map_err(|_| KekError::BadBlob)?;
        let mut buf = plaintext.to_vec();
        self.key
            .seal_in_place_append_tag(
                Nonce::assume_unique_for_key(nonce),
                Aad::from(DEV_PREFIX.as_bytes()),
                &mut buf,
            )
            .map_err(|_| KekError::BadBlob)?;
        let mut out = nonce.to_vec();
        out.extend_from_slice(&buf);
        Ok(format!("{DEV_PREFIX}{}", B64.encode(out)))
    }

    pub fn unseal(&self, blob: &str) -> Result<Zeroizing<Vec<u8>>, KekError> {
        let raw = blob
            .strip_prefix(DEV_PREFIX)
            .and_then(|s| B64.decode(s).ok())
            .ok_or(KekError::BadBlob)?;
        if raw.len() < NONCE_LEN {
            return Err(KekError::BadBlob);
        }
        let (nonce, ct) = raw.split_at(NONCE_LEN);
        let nonce: [u8; NONCE_LEN] = nonce.try_into().map_err(|_| KekError::BadBlob)?;
        let mut buf = Zeroizing::new(ct.to_vec());
        let n = self
            .key
            .open_in_place(
                Nonce::assume_unique_for_key(nonce),
                Aad::from(DEV_PREFIX.as_bytes()),
                &mut buf,
            )
            .map_err(|_| KekError::BadBlob)?
            .len();
        buf.truncate(n);
        Ok(buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{Json, Router, http::HeaderMap, http::StatusCode, routing::post};

    #[test]
    fn dev_sealer_round_trip_and_isolation() {
        let a = InsecureDevSealer::new().unwrap();
        let b = InsecureDevSealer::new().unwrap();
        let blob = a.seal(b"rahasia").unwrap();
        assert_eq!(&a.unseal(&blob).unwrap()[..], b"rahasia");
        assert!(b.unseal(&blob).is_err(), "KEK lain harus gagal");
    }

    /// Server palsu yang meniru endpoint encrypt/decrypt Transit secukupnya.
    async fn fake_transit(token: &'static str) -> String {
        let check = move |h: &HeaderMap| {
            h.get("X-Vault-Token").and_then(|v| v.to_str().ok()) == Some(token)
        };
        let app = Router::new()
            .route(
                "/v1/transit/encrypt/jabatan-kek",
                post(move |h: HeaderMap, Json(b): Json<serde_json::Value>| async move {
                    if !check(&h) {
                        return (StatusCode::FORBIDDEN, Json(serde_json::json!({"errors": ["permission denied"]})));
                    }
                    let pt = b["plaintext"].as_str().unwrap_or_default().chars().rev().collect::<String>();
                    (StatusCode::OK, Json(serde_json::json!({"data": {"ciphertext": format!("vault:v1:{pt}")}})))
                }),
            )
            .route(
                "/v1/transit/decrypt/jabatan-kek",
                post(move |h: HeaderMap, Json(b): Json<serde_json::Value>| async move {
                    if !check(&h) {
                        return (StatusCode::FORBIDDEN, Json(serde_json::json!({"errors": ["permission denied"]})));
                    }
                    let ct = b["ciphertext"].as_str().unwrap_or_default();
                    let pt = ct.trim_start_matches("vault:v1:").chars().rev().collect::<String>();
                    (StatusCode::OK, Json(serde_json::json!({"data": {"plaintext": pt}})))
                }),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        format!("http://{addr}")
    }

    fn transit(addr: String, token_file: PathBuf) -> Transit {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        Transit {
            addr,
            mount: "transit".into(),
            key_name: "jabatan-kek".into(),
            namespace: None,
            token_file,
            http: Transit::http_client(None).unwrap(),
        }
    }

    fn token_file(content: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        let mut r = [0u8; 8];
        rand::fill(&mut r).unwrap();
        p.push(format!("ks-token-{}", u64::from_be_bytes(r)));
        std::fs::write(&p, content).unwrap();
        p
    }

    #[tokio::test]
    async fn transit_round_trip() {
        let addr = fake_transit("s.token").await;
        let t = transit(addr, token_file("s.token\n"));
        let blob = t.seal(b"rahasia").await.unwrap();
        assert!(blob.starts_with("vault:v1:"));
        assert_eq!(&t.unseal(&blob).await.unwrap()[..], b"rahasia");
    }

    #[tokio::test]
    async fn transit_wrong_token() {
        let addr = fake_transit("s.benar").await;
        let t = transit(addr, token_file("s.salah"));
        assert!(matches!(
            t.seal(b"x").await,
            Err(KekError::Rejected { status: 403, .. })
        ));
    }
}
