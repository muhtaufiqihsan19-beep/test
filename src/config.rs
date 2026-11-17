//! Konfigurasi dari environment variable.

use std::env;
use std::path::PathBuf;
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct Config {
    /// KS_LISTEN, default 0.0.0.0:8443 (API internal, mTLS).
    pub listen: String,
    /// KS_HEALTH_LISTEN, default 0.0.0.0:8080 (hanya /healthz dan /readyz untuk probe Kubernetes).
    pub health_listen: String,
    /// KS_DEV=1: HTTP tanpa TLS di localhost dan KEK di memori. Dilarang di staging/produksi.
    pub dev: bool,
    pub tls_cert: Option<PathBuf>,
    pub tls_key: Option<PathBuf>,
    /// CA yang menandatangani sertifikat klien Key Service API.
    pub tls_client_ca: Option<PathBuf>,
    /// KS_TLS_REQUIRE_PQ=1: hanya terima key exchange X25519MLKEM768.
    pub tls_require_pq: bool,
    /// KS_ALLOWED_CLIENTS: DNS/URI SAN klien yang diizinkan, dipisah koma.
    pub allowed_clients: Vec<String>,
    /// KS_DEFAULT_SUITE: algorithm_id untuk kunci jabatan baru.
    pub default_suite: Option<String>,
    pub max_body_bytes: usize,
    pub max_document_bytes: usize,
    /// KS_SHUTDOWN_GRACE_SECS: batas waktu menunggu permintaan yang sedang berjalan selesai
    /// setelah SIGTERM (default 20, harus di bawah terminationGracePeriodSeconds Kubernetes).
    pub shutdown_grace: Duration,

    pub openbao_addr: Option<String>,
    pub openbao_ca: Option<PathBuf>,
    pub openbao_token_file: PathBuf,
    pub openbao_mount: String,
    pub openbao_kek_name: String,
    pub openbao_namespace: Option<String>,
}

fn var(key: &str) -> Option<String> {
    env::var(key).ok().filter(|v| !v.trim().is_empty())
}

fn mb(key: &str, default: usize) -> Result<usize, String> {
    match var(key) {
        None => Ok(default << 20),
        Some(v) => v
            .parse::<usize>()
            .ok()
            .filter(|n| *n > 0 && *n <= 512)
            .map(|n| n << 20)
            .ok_or_else(|| format!("{key} harus bilangan 1..512 (MB)")),
    }
}

fn secs(key: &str, default: u64) -> Result<Duration, String> {
    match var(key) {
        None => Ok(Duration::from_secs(default)),
        Some(v) => v
            .parse::<u64>()
            .ok()
            .filter(|n| (1..=300).contains(n))
            .map(Duration::from_secs)
            .ok_or_else(|| format!("{key} harus bilangan 1..300 (detik)")),
    }
}

impl Config {
    pub fn from_env() -> Result<Self, String> {
        let c = Config {
            listen: var("KS_LISTEN").unwrap_or_else(|| "0.0.0.0:8443".into()),
            health_listen: var("KS_HEALTH_LISTEN").unwrap_or_else(|| "0.0.0.0:8080".into()),
            dev: var("KS_DEV").as_deref() == Some("1"),
            tls_cert: var("KS_TLS_CERT").map(PathBuf::from),
            tls_key: var("KS_TLS_KEY").map(PathBuf::from),
            tls_client_ca: var("KS_TLS_CLIENT_CA").map(PathBuf::from),
            tls_require_pq: var("KS_TLS_REQUIRE_PQ").as_deref() == Some("1"),
            allowed_clients: var("KS_ALLOWED_CLIENTS")
                .map(|v| {
                    v.split(',')
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty())
                        .collect()
                })
                .unwrap_or_default(),
            default_suite: var("KS_DEFAULT_SUITE"),
            max_body_bytes: mb("KS_MAX_BODY_MB", 64)?,
            max_document_bytes: mb("KS_MAX_DOCUMENT_MB", 40)?,
            shutdown_grace: secs("KS_SHUTDOWN_GRACE_SECS", 20)?,
            openbao_addr: var("OPENBAO_ADDR"),
            openbao_ca: var("OPENBAO_CACERT").map(PathBuf::from),
            openbao_token_file: var("OPENBAO_TOKEN_FILE")
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("/vault/secrets/token")),
            openbao_mount: var("OPENBAO_TRANSIT_MOUNT").unwrap_or_else(|| "transit".into()),
            openbao_kek_name: var("OPENBAO_KEK_NAME").unwrap_or_else(|| "jabatan-kek".into()),
            openbao_namespace: var("OPENBAO_NAMESPACE"),
        };
        if c.dev {
            return Ok(c);
        }
        let mut missing = Vec::new();
        for (k, present) in [
            ("KS_TLS_CERT", c.tls_cert.is_some()),
            ("KS_TLS_KEY", c.tls_key.is_some()),
            ("KS_TLS_CLIENT_CA", c.tls_client_ca.is_some()),
            ("KS_ALLOWED_CLIENTS", !c.allowed_clients.is_empty()),
            ("KS_DEFAULT_SUITE", c.default_suite.is_some()),
            ("OPENBAO_ADDR", c.openbao_addr.is_some()),
            ("OPENBAO_CACERT", c.openbao_ca.is_some()),
        ] {
            if !present {
                missing.push(k);
            }
        }
        if !missing.is_empty() {
            return Err(format!(
                "konfigurasi wajib belum diisi: {}",
                missing.join(", ")
            ));
        }
        if !c
            .openbao_addr
            .as_deref()
            .unwrap_or_default()
            .starts_with("https://")
        {
            return Err("OPENBAO_ADDR harus https".into());
        }
        Ok(c)
    }
}
