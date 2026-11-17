//! Konfigurasi TLS 1.3 + mTLS dan pemeriksaan SAN klien.

use std::path::Path;
use std::sync::Arc;

use rustls::RootCertStore;
use rustls::crypto::aws_lc_rs as provider;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use x509_parser::extensions::GeneralName;

fn load_certs(path: &Path) -> Result<Vec<CertificateDer<'static>>, String> {
    CertificateDer::pem_file_iter(path)
        .map_err(|e| format!("{}: {e}", path.display()))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("{}: {e}", path.display()))
}

/// ServerConfig: hanya TLS 1.3, wajib sertifikat klien dari CA yang ditentukan.
/// Provider aws-lc-rs menawarkan X25519MLKEM768 (hybrid PQC) secara bawaan;
/// `require_pq` membatasi hanya ke grup itu (klien PHP perlu OpenSSL 3.5+).
pub fn server_config(
    cert: &Path,
    key: &Path,
    client_ca: &Path,
    require_pq: bool,
) -> Result<rustls::ServerConfig, String> {
    let mut crypto = provider::default_provider();
    if require_pq {
        crypto.kx_groups = vec![provider::kx_group::X25519MLKEM768];
    }
    let crypto = Arc::new(crypto);

    let mut roots = RootCertStore::empty();
    for c in load_certs(client_ca)? {
        roots.add(c).map_err(|e| format!("CA klien: {e}"))?;
    }
    let verifier = WebPkiClientVerifier::builder_with_provider(Arc::new(roots), crypto.clone())
        .build()
        .map_err(|e| format!("verifier klien: {e}"))?;

    let certs = load_certs(cert)?;
    let key = PrivateKeyDer::from_pem_file(key).map_err(|e| format!("{}: {e}", key.display()))?;

    let mut cfg = rustls::ServerConfig::builder_with_provider(crypto)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| e.to_string())?
        .with_client_cert_verifier(verifier)
        .with_single_cert(certs, key)
        .map_err(|e| format!("sertifikat server: {e}"))?;
    cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(cfg)
}

/// Apakah sertifikat klien memuat salah satu DNS/URI SAN yang diizinkan.
pub fn san_allowed(cert_der: &[u8], allowed: &[String]) -> bool {
    let Ok((_, cert)) = x509_parser::parse_x509_certificate(cert_der) else {
        return false;
    };
    let Ok(Some(san)) = cert.subject_alternative_name() else {
        return false;
    };
    san.value.general_names.iter().any(|name| match name {
        GeneralName::DNSName(d) => allowed.iter().any(|a| a == d),
        GeneralName::URI(u) => allowed.iter().any(|a| a == u),
        _ => false,
    })
}
