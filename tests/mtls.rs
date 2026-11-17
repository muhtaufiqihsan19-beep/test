//! Uji integrasi mTLS end-to-end.
//!
//! Uji ini menjalankan biner `crypto-service` yang sebenarnya (bukan router di dalam proses)
//! dengan sertifikat yang dibuat di dalam uji, lalu memanggilnya sebagai klien TLS 1.3.
//! Server berjalan dengan `KS_DEV=1` hanya agar KEK memakai sealer dev di memori (tanpa
//! OpenBao); jalur TLS, mTLS, dan pemeriksaan SAN sama persis dengan produksi.

use std::io::{BufRead, BufReader, Write};
use std::net::{SocketAddr, TcpListener as StdListener, TcpStream as StdStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use rcgen::{
    BasicConstraints, CertificateParams, CertifiedIssuer, DnType, ExtendedKeyUsagePurpose, IsCa,
    KeyPair, KeyUsagePurpose,
};
use rustls::crypto::SupportedKxGroup;
use rustls::crypto::aws_lc_rs::{self as provider, kx_group};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::{ClientConfig, NamedGroup, RootCertStore};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

const ALLOWED_SAN: &str = "key-service-api.keyservice.svc";
const OTHER_SAN: &str = "e-office.eoffice.svc";

// ---------------------------------------------------------------- sertifikat uji

struct Leaf {
    cert: CertificateDer<'static>,
    key: PrivateKeyDer<'static>,
    cert_pem: String,
    key_pem: String,
}

fn new_ca(name: &str) -> CertifiedIssuer<'static, KeyPair> {
    let mut p = CertificateParams::new(Vec::<String>::new()).unwrap();
    p.distinguished_name.push(DnType::CommonName, name);
    p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    p.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    CertifiedIssuer::self_signed(p, KeyPair::generate().unwrap()).unwrap()
}

fn leaf(
    issuer: &CertifiedIssuer<'static, KeyPair>,
    san: &str,
    eku: ExtendedKeyUsagePurpose,
) -> Leaf {
    let mut p = CertificateParams::new(vec![san.to_string()]).unwrap();
    p.distinguished_name.push(DnType::CommonName, san);
    p.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    p.extended_key_usages = vec![eku];
    let key = KeyPair::generate().unwrap();
    let cert = p.signed_by(&key, issuer).unwrap();
    Leaf {
        cert: cert.der().clone(),
        key: PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
        cert_pem: cert.pem(),
        key_pem: key.serialize_pem(),
    }
}

struct Pki {
    dir: PathBuf,
    ca_der: CertificateDer<'static>,
    allowed: Leaf,
    other_san: Leaf,
    rogue_ca_client: Leaf,
}

fn pki() -> Pki {
    let mut dir = std::env::temp_dir();
    let mut r = [0u8; 8];
    aws_lc_rs::rand::fill(&mut r).unwrap();
    dir.push(format!("ks-mtls-{}", u64::from_be_bytes(r)));
    std::fs::create_dir_all(&dir).unwrap();

    let ca = new_ca("perisai-test-ca");
    let server = leaf(&ca, "localhost", ExtendedKeyUsagePurpose::ServerAuth);
    std::fs::write(dir.join("ca.crt"), ca.pem()).unwrap();
    std::fs::write(dir.join("server.crt"), &server.cert_pem).unwrap();
    std::fs::write(dir.join("server.key"), &server.key_pem).unwrap();

    let rogue = new_ca("rogue-ca");
    Pki {
        ca_der: ca.der().clone(),
        allowed: leaf(&ca, ALLOWED_SAN, ExtendedKeyUsagePurpose::ClientAuth),
        other_san: leaf(&ca, OTHER_SAN, ExtendedKeyUsagePurpose::ClientAuth),
        // SAN benar, tetapi ditandatangani CA lain.
        rogue_ca_client: leaf(&rogue, ALLOWED_SAN, ExtendedKeyUsagePurpose::ClientAuth),
        dir,
    }
}

// ---------------------------------------------------------------- server sungguhan

struct Server {
    child: Child,
    api: SocketAddr,
    health: SocketAddr,
    log: PathBuf,
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Server {
    fn log(&self) -> String {
        std::fs::read_to_string(&self.log).unwrap_or_default()
    }
}

fn free_port() -> SocketAddr {
    StdListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
}

fn start(pki: &Pki, require_pq: bool) -> Server {
    start_with(pki, require_pq, &[])
}

fn start_with(pki: &Pki, require_pq: bool, extra_env: &[(&str, &str)]) -> Server {
    let (api, health) = (free_port(), free_port());
    let log = pki.dir.join(format!(
        "server-{}-{}.log",
        if require_pq { "pq" } else { "default" },
        api.port()
    ));
    let p = |f: &str| pki.dir.join(f);
    let child = Command::new(env!("CARGO_BIN_EXE_crypto-service"))
        .env("KS_DEV", "1")
        .env("KS_LISTEN", api.to_string())
        .env("KS_HEALTH_LISTEN", health.to_string())
        .env("KS_TLS_CERT", p("server.crt"))
        .env("KS_TLS_KEY", p("server.key"))
        .env("KS_TLS_CLIENT_CA", p("ca.crt"))
        .env("KS_ALLOWED_CLIENTS", ALLOWED_SAN)
        .env("KS_TLS_REQUIRE_PQ", if require_pq { "1" } else { "0" })
        .env("RUST_LOG", "info")
        .envs(extra_env.iter().copied())
        .stdout(Stdio::from(std::fs::File::create(&log).unwrap()))
        .stderr(Stdio::null())
        .spawn()
        .expect("biner crypto-service");
    let mut s = Server {
        child,
        api,
        health,
        log,
    };
    wait_ready(&mut s, health);
    s
}

/// Menunggu port health menjawab 204 dan port API menerima koneksi TCP.
fn wait_ready(s: &mut Server, health: SocketAddr) {
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        if let Some(status) = s.child.try_wait().unwrap() {
            panic!("server berhenti ({status}):\n{}", s.log());
        }
        let healthy = StdStream::connect(health)
            .and_then(|mut c| {
                c.set_read_timeout(Some(Duration::from_secs(2)))?;
                c.write_all(b"GET /healthz HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")?;
                let mut line = String::new();
                BufReader::new(c).read_line(&mut line)?;
                Ok(line.starts_with("HTTP/1.1 204"))
            })
            .unwrap_or(false);
        if healthy && StdStream::connect(s.api).is_ok() {
            return;
        }
        assert!(Instant::now() < deadline, "server tidak siap:\n{}", s.log());
        std::thread::sleep(Duration::from_millis(100));
    }
}

// ---------------------------------------------------------------- klien

fn client(
    pki: &Pki,
    identity: Option<&Leaf>,
    groups: Option<Vec<&'static dyn SupportedKxGroup>>,
) -> ClientConfig {
    let mut crypto = provider::default_provider();
    if let Some(g) = groups {
        crypto.kx_groups = g;
    }
    let mut roots = RootCertStore::empty();
    roots.add(pki.ca_der.clone()).unwrap();
    let b = ClientConfig::builder_with_provider(Arc::new(crypto))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_root_certificates(roots);
    match identity {
        Some(l) => b
            .with_client_auth_cert(vec![l.cert.clone()], l.key.clone_key())
            .unwrap(),
        None => b.with_no_client_auth(),
    }
}

#[derive(Debug)]
enum Outcome {
    /// Respons HTTP diterima beserta grup key exchange yang disepakati.
    Http(String, Option<NamedGroup>),
    /// Handshake gagal.
    Handshake(String),
    /// Handshake selesai di sisi klien, tetapi server memutus tanpa respons HTTP.
    NoResponse(String),
}

async fn get(cfg: ClientConfig, addr: SocketAddr, path: &str) -> Outcome {
    let tcp = TcpStream::connect(addr).await.unwrap();
    let name = ServerName::try_from("localhost").unwrap();
    let mut tls = match TlsConnector::from(Arc::new(cfg)).connect(name, tcp).await {
        Ok(t) => t,
        Err(e) => return Outcome::Handshake(e.to_string()),
    };
    let group = tls
        .get_ref()
        .1
        .negotiated_key_exchange_group()
        .map(|g| g.name());
    let req = format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
    if let Err(e) = tls.write_all(req.as_bytes()).await {
        return Outcome::NoResponse(format!("tulis: {e}"));
    }
    let mut buf = Vec::new();
    let res = tokio::time::timeout(Duration::from_secs(10), tls.read_to_end(&mut buf))
        .await
        .expect("baca timeout");
    let text = String::from_utf8_lossy(&buf).into_owned();
    if text.starts_with("HTTP/") {
        Outcome::Http(text, group)
    } else {
        Outcome::NoResponse(match res {
            Ok(_) => "EOF tanpa data".into(),
            Err(e) => e.to_string(),
        })
    }
}

fn status_line(resp: &str) -> &str {
    resp.lines().next().unwrap_or_default()
}

fn wait_log(s: &Server, needle: &str) -> bool {
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if s.log().contains(needle) {
            return true;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    false
}

// ---------------------------------------------------------------- uji

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mtls_access_control() {
    let pki = pki();
    let s = start(&pki, false);

    // 1. Klien yang diizinkan: 200, dan hybrid PQC disepakati secara bawaan.
    match get(
        client(&pki, Some(&pki.allowed), None),
        s.api,
        "/internal/v1/suites",
    )
    .await
    {
        Outcome::Http(resp, group) => {
            assert_eq!(status_line(&resp), "HTTP/1.1 200 OK", "{resp}");
            assert!(
                resp.contains("X25519-MLKEM768-HKDFSHA256-AES256GCM-v1"),
                "{resp}"
            );
            assert!(
                resp.to_ascii_lowercase()
                    .contains("cache-control: no-store")
            );
            assert_eq!(group, Some(NamedGroup::X25519MLKEM768));
        }
        o => panic!("klien sah ditolak: {o:?}\n{}", s.log()),
    }

    // 2. Klien dari CA yang sama tetapi SAN di luar KS_ALLOWED_CLIENTS: koneksi diputus
    //    setelah handshake tanpa respons HTTP, dan tercatat sebagai security event.
    let o = get(
        client(&pki, Some(&pki.other_san), None),
        s.api,
        "/internal/v1/suites",
    )
    .await;
    assert!(matches!(o, Outcome::NoResponse(_)), "SAN lain: {o:?}");
    assert!(
        wait_log(&s, "klien mTLS di luar daftar KS_ALLOWED_CLIENTS"),
        "log tidak mencatat penolakan SAN:\n{}",
        s.log()
    );

    // 3. Tanpa sertifikat klien: ditolak oleh verifier TLS (TLS 1.3 bisa melaporkan alert
    //    saat handshake atau saat baca pertama), tidak pernah ada respons HTTP.
    let o = get(client(&pki, None, None), s.api, "/internal/v1/suites").await;
    match &o {
        Outcome::Handshake(e) | Outcome::NoResponse(e) => {
            assert!(
                e.contains("CertificateRequired") || e.contains("alert"),
                "{o:?}"
            )
        }
        Outcome::Http(..) => panic!("tanpa sertifikat klien seharusnya ditolak: {o:?}"),
    }

    // 4. SAN benar tetapi ditandatangani CA lain: ditolak.
    let o = get(
        client(&pki, Some(&pki.rogue_ca_client), None),
        s.api,
        "/internal/v1/suites",
    )
    .await;
    assert!(
        !matches!(o, Outcome::Http(..)),
        "CA asing seharusnya ditolak: {o:?}"
    );

    // 5. Server tetap melayani klien sah setelah semua penolakan di atas.
    let o = get(
        client(&pki, Some(&pki.allowed), None),
        s.api,
        "/internal/v1/suites",
    )
    .await;
    assert!(
        matches!(&o, Outcome::Http(r, _) if r.starts_with("HTTP/1.1 200")),
        "{o:?}"
    );

    // Klien lama tanpa PQC tetap dilayani bila KS_TLS_REQUIRE_PQ tidak aktif.
    let o = get(
        client(&pki, Some(&pki.allowed), Some(vec![kx_group::X25519])),
        s.api,
        "/internal/v1/suites",
    )
    .await;
    assert!(
        matches!(&o, Outcome::Http(r, Some(NamedGroup::X25519)) if r.starts_with("HTTP/1.1 200")),
        "{o:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mtls_require_pq() {
    let pki = pki();
    let s = start(&pki, true);

    // Klien yang hanya menawarkan X25519MLKEM768: diterima.
    let o = get(
        client(
            &pki,
            Some(&pki.allowed),
            Some(vec![kx_group::X25519MLKEM768]),
        ),
        s.api,
        "/internal/v1/suites",
    )
    .await;
    match &o {
        Outcome::Http(resp, group) => {
            assert_eq!(status_line(resp), "HTTP/1.1 200 OK", "{resp}");
            assert_eq!(*group, Some(NamedGroup::X25519MLKEM768));
        }
        _ => panic!("klien PQ ditolak: {o:?}\n{}", s.log()),
    }

    // Klien dengan konfigurasi bawaan (PQ lebih dulu, klasik sebagai cadangan): tetap PQ.
    let o = get(
        client(&pki, Some(&pki.allowed), None),
        s.api,
        "/internal/v1/suites",
    )
    .await;
    assert!(
        matches!(&o, Outcome::Http(_, Some(NamedGroup::X25519MLKEM768))),
        "{o:?}"
    );

    // Klien yang hanya menawarkan grup klasik: handshake gagal.
    for (name, g) in [
        ("X25519", kx_group::X25519),
        ("secp256r1", kx_group::SECP256R1),
    ] {
        let o = get(client(&pki, Some(&pki.allowed), Some(vec![g])), s.api, "/").await;
        assert!(matches!(o, Outcome::Handshake(_)), "{name}: {o:?}");
    }

    // Pemeriksaan SAN tetap berlaku di mode hanya-PQ.
    let o = get(
        client(
            &pki,
            Some(&pki.other_san),
            Some(vec![kx_group::X25519MLKEM768]),
        ),
        s.api,
        "/internal/v1/suites",
    )
    .await;
    assert!(matches!(o, Outcome::NoResponse(_)), "{o:?}");
}

// ---------------------------------------------------------------- shutdown bertahap

#[cfg(unix)]
mod shutdown {
    use super::*;
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD as B64;
    use tokio_rustls::client::TlsStream;

    async fn connect(pki: &Pki, addr: SocketAddr) -> TlsStream<TcpStream> {
        let cfg = client(pki, Some(&pki.allowed), None);
        let tcp = TcpStream::connect(addr).await.unwrap();
        TlsConnector::from(Arc::new(cfg))
            .connect(ServerName::try_from("localhost").unwrap(), tcp)
            .await
            .unwrap()
    }

    fn post_head(path: &str, len: usize) -> String {
        format!(
            "POST {path} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\n\
             Content-Length: {len}\r\nConnection: close\r\n\r\n"
        )
    }

    async fn read_all(tls: &mut TlsStream<TcpStream>) -> String {
        let mut buf = Vec::new();
        let _ = tokio::time::timeout(Duration::from_secs(20), tls.read_to_end(&mut buf))
            .await
            .expect("baca timeout");
        String::from_utf8_lossy(&buf).into_owned()
    }

    /// Satu permintaan JSON lengkap; mengembalikan body respons.
    async fn post(pki: &Pki, addr: SocketAddr, path: &str, body: &str) -> String {
        let mut tls = connect(pki, addr).await;
        tls.write_all(post_head(path, body.len()).as_bytes())
            .await
            .unwrap();
        tls.write_all(body.as_bytes()).await.unwrap();
        let resp = read_all(&mut tls).await;
        assert!(resp.starts_with("HTTP/1.1 2"), "{path}: {resp}");
        resp.split("\r\n\r\n")
            .nth(1)
            .unwrap_or_default()
            .to_string()
    }

    fn readyz(health: SocketAddr) -> Option<String> {
        let mut c = StdStream::connect(health).ok()?;
        c.set_read_timeout(Some(Duration::from_secs(2))).ok()?;
        c.write_all(b"GET /readyz HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
            .ok()?;
        let mut line = String::new();
        BufReader::new(c).read_line(&mut line).ok()?;
        Some(line)
    }

    fn sigterm(s: &Server) {
        let ok = Command::new("kill")
            .args(["-TERM", &s.child.id().to_string()])
            .status()
            .unwrap()
            .success();
        assert!(ok, "kill -TERM gagal");
    }

    fn until(what: &str, secs: u64, mut f: impl FnMut() -> bool) {
        let deadline = Instant::now() + Duration::from_secs(secs);
        while !f() {
            assert!(
                Instant::now() < deadline,
                "tidak terjadi dalam {secs} detik: {what}"
            );
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    /// Body seal sekitar 2 MiB untuk satu jabatan.
    async fn seal_body(pki: &Pki, s: &Server) -> String {
        let key = post(
            pki,
            s.api,
            "/internal/v1/jabatan-keys",
            r#"{"jabatan_code":"KEPALA-BIRO","key_version":1}"#,
        )
        .await;
        let key: serde_json::Value = serde_json::from_str(&key).unwrap();
        serde_json::json!({
            "document_id": "ND-DRAIN-1",
            "version": 1,
            "plaintext": B64.encode(vec![0x25u8; 2 << 20]),
            "recipients": [{
                "jabatan_code": key["jabatan_code"], "key_version": key["key_version"],
                "suite_id": key["suite_id"], "public_key": key["public_key"],
            }],
        })
        .to_string()
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn inflight_request_completes_after_sigterm() {
        let pki = pki();
        let mut s = start_with(&pki, false, &[("KS_SHUTDOWN_GRACE_SECS", "15")]);
        let body = seal_body(&pki, &s).await;
        let (first, rest) = body.as_bytes().split_at(body.len() / 2);

        // Permintaan seal mulai: header dan separuh body terkirim, lalu SIGTERM.
        let mut tls = connect(&pki, s.api).await;
        tls.write_all(post_head("/internal/v1/seal", body.len()).as_bytes())
            .await
            .unwrap();
        tls.write_all(first).await.unwrap();
        tls.flush().await.unwrap();
        tokio::time::sleep(Duration::from_millis(300)).await;
        sigterm(&s);

        // Selama drain: readyz 503 dan koneksi baru ditolak.
        until("readyz 503", 5, || {
            readyz(s.health).is_some_and(|l| l.starts_with("HTTP/1.1 503"))
        });
        until("port API menolak koneksi baru", 5, || {
            StdStream::connect(s.api).is_err()
        });
        assert!(
            s.child.try_wait().unwrap().is_none(),
            "proses berhenti terlalu cepat"
        );

        // Sisa body dikirim: permintaan yang sedang berjalan tetap selesai dengan 200.
        tls.write_all(rest).await.unwrap();
        let resp = read_all(&mut tls).await;
        assert!(
            resp.starts_with("HTTP/1.1 200"),
            "{}",
            &resp[..resp.len().min(300)]
        );
        assert!(resp.contains("\"ciphertext\""));

        // Setelah koneksi terakhir selesai, proses keluar dengan sukses sebelum batas waktu.
        let mut status = None;
        until("proses keluar", 10, || {
            status = s.child.try_wait().unwrap();
            status.is_some()
        });
        assert!(status.unwrap().success(), "exit status {status:?}");
        assert!(s.log().contains("semua koneksi selesai"), "{}", s.log());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn shutdown_deadline_is_enforced() {
        let pki = pki();
        let mut s = start_with(&pki, false, &[("KS_SHUTDOWN_GRACE_SECS", "2")]);

        // Permintaan yang tidak pernah selesai (body tidak dikirim lengkap).
        let mut tls = connect(&pki, s.api).await;
        tls.write_all(post_head("/internal/v1/seal", 1 << 20).as_bytes())
            .await
            .unwrap();
        tls.write_all(b"{\"document_id\":").await.unwrap();
        tls.flush().await.unwrap();
        tokio::time::sleep(Duration::from_millis(300)).await;

        let t0 = Instant::now();
        sigterm(&s);
        let mut status = None;
        until("proses keluar setelah batas waktu", 10, || {
            status = s.child.try_wait().unwrap();
            status.is_some()
        });
        let took = t0.elapsed();
        assert!(
            took >= Duration::from_millis(1800) && took < Duration::from_secs(6),
            "keluar setelah {took:?}, seharusnya sekitar 2 detik"
        );
        assert!(status.unwrap().success());
        assert!(
            s.log().contains("batas waktu shutdown habis"),
            "{}",
            s.log()
        );
    }
}
