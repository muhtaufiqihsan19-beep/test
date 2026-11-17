//! Menjalankan Crypto Service Key Service E-Office.

use std::net::SocketAddr;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder as ConnBuilder;
use hyper_util::server::graceful::GracefulShutdown;
use hyper_util::service::TowerToHyperService;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tracing_subscriber::EnvFilter;

use crypto_service::config::Config;
use crypto_service::httpapi::{self, AppState};
use crypto_service::jabatankey::Manager;
use crypto_service::kek::{InsecureDevSealer, Sealer, Transit};
use crypto_service::service::Service;
use crypto_service::{keywrap, tls};

#[tokio::main]
async fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();
    // Satu-satunya provider kripto untuk rustls dan reqwest: AWS-LC.
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            tracing::error!(error = %e, "berhenti");
            ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<(), String> {
    let cfg = Config::from_env()?;

    let default_suite = cfg
        .default_suite
        .clone()
        .unwrap_or_else(|| keywrap::ID_V1.to_string());
    let registry = Arc::new(keywrap::registry(&default_suite).map_err(|e| {
        format!(
            "KS_DEFAULT_SUITE: {e} (tersedia: {:?})",
            keywrap::suites().iter().map(|s| s.id()).collect::<Vec<_>>()
        )
    })?);

    let sealer = match &cfg.openbao_addr {
        None if cfg.dev => {
            tracing::warn!(
                "MODE DEV: KEK di memori, kunci jabatan hilang saat restart. Jangan dipakai di staging/produksi."
            );
            Sealer::Dev(InsecureDevSealer::new().map_err(|e| e.to_string())?)
        }
        None => return Err("OPENBAO_ADDR wajib di luar mode dev".into()),
        Some(addr) => Sealer::Transit(Transit {
            addr: addr.clone(),
            mount: cfg.openbao_mount.clone(),
            key_name: cfg.openbao_kek_name.clone(),
            namespace: cfg.openbao_namespace.clone(),
            token_file: cfg.openbao_token_file.clone(),
            http: Transit::http_client(cfg.openbao_ca.as_deref()).map_err(|e| e.to_string())?,
        }),
    };

    let service = Service {
        registry: registry.clone(),
        keys: Manager {
            registry: registry.clone(),
            sealer,
        },
        max_plaintext: cfg.max_document_bytes,
        chunk_size: 0,
    };
    let state = Arc::new(AppState::new(service));
    let app = httpapi::router(state.clone(), cfg.max_body_bytes);

    // Port health tanpa mTLS untuk probe Kubernetes.
    let health = TcpListener::bind(&cfg.health_listen)
        .await
        .map_err(|e| format!("{}: {e}", cfg.health_listen))?;
    let health_app = httpapi::health_router(state.clone());
    tokio::spawn(async move {
        if let Err(e) = axum::serve(health, health_app).await {
            tracing::error!(error = %e, "server health berhenti");
        }
    });

    let listener = TcpListener::bind(&cfg.listen)
        .await
        .map_err(|e| format!("{}: {e}", cfg.listen))?;
    tracing::info!(listen = %cfg.listen, health = %cfg.health_listen, default_suite = %default_suite, suites = ?registry.ids(), tls = !cfg.dev || cfg.tls_cert.is_some(), "crypto-service mulai");

    match (&cfg.tls_cert, &cfg.tls_key, &cfg.tls_client_ca) {
        (Some(cert), Some(key), Some(ca)) => {
            let tls_cfg = tls::server_config(cert, key, ca, cfg.tls_require_pq)?;
            serve_mtls(
                listener,
                TlsAcceptor::from(Arc::new(tls_cfg)),
                app,
                Arc::new(cfg.allowed_clients.clone()),
                state,
                cfg.shutdown_grace,
            )
            .await
        }
        _ if cfg.dev => {
            let local: SocketAddr = listener.local_addr().map_err(|e| e.to_string())?;
            if !local.ip().is_loopback() {
                return Err(
                    "mode dev tanpa TLS hanya boleh listen di loopback (KS_LISTEN=127.0.0.1:8443)"
                        .into(),
                );
            }
            axum::serve(listener, app)
                .with_graceful_shutdown(async move {
                    shutdown_signal().await;
                    state.start_draining();
                })
                .await
                .map_err(|e| e.to_string())
        }
        _ => Err("KS_TLS_CERT, KS_TLS_KEY, dan KS_TLS_CLIENT_CA wajib di luar mode dev".into()),
    }
}

/// Loop accept mTLS: setiap koneksi diperiksa SAN sertifikat kliennya sebelum dilayani.
///
/// Saat SIGTERM: `/readyz` menjadi 503, listener ditutup (koneksi baru ditolak), lalu
/// koneksi yang sedang berjalan diberi sinyal graceful shutdown (HTTP/1 menyelesaikan
/// permintaan berjalan lalu menutup, HTTP/2 mengirim GOAWAY). Proses menunggu sampai
/// semuanya selesai atau `grace` habis, mana yang lebih dulu.
async fn serve_mtls(
    listener: TcpListener,
    acceptor: TlsAcceptor,
    app: axum::Router,
    allowed: Arc<Vec<String>>,
    state: Arc<AppState>,
    grace: Duration,
) -> Result<(), String> {
    let graceful = GracefulShutdown::new();
    let shutdown = shutdown_signal();
    tokio::pin!(shutdown);
    loop {
        tokio::select! {
            _ = &mut shutdown => break,
            accepted = listener.accept() => {
                let (tcp, peer) = match accepted {
                    Ok(v) => v,
                    Err(e) => {
                        tracing::warn!(error = %e, "accept gagal");
                        continue;
                    }
                };
                // Watcher dibuat saat accept, sehingga koneksi yang masih handshake juga ditunggu.
                let watcher = graceful.watcher();
                let (acceptor, app, allowed) = (acceptor.clone(), app.clone(), allowed.clone());
                tokio::spawn(async move {
                    let tls = match tokio::time::timeout(Duration::from_secs(10), acceptor.accept(tcp)).await {
                        Ok(Ok(s)) => s,
                        Ok(Err(e)) => {
                            tracing::warn!(%peer, error = %e, "handshake TLS gagal");
                            return;
                        }
                        Err(_) => {
                            tracing::warn!(%peer, "handshake TLS timeout");
                            return;
                        }
                    };
                    let permitted = tls
                        .get_ref()
                        .1
                        .peer_certificates()
                        .and_then(|c| c.first())
                        .is_some_and(|c| tls::san_allowed(c.as_ref(), &allowed));
                    if !permitted {
                        tracing::warn!(%peer, security_event = true, "klien mTLS di luar daftar KS_ALLOWED_CLIENTS");
                        return;
                    }
                    let svc = TowerToHyperService::new(app);
                    let conn = ConnBuilder::new(TokioExecutor::new())
                        .serve_connection(TokioIo::new(tls), svc)
                        .into_owned();
                    if let Err(e) = watcher.watch(conn).await {
                        tracing::debug!(%peer, error = %e, "koneksi selesai dengan error");
                    }
                });
            }
        }
    }

    state.start_draining();
    drop(listener);
    let open = graceful.count();
    tracing::info!(
        open_connections = open,
        grace_secs = grace.as_secs(),
        "SIGTERM: berhenti menerima koneksi, menunggu permintaan berjalan selesai"
    );
    tokio::select! {
        _ = graceful.shutdown() => {
            tracing::info!("semua koneksi selesai, berhenti");
        }
        _ = tokio::time::sleep(grace) => {
            tracing::warn!(grace_secs = grace.as_secs(), "batas waktu shutdown habis, koneksi tersisa diputus");
        }
    }
    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let term = async {
        if let Ok(mut s) = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            s.recv().await;
        }
    };
    #[cfg(not(unix))]
    let term = std::future::pending::<()>();
    tokio::select! {
        _ = ctrl_c => {},
        _ = term => {},
    }
}
