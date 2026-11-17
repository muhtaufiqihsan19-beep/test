//! API internal Crypto Service. Hanya Key Service API yang boleh memanggil
//! (mTLS + daftar SAN diperiksa per koneksi di `main.rs`). Data biner dikirim
//! sebagai base64 di JSON; respons `open` berupa byte PDF mentah.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, Request, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::agility::CryptoError;
use crate::eks1;
use crate::jabatankey::KeyError;
use crate::kek::Sealer;
use crate::service::{KeyHolder, Recipient, Service, ServiceError, WrappedKey};

pub struct AppState {
    pub service: Service,
    /// Diisi `true` saat SIGTERM diterima: `/readyz` langsung 503 agar Kubernetes berhenti
    /// mengirim lalu lintas baru selama permintaan yang berjalan diselesaikan.
    pub draining: AtomicBool,
}

impl AppState {
    pub fn new(service: Service) -> Self {
        Self {
            service,
            draining: AtomicBool::new(false),
        }
    }

    /// Menandai layanan sedang berhenti.
    pub fn start_draining(&self) {
        self.draining.store(true, Ordering::SeqCst);
    }

    pub fn is_draining(&self) -> bool {
        self.draining.load(Ordering::SeqCst)
    }
}

mod b64 {
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&STANDARD.encode(v))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        STANDARD
            .decode(s.as_bytes())
            .map_err(serde::de::Error::custom)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RecipientJson {
    jabatan_code: String,
    key_version: u32,
    suite_id: String,
    #[serde(with = "b64")]
    public_key: Vec<u8>,
}

impl From<RecipientJson> for Recipient {
    fn from(r: RecipientJson) -> Self {
        Recipient {
            jabatan_code: r.jabatan_code,
            key_version: r.key_version,
            suite_id: r.suite_id,
            public_key: r.public_key,
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HolderJson {
    jabatan_code: String,
    key_version: u32,
    suite_id: String,
    #[serde(with = "b64")]
    wrapped_key: Vec<u8>,
    private_blob: String,
}

impl From<HolderJson> for KeyHolder {
    fn from(h: HolderJson) -> Self {
        KeyHolder {
            key: WrappedKey {
                jabatan_code: h.jabatan_code,
                key_version: h.key_version,
                suite_id: h.suite_id,
                wrapped_key: h.wrapped_key,
            },
            private_blob: h.private_blob,
        }
    }
}

#[derive(Serialize)]
struct WrappedJson {
    jabatan_code: String,
    key_version: u32,
    suite_id: String,
    #[serde(with = "b64")]
    wrapped_key: Vec<u8>,
}

fn to_json(wk: Vec<WrappedKey>) -> Vec<WrappedJson> {
    wk.into_iter()
        .map(|w| WrappedJson {
            jabatan_code: w.jabatan_code,
            key_version: w.key_version,
            suite_id: w.suite_id,
            wrapped_key: w.wrapped_key,
        })
        .collect()
}

/// Kesalahan API; pesan ke klien sengaja singkat, detail hanya di log.
pub struct ApiError(StatusCode, &'static str);

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.0, Json(serde_json::json!({ "error": self.1 }))).into_response()
    }
}

impl From<ServiceError> for ApiError {
    fn from(e: ServiceError) -> Self {
        match e {
            ServiceError::BadRequest(reason) => {
                tracing::warn!(%reason, "permintaan ditolak");
                ApiError(StatusCode::BAD_REQUEST, "bad_request")
            }
            ServiceError::TooLarge => ApiError(StatusCode::PAYLOAD_TOO_LARGE, "document_too_large"),
            ServiceError::Open => {
                // Bisa berarti data diubah, kunci salah, atau blob ditukar: perlu diselidiki.
                tracing::warn!(security_event = true, "dokumen atau kunci gagal dibuka");
                ApiError(StatusCode::UNPROCESSABLE_ENTITY, "open_failed")
            }
            ServiceError::Internal(reason) => {
                tracing::error!(%reason, "kesalahan internal");
                ApiError(StatusCode::INTERNAL_SERVER_ERROR, "internal")
            }
        }
    }
}

fn parse<T: DeserializeOwned>(body: &Bytes) -> Result<T, ApiError> {
    serde_json::from_slice(body).map_err(|e| {
        tracing::warn!(error = %e, "JSON tidak valid");
        ApiError(StatusCode::BAD_REQUEST, "invalid_json")
    })
}

/// Router API internal (port mTLS).
pub fn router(state: Arc<AppState>, max_body: usize) -> Router {
    Router::new()
        .route("/internal/v1/suites", get(suites))
        .route("/internal/v1/jabatan-keys", post(jabatan_keys))
        .route("/internal/v1/seal", post(seal))
        .route("/internal/v1/open", post(open))
        .route("/internal/v1/rewrap", post(rewrap))
        .layer(DefaultBodyLimit::max(max_body))
        .layer(middleware::from_fn(common_headers_and_log))
        .with_state(state)
}

/// Router health (port terpisah tanpa mTLS, untuk probe Kubernetes).
pub fn health_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/healthz", get(|| async { StatusCode::NO_CONTENT }))
        .route("/readyz", get(readyz))
        .with_state(state)
}

async fn common_headers_and_log(req: Request, next: Next) -> Response {
    let start = Instant::now();
    let method = req.method().clone();
    let path = req.uri().path().to_string();
    let request_id = req
        .headers()
        .get("x-request-id")
        .and_then(|v| v.to_str().ok())
        .filter(|v| v.len() <= 64)
        .map(str::to_string)
        .unwrap_or_else(|| {
            let mut b = [0u8; 8];
            let _ = aws_lc_rs::rand::fill(&mut b);
            b.iter().map(|x| format!("{x:02x}")).collect()
        });
    let mut resp = next.run(req).await;
    let h = resp.headers_mut();
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    h.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    if let Ok(v) = HeaderValue::from_str(&request_id) {
        h.insert("x-request-id", v);
    }
    tracing::info!(
        %request_id, %method, %path,
        status = resp.status().as_u16(),
        duration_ms = start.elapsed().as_millis() as u64,
        "request"
    );
    resp
}

async fn readyz(State(st): State<Arc<AppState>>) -> StatusCode {
    if st.is_draining() {
        return StatusCode::SERVICE_UNAVAILABLE;
    }
    // Siap bila KEK bisa dipakai: uji seal-unseal kecil.
    let sealer: &Sealer = &st.service.keys.sealer;
    let ok = match sealer.seal(b"readyz").await {
        Ok(blob) => sealer.unseal(&blob).await.is_ok(),
        Err(_) => false,
    };
    if ok {
        StatusCode::NO_CONTENT
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    }
}

async fn suites(State(st): State<Arc<AppState>>) -> Json<serde_json::Value> {
    let reg = &st.service.registry;
    Json(serde_json::json!({
        "default": reg.default_suite().id(),
        "available": reg.ids(),
        "content_alg": eks1::CONTENT_ALG,
    }))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct JabatanKeyReq {
    jabatan_code: String,
    key_version: u32,
    #[serde(default)]
    suite_id: Option<String>,
}

async fn jabatan_keys(State(st): State<Arc<AppState>>, body: Bytes) -> Result<Response, ApiError> {
    let req: JabatanKeyReq = parse(&body)?;
    let g = st
        .service
        .keys
        .generate(&req.jabatan_code, req.key_version, req.suite_id.as_deref())
        .await
        .map_err(|e| match e {
            KeyError::Crypto(CryptoError::UnknownSuite(_) | CryptoError::InvalidContext) => {
                ServiceError::BadRequest(e.to_string())
            }
            other => ServiceError::Internal(other.to_string()),
        })?;
    use base64::Engine;
    let enc = base64::engine::general_purpose::STANDARD;
    Ok((
        StatusCode::CREATED,
        Json(serde_json::json!({
            "jabatan_code": g.identity.jabatan_code,
            "key_version": g.identity.key_version,
            "suite_id": g.identity.suite_id,
            "public_key": enc.encode(&g.public_key),
            "private_blob": g.private_blob,
        })),
    )
        .into_response())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SealReq {
    document_id: String,
    version: u32,
    #[serde(with = "b64")]
    plaintext: Vec<u8>,
    recipients: Vec<RecipientJson>,
}

#[derive(Serialize)]
struct SealResp {
    document_id: String,
    version: u32,
    content_alg: &'static str,
    #[serde(with = "b64")]
    ciphertext: Vec<u8>,
    wrapped_keys: Vec<WrappedJson>,
}

async fn seal(State(st): State<Arc<AppState>>, body: Bytes) -> Result<Json<SealResp>, ApiError> {
    let mut req: SealReq = parse(&body)?;
    drop(body);
    let recipients: Vec<Recipient> = std::mem::take(&mut req.recipients)
        .into_iter()
        .map(Into::into)
        .collect();
    let result = st
        .service
        .seal(&req.document_id, req.version, &req.plaintext, &recipients);
    req.plaintext.zeroize();
    let sealed = result?;
    Ok(Json(SealResp {
        document_id: req.document_id,
        version: req.version,
        content_alg: eks1::CONTENT_ALG,
        ciphertext: sealed.ciphertext,
        wrapped_keys: to_json(sealed.wrapped_keys),
    }))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OpenReq {
    document_id: String,
    version: u32,
    #[serde(with = "b64")]
    ciphertext: Vec<u8>,
    key: HolderJson,
}

async fn open(State(st): State<Arc<AppState>>, body: Bytes) -> Result<Response, ApiError> {
    let req: OpenReq = parse(&body)?;
    drop(body);
    let holder: KeyHolder = req.key.into();
    let plain = st
        .service
        .open(&req.document_id, req.version, &holder, &req.ciphertext)
        .await?;
    // Salinan ke body respons tidak bisa di-zeroize setelah terkirim; salinan kerja dihapus saat drop.
    Ok((
        StatusCode::OK,
        [(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/octet-stream"),
        )],
        plain.to_vec(),
    )
        .into_response())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RewrapReq {
    document_id: String,
    version: u32,
    source: HolderJson,
    targets: Vec<RecipientJson>,
}

async fn rewrap(
    State(st): State<Arc<AppState>>,
    body: Bytes,
) -> Result<Json<serde_json::Value>, ApiError> {
    let req: RewrapReq = parse(&body)?;
    let source: KeyHolder = req.source.into();
    let targets: Vec<Recipient> = req.targets.into_iter().map(Into::into).collect();
    let wk = st
        .service
        .rewrap(&req.document_id, req.version, &source, &targets)
        .await?;
    Ok(Json(serde_json::json!({ "wrapped_keys": to_json(wk) })))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jabatankey::Manager;
    use crate::kek::InsecureDevSealer;
    use crate::keywrap;
    use axum::body::Body;
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD as B64;
    use http_body_util::BodyExt;
    use serde_json::{Value, json};
    use tower::ServiceExt;

    fn app() -> Router {
        let registry = Arc::new(keywrap::registry(keywrap::ID_V1).unwrap());
        let service = Service {
            registry: registry.clone(),
            keys: Manager {
                registry,
                sealer: Sealer::Dev(InsecureDevSealer::new().unwrap()),
            },
            max_plaintext: 1 << 20,
            chunk_size: 4096,
        };
        router(Arc::new(AppState::new(service)), 4 << 20)
    }

    async fn call(app: &Router, path: &str, body: Value) -> (StatusCode, Vec<u8>) {
        let req = axum::http::Request::post(path)
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        let status = resp.status();
        (
            status,
            resp.into_body()
                .collect()
                .await
                .unwrap()
                .to_bytes()
                .to_vec(),
        )
    }

    async fn key(app: &Router, code: &str) -> Value {
        let (s, b) = call(
            app,
            "/internal/v1/jabatan-keys",
            json!({"jabatan_code": code, "key_version": 1}),
        )
        .await;
        assert_eq!(s, StatusCode::CREATED);
        serde_json::from_slice(&b).unwrap()
    }

    fn rcpt(k: &Value) -> Value {
        json!({"jabatan_code": k["jabatan_code"], "key_version": 1, "suite_id": k["suite_id"], "public_key": k["public_key"]})
    }

    fn holder(k: &Value, wrapped_key: &Value) -> Value {
        json!({"jabatan_code": k["jabatan_code"], "key_version": 1, "suite_id": k["suite_id"],
               "wrapped_key": wrapped_key, "private_blob": k["private_blob"]})
    }

    #[tokio::test]
    async fn end_to_end() {
        let app = app();
        let (biro, bagian, tu) = (
            key(&app, "KEPALA-BIRO").await,
            key(&app, "KEPALA-BAGIAN").await,
            key(&app, "TU-BIRO").await,
        );
        let pdf = b"%PDF-1.7 naskah dinas sangat rahasia";

        let (s, b) = call(&app, "/internal/v1/seal", json!({
            "document_id": "ND-77", "version": 1, "plaintext": B64.encode(pdf), "recipients": [rcpt(&biro)],
        })).await;
        assert_eq!(s, StatusCode::OK);
        let sealed: Value = serde_json::from_slice(&b).unwrap();
        let ct = B64.decode(sealed["ciphertext"].as_str().unwrap()).unwrap();
        assert!(
            !ct.windows(14).any(|w| w == b"sangat rahasia"),
            "plaintext bocor"
        );
        let wk = &sealed["wrapped_keys"][0]["wrapped_key"];

        let (s, b) = call(&app, "/internal/v1/open", json!({
            "document_id": "ND-77", "version": 1, "ciphertext": sealed["ciphertext"], "key": holder(&biro, wk),
        })).await;
        assert_eq!((s, b.as_slice()), (StatusCode::OK, &pdf[..]));

        // TU memakai kunci terbungkus milik Kepala Biro dengan blob miliknya sendiri: ditolak.
        let (s, _) = call(&app, "/internal/v1/open", json!({
            "document_id": "ND-77", "version": 1, "ciphertext": sealed["ciphertext"], "key": holder(&tu, wk),
        })).await;
        assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY);

        // Disposisi ke Kepala Bagian.
        let (s, b) = call(&app, "/internal/v1/rewrap", json!({
            "document_id": "ND-77", "version": 1, "source": holder(&biro, wk), "targets": [rcpt(&bagian)],
        })).await;
        assert_eq!(s, StatusCode::OK);
        let rw: Value = serde_json::from_slice(&b).unwrap();
        let (s, b) = call(
            &app,
            "/internal/v1/open",
            json!({
                "document_id": "ND-77", "version": 1, "ciphertext": sealed["ciphertext"],
                "key": holder(&bagian, &rw["wrapped_keys"][0]["wrapped_key"]),
            }),
        )
        .await;
        assert_eq!((s, b.as_slice()), (StatusCode::OK, &pdf[..]));
    }

    #[tokio::test]
    async fn bad_input() {
        let app = app();
        let (s, _) = call(
            &app,
            "/internal/v1/seal",
            json!({"document_id": "D", "version": 1, "unknown": true}),
        )
        .await;
        assert_eq!(s, StatusCode::BAD_REQUEST);
        let (s, _) = call(
            &app,
            "/internal/v1/jabatan-keys",
            json!({"jabatan_code": "X", "key_version": 1, "suite_id": "RSA"}),
        )
        .await;
        assert_eq!(s, StatusCode::BAD_REQUEST);
        let big = B64.encode(vec![0u8; 5 << 20]);
        let (s, _) = call(
            &app,
            "/internal/v1/seal",
            json!({"document_id": "D", "version": 1, "plaintext": big, "recipients": []}),
        )
        .await;
        assert_eq!(s, StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[tokio::test]
    async fn security_headers() {
        let app = app();
        let req = axum::http::Request::get("/internal/v1/suites")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.headers()["cache-control"], "no-store");
        assert!(resp.headers().contains_key("x-request-id"));
    }
}
