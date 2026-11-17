//! Suite pembungkus DEK per jabatan (Hybrid PQC).

use std::sync::Arc;

use crate::agility::{CryptoError, Registry, Suite};

pub mod v1;

pub use v1::{ID_V1, V1};

/// Semua suite yang tersedia di build ini.
///
/// Suite HPKE X-Wing (MLKEM768-X25519, draft-ietf-hpke-pq) menyusul setelah
/// tim kripto menetapkan crate yang teruji; cukup tambahkan di sini.
pub fn suites() -> Vec<Arc<dyn Suite>> {
    vec![Arc::new(V1)]
}

/// Registri dengan semua suite dan default yang diminta.
pub fn registry(default_id: &str) -> Result<Registry, CryptoError> {
    Registry::new(suites(), default_id)
}
