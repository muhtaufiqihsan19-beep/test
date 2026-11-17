//! Registri suite pembungkus kunci berdasarkan `algorithm_id`, sehingga
//! algoritma bisa diganti tanpa membongkar dokumen lama.

use std::collections::BTreeMap;
use std::sync::Arc;

use thiserror::Error;
use zeroize::Zeroizing;

/// Kesalahan kripto. Varian `Unwrap` sengaja tidak membedakan penyebab.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum CryptoError {
    #[error("input tidak valid")]
    InvalidInput,
    #[error("context tidak valid")]
    InvalidContext,
    #[error("gagal membuka kunci")]
    Unwrap,
    #[error("algorithm_id tidak dikenal: {0}")]
    UnknownSuite(String),
    #[error("kegagalan internal kripto")]
    Internal,
}

/// Mengikat satu kunci terbungkus ke satu dokumen, versi, dan jabatan.
/// Context masuk ke derivasi kunci dan AAD, sehingga kunci terbungkus yang
/// disalin ke dokumen atau jabatan lain gagal dibuka.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Context {
    pub document_id: String,
    pub version: u32,
    pub jabatan_code: String,
    pub key_version: u32,
}

const CONTEXT_LABEL: &[u8] = b"perisai-keyservice/context/v1";

impl Context {
    pub fn validate(&self) -> Result<(), CryptoError> {
        let ok_str = |s: &str| !s.is_empty() && s.len() <= 255;
        if !ok_str(&self.document_id)
            || !ok_str(&self.jabatan_code)
            || self.version == 0
            || self.key_version == 0
        {
            return Err(CryptoError::InvalidContext);
        }
        Ok(())
    }

    /// Encoding kanonik tanpa ambiguitas (setiap field diberi prefix panjang).
    pub fn encode(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(64 + self.document_id.len() + self.jabatan_code.len());
        append_lp(&mut b, CONTEXT_LABEL);
        append_lp(&mut b, self.document_id.as_bytes());
        b.extend_from_slice(&self.version.to_be_bytes());
        append_lp(&mut b, self.jabatan_code.as_bytes());
        b.extend_from_slice(&self.key_version.to_be_bytes());
        b
    }
}

/// Menambahkan data dengan prefix panjang 4 byte big-endian.
pub fn append_lp(buf: &mut Vec<u8>, data: &[u8]) {
    let len = u32::try_from(data.len()).expect("field terlalu panjang");
    buf.extend_from_slice(&len.to_be_bytes());
    buf.extend_from_slice(data);
}

/// Pasangan kunci jabatan. Kunci privat otomatis dihapus dari memori saat drop.
pub struct KeyPair {
    pub public_key: Vec<u8>,
    pub private_key: Zeroizing<Vec<u8>>,
}

/// Satu skema pembungkus DEK untuk jabatan.
pub trait Suite: Send + Sync {
    /// `algorithm_id` yang disimpan di setiap baris `document_keys`.
    fn id(&self) -> &'static str;
    fn generate_key_pair(&self) -> Result<KeyPair, CryptoError>;
    fn wrap(&self, public_key: &[u8], dek: &[u8], ctx: &Context) -> Result<Vec<u8>, CryptoError>;
    fn unwrap(
        &self,
        private_key: &[u8],
        wrapped: &[u8],
        ctx: &Context,
    ) -> Result<Zeroizing<Vec<u8>>, CryptoError>;
}

/// Registri tidak berubah setelah dibuat, sehingga aman dibagi antar-thread tanpa lock.
pub struct Registry {
    suites: BTreeMap<&'static str, Arc<dyn Suite>>,
    default_id: &'static str,
}

impl Registry {
    pub fn new(suites: Vec<Arc<dyn Suite>>, default_id: &str) -> Result<Self, CryptoError> {
        let suites: BTreeMap<_, _> = suites.into_iter().map(|s| (s.id(), s)).collect();
        let default_id = suites
            .keys()
            .copied()
            .find(|id| *id == default_id)
            .ok_or_else(|| CryptoError::UnknownSuite(default_id.to_string()))?;
        Ok(Self { suites, default_id })
    }

    pub fn lookup(&self, id: &str) -> Result<Arc<dyn Suite>, CryptoError> {
        self.suites
            .get(id)
            .cloned()
            .ok_or_else(|| CryptoError::UnknownSuite(id.to_string()))
    }

    pub fn default_suite(&self) -> Arc<dyn Suite> {
        self.suites[self.default_id].clone()
    }

    pub fn ids(&self) -> Vec<&'static str> {
        self.suites.keys().copied().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_is_unambiguous() {
        let a = Context {
            document_id: "AB".into(),
            version: 1,
            jabatan_code: "C".into(),
            key_version: 1,
        };
        let b = Context {
            document_id: "A".into(),
            version: 1,
            jabatan_code: "BC".into(),
            key_version: 1,
        };
        assert_ne!(a.encode(), b.encode());
    }

    #[test]
    fn validate_rejects_empty() {
        let c = Context {
            document_id: String::new(),
            version: 1,
            jabatan_code: "X".into(),
            key_version: 1,
        };
        assert_eq!(c.validate(), Err(CryptoError::InvalidContext));
    }
}
