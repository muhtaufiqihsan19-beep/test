//! Pasangan kunci per jabatan: dibuat di Crypto Service, kunci privat dibungkus
//! KEK (OpenBao Transit) bersama identitasnya, dan hanya dibuka sesaat.
//!
//! Identitas (suite, kode jabatan, versi kunci) ikut dibungkus sehingga blob
//! yang ditukar antarbaris di database terdeteksi.

use std::sync::Arc;

use thiserror::Error;
use zeroize::Zeroizing;

use crate::agility::{CryptoError, Registry, append_lp};
use crate::kek::{KekError, Sealer};

const ENV_MAGIC: &[u8; 4] = b"JKB1";

#[derive(Debug, Error)]
pub enum KeyError {
    #[error(transparent)]
    Crypto(#[from] CryptoError),
    #[error(transparent)]
    Kek(#[from] KekError),
    #[error("blob tidak cocok dengan identitas kunci")]
    Mismatch,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    pub jabatan_code: String,
    pub key_version: u32,
    pub suite_id: String,
}

pub struct Generated {
    pub identity: Identity,
    pub public_key: Vec<u8>,
    pub private_blob: String,
}

pub struct Manager {
    pub registry: Arc<Registry>,
    pub sealer: Sealer,
}

/// Menyusun amplop JKB1: `"JKB1" || LP(suite_id) || LP(jabatan_code) || key_version(4)
/// || LP(kunci privat)`, dengan `LP` = panjang 4 byte big-endian lalu isinya.
/// Publik agar bisa dipakai uji dan target fuzz; formatnya tidak boleh berubah.
pub fn encode_envelope(id: &Identity, private_key: &[u8]) -> Zeroizing<Vec<u8>> {
    let mut b = Zeroizing::new(Vec::with_capacity(64 + private_key.len()));
    b.extend_from_slice(ENV_MAGIC);
    append_lp(&mut b, id.suite_id.as_bytes());
    append_lp(&mut b, id.jabatan_code.as_bytes());
    b.extend_from_slice(&id.key_version.to_be_bytes());
    append_lp(&mut b, private_key);
    b
}

/// Membaca amplop JKB1 hasil `encode_envelope`. Menolak magic salah, panjang tidak cukup,
/// UTF-8 tidak valid, dan sisa byte di akhir.
pub fn decode_envelope(mut b: &[u8]) -> Result<(Identity, Zeroizing<Vec<u8>>), KeyError> {
    fn take<'a>(b: &mut &'a [u8], n: usize) -> Result<&'a [u8], KeyError> {
        if b.len() < n {
            return Err(KeyError::Mismatch);
        }
        let (head, tail) = b.split_at(n);
        *b = tail;
        Ok(head)
    }
    fn take_u32(b: &mut &[u8]) -> Result<u32, KeyError> {
        Ok(u32::from_be_bytes(
            take(b, 4)?.try_into().map_err(|_| KeyError::Mismatch)?,
        ))
    }
    fn take_lp<'a>(b: &mut &'a [u8]) -> Result<&'a [u8], KeyError> {
        let n = take_u32(b)? as usize;
        take(b, n)
    }

    if take(&mut b, 4)? != ENV_MAGIC {
        return Err(KeyError::Mismatch);
    }
    let suite_id = String::from_utf8(take_lp(&mut b)?.to_vec()).map_err(|_| KeyError::Mismatch)?;
    let jabatan_code =
        String::from_utf8(take_lp(&mut b)?.to_vec()).map_err(|_| KeyError::Mismatch)?;
    let key_version = take_u32(&mut b)?;
    let private_key = Zeroizing::new(take_lp(&mut b)?.to_vec());
    if !b.is_empty() {
        return Err(KeyError::Mismatch);
    }
    Ok((
        Identity {
            jabatan_code,
            key_version,
            suite_id,
        },
        private_key,
    ))
}

impl Manager {
    /// Membuat pasangan kunci baru. `suite_id` kosong berarti suite default.
    pub async fn generate(
        &self,
        jabatan_code: &str,
        key_version: u32,
        suite_id: Option<&str>,
    ) -> Result<Generated, KeyError> {
        if jabatan_code.is_empty() || jabatan_code.len() > 255 || key_version == 0 {
            return Err(CryptoError::InvalidContext.into());
        }
        let suite = match suite_id {
            Some(id) if !id.is_empty() => self.registry.lookup(id)?,
            _ => self.registry.default_suite(),
        };
        let kp = suite.generate_key_pair()?;
        let identity = Identity {
            jabatan_code: jabatan_code.to_string(),
            key_version,
            suite_id: suite.id().to_string(),
        };
        let env = encode_envelope(&identity, &kp.private_key);
        let private_blob = self.sealer.seal(&env).await?;
        Ok(Generated {
            identity,
            public_key: kp.public_key,
            private_blob,
        })
    }

    /// Membuka kunci privat untuk satu operasi; dihapus dari memori saat drop.
    pub async fn open_private(
        &self,
        want: &Identity,
        blob: &str,
    ) -> Result<Zeroizing<Vec<u8>>, KeyError> {
        let env = self.sealer.unseal(blob).await?;
        let (got, private_key) = decode_envelope(&env)?;
        if &got != want {
            return Err(KeyError::Mismatch);
        }
        Ok(private_key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kek::InsecureDevSealer;
    use crate::keywrap;

    fn manager() -> Manager {
        Manager {
            registry: Arc::new(keywrap::registry(keywrap::ID_V1).unwrap()),
            sealer: Sealer::Dev(InsecureDevSealer::new().unwrap()),
        }
    }

    #[tokio::test]
    async fn generate_and_open() {
        let m = manager();
        let g = m.generate("KEPALA-BIRO-UMUM", 1, None).await.unwrap();
        assert_eq!(g.identity.suite_id, keywrap::ID_V1);
        assert_eq!(g.public_key.len(), keywrap::v1::PUBLIC_KEY_LEN);
        let k = m.open_private(&g.identity, &g.private_blob).await.unwrap();
        assert_eq!(k.len(), keywrap::v1::PRIVATE_KEY_LEN);
    }

    #[tokio::test]
    async fn blob_swap_detected() {
        let m = manager();
        let a = m.generate("KEPALA-BIRO-UMUM", 1, None).await.unwrap();
        let b = m.generate("KEPALA-BAGIAN-TU", 1, None).await.unwrap();
        assert!(matches!(
            m.open_private(&a.identity, &b.private_blob).await,
            Err(KeyError::Mismatch)
        ));
        let mut wrong_version = a.identity.clone();
        wrong_version.key_version = 2;
        assert!(matches!(
            m.open_private(&wrong_version, &a.private_blob).await,
            Err(KeyError::Mismatch)
        ));
    }

    #[test]
    fn malformed_envelopes() {
        let cases: [&[u8]; 4] = [
            b"",
            b"JKB1",
            b"XXXX\x00\x00\x00\x01a",
            b"JKB1\xff\xff\xff\xff",
        ];
        for bad in cases {
            assert!(decode_envelope(bad).is_err());
        }
    }
}
