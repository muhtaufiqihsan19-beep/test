//! Inti Crypto Service: seal, open, rewrap.
//!
//! Crypto Service tidak memutuskan siapa boleh membuka; keputusan akses ada di
//! Key Service API (Laravel). Layanan ini hanya menjalankan kriptografi dan
//! menolak apa pun yang tidak konsisten.

use std::collections::HashSet;
use std::sync::Arc;

use aws_lc_rs::rand;
use thiserror::Error;
use zeroize::Zeroizing;

use crate::agility::{Context, CryptoError, Registry};
use crate::eks1;
use crate::jabatankey::{Identity, KeyError, Manager};
use crate::kek::KekError;
use crate::keywrap::v1::DEK_LEN;

#[derive(Debug, Error)]
pub enum ServiceError {
    #[error("permintaan tidak valid: {0}")]
    BadRequest(String),
    /// Sengaja generik: data diubah, kunci salah, atau blob ditukar.
    #[error("dokumen atau kunci gagal dibuka")]
    Open,
    #[error("dokumen melebihi batas ukuran")]
    TooLarge,
    #[error("kesalahan internal: {0}")]
    Internal(String),
}

/// Jabatan penerima beserta kunci publiknya (dari tabel jabatan_keys).
#[derive(Debug, Clone)]
pub struct Recipient {
    pub jabatan_code: String,
    pub key_version: u32,
    pub suite_id: String,
    pub public_key: Vec<u8>,
}

/// Satu baris document_keys.
#[derive(Debug, Clone)]
pub struct WrappedKey {
    pub jabatan_code: String,
    pub key_version: u32,
    pub suite_id: String,
    pub wrapped_key: Vec<u8>,
}

/// Kunci terbungkus milik satu jabatan beserta blob kunci privatnya.
#[derive(Debug, Clone)]
pub struct KeyHolder {
    pub key: WrappedKey,
    pub private_blob: String,
}

pub struct Service {
    pub registry: Arc<Registry>,
    pub keys: Manager,
    pub max_plaintext: usize,
    pub chunk_size: u32,
}

pub struct Sealed {
    pub ciphertext: Vec<u8>,
    pub wrapped_keys: Vec<WrappedKey>,
}

impl Service {
    fn wrap_all(
        &self,
        document_id: &str,
        version: u32,
        dek: &[u8],
        recipients: &[Recipient],
    ) -> Result<Vec<WrappedKey>, ServiceError> {
        if recipients.is_empty() {
            return Err(ServiceError::BadRequest("penerima kosong".into()));
        }
        let mut seen = HashSet::new();
        let mut out = Vec::with_capacity(recipients.len());
        for r in recipients {
            if !seen.insert(r.jabatan_code.as_str()) {
                return Err(ServiceError::BadRequest(format!(
                    "jabatan {} ganda",
                    r.jabatan_code
                )));
            }
            let suite = self
                .registry
                .lookup(&r.suite_id)
                .map_err(|e| ServiceError::BadRequest(e.to_string()))?;
            let ctx = Context {
                document_id: document_id.to_string(),
                version,
                jabatan_code: r.jabatan_code.clone(),
                key_version: r.key_version,
            };
            let wrapped_key = suite.wrap(&r.public_key, dek, &ctx).map_err(|e| {
                ServiceError::BadRequest(format!("kunci publik {}: {e}", r.jabatan_code))
            })?;
            out.push(WrappedKey {
                jabatan_code: r.jabatan_code.clone(),
                key_version: r.key_version,
                suite_id: suite.id().to_string(),
                wrapped_key,
            });
        }
        Ok(out)
    }

    /// Membuat DEK baru, mengenkripsi plaintext (EKS1), lalu membungkus DEK
    /// untuk setiap penerima. DEK tidak pernah keluar dari fungsi ini.
    /// Setiap versi dokumen (termasuk setiap TTE) wajib memakai `seal` baru.
    pub fn seal(
        &self,
        document_id: &str,
        version: u32,
        plaintext: &[u8],
        recipients: &[Recipient],
    ) -> Result<Sealed, ServiceError> {
        if document_id.is_empty() || version == 0 {
            return Err(ServiceError::BadRequest(
                "document_id dan version wajib".into(),
            ));
        }
        if plaintext.len() > self.max_plaintext {
            return Err(ServiceError::TooLarge);
        }
        let mut dek = Zeroizing::new([0u8; DEK_LEN]);
        rand::fill(&mut dek[..]).map_err(|_| ServiceError::Internal("RNG".into()))?;

        // Bungkus dulu agar kunci publik yang rusak ditolak sebelum enkripsi.
        let wrapped_keys = self.wrap_all(document_id, version, &dek[..], recipients)?;
        let mut ciphertext = Vec::with_capacity(plaintext.len() + plaintext.len() / 64 + 256);
        eks1::encrypt(
            &mut ciphertext,
            plaintext,
            &dek[..],
            document_id,
            version,
            self.chunk_size,
        )
        .map_err(|e| ServiceError::BadRequest(e.to_string()))?;
        Ok(Sealed {
            ciphertext,
            wrapped_keys,
        })
    }

    async fn unwrap_dek(
        &self,
        document_id: &str,
        version: u32,
        holder: &KeyHolder,
    ) -> Result<Zeroizing<Vec<u8>>, ServiceError> {
        let suite = self
            .registry
            .lookup(&holder.key.suite_id)
            .map_err(|e| ServiceError::BadRequest(e.to_string()))?;
        let private_key = self
            .keys
            .open_private(
                &Identity {
                    jabatan_code: holder.key.jabatan_code.clone(),
                    key_version: holder.key.key_version,
                    suite_id: suite.id().to_string(),
                },
                &holder.private_blob,
            )
            .await
            .map_err(|e| match e {
                // Gangguan infrastruktur (OpenBao mati, token hilang): 500, bukan masalah dokumen.
                KeyError::Kek(
                    KekError::Transport(_)
                    | KekError::Token
                    | KekError::Config(_)
                    | KekError::BadResponse,
                ) => ServiceError::Internal(e.to_string()),
                // Blob ditolak, ditukar, atau rusak.
                _ => ServiceError::Open,
            })?;
        let ctx = Context {
            document_id: document_id.to_string(),
            version,
            jabatan_code: holder.key.jabatan_code.clone(),
            key_version: holder.key.key_version,
        };
        suite
            .unwrap(&private_key, &holder.key.wrapped_key, &ctx)
            .map_err(|_: CryptoError| ServiceError::Open)
    }

    /// Membuka dokumen untuk satu jabatan. Plaintext hanya dikembalikan bila
    /// SELURUH file lolos autentikasi dan header cocok dengan dokumen/versi.
    pub async fn open(
        &self,
        document_id: &str,
        version: u32,
        holder: &KeyHolder,
        ciphertext: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, ServiceError> {
        let dek = self.unwrap_dek(document_id, version, holder).await?;
        let mut out = Zeroizing::new(Vec::with_capacity(ciphertext.len()));
        let header = eks1::decrypt(&mut *out, ciphertext, &dek).map_err(|_| ServiceError::Open)?;
        if header.document_id != document_id || header.version != version {
            return Err(ServiceError::Open);
        }
        if out.len() > self.max_plaintext {
            return Err(ServiceError::TooLarge);
        }
        Ok(out)
    }

    /// Membungkus DEK yang sama untuk jabatan tambahan (disposisi, Plh/Plt,
    /// escrow) tanpa mengenkripsi ulang PDF. Sumber harus jabatan yang memegang kunci.
    pub async fn rewrap(
        &self,
        document_id: &str,
        version: u32,
        source: &KeyHolder,
        targets: &[Recipient],
    ) -> Result<Vec<WrappedKey>, ServiceError> {
        if targets
            .iter()
            .any(|t| t.jabatan_code == source.key.jabatan_code)
        {
            return Err(ServiceError::BadRequest("target sama dengan sumber".into()));
        }
        let dek = self.unwrap_dek(document_id, version, source).await?;
        self.wrap_all(document_id, version, &dek, targets)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jabatankey::Generated;
    use crate::kek::{InsecureDevSealer, Sealer};
    use crate::keywrap;
    use std::collections::HashMap;

    async fn setup() -> (Service, HashMap<&'static str, Generated>) {
        let registry = Arc::new(keywrap::registry(keywrap::ID_V1).unwrap());
        let keys = Manager {
            registry: registry.clone(),
            sealer: Sealer::Dev(InsecureDevSealer::new().unwrap()),
        };
        let mut gen_keys = HashMap::new();
        for code in [
            "STAF-UMUM",
            "KETUA-TIM",
            "KEPALA-BAGIAN",
            "KEPALA-BIRO",
            "TU-BIRO",
        ] {
            gen_keys.insert(code, keys.generate(code, 1, None).await.unwrap());
        }
        (
            Service {
                registry,
                keys,
                max_plaintext: 1 << 20,
                chunk_size: 4096,
            },
            gen_keys,
        )
    }

    fn rcpt(g: &Generated) -> Recipient {
        Recipient {
            jabatan_code: g.identity.jabatan_code.clone(),
            key_version: g.identity.key_version,
            suite_id: g.identity.suite_id.clone(),
            public_key: g.public_key.clone(),
        }
    }

    /// Kunci terbungkus milik `g`; bila bukan penerima, pakai milik orang lain dengan blob `g`.
    fn holder(g: &Generated, wk: &[WrappedKey]) -> KeyHolder {
        let key = wk
            .iter()
            .find(|w| w.jabatan_code == g.identity.jabatan_code)
            .cloned()
            .unwrap_or_else(|| WrappedKey {
                jabatan_code: g.identity.jabatan_code.clone(),
                key_version: g.identity.key_version,
                ..wk[0].clone()
            });
        KeyHolder {
            key,
            private_blob: g.private_blob.clone(),
        }
    }

    #[tokio::test]
    async fn only_recipients_can_open() {
        let (s, k) = setup().await;
        let mut pdf = vec![0u8; 10_000];
        rand::fill(&mut pdf).unwrap();
        let sealed = s
            .seal(
                "ND-1",
                1,
                &pdf,
                &[rcpt(&k["STAF-UMUM"]), rcpt(&k["KETUA-TIM"])],
            )
            .unwrap();
        for code in ["STAF-UMUM", "KETUA-TIM"] {
            let got = s
                .open(
                    "ND-1",
                    1,
                    &holder(&k[code], &sealed.wrapped_keys),
                    &sealed.ciphertext,
                )
                .await
                .unwrap();
            assert_eq!(&got[..], &pdf[..], "{code}");
        }
        let tu = holder(&k["TU-BIRO"], &sealed.wrapped_keys);
        assert!(matches!(
            s.open("ND-1", 1, &tu, &sealed.ciphertext).await,
            Err(ServiceError::Open)
        ));
    }

    #[tokio::test]
    async fn wrong_document_or_version() {
        let (s, k) = setup().await;
        let sealed = s
            .seal("ND-1", 1, b"isi", &[rcpt(&k["KEPALA-BIRO"])])
            .unwrap();
        let h = holder(&k["KEPALA-BIRO"], &sealed.wrapped_keys);
        assert!(s.open("ND-2", 1, &h, &sealed.ciphertext).await.is_err());
        assert!(s.open("ND-1", 2, &h, &sealed.ciphertext).await.is_err());
    }

    #[tokio::test]
    async fn approval_chain_new_version_new_dek() {
        // Staf membuat draf v1; Ketua Tim TTE menghasilkan v2 dengan DEK baru.
        let (s, k) = setup().await;
        let chain: Vec<_> = ["STAF-UMUM", "KETUA-TIM", "KEPALA-BAGIAN", "KEPALA-BIRO"]
            .iter()
            .map(|c| rcpt(&k[c]))
            .collect();
        let v1 = s.seal("ND-9", 1, b"draf", &chain).unwrap();
        let v2 = s.seal("ND-9", 2, b"draf + TTE Ketua Tim", &chain).unwrap();
        let old = holder(&k["KEPALA-BIRO"], &v1.wrapped_keys);
        assert!(s.open("ND-9", 2, &old, &v2.ciphertext).await.is_err());
        let new = holder(&k["KEPALA-BIRO"], &v2.wrapped_keys);
        assert_eq!(
            &s.open("ND-9", 2, &new, &v2.ciphertext).await.unwrap()[..],
            b"draf + TTE Ketua Tim"
        );
    }

    #[tokio::test]
    async fn rewrap_for_disposisi() {
        let (s, k) = setup().await;
        let sealed = s
            .seal("ND-5", 3, b"surat masuk", &[rcpt(&k["KEPALA-BIRO"])])
            .unwrap();
        let added = s
            .rewrap(
                "ND-5",
                3,
                &holder(&k["KEPALA-BIRO"], &sealed.wrapped_keys),
                &[rcpt(&k["KEPALA-BAGIAN"])],
            )
            .await
            .unwrap();
        let got = s
            .open(
                "ND-5",
                3,
                &holder(&k["KEPALA-BAGIAN"], &added),
                &sealed.ciphertext,
            )
            .await
            .unwrap();
        assert_eq!(&got[..], b"surat masuk");
        // Jabatan yang tidak memegang kunci tidak bisa menjadi sumber rewrap.
        let tu = holder(&k["TU-BIRO"], &sealed.wrapped_keys);
        assert!(
            s.rewrap("ND-5", 3, &tu, &[rcpt(&k["STAF-UMUM"])])
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn seal_validation() {
        let (s, k) = setup().await;
        let r = rcpt(&k["KEPALA-BIRO"]);
        assert!(matches!(
            s.seal("ND-1", 1, b"", &[]),
            Err(ServiceError::BadRequest(_))
        ));
        assert!(matches!(
            s.seal("ND-1", 1, b"", &[r.clone(), r.clone()]),
            Err(ServiceError::BadRequest(_))
        ));
        let mut bad = r.clone();
        bad.suite_id = "RSA-OAEP".into();
        assert!(matches!(
            s.seal("ND-1", 1, b"", &[bad]),
            Err(ServiceError::BadRequest(_))
        ));
        assert!(matches!(
            s.seal(
                "ND-1",
                1,
                &vec![0u8; (1 << 20) + 1],
                std::slice::from_ref(&r)
            ),
            Err(ServiceError::TooLarge)
        ));
        assert!(s.seal("ND-1", 1, &vec![0u8; 1 << 20], &[r]).is_ok());
    }
}
