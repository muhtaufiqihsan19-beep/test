//! Suite v1: X25519 + ML-KEM-768, digabung HKDF-SHA256, DEK dibungkus AES-256-GCM.
//!
//! Format:
//!
//! ```text
//! kunci publik  = X25519 publik (32) || ML-KEM-768 encapsulation key (1184)
//! kunci privat  = X25519 seed (32) || ML-KEM-768 encapsulation key (1184)
//!                 || ML-KEM-768 decapsulation key (2400)
//!                 (encapsulation key ikut disimpan karena dibutuhkan untuk pengikatan `info`)
//! terbungkus    = X25519 publik efemeral (32) || kapsul ML-KEM (1088)
//!                 || nonce (12) || DEK terenkripsi (32) || tag (16)
//!
//! KEK = HKDF-SHA256(IKM = rahasia ML-KEM || rahasia X25519, salt = kosong,
//!       info = LP(label) || LP(pub efemeral) || LP(X25519 pub jabatan)
//!              || LP(SHA-256(pub jabatan)) || LP(kapsul ML-KEM) || LP(context))
//! AAD AES-GCM = context
//! ```
//!
//! `LP(x)` = panjang `x` (4 byte big-endian) diikuti `x`; `context` adalah
//! `Context::encode()` di `agility.rs`.

use aws_lc_rs::aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};
use aws_lc_rs::agreement::{self, PrivateKey, UnparsedPublicKey, X25519};
use aws_lc_rs::digest;
use aws_lc_rs::encoding::{AsBigEndian, Curve25519SeedBin};
use aws_lc_rs::hkdf;
use aws_lc_rs::kem::{Ciphertext, DecapsulationKey, EncapsulationKey, ML_KEM_768};
use aws_lc_rs::rand;
use zeroize::Zeroizing;

use crate::agility::{Context, CryptoError, KeyPair, Suite, append_lp};

pub const ID_V1: &str = "X25519-MLKEM768-HKDFSHA256-AES256GCM-v1";
const LABEL: &[u8] = b"perisai-keyservice/keywrap/X25519-MLKEM768-HKDFSHA256-AES256GCM/v1";

const X25519_LEN: usize = 32;
const MLKEM768_EK_LEN: usize = 1184;
const MLKEM768_DK_LEN: usize = 2400;
const MLKEM768_CT_LEN: usize = 1088;
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;
pub const DEK_LEN: usize = 32;

pub const PUBLIC_KEY_LEN: usize = X25519_LEN + MLKEM768_EK_LEN;
pub const PRIVATE_KEY_LEN: usize = X25519_LEN + MLKEM768_EK_LEN + MLKEM768_DK_LEN;
pub const WRAPPED_LEN: usize = X25519_LEN + MLKEM768_CT_LEN + NONCE_LEN + DEK_LEN + TAG_LEN;

pub struct V1;

fn internal<E>(_: E) -> CryptoError {
    CryptoError::Internal
}

fn x25519_seed(k: &PrivateKey) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    let seed: Curve25519SeedBin<'static> =
        AsBigEndian::<Curve25519SeedBin<'static>>::as_be_bytes(k).map_err(internal)?;
    Ok(Zeroizing::new(seed.as_ref().to_vec()))
}

fn x25519_agree(
    my: &PrivateKey,
    peer: &[u8],
    err: CryptoError,
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    let peer = UnparsedPublicKey::new(&X25519, peer);
    let ss = agreement::agree(my, peer, err.clone(), |km| Ok(Zeroizing::new(km.to_vec())))?;
    // Tolak hasil semua nol (titik berorde rendah).
    if ss.iter().all(|b| *b == 0) {
        return Err(err);
    }
    Ok(ss)
}

fn derive_kek(
    ss_m: &[u8],
    ss_x: &[u8],
    eph_pub: &[u8],
    recipient_pub: &[u8],
    kem_ct: &[u8],
    ctx: &Context,
) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
    let mut ikm = Zeroizing::new(Vec::with_capacity(ss_m.len() + ss_x.len()));
    ikm.extend_from_slice(ss_m);
    ikm.extend_from_slice(ss_x);

    let pub_hash = digest::digest(&digest::SHA256, recipient_pub);
    let mut info = Vec::with_capacity(256 + kem_ct.len());
    append_lp(&mut info, LABEL);
    append_lp(&mut info, eph_pub);
    append_lp(&mut info, &recipient_pub[..X25519_LEN]);
    append_lp(&mut info, pub_hash.as_ref());
    append_lp(&mut info, kem_ct);
    append_lp(&mut info, &ctx.encode());

    let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, &[]);
    let prk = salt.extract(&ikm);
    let info_parts = [info.as_slice()];
    let okm = prk
        .expand(&info_parts, hkdf::HKDF_SHA256)
        .map_err(internal)?;
    let mut kek = Zeroizing::new([0u8; 32]);
    okm.fill(&mut kek[..]).map_err(internal)?;
    Ok(kek)
}

fn aead_key(key: &[u8]) -> Result<LessSafeKey, CryptoError> {
    Ok(LessSafeKey::new(
        UnboundKey::new(&AES_256_GCM, key).map_err(internal)?,
    ))
}

impl Suite for V1 {
    fn id(&self) -> &'static str {
        ID_V1
    }

    fn generate_key_pair(&self) -> Result<KeyPair, CryptoError> {
        let x = PrivateKey::generate(&X25519).map_err(internal)?;
        let x_pub = x.compute_public_key().map_err(internal)?;
        let x_seed = x25519_seed(&x)?;

        let dk = DecapsulationKey::generate(&ML_KEM_768).map_err(internal)?;
        let ek = dk.encapsulation_key().map_err(internal)?;
        let ek_bytes = ek.key_bytes().map_err(internal)?;
        let dk_bytes = dk.key_bytes().map_err(internal)?;
        if ek_bytes.as_ref().len() != MLKEM768_EK_LEN || dk_bytes.as_ref().len() != MLKEM768_DK_LEN
        {
            return Err(CryptoError::Internal);
        }

        let mut public_key = Vec::with_capacity(PUBLIC_KEY_LEN);
        public_key.extend_from_slice(x_pub.as_ref());
        public_key.extend_from_slice(ek_bytes.as_ref());

        let mut private_key = Zeroizing::new(Vec::with_capacity(PRIVATE_KEY_LEN));
        private_key.extend_from_slice(&x_seed);
        private_key.extend_from_slice(ek_bytes.as_ref());
        private_key.extend_from_slice(dk_bytes.as_ref());
        Ok(KeyPair {
            public_key,
            private_key,
        })
    }

    fn wrap(&self, public_key: &[u8], dek: &[u8], ctx: &Context) -> Result<Vec<u8>, CryptoError> {
        if public_key.len() != PUBLIC_KEY_LEN || dek.len() != DEK_LEN {
            return Err(CryptoError::InvalidInput);
        }
        ctx.validate()?;
        let (recipient_x, recipient_ek) = public_key.split_at(X25519_LEN);
        let ek = EncapsulationKey::new(&ML_KEM_768, recipient_ek)
            .map_err(|_| CryptoError::InvalidInput)?;

        let eph = PrivateKey::generate(&X25519).map_err(internal)?;
        let eph_pub = eph.compute_public_key().map_err(internal)?;
        let ss_x = x25519_agree(&eph, recipient_x, CryptoError::InvalidInput)?;
        let (kem_ct, ss_m) = ek.encapsulate().map_err(internal)?;

        let kek = derive_kek(
            ss_m.as_ref(),
            &ss_x,
            eph_pub.as_ref(),
            public_key,
            kem_ct.as_ref(),
            ctx,
        )?;
        let key = aead_key(&kek[..])?;

        let mut nonce = [0u8; NONCE_LEN];
        rand::fill(&mut nonce).map_err(internal)?;
        let mut sealed = dek.to_vec();
        key.seal_in_place_append_tag(
            Nonce::assume_unique_for_key(nonce),
            Aad::from(ctx.encode().as_slice()),
            &mut sealed,
        )
        .map_err(internal)?;

        let mut out = Vec::with_capacity(WRAPPED_LEN);
        out.extend_from_slice(eph_pub.as_ref());
        out.extend_from_slice(kem_ct.as_ref());
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&sealed);
        debug_assert_eq!(out.len(), WRAPPED_LEN);
        Ok(out)
    }

    fn unwrap(
        &self,
        private_key: &[u8],
        wrapped: &[u8],
        ctx: &Context,
    ) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
        if private_key.len() != PRIVATE_KEY_LEN || wrapped.len() != WRAPPED_LEN {
            return Err(CryptoError::Unwrap);
        }
        ctx.validate().map_err(|_| CryptoError::Unwrap)?;

        let (x_seed, rest) = private_key.split_at(X25519_LEN);
        let (ek_bytes, dk_bytes) = rest.split_at(MLKEM768_EK_LEN);
        let x = PrivateKey::from_private_key(&X25519, x_seed).map_err(|_| CryptoError::Unwrap)?;
        let x_pub = x.compute_public_key().map_err(|_| CryptoError::Unwrap)?;
        let dk = DecapsulationKey::new(&ML_KEM_768, dk_bytes).map_err(|_| CryptoError::Unwrap)?;

        let (eph_pub, rest) = wrapped.split_at(X25519_LEN);
        let (kem_ct, rest) = rest.split_at(MLKEM768_CT_LEN);
        let (nonce, sealed) = rest.split_at(NONCE_LEN);

        let ss_x = x25519_agree(&x, eph_pub, CryptoError::Unwrap)?;
        // ML-KEM implicit rejection: kapsul rusak menghasilkan rahasia acak, lalu gagal di AES-GCM.
        let ss_m = dk
            .decapsulate(Ciphertext::from(kem_ct))
            .map_err(|_| CryptoError::Unwrap)?;

        let mut recipient_pub = Vec::with_capacity(PUBLIC_KEY_LEN);
        recipient_pub.extend_from_slice(x_pub.as_ref());
        recipient_pub.extend_from_slice(ek_bytes);

        let kek = derive_kek(ss_m.as_ref(), &ss_x, eph_pub, &recipient_pub, kem_ct, ctx)
            .map_err(|_| CryptoError::Unwrap)?;
        let key = aead_key(&kek[..]).map_err(|_| CryptoError::Unwrap)?;

        let nonce: [u8; NONCE_LEN] = nonce.try_into().map_err(|_| CryptoError::Unwrap)?;
        let mut buf = Zeroizing::new(sealed.to_vec());
        let plain_len = key
            .open_in_place(
                Nonce::assume_unique_for_key(nonce),
                Aad::from(ctx.encode().as_slice()),
                &mut buf,
            )
            .map_err(|_| CryptoError::Unwrap)?
            .len();
        if plain_len != DEK_LEN {
            return Err(CryptoError::Unwrap);
        }
        buf.truncate(plain_len);
        Ok(buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx() -> Context {
        Context {
            document_id: "ND-2026-0001".into(),
            version: 1,
            jabatan_code: "KEPALA-BIRO-UMUM".into(),
            key_version: 1,
        }
    }

    fn dek() -> Vec<u8> {
        let mut d = vec![0u8; DEK_LEN];
        rand::fill(&mut d).unwrap();
        d
    }

    #[test]
    fn sizes() {
        let kp = V1.generate_key_pair().unwrap();
        assert_eq!(kp.public_key.len(), PUBLIC_KEY_LEN);
        assert_eq!(kp.private_key.len(), PRIVATE_KEY_LEN);
        let w = V1.wrap(&kp.public_key, &dek(), &ctx()).unwrap();
        assert_eq!(w.len(), WRAPPED_LEN);
    }

    #[test]
    fn round_trip_and_randomized() {
        let kp = V1.generate_key_pair().unwrap();
        let d = dek();
        let w1 = V1.wrap(&kp.public_key, &d, &ctx()).unwrap();
        let w2 = V1.wrap(&kp.public_key, &d, &ctx()).unwrap();
        assert_ne!(w1, w2, "pembungkusan harus acak");
        assert_eq!(
            &V1.unwrap(&kp.private_key, &w1, &ctx()).unwrap()[..],
            &d[..]
        );
        assert_eq!(
            &V1.unwrap(&kp.private_key, &w2, &ctx()).unwrap()[..],
            &d[..]
        );
    }

    type Mutation = (&'static str, Box<dyn Fn(&mut Context)>);

    #[test]
    fn context_binding() {
        let kp = V1.generate_key_pair().unwrap();
        let w = V1.wrap(&kp.public_key, &dek(), &ctx()).unwrap();
        let mutations: Vec<Mutation> = vec![
            (
                "dokumen lain",
                Box::new(|c: &mut Context| c.document_id = "ND-2026-0002".into()),
            ),
            ("versi lain", Box::new(|c: &mut Context| c.version = 2)),
            (
                "jabatan lain",
                Box::new(|c: &mut Context| c.jabatan_code = "KEPALA-BAGIAN".into()),
            ),
            (
                "versi kunci lain",
                Box::new(|c: &mut Context| c.key_version = 2),
            ),
        ];
        for (name, m) in mutations {
            let mut c = ctx();
            m(&mut c);
            assert_eq!(
                V1.unwrap(&kp.private_key, &w, &c).unwrap_err(),
                CryptoError::Unwrap,
                "{name}"
            );
        }
    }

    #[test]
    fn wrong_private_key() {
        let a = V1.generate_key_pair().unwrap();
        let b = V1.generate_key_pair().unwrap();
        let w = V1.wrap(&a.public_key, &dek(), &ctx()).unwrap();
        assert!(V1.unwrap(&b.private_key, &w, &ctx()).is_err());
    }

    #[test]
    fn tamper_every_region() {
        let kp = V1.generate_key_pair().unwrap();
        let w = V1.wrap(&kp.public_key, &dek(), &ctx()).unwrap();
        for pos in [
            0,
            5,
            31,
            32,
            100,
            600,
            X25519_LEN + MLKEM768_CT_LEN,
            w.len() - 17,
            w.len() - 1,
        ] {
            let mut bad = w.clone();
            bad[pos] ^= 0x01;
            assert!(
                V1.unwrap(&kp.private_key, &bad, &ctx()).is_err(),
                "byte {pos}"
            );
        }
        assert!(
            V1.unwrap(&kp.private_key, &w[..w.len() - 1], &ctx())
                .is_err()
        );
    }

    #[test]
    fn invalid_inputs() {
        let kp = V1.generate_key_pair().unwrap();
        assert!(V1.wrap(&kp.public_key, &[0u8; 16], &ctx()).is_err());
        assert!(V1.wrap(&kp.public_key[..10], &dek(), &ctx()).is_err());
        let empty = Context {
            document_id: String::new(),
            version: 0,
            jabatan_code: String::new(),
            key_version: 0,
        };
        assert!(V1.wrap(&kp.public_key, &dek(), &empty).is_err());
    }

    #[test]
    fn low_order_x25519_point_rejected() {
        let kp = V1.generate_key_pair().unwrap();
        let mut bad = kp.public_key.clone();
        bad[..X25519_LEN].fill(0);
        assert!(V1.wrap(&bad, &dek(), &ctx()).is_err());
    }

    #[test]
    fn private_key_round_trips_through_bytes() {
        // Kunci privat disimpan sebagai byte lalu dimuat ulang: harus tetap bisa membuka.
        let kp = V1.generate_key_pair().unwrap();
        let stored = kp.private_key.to_vec();
        let d = dek();
        let w = V1.wrap(&kp.public_key, &d, &ctx()).unwrap();
        assert_eq!(&V1.unwrap(&stored, &w, &ctx()).unwrap()[..], &d[..]);
    }
}
