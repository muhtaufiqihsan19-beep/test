//! Crypto Service untuk Key Service E-Office.
//!
//! Prinsip (Opsi 1): modul ini milik Perisai Squad, tetapi semua primitif
//! kriptografi (ML-KEM-768, X25519, HKDF-SHA256, AES-256-GCM, SHA-256, RNG)
//! diambil dari AWS-LC lewat `aws-lc-rs`. Tidak ada primitif yang ditulis sendiri.
//! Yang ditulis sendiri: susunan skema, format file, pengikatan konteks,
//! manajemen kunci jabatan, dan API internal.

#![forbid(unsafe_code)]

pub mod agility;
pub mod config;
pub mod eks1;
pub mod httpapi;
pub mod jabatankey;
pub mod kek;
pub mod keywrap;
pub mod service;
pub mod tls;
