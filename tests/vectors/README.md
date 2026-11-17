# Test vector resmi

Vektor di folder ini dipakai oleh `tests/kat.rs` (`cargo test --test kat`) untuk menguji
primitif AWS-LC yang dipakai Crypto Service, lewat API `aws-lc-rs` yang sama dengan kode produksi.
Jangan mengubah isi vektor. Bila perlu memperbarui, ambil ulang dari sumber dan perbarui tabel ini.

| Berkas | Sumber | Versi | SHA-256 | Lisensi |
| --- | --- | --- | --- | --- |
| `acvp/ML-KEM-768-encapDecap.json` | [NIST ACVP-Server](https://github.com/usnistgov/ACVP-Server) `gen-val/json-files/ML-KEM-encapDecap-FIPS203/internalProjection.json`, hanya grup ML-KEM-768 | commit `975de31eb83d87039ec88934fdc47d8c312b892d` (12 Agustus 2026) | `d618f903c2f4a78e595f9becf218f41f5c69727c538c5a0f71686f80c3d80917` (asli: `a556952c...b810f`) | Pemberitahuan NIST, lihat `acvp/NOTICE` |
| `wycheproof/x25519_test.json` | [C2SP Wycheproof](https://github.com/C2SP/wycheproof) `testvectors_v1/` | commit `65ca494727a52944c204441c860b039e6786b99b` (11 November 2026) | `35c3f5231cf25cc640b524d403461deee9e49441d5d915a3a25b2c8ff5adbe7d` | Apache-2.0, lihat `wycheproof/LICENSE` |
| `wycheproof/aes_gcm_test.json` | idem | idem | `985e5ecc172e181eaf49e89508b9470dcf478002eb7e8559c707eb42dc97dfe7` | Apache-2.0 |
| `wycheproof/hkdf_sha256_test.json` | idem | idem | `bb2b462a38b251cb52a2aede706d6d4b62b26864f4e80c95497507ddb07c5f1e` | Apache-2.0 |

Berkas Wycheproof disalin tanpa perubahan. Berkas ACVP disaring ke ML-KEM-768 saja;
rincian perubahan ada di `acvp/NOTICE` sesuai syarat lisensi NIST.

## Cakupan uji

| Uji | Kasus | Yang diperiksa |
| --- | --- | --- |
| ML-KEM-768 encapsulation (ACVP AFT) | 25 | ek dan dk dimuat ulang tanpa perubahan; kapsul `c` dari NIST dibuka dk menjadi `k` yang sama; encapsulate acak ke ek bisa dibuka dk |
| ML-KEM-768 decapsulation (ACVP VAL) | 10 | 5 kapsul sah dan 5 kapsul diubah (implicit rejection) menghasilkan `k` persis |
| ML-KEM-768 encapsulationKeyCheck | 10 | FIPS 203 bagian 7.2: ek yang gagal pemeriksaan modulus tidak bisa dipakai encapsulate |
| ML-KEM-768 decapsulationKeyCheck | 10 | FIPS 203 bagian 7.3: dk dengan H(ek) yang diubah tidak bisa dipakai decapsulate |
| keywrap v1 menolak ek tidak valid | 10 | `V1::wrap` menolak kunci publik jabatan berisi ek dari kasus di atas |
| X25519 | 518 | 264 valid cocok; 223 acceptable diterima dan cocok; 31 acceptable dengan hasil nol ditolak |
| AES-256-GCM | 66 | Grup kunci 256 bit, nonce 96 bit, tag 128 bit: 39 valid (enkripsi dan dekripsi cocok), 27 invalid ditolak |
| HKDF-SHA256 | 86 | 83 valid cocok; 3 invalid (panjang keluaran di atas 255 x 32 byte) ditolak |

## Batasan yang perlu diketahui tim kripto

1. **Langkah deterministik ML-KEM tidak bisa diuji byte per byte.** `aws-lc-rs` 1.19 tidak membuka
   API encapsulate dengan input `m` atau keygen dengan seed `(d, z)`. Karena itu langkah
   `m -> (c, k)` di grup encapsulation dan seluruh berkas `ML-KEM-keyGen-FIPS203` tidak diuji di
   sini. Yang diuji adalah sisi decapsulation dengan keluaran resmi NIST. Implementasi AWS-LC
   sendiri menjalankan vektor ACVP di test suite-nya, dan build `fips` memakai modul tervalidasi.
2. **Pemeriksaan kunci FIPS 203 berjalan saat kunci dipakai, bukan saat dimuat.**
   `EncapsulationKey::new` dan `DecapsulationKey::new` hanya memeriksa panjang. Pemeriksaan
   modulus (7.2) dan hash (7.3) dijalankan AWS-LC saat encapsulate dan decapsulate. Hasilnya tetap
   aman karena kunci yang gagal tidak pernah menghasilkan rahasia, dan `keywrap::v1` selalu
   memuat lalu langsung memakai kunci dalam satu panggilan.
3. **AES-GCM dengan nonce selain 96 bit tidak diuji** karena `aws-lc-rs` dan Crypto Service hanya
   memakai nonce 96 bit.
