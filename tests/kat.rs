//! Known-answer test (KAT) resmi untuk primitif AWS-LC yang dipakai Crypto Service.
//!
//! Sumber dan lisensi vektor ada di `tests/vectors/README.md`. Uji ini memanggil
//! API publik `aws-lc-rs` yang sama dengan yang dipakai kode produksi.

use std::collections::BTreeMap;
use std::path::PathBuf;

use aws_lc_rs::aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};
use aws_lc_rs::agreement::{self, PrivateKey, UnparsedPublicKey, X25519};
use aws_lc_rs::hkdf;
use aws_lc_rs::kem::{Ciphertext, DecapsulationKey, EncapsulationKey, ML_KEM_768};
use serde_json::Value;

fn load(rel: &str) -> Value {
    let p: PathBuf = [env!("CARGO_MANIFEST_DIR"), "tests", "vectors", rel]
        .iter()
        .collect();
    let s = std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("{}: {e}", p.display()));
    serde_json::from_str(&s).unwrap()
}

fn hex(v: &Value) -> Vec<u8> {
    let s = v.as_str().expect("field hex");
    assert!(s.len().is_multiple_of(2), "hex ganjil");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex tidak valid"))
        .collect()
}

/// Ringkasan jumlah kasus per kategori, dicetak agar terlihat di keluaran uji.
#[derive(Default)]
struct Tally(BTreeMap<String, usize>);

impl Tally {
    fn hit(&mut self, k: impl Into<String>) {
        *self.0.entry(k.into()).or_default() += 1;
    }
    fn print(&self, name: &str) {
        println!("{name}: {:?}", self.0);
    }
}

// ---------------------------------------------------------------- ML-KEM-768 (NIST ACVP)

#[test]
fn acvp_mlkem768_encapsulation() {
    let v = load("acvp/ML-KEM-768-encapDecap.json");
    let mut t = Tally::default();
    for g in v["testGroups"].as_array().unwrap() {
        if g["function"] != "encapsulation" {
            continue;
        }
        assert_eq!(g["parameterSet"], "ML-KEM-768");
        for tc in g["tests"].as_array().unwrap() {
            let id = &tc["tcId"];
            let (ek, dk, c, k) = (hex(&tc["ek"]), hex(&tc["dk"]), hex(&tc["c"]), hex(&tc["k"]));

            // ek dimuat dan diserialisasi ulang tanpa perubahan.
            let ek_key = EncapsulationKey::new(&ML_KEM_768, &ek).expect("ek valid");
            assert_eq!(ek_key.key_bytes().unwrap().as_ref(), &ek[..], "tc {id}: ek");

            // dk dimuat dan diserialisasi ulang tanpa perubahan. Catatan: aws-lc-rs tidak bisa
            // menurunkan ek dari dk yang dimuat lewat `new` (terdokumentasi di
            // `DecapsulationKey::encapsulation_key`); karena itu keywrap::v1 menyimpan ek
            // terpisah di kunci privat. Di sini cukup dicek bahwa ek ada di dalam dk sesuai
            // tata letak FIPS 203 (dk = dk_PKE(1152) || ek(1184) || H(ek)(32) || z(32)).
            let dk_key = DecapsulationKey::new(&ML_KEM_768, &dk).expect("dk valid");
            assert_eq!(dk_key.key_bytes().unwrap().as_ref(), &dk[..], "tc {id}: dk");
            assert_eq!(&dk[1152..1152 + 1184], &ek[..], "tc {id}: ek di dalam dk");

            // Kapsul hasil NIST (dari m vektor) dibuka AWS-LC menjadi k yang sama.
            let got = dk_key.decapsulate(Ciphertext::from(&c[..])).unwrap();
            assert_eq!(got.as_ref(), &k[..], "tc {id}: k");

            // aws-lc-rs tidak membuka API encapsulate deterministik (input m), jadi
            // langkah m -> (c, k) tidak bisa dibandingkan byte per byte. Sebagai gantinya:
            // encapsulate acak ke ek vektor harus bisa dibuka dk vektor.
            let (c2, k2) = ek_key.encapsulate().unwrap();
            let k3 = dk_key.decapsulate(c2).unwrap();
            assert_eq!(k2.as_ref(), k3.as_ref(), "tc {id}: round trip");
            t.hit("encapsulation (c,k vektor dibuka; m->c tidak diuji)");
        }
    }
    t.print("ACVP ML-KEM-768 encapsulation");
    assert_eq!(t.0.values().sum::<usize>(), 25);
}

#[test]
fn acvp_mlkem768_decapsulation() {
    let v = load("acvp/ML-KEM-768-encapDecap.json");
    let mut t = Tally::default();
    for g in v["testGroups"].as_array().unwrap() {
        if g["function"] != "decapsulation" {
            continue;
        }
        for tc in g["tests"].as_array().unwrap() {
            let dk = DecapsulationKey::new(&ML_KEM_768, &hex(&tc["dk"])).unwrap();
            let got = dk
                .decapsulate(Ciphertext::from(&hex(&tc["c"])[..]))
                .unwrap();
            assert_eq!(got.as_ref(), &hex(&tc["k"])[..], "tc {}", tc["tcId"]);
            // reason: "valid decapsulation" atau variasi kapsul yang diubah (implicit rejection).
            t.hit(tc["reason"].as_str().unwrap_or("?"));
        }
    }
    t.print("ACVP ML-KEM-768 decapsulation");
    assert_eq!(t.0.values().sum::<usize>(), 10);
}

#[test]
fn acvp_mlkem768_encapsulation_key_check() {
    // FIPS 203 bagian 7.2: pemeriksaan modulus pada ek.
    //
    // AWS-LC menjalankan pemeriksaan ini saat ek DIPAKAI (encapsulate), bukan saat
    // `EncapsulationKey::new` (yang hanya memeriksa panjang). Itu tetap memenuhi FIPS 203
    // ("sebelum Encaps"): ek yang gagal tidak pernah menghasilkan kapsul. Uji ini memastikan
    // perilaku persis itu, dan `keywrap_v1_rejects_invalid_ek` memastikan kode kita ikut menolak.
    let v = load("acvp/ML-KEM-768-encapDecap.json");
    let mut t = Tally::default();
    for g in v["testGroups"].as_array().unwrap() {
        if g["function"] != "encapsulationKeyCheck" {
            continue;
        }
        for tc in g["tests"].as_array().unwrap() {
            let want = tc["testPassed"].as_bool().unwrap();
            let ek = EncapsulationKey::new(&ML_KEM_768, &hex(&tc["ek"])).expect("panjang benar");
            let got = ek.encapsulate().is_ok();
            assert_eq!(got, want, "tc {} ({})", tc["tcId"], tc["reason"]);
            t.hit(format!("passed={want}"));
        }
    }
    t.print("ACVP ML-KEM-768 encapsulationKeyCheck");
    assert_eq!(t.0.values().sum::<usize>(), 10);
}

#[test]
fn acvp_mlkem768_decapsulation_key_check() {
    // FIPS 203 bagian 7.3: pemeriksaan hash H(ek) di dalam dk.
    //
    // Sama seperti ek: AWS-LC memeriksa dk saat decapsulate, bukan saat `new`. dk yang gagal
    // tidak pernah menghasilkan rahasia bersama, sehingga keywrap::v1::unwrap gagal tertutup.
    let v = load("acvp/ML-KEM-768-encapDecap.json");
    let mut t = Tally::default();
    for g in v["testGroups"].as_array().unwrap() {
        if g["function"] != "decapsulationKeyCheck" {
            continue;
        }
        for tc in g["tests"].as_array().unwrap() {
            let want = tc["testPassed"].as_bool().unwrap();
            let dk = DecapsulationKey::new(&ML_KEM_768, &hex(&tc["dk"])).expect("panjang benar");
            // Kapsul sah ke ek pasangannya; dk yang valid harus bisa membukanya.
            let ek = EncapsulationKey::new(&ML_KEM_768, &hex(&tc["ek"])).unwrap();
            let (c, k) = ek.encapsulate().unwrap();
            let got = match dk.decapsulate(c) {
                Ok(k2) => {
                    assert_eq!(k2.as_ref(), k.as_ref(), "tc {}: k", tc["tcId"]);
                    true
                }
                Err(_) => false,
            };
            assert_eq!(got, want, "tc {} ({})", tc["tcId"], tc["reason"]);
            t.hit(format!("passed={want}"));
        }
    }
    t.print("ACVP ML-KEM-768 decapsulationKeyCheck");
    assert_eq!(t.0.values().sum::<usize>(), 10);
}

#[test]
fn keywrap_v1_rejects_invalid_ek() {
    // Kunci publik jabatan dengan ek yang gagal pemeriksaan modulus (vektor NIST) harus
    // ditolak oleh suite v1, bukan menghasilkan DEK terbungkus.
    use crypto_service::agility::{Context, Suite};
    use crypto_service::keywrap::V1;
    let v = load("acvp/ML-KEM-768-encapDecap.json");
    let ctx = Context {
        document_id: "KAT".into(),
        version: 1,
        jabatan_code: "KAT".into(),
        key_version: 1,
    };
    let good = V1.generate_key_pair().unwrap().public_key;
    let mut n = 0;
    for g in v["testGroups"].as_array().unwrap() {
        if g["function"] != "encapsulationKeyCheck" {
            continue;
        }
        for tc in g["tests"].as_array().unwrap() {
            let mut pk = good[..32].to_vec();
            pk.extend_from_slice(&hex(&tc["ek"]));
            let ok = V1.wrap(&pk, &[7u8; 32], &ctx).is_ok();
            assert_eq!(ok, tc["testPassed"].as_bool().unwrap(), "tc {}", tc["tcId"]);
            n += 1;
        }
    }
    assert_eq!(n, 10);
}

// ---------------------------------------------------------------- X25519 (Wycheproof)

#[test]
fn wycheproof_x25519() {
    let v = load("wycheproof/x25519_test.json");
    let mut t = Tally::default();
    for g in v["testGroups"].as_array().unwrap() {
        assert_eq!(g["curve"], "curve25519");
        for tc in g["tests"].as_array().unwrap() {
            let id = &tc["tcId"];
            let result = tc["result"].as_str().unwrap();
            let shared = hex(&tc["shared"]);
            let sk = PrivateKey::from_private_key(&X25519, &hex(&tc["private"]))
                .unwrap_or_else(|_| panic!("tc {id}: kunci privat ditolak"));
            let pk = hex(&tc["public"]);
            let got = agreement::agree(&sk, UnparsedPublicKey::new(&X25519, &pk), (), |k| {
                Ok(k.to_vec())
            });
            match (result, got) {
                ("valid", Ok(k)) => {
                    assert_eq!(k, shared, "tc {id}");
                    t.hit("valid: cocok");
                }
                ("valid", Err(())) => panic!("tc {id}: kasus valid ditolak"),
                ("acceptable", Ok(k)) => {
                    assert_eq!(k, shared, "tc {id}");
                    t.hit("acceptable: diterima, cocok");
                }
                // Penolakan hanya boleh untuk hasil nol (titik berorde rendah). Kode kita
                // (keywrap::v1) juga menolak hasil nol secara eksplisit.
                ("acceptable", Err(())) => {
                    assert!(
                        shared.iter().all(|b| *b == 0),
                        "tc {id}: kasus acceptable ditolak padahal hasil bukan nol"
                    );
                    t.hit("acceptable: ditolak (hasil nol)");
                }
                (r, _) => panic!("tc {id}: result {r} tidak dikenal"),
            }
        }
    }
    t.print("Wycheproof X25519");
    assert_eq!(t.0.values().sum::<usize>(), 518);
}

// ---------------------------------------------------------------- AES-256-GCM (Wycheproof)

#[test]
fn wycheproof_aes256gcm() {
    let v = load("wycheproof/aes_gcm_test.json");
    let mut t = Tally::default();
    for g in v["testGroups"].as_array().unwrap() {
        // Hanya parameter yang dipakai: kunci 256 bit, nonce 96 bit, tag 128 bit.
        // aws-lc-rs AES_256_GCM hanya menerima nonce 96 bit, jadi grup lain tidak relevan.
        if g["keySize"] != 256 || g["ivSize"] != 96 || g["tagSize"] != 128 {
            continue;
        }
        for tc in g["tests"].as_array().unwrap() {
            let id = &tc["tcId"];
            let key = LessSafeKey::new(UnboundKey::new(&AES_256_GCM, &hex(&tc["key"])).unwrap());
            let iv: [u8; 12] = hex(&tc["iv"]).try_into().unwrap();
            let (aad, msg) = (hex(&tc["aad"]), hex(&tc["msg"]));
            let mut sealed = hex(&tc["ct"]);
            sealed.extend_from_slice(&hex(&tc["tag"]));
            let opened = {
                let mut buf = sealed.clone();
                key.open_in_place(
                    Nonce::assume_unique_for_key(iv),
                    Aad::from(&aad[..]),
                    &mut buf,
                )
                .map(|p| p.to_vec())
            };
            match tc["result"].as_str().unwrap() {
                "valid" => {
                    assert_eq!(
                        opened.expect("valid harus terbuka"),
                        msg,
                        "tc {id}: dekripsi"
                    );
                    let mut buf = msg.clone();
                    key.seal_in_place_append_tag(
                        Nonce::assume_unique_for_key(iv),
                        Aad::from(&aad[..]),
                        &mut buf,
                    )
                    .unwrap();
                    assert_eq!(buf, sealed, "tc {id}: enkripsi");
                    t.hit("valid");
                }
                "invalid" => {
                    assert!(opened.is_err(), "tc {id}: invalid harus ditolak");
                    t.hit("invalid");
                }
                r => panic!("tc {id}: result {r} tidak dikenal"),
            }
        }
    }
    t.print("Wycheproof AES-256-GCM (iv 96, tag 128)");
    assert_eq!(t.0.values().sum::<usize>(), 66);
}

// ---------------------------------------------------------------- HKDF-SHA256 (Wycheproof)

struct Len(usize);

impl hkdf::KeyType for Len {
    fn len(&self) -> usize {
        self.0
    }
}

fn hkdf_sha256(ikm: &[u8], salt: &[u8], info: &[u8], len: usize) -> Option<Vec<u8>> {
    let prk = hkdf::Salt::new(hkdf::HKDF_SHA256, salt).extract(ikm);
    let info = [info];
    let okm = prk.expand(&info, Len(len)).ok()?;
    let mut out = vec![0u8; len];
    okm.fill(&mut out).ok()?;
    Some(out)
}

#[test]
fn wycheproof_hkdf_sha256() {
    let v = load("wycheproof/hkdf_sha256_test.json");
    let mut t = Tally::default();
    for g in v["testGroups"].as_array().unwrap() {
        for tc in g["tests"].as_array().unwrap() {
            let id = &tc["tcId"];
            let size = tc["size"].as_u64().unwrap() as usize;
            let got = hkdf_sha256(&hex(&tc["ikm"]), &hex(&tc["salt"]), &hex(&tc["info"]), size);
            match tc["result"].as_str().unwrap() {
                "valid" => {
                    assert_eq!(got.as_deref(), Some(&hex(&tc["okm"])[..]), "tc {id}");
                    t.hit("valid");
                }
                // Kasus invalid: panjang keluaran melebihi 255 * 32 byte.
                "invalid" => {
                    assert!(got.is_none(), "tc {id}: invalid harus ditolak");
                    t.hit("invalid");
                }
                r => panic!("tc {id}: result {r} tidak dikenal"),
            }
        }
    }
    t.print("Wycheproof HKDF-SHA256");
    assert_eq!(t.0.values().sum::<usize>(), 86);
}
