use rand::thread_rng;
use serde::{Deserialize, Serialize};

// ── ML-KEM (NIST FIPS 203) — Key Encapsulation Mechanism ───────────────────
use ml_kem::kem::{EncapsulationKey, DecapsulationKey, Encapsulate, Decapsulate};
use ml_kem::{KemCore, MlKem768, MlKem768Params, EncodedSizeUser};

// ── ML-DSA (NIST FIPS 204) — Digital Signature Algorithm ───────────────────
use ml_dsa::{MlDsa65, signature::{Signer, Verifier, Keypair}};
use ml_dsa::Generate;
// PKCS8 DER serialization for signing keys (raw &[u8] TryFrom not available)
use ml_dsa::pkcs8::{DecodePrivateKey, EncodePrivateKey};
// SPKI DER serialization for verifying keys (SubjectPublicKeyInfo format)
use ml_dsa::pkcs8::spki::{DecodePublicKey, EncodePublicKey};

// ── Public types used by main.rs ─────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct KyberKeyPair {
    pub public_key_hex: String,
    pub secret_key_hex: String,
    pub algorithm: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct KyberEncapsulation {
    pub ciphertext_hex: String,
    pub shared_secret_hex: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DilithiumKeyPair {
    pub public_key_hex: String,
    pub secret_key_hex: String,
    pub algorithm: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DilithiumSignature {
    pub signature_hex: String,
    pub public_key_hex: String,
    pub algorithm: String,
}

#[derive(Debug, Deserialize)]
pub struct PqcSignRequest {
    pub log_entry: String,
    pub secret_key: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct PqcSignResponse {
    pub algorithm: String,
    pub public_key: String,
    pub signature: String,
    pub verified: bool,
    pub worm_entry_hash: String,
}

pub struct PqcEngine;

impl PqcEngine {
    // ── ML-KEM-768: Key Encapsulation ────────────────────────────────────────
    //
    // Uses real NIST FIPS-203 ML-KEM-768 algorithm via the RustCrypto `ml-kem`
    // crate. The keys are genuine Module-Lattice-based cryptographic objects,
    // not pseudo-random byte expansions.

    /// Generate a real ML-KEM-768 keypair (encapsulation + decapsulation keys).
    pub fn kyber768_generate_keypair() -> KyberKeyPair {
        let mut rng = thread_rng();
        let (dk, ek) = MlKem768::generate(&mut rng);
        KyberKeyPair {
            public_key_hex: hex::encode(ek.as_bytes()),
            secret_key_hex: hex::encode(dk.as_bytes()),
            algorithm: "ML-KEM-768".to_string(),
        }
    }

    /// Encapsulate a shared secret with a real ML-KEM-768 public key.
    pub fn kyber768_encapsulate(public_key_hex: &str) -> KyberEncapsulation {
        let mut rng = thread_rng();
        let pk_bytes = hex::decode(public_key_hex).expect("Invalid hex for ML-KEM-768 public key");
        let arr = pk_bytes.as_slice().try_into().expect("Invalid ML-KEM-768 public key size");
        let ek = EncapsulationKey::<MlKem768Params>::from_bytes(arr);
        let (ct, ss) = ek.encapsulate(&mut rng).unwrap();
        KyberEncapsulation {
            ciphertext_hex: hex::encode(ct),
            shared_secret_hex: hex::encode(ss),
        }
    }

    /// Decapsulate a shared secret with a real ML-KEM-768 secret key.
    pub fn kyber768_decapsulate(secret_key_hex: &str, ciphertext_hex: &str) -> String {
        let sk_bytes = hex::decode(secret_key_hex).expect("Invalid hex for ML-KEM-768 secret key");
        let sk_arr = sk_bytes.as_slice().try_into().expect("Invalid ML-KEM-768 secret key size");
        let dk = DecapsulationKey::<MlKem768Params>::from_bytes(sk_arr);
        let ct_bytes = hex::decode(ciphertext_hex).expect("Invalid hex for ML-KEM-768 ciphertext");
        let ct = ct_bytes.as_slice().try_into().expect("Invalid ML-KEM-768 ciphertext bytes");
        let ss = dk.decapsulate(&ct).unwrap();
        hex::encode(ss)
    }

    // ── ML-DSA-65: Digital Signatures ────────────────────────────────────────
    //
    // Uses real NIST FIPS-204 ML-DSA-65 algorithm via the RustCrypto `ml-dsa`
    // crate. Keys are serialized as PKCS8/SPKI DER (the standard format for
    // ML-DSA keys) because the raw-bytes TryFrom path is not exposed by the
    // crate — only the ASN.1-structured formats are stable public API.

    /// Generate a real ML-DSA-65 keypair. Keys are hex-encoded PKCS8/SPKI DER.
    pub fn dilithium_generate_keypair() -> DilithiumKeyPair {
        let sk = ml_dsa::SigningKey::<MlDsa65>::generate();

        // Encode signing key as PKCS8 DER (PrivateKeyInfo format, RFC 5958)
        let sk_der = sk
            .to_pkcs8_der()
            .expect("ML-DSA-65 signing key PKCS8 DER encoding failed");

        // Encode verifying key as SPKI DER (SubjectPublicKeyInfo format, RFC 5480)
        let vk_der = sk.verifying_key()
            .to_public_key_der()
            .expect("ML-DSA-65 verifying key SPKI DER encoding failed");

        DilithiumKeyPair {
            public_key_hex: hex::encode(vk_der.as_bytes()),
            secret_key_hex: hex::encode(sk_der.as_bytes()),
            algorithm: "ML-DSA-65".to_string(),
        }
    }

    /// Sign a WORM audit entry using a real ML-DSA-65 signing key.
    pub fn dilithium_sign_worm_log(entry: &str, secret_key_hex: &str) -> DilithiumSignature {
        let sk_bytes =
            hex::decode(secret_key_hex).expect("Invalid hex for ML-DSA-65 secret key");

        // Deserialize from PKCS8 DER — this is the real cryptographic key material
        let signing_key = ml_dsa::SigningKey::<MlDsa65>::from_pkcs8_der(&sk_bytes)
            .expect("Invalid ML-DSA-65 PKCS8 DER secret key");

        // Perform real ML-DSA-65 lattice-based signing
        let sig = signing_key.sign(entry.as_bytes());

        // Encode the verifying key so the caller can store it
        let vk_der = signing_key
            .verifying_key()
            .to_public_key_der()
            .expect("ML-DSA-65 verifying key SPKI DER encoding failed");

        DilithiumSignature {
            signature_hex: hex::encode(sig.encode()),
            public_key_hex: hex::encode(vk_der.as_bytes()),
            algorithm: "ML-DSA-65".to_string(),
        }
    }

    /// Verify a ML-DSA-65 signature over a WORM audit entry.
    ///
    /// This is a REAL verification — not `!sig.is_empty()`.
    /// A wrong message, wrong key, or tampered signature all return `false`.
    pub fn dilithium_verify_worm_log(
        entry: &str,
        signature_hex: &str,
        public_key_hex: &str,
    ) -> bool {
        // Decode hex-encoded SPKI DER verifying key
        let pk_bytes = match hex::decode(public_key_hex) {
            Ok(b) => b,
            Err(_) => return false,
        };
        let vk = match ml_dsa::VerifyingKey::<MlDsa65>::from_public_key_der(&pk_bytes) {
            Ok(vk) => vk,
            Err(_) => return false,
        };

        // Decode hex-encoded signature
        let sig_bytes = match hex::decode(signature_hex) {
            Ok(b) => b,
            Err(_) => return false,
        };

        let sig_arr = match sig_bytes.as_slice().try_into() {
            Ok(arr) => arr,
            Err(_) => return false,
        };
        let sig = match ml_dsa::Signature::<MlDsa65>::decode(&sig_arr) {
            Some(sig) => sig,
            None => return false,
        };

        // Real ML-DSA-65 lattice-based signature verification
        vk.verify(entry.as_bytes(), &sig).is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Full ML-KEM-768 round-trip: generate → encapsulate → decapsulate.
    /// The shared secrets from encapsulation and decapsulation MUST match.
    #[test]
    fn test_kyber768_full_cycle() {
        let keypair = PqcEngine::kyber768_generate_keypair();
        assert_eq!(keypair.algorithm, "ML-KEM-768");
        assert!(!keypair.public_key_hex.is_empty());
        assert!(!keypair.secret_key_hex.is_empty());

        let enc = PqcEngine::kyber768_encapsulate(&keypair.public_key_hex);
        assert!(!enc.ciphertext_hex.is_empty());
        assert!(!enc.shared_secret_hex.is_empty());

        let dec_ss =
            PqcEngine::kyber768_decapsulate(&keypair.secret_key_hex, &enc.ciphertext_hex);
        // IND-CCA2 correctness: both sides must derive the same shared secret
        assert_eq!(enc.shared_secret_hex, dec_ss);
    }

    /// Full ML-DSA-65 round-trip: generate → sign → verify.
    /// Also verifies that a tampered message correctly FAILS (the old fake
    /// implementation returned true for any non-empty inputs).
    #[test]
    fn test_dilithium_full_cycle() {
        let keypair = PqcEngine::dilithium_generate_keypair();
        assert_eq!(keypair.algorithm, "ML-DSA-65");
        assert!(!keypair.public_key_hex.is_empty());
        assert!(!keypair.secret_key_hex.is_empty());

        let entry = "WORM AUDIT: suspicious lateral movement detected from 10.0.0.42";
        let sig = PqcEngine::dilithium_sign_worm_log(entry, &keypair.secret_key_hex);
        assert_eq!(sig.algorithm, "ML-DSA-65");
        assert!(!sig.signature_hex.is_empty());
        // The public key embedded in the signature must match the generated one
        assert_eq!(sig.public_key_hex, keypair.public_key_hex);

        // ✅ Correct entry + correct key → must verify
        let is_valid = PqcEngine::dilithium_verify_worm_log(
            entry,
            &sig.signature_hex,
            &keypair.public_key_hex,
        );
        assert!(is_valid, "Valid ML-DSA-65 signature must verify successfully");

        // ❌ Tampered entry → must FAIL (this is the key difference from the fake impl)
        let is_tampered = PqcEngine::dilithium_verify_worm_log(
            "TAMPERED: injected false audit record",
            &sig.signature_hex,
            &keypair.public_key_hex,
        );
        assert!(!is_tampered, "Tampered entry must NOT pass ML-DSA-65 verification");

        // ❌ Wrong key → must FAIL
        let other_keypair = PqcEngine::dilithium_generate_keypair();
        let is_wrong_key = PqcEngine::dilithium_verify_worm_log(
            entry,
            &sig.signature_hex,
            &other_keypair.public_key_hex,
        );
        assert!(!is_wrong_key, "Wrong public key must NOT pass ML-DSA-65 verification");
    }
}
