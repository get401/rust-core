use std::sync::Arc;

use base64::{engine::general_purpose::STANDARD, Engine};
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};

use crate::{client::Get401Client, error::Get401Error, models::TokenClaims};

const REQUIRED_ALGORITHM: Algorithm = Algorithm::EdDSA;

// ---------------------------------------------------------------------------
// Key loading helpers
// ---------------------------------------------------------------------------

/// Convert raw DER bytes to a PEM string (PUBLIC KEY block).
fn der_to_pem(der: &[u8]) -> String {
    let b64 = STANDARD.encode(der);
    let lines = b64
        .as_bytes()
        .chunks(64)
        .map(|c| std::str::from_utf8(c).expect("base64 is always valid UTF-8"))
        .collect::<Vec<_>>()
        .join("\n");
    format!("-----BEGIN PUBLIC KEY-----\n{lines}\n-----END PUBLIC KEY-----\n")
}

/// Wrap 32 raw Ed25519 bytes in a DER-encoded SubjectPublicKeyInfo structure.
fn raw_to_spki(raw: &[u8]) -> Vec<u8> {
    // SEQUENCE { SEQUENCE { OID 1.3.101.112 } BIT STRING { 0x00 || raw } }
    let mut spki = vec![
        0x30, 0x2a, // SEQUENCE (42 bytes)
        0x30, 0x05, // SEQUENCE (5 bytes) — AlgorithmIdentifier
        0x06, 0x03, 0x2b, 0x65, 0x70, // OID 1.3.101.112 = id-EdDSA / Ed25519
        0x03, 0x21, // BIT STRING (33 bytes)
        0x00, // no unused bits
    ];
    spki.extend_from_slice(raw);
    spki
}

/// Decode a base64 public key into a [`DecodingKey`].
///
/// Tries DER-encoded SubjectPublicKeyInfo first (the typical API format),
/// then falls back to raw 32-byte Ed25519 key material.
fn load_public_key(public_key_b64: &str) -> Result<DecodingKey, Get401Error> {
    let key_bytes = STANDARD
        .decode(public_key_b64)
        .map_err(|e| Get401Error::InvalidToken(format!("Invalid public key encoding: {e}")))?;

    // Attempt 1 — assume DER SubjectPublicKeyInfo, convert to PEM.
    let pem = der_to_pem(&key_bytes);
    if let Ok(key) = DecodingKey::from_ed_pem(pem.as_bytes()) {
        return Ok(key);
    }

    // Attempt 2 — raw 32-byte Ed25519 key; wrap in SPKI DER, then PEM.
    if key_bytes.len() == 32 {
        let spki = raw_to_spki(&key_bytes);
        let pem = der_to_pem(&spki);
        return DecodingKey::from_ed_pem(pem.as_bytes())
            .map_err(|e| Get401Error::InvalidToken(format!("Invalid Ed25519 raw key: {e}")));
    }

    Err(Get401Error::InvalidToken(
        "Unsupported public key format (expected DER SPKI or raw Ed25519)".to_string(),
    ))
}

// ---------------------------------------------------------------------------
// TokenVerifier
// ---------------------------------------------------------------------------

/// Verifies get401 JWT access tokens.
///
/// Enforces EdDSA algorithm, validates the signature against the cached public
/// key, and checks expiry before returning parsed [`TokenClaims`].
///
/// Wrap in an [`Arc`] and share across handlers:
///
/// ```rust
/// use std::sync::Arc;
/// use get401::{Get401Client, TokenVerifier};
///
/// let client = Arc::new(Get401Client::new("app-id", "https://myapp.com"));
/// let verifier = Arc::new(TokenVerifier::new(client));
/// ```
pub struct TokenVerifier {
    client: Arc<Get401Client>,
}

impl TokenVerifier {
    pub fn new(client: Arc<Get401Client>) -> Self {
        Self { client }
    }

    /// Verify `token` and return its claims.
    ///
    /// # Errors
    /// - [`Get401Error::InvalidAlgorithm`] — token does not declare `EdDSA`.
    /// - [`Get401Error::InvalidToken`] — malformed token or bad signature.
    /// - [`Get401Error::TokenExpired`] — `exp` claim is in the past.
    /// - [`Get401Error::PublicKeyFetch`] — public key could not be retrieved.
    pub async fn verify(&self, token: &str) -> Result<TokenClaims, Get401Error> {
        // Step 1 — reject any non-EdDSA algorithm *before* any network call.
        self.assert_algorithm(token)?;

        // Step 2 — get (cached) public key.
        let key_data = self.client.get_public_key().await?;
        let decoding_key = load_public_key(&key_data.public_key)?;

        // Step 3 — verify signature and expiry.
        let mut validation = Validation::new(REQUIRED_ALGORITHM);
        validation.validate_aud = false; // get401 tokens do not use 'aud'

        decode::<TokenClaims>(token, &decoding_key, &validation)
            .map(|data| data.claims)
            .map_err(|e| {
                if *e.kind() == jsonwebtoken::errors::ErrorKind::ExpiredSignature {
                    Get401Error::TokenExpired
                } else {
                    Get401Error::InvalidToken(e.to_string())
                }
            })
    }

    fn assert_algorithm(&self, token: &str) -> Result<(), Get401Error> {
        let header = decode_header(token)
            .map_err(|e| Get401Error::InvalidToken(format!("Malformed token header: {e}")))?;

        if header.alg != REQUIRED_ALGORITHM {
            return Err(Get401Error::InvalidAlgorithm(format!("{:?}", header.alg)));
        }

        Ok(())
    }
}
