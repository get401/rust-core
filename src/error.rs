use thiserror::Error;

/// All errors produced by the get401 SDK.
#[derive(Debug, Error)]
pub enum Get401Error {
    /// The JWT `exp` claim is in the past.
    #[error("Token has expired")]
    TokenExpired,

    /// The token is malformed, its signature is invalid, or required claims are missing.
    #[error("Invalid token: {0}")]
    InvalidToken(String),

    /// The token declares a signing algorithm other than EdDSA.
    ///
    /// This check is performed *before* any network call to prevent
    /// algorithm-substitution attacks (`none`, `HS256`, `RS256`, …).
    #[error("Token uses disallowed algorithm '{0}'; only EdDSA (Ed25519) is accepted")]
    InvalidAlgorithm(String),

    /// The get401 backend could not be reached or returned an error.
    #[error("Failed to fetch public key: {0}")]
    PublicKeyFetch(String),

    /// The token does not carry the required roles or scope.
    #[error("Insufficient permissions")]
    InsufficientPermissions,
}
