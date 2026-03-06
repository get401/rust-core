use serde::{Deserialize, Serialize};

/// Public key response cached from the get401 backend.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicKeyData {
    /// Base64-encoded Ed25519 public key.
    pub public_key: String,
    /// Always `"EdDSA"`.
    pub algorithm: String,
    /// Unix timestamp after which the key must be re-fetched.
    pub expires_at: u64,
}

/// Verified and parsed claims from a get401 JWT access token.
///
/// Use [`sub`](TokenClaims::sub) to uniquely identify the authenticated user.
/// Check [`roles`](TokenClaims::roles) and [`scope`](TokenClaims::scope) to
/// authorise specific actions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenClaims {
    /// User's public ID.
    pub sub: String,
    /// Expiration Unix timestamp.
    pub exp: u64,
    /// Issued-at Unix timestamp.
    pub iat: u64,
    /// Token issuer.
    #[serde(default)]
    pub iss: String,
    /// Roles granted to the user.
    ///
    /// A fully authenticated user carries `"USER"`. Intermediate auth-flow
    /// roles include `"OTP_VERIFY"`, `"EMAIL_SETUP"`, and `"RECOVERY"`.
    #[serde(default)]
    pub roles: Vec<String>,
    /// Comma-separated scope string (e.g. `"read,write"`).
    #[serde(default)]
    pub scope: String,
}

impl TokenClaims {
    /// Return `true` if `role` is present in the token.
    pub fn has_role(&self, role: &str) -> bool {
        self.roles.iter().any(|r| r == role)
    }

    /// Return `true` if at least one of `roles` is present in the token.
    pub fn has_any_role(&self, roles: &[&str]) -> bool {
        roles.iter().any(|r| self.has_role(r))
    }

    /// Return `true` if every role in `roles` is present in the token.
    pub fn has_all_roles(&self, roles: &[&str]) -> bool {
        roles.iter().all(|r| self.has_role(r))
    }

    /// The scope claim split into individual items.
    pub fn scopes(&self) -> Vec<&str> {
        self.scope
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .collect()
    }

    /// Return `true` if `scope` is present in the token's scope claim.
    pub fn has_scope(&self, scope: &str) -> bool {
        self.scopes().contains(&scope)
    }

    /// Return `true` when the token belongs to a fully authenticated user
    /// (i.e. `roles` contains `"USER"`).
    pub fn is_authenticated_user(&self) -> bool {
        self.has_role("USER")
    }
}
