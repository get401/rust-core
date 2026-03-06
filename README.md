# get401

Core Rust SDK for [get401](https://get401.com) authentication. Verifies EdDSA/Ed25519 JWTs, fetches and caches the public key, and parses token claims.

> **Backend only.** Designed for Rust server applications. Used directly by [`get401/rust-axum`](https://github.com/get401/rust-axum).

## Installation

```toml
[dependencies]
get401 = "0.1"
tokio = { version = "1", features = ["full"] }
```

## Quick start

```rust
use std::sync::Arc;
use get401::{Get401Client, TokenVerifier};

let client = Arc::new(Get401Client::new("your-app-id", "https://yourapp.com"));
let verifier = TokenVerifier::new(Arc::clone(&client));

let claims = verifier.verify(&token).await?;
println!("{}", claims.sub);        // user public ID
println!("{:?}", claims.roles);    // ["USER"]
println!("{}", claims.scope);      // "read,write"
```

## Configuration

```rust
// Default host (https://app.get401.com)
Get401Client::new("app-id", "https://yourapp.com")

// Custom host (self-hosted / staging)
Get401Client::with_host("app-id", "https://yourapp.com", "https://auth.internal")
```

The client sends `X-App-Id` and `Origin` headers as required by the get401 API.

## TokenClaims reference

| Field | Type | Description |
|-------|------|-------------|
| `sub` | `String` | User's public ID |
| `exp` | `u64` | Expiration Unix timestamp |
| `iat` | `u64` | Issued-at Unix timestamp |
| `iss` | `String` | Token issuer |
| `roles` | `Vec<String>` | Roles granted — e.g. `["USER"]` |
| `scope` | `String` | Comma-separated scope string |

### Helper methods

```rust
claims.has_role("USER")                          // bool
claims.has_any_role(&["USER", "ADMIN"])          // bool
claims.has_all_roles(&["USER", "PREMIUM"])       // bool

claims.has_scope("read")                         // bool
claims.scopes()                                  // Vec<&str>

claims.is_authenticated_user()                   // true when roles contains "USER"
```

## Error handling

```rust
use get401::Get401Error;

match verifier.verify(&token).await {
    Ok(claims) => { /* use claims */ }
    Err(Get401Error::TokenExpired)           => { /* re-login */ }
    Err(Get401Error::InvalidAlgorithm(alg)) => { /* wrong algorithm */ }
    Err(Get401Error::InvalidToken(msg))     => { /* bad signature / malformed */ }
    Err(Get401Error::PublicKeyFetch(msg))   => { /* backend unreachable */ }
    Err(Get401Error::InsufficientPermissions) => { /* missing role/scope */ }
}
```

## Public key caching

The client caches the public key automatically until the backend-provided `expires_at` timestamp passes. Concurrent requests during a refresh are de-duplicated via a `tokio::sync::RwLock`.

```rust
// Force a refresh
client.refresh_public_key().await?;
```

## Thread safety

`Get401Client` uses `tokio::sync::RwLock` internally. Wrap it in an `Arc` and clone freely across tasks:

```rust
let client = Arc::new(Get401Client::new("app-id", "https://yourapp.com"));
let verifier = Arc::new(TokenVerifier::new(Arc::clone(&client)));

// Share verifier across handlers
let v1 = Arc::clone(&verifier);
let v2 = Arc::clone(&verifier);
```
