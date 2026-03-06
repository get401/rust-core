//! Core Rust SDK for [get401](https://get401.com) authentication.
//!
//! Handles public-key retrieval (with automatic expiry-based caching),
//! EdDSA/Ed25519 JWT verification, and token claim parsing.
//!
//! # Quick start
//!
//! ```rust,no_run
//! use std::sync::Arc;
//! use get401::{Get401Client, TokenVerifier};
//!
//! #[tokio::main]
//! async fn main() {
//!     let client = Arc::new(Get401Client::new("app-id", "https://myapp.com"));
//!     let verifier = TokenVerifier::new(client);
//!
//!     let claims = verifier.verify(&token).await.unwrap();
//!     println!("{}", claims.sub);   // user public ID
//!     println!("{:?}", claims.roles); // ["USER"]
//! }
//! ```

pub mod client;
pub mod error;
pub mod models;
pub mod verifier;

pub use client::Get401Client;
pub use error::Get401Error;
pub use models::{PublicKeyData, TokenClaims};
pub use verifier::TokenVerifier;
