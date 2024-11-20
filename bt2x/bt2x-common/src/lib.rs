//! # BT²X Common
//! This crate contains functionality that is meant to be shared across different components.

pub mod artifact;
pub mod error;
/// Gossiping primitives.
pub mod gossip;
/// Merkle proof implementations.
pub mod merkle;
/// Custom Rekor data types.
pub mod rekor;
/// SCT validation.
pub mod sct;
/// Serde data structures.
pub mod serde;
/// Data structures related to configuring Sigstore related applications.
pub mod sigstore_config;
/// TUF integration into BT²X.
pub mod tuf;
/// Verification implementation.
pub mod verifier;
