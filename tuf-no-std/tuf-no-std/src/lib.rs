#![cfg_attr(not(test), no_std)]
//! A no `no-std` rust implementation for TUF based on the [DER format](https://en.wikipedia.org/wiki/X.690#DER_encoding).
//! This implementation aims to fulfill the [TUF specification](https://theupdateframework.github.io/specification/v1.0.33/index.html),
//! however, it is not guaranteed that it does so fully.
//!
//! ## Why DER?
//! - DER is an encoding that is deterministic,
//! which is important for TUF as it requires signatures of *canonically* encoded files.
//! - DER parsing and encoding is more readily available than for canonical JSON, which is the default format for TUF, which does not have a `no-std` implementation.
//! - Additionally, DER is also required for certificate parsing and therefore potentially adds less overhead regarding dependencies.
//! - DER allows a great degree of parsing without requiring [ownership](https://doc.rust-lang.org/book/ch04-01-what-is-ownership.html) over the encoded data or copying it. Which is desirable for parsing on embedded devices.
//!
//! ## Example
//!
//! **Note:** this example use the sync functions, the same functions also exist as async functions.
//!
//! ```ignore
//! use tuf_no_std::utils::MemoryStorage;
//! use tuf_no_std::storage::TufStorage;
//! use tuf_no_std::remote::TufTransport;
//! use tuf_no_std::{update_repo, fetch_and_verify_target_file};
//! use heapless::Vec;
//! const TUF_ROOT = include_bytes("path/to/root.der");
//!
//! // initialize storage and transport
//! let mut storage = MemoryStorage {
//!     root: Vec::<_, _>::from(TUF_ROOT),
//!     uncommitted_root: None,
//!     timestamp: None,
//!     snapshot: None,
//!     targets: None,
//! };
//!
//! let mut transport = { panic!("add your own transport here")};
//!
//!
//! let update_start = { panic!("create an timestamp of this moment here") };
//!
//! update_repo(
//!     &mut storage,
//!     &mut transport,
//!     10,
//!     update_start,
//! ).expect("update repo failed");
//!
//! // fetching and verifying files using the updated repo
//! // allocate buffer to store the data
//! let mut buf = [0u8; 4096];
//! let verified_file = fetch_and_verify_target_file(
//!     &mut storage,
//!     &mut transport,
//!     b"hello-world.txt",
//!     &mut buf,
//! ).expect("could not fetch and verify target file");
//! ```
//! ## Storage
//!
//! If you need a implementor of the [TufStorage] trait you can use [utils::MemoryStorage] or implement your own solution using the trait.
//!
//! ## TufTransport/Remote
//!
//! This crate does not provide an implementation for the [TufTransport] and [TufTransportAsync] traits.
//! You can find one for platforms that use the [`embassy-net`](https://docs.embassy.dev/embassy-net/git/default/index.html) crate in the `bt2x-ota-common` crate.
//!

#[cfg(feature = "async")]
use common::remote::TufTransportAsync;
pub use der::asn1::UtcTime;
pub use der::DateTime;
use role::targets::verify_target_file;
pub use tuf_no_std_common::{remote::TufTransport, storage::TufStorage, TufError};

use crate::role::{
    root::update_root, snapshot::update_snapshot, targets::update_targets,
    timestamp::update_timestamp,
};
#[cfg(feature = "async")]
use crate::role::{
    snapshot::update_snapshot_async, targets::update_targets_async,
    timestamp::update_timestamp_async,
};
extern crate alloc;

/// Module for builders to create TUF repositories.
pub mod builder;
/// Canonical encoding of metadata files.
pub mod canonical;
/// Abstract the concept of a file format that implements TUF.
pub mod format;
/// Implementation of TUF roles.
pub mod role;
/// Trait to abstract signatures.
mod signature;
/// Error types and more traits.
pub use tuf_no_std_common as common;
/// Utility functions.
pub mod utils;
/// Re-export of heapless for convenience.
pub use heapless;
/// Re-export of constants.
pub use tuf_no_std_common::constants;
/// Re-export of errors.
pub use tuf_no_std_common::error;
/// Fetching TUF files from remotes.
pub use tuf_no_std_common::remote;
/// Storage of TUF files. Only has traits, there is an in-memory implementation available in [utils::MemoryStorage].
pub use tuf_no_std_common::storage;
pub enum TufFormat {
    #[cfg(feature = "der")]
    Der,
}

/// Run a full TUF repo update. For more information refer to the [TUF specification](https://theupdateframework.github.io/specification/latest/).
/// This requires an initial root file in the `storage` object. The number specified in `max_fetches` limits the number of attempts to fetch new roots.
/// The value provided by `update_start` should be right before the update was started.
#[cfg(feature = "async")]
pub fn update_repo<S: TufStorage, T: TufTransport>(
    storage: &mut S,
    transport: &mut T,
    max_fetches: u32,
    update_start: impl TryInto<UtcTime>,
) -> Result<(), TufError> {
    let update_start = &update_start
        .try_into()
        .map_err(|_| TufError::InvalidUtcTimestamp)?;
    update_root(transport, storage, max_fetches, update_start)?;
    update_timestamp(transport, storage, update_start)?;
    update_snapshot(transport, storage, update_start)?;
    update_targets(transport, storage, update_start)?;
    Ok(())
}

/// Run a full TUF repo update. For more information refer to the [TUF specification](https://theupdateframework.github.io/specification/latest/).
/// This requires an initial root file in the `storage` object. The number specified in `max_fetches` limits the number of attempts to fetch new roots.
/// The value provided by `update_start` should be right before the update was started.
#[cfg(feature = "async")]
pub async fn update_repo_async<S: TufStorage, T: TufTransportAsync>(
    storage: &mut S,
    transport: &mut T,
    max_fetches: u32,
    update_start: impl TryInto<UtcTime>,
) -> Result<(), TufError> {
    use role::root::update_root_async;

    let update_start = &update_start
        .try_into()
        .map_err(|_| TufError::InvalidUtcTimestamp)?;
    update_root_async(transport, storage, max_fetches, update_start).await?;
    update_timestamp_async(transport, storage, update_start).await?;
    update_snapshot_async(transport, storage, update_start).await?;
    update_targets_async(transport, storage, update_start).await?;
    Ok(())
}

/// Fetches and verifies the target file at the specified `metapath`.
/// This requires an updated TUF repo.
pub fn fetch_and_verify_target_file<'o, S: TufStorage, T: TufTransport>(
    storage: &mut S,
    transport: &mut T,
    metapath: &[u8],
    out: &'o mut [u8],
) -> Result<&'o [u8], TufError> {
    let target_file = transport
        .fetch_target_file(metapath, out)
        .map_err(|_| TufError::FetchError)?;
    let targets = storage
        .current_targets()
        .ok_or(TufError::MissingTargetsFile)?;
    verify_target_file(targets, metapath, target_file)?;
    Ok(target_file)
}

/// Fetches and verifies the target file at the specified `metapath`.
/// This requires an updated TUF repo.
#[cfg(feature = "async")]
pub async fn fetch_and_verify_target_file_async<'o, S: TufStorage, T: TufTransportAsync>(
    storage: &mut S,
    transport: &mut T,
    metapath: &[u8],
    out: &'o mut [u8],
) -> Result<&'o [u8], TufError> {
    let target_file = transport
        .fetch_target_file(metapath, out)
        .await
        .map_err(|_| TufError::FetchError)?;
    let targets = storage
        .current_targets()
        .ok_or(TufError::MissingTargetsFile)?;
    verify_target_file(targets, metapath, target_file)?;
    Ok(target_file)
}
