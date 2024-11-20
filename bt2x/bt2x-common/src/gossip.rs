//! ## Example: parsing and verifying a Checkpoint
//!
//!```ignore
//! use bt2x_common::gossip::{Checkpoint, send_checkpoint};
//! #[tokio::main]
//! async fn main() {
//!     // parse a checkpoint
//!     let checkpoint: Checkpoint = "rekor.sigstore.dev - 2605736670972794746\n16895256\n/pOURNyljCZ3+Se0BHOmRJfTix2FC32SbGpRcMlUdwI=\nTimestamp: 1684488982407313166\n\n— rekor.sigstore.dev wNI9ajBEAiALqNNUxhyD9Ja38iUUMWNNI7mNGZO0qGrmDsdVLhxXxwIgBqn7Dnjqr2INJJ/VAovLgNBORFa5rRIwPQUcIska7n4=\n"
//!         .parse()
//!         .expect("failed to parse checkpoint");
//!     
//!     // send the checkpoint to a monitor
//!     send_checkpoint(
//!         &url::Url::parse("https://example.net").unwrap(),
//!         &checkpoint,
//!     )
//!     .await
//!     .expect("failure during gossiping");
//! }
//! ```

//!

use crate::error::Bt2XError;
use crate::rekor::RekorClient;
use crate::verifier::bt::verify_consistency;
use anyhow::{anyhow, Context};
use base64::prelude::BASE64_STANDARD;
use base64::Engine;
use serde::{Deserialize, Serialize};
use sigstore::crypto::{CosignVerificationKey, Signature};
use std::cmp::Ordering;
use std::str::FromStr;
use tracing::debug;
use url::Url;

#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
pub struct Gossip {
    pub checkpoint: Checkpoint,
}

/// Data structure to represent a parsed checkpoint.
/// The following example shows a the encoding of a checkpoint, as distributed by the log.
/// ```
/// use bt2x_common::gossip::Checkpoint;
///
/// let checkpoint: Checkpoint = "rekor.sigstore.dev - 2605736670972794746\n16895256\n/pOURNyljCZ3+Se0BHOmRJfTix2FC32SbGpRcMlUdwI=\nTimestamp: 1684488982407313166\n\n— rekor.sigstore.dev wNI9ajBEAiALqNNUxhyD9Ja38iUUMWNNI7mNGZO0qGrmDsdVLhxXxwIgBqn7Dnjqr2INJJ/VAovLgNBORFa5rRIwPQUcIska7n4=\n"
///     .parse()
///     .expect("failed to parse checkpoint");
/// ```
#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
pub struct Checkpoint {
    pub root_hash: [u8; 32],
    pub tree_size: usize,
    pub key_fingerprint: [u8; 4],
    pub sig: Vec<u8>,
    pub timestamp: i64,
    pub identity: String,
    pub tree_id: i64,
}

impl FromStr for Checkpoint {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        let s = s.trim_start_matches('"').trim_end_matches('"');
        let checkpoint = s;
        let [data, sig] = checkpoint.split("\n\n").collect::<Vec<_>>()[..] else {
            return Err(anyhow!("checkpoint did not split correctly {s:?}"));
        };
        let [_, name, sig_b64] = sig.split(' ').collect::<Vec<_>>()[..] else {
            return Err(anyhow!("signature did not split correctly {s:?}"));
        };
        let sig = BASE64_STANDARD
            .decode(sig_b64.trim_end())
            .context("failed to decode signature")?;
        // first four bytes of signature are fingerprint of key
        let (key_fingerprint, sig) = sig.split_at(4);

        let [tree, size, root_hash_b64, ts] = data.split('\n').collect::<Vec<_>>()[..] else {
            return Err(anyhow!("data did not split correctly {data:?}"));
        };
        let [identity, _, tree_id] = tree.split(' ').collect::<Vec<_>>()[..] else {
            return Err(anyhow!("identity did not split correctly"));
        };
        let root_hash = BASE64_STANDARD
            .decode(root_hash_b64)
            .context("failed to decode root hash")
            .and_then(|v| {
                <[u8; 32]>::try_from(v).map_err(|err| anyhow!("could not convert hash {err:?}"))
            })?;

        let tree_size = size.parse().context("could not parse tree size")?;
        let ts = ts
            .trim_start_matches("Timestamp: ")
            .parse()
            .context("could not parse timestamp")?;
        let tree_id = tree_id.parse().context("could not parse tree_id")?;

        if name != identity {
            return Err(anyhow!("mismatching information regarding identity of log"));
        }
        Ok(Checkpoint {
            timestamp: ts,
            tree_size,
            root_hash,
            tree_id,
            identity: identity.into(),
            sig: sig.into(),
            key_fingerprint: key_fingerprint.try_into().expect("this should never fail"),
        })
    }
}

impl Checkpoint {
    pub fn to_signed_note(&self) -> String {
        let Checkpoint {
            identity,
            sig,
            key_fingerprint,
            ..
        } = self;
        let sig_b64 = BASE64_STANDARD.encode([key_fingerprint.as_slice(), sig.as_slice()].concat());
        let note = self.create_note();
        format!("{note}\n— {identity} {sig_b64}\n")
    }
}

impl Checkpoint {
    /// Create a so called `note` from the checkpoint.
    /// Which is the encoding of the checkpoint used to create signatures.
    pub fn create_note(&self) -> String {
        let Checkpoint {
            timestamp,
            identity: name,
            root_hash,
            tree_size,
            tree_id,
            ..
        } = self;
        let root_hash_b64 = BASE64_STANDARD.encode(root_hash);
        format!("{name} - {tree_id}\n{tree_size}\n{root_hash_b64}\nTimestamp: {timestamp}\n")
    }

    /// Verifies that the checkpoint was signed with the given Rekor key.
    pub fn verify_signature(&self, key: &CosignVerificationKey) -> Result<(), Bt2XError> {
        key.verify_signature(Signature::Raw(&self.sig), self.create_note().as_bytes())
            .map_err(|_| Bt2XError::CheckpointSignatureValidationFailed)
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub enum GossipResponse {
    Success(Checkpoint),
    Failure(MonitorError),
}

/// Fetch a checkpoint from the log and verify its signature.
pub async fn fetch_and_verify_signature(
    rekor_client: &RekorClient,
    rekor_key: &CosignVerificationKey,
) -> Result<Checkpoint, Bt2XError> {
    // Fetch log info, parse it and then verify it using the provided key.
    rekor_client
        .get_log_info()
        .await
        .map_err(Bt2XError::FailedToFetchLogInfo)
        .and_then(|log_info| {
            log_info
                .signed_tree_head
                .parse::<Checkpoint>()
                .map_err(Bt2XError::FailedToParseLogCheckpoint)
        })
        .and_then(|checkpoint| {
            checkpoint.verify_signature(rekor_key)?;
            Ok(checkpoint)
        })
}

/// Verify that two checkpoints are consistent by requesting the corresponding consistency proof from the log.
pub async fn verify_checkpoints(
    trusted_checkpoint: Checkpoint,
    requested_checkpoint: Checkpoint,
    rekor_client: &RekorClient,
) -> Result<Checkpoint, Bt2XError> {
    let (old, new) = match Ord::cmp(
        &trusted_checkpoint.tree_size,
        &requested_checkpoint.tree_size,
    ) {
        Ordering::Less => {
            debug!("requested checkpoint is newer than trusted checkpoint");
            (trusted_checkpoint, requested_checkpoint)
        }
        Ordering::Equal | Ordering::Greater => {
            debug!("requested checkpoint is older than trusted checkpoint");
            (requested_checkpoint, trusted_checkpoint)
        }
    };
    debug!(
        "fetching log proof for: {:?}",
        (new.tree_size, Some(old.tree_size))
    );
    let proof = rekor_client
        .get_log_proof(new.tree_size, Some(old.tree_size), None)
        .await
        .map_err(Bt2XError::FailedToFetchLogProof)?;
    debug!("successfully fetched proof from log");
    verify_consistency(
        old.tree_size,
        new.tree_size,
        &proof,
        &old.root_hash,
        &new.root_hash,
    )
    .map(|_| new)
}

#[derive(Debug, Serialize, Deserialize, PartialEq, thiserror::Error)]
pub enum MonitorError {
    #[error("verifying {request_data:?} using {pubkey:?} failed")]
    FailedSignatureVerification {
        pubkey: (),
        request_data: Checkpoint,
    },
    #[error("verifying consistency of {request_data:?} using {other:?} failed")]
    Inconsistent {
        other: Checkpoint,
        request_data: Checkpoint,
    },
}

/// Send a checkpoint to the Rekor monitor at the provided URL.
pub async fn send_checkpoint(
    server_url: &Url,
    current_checkpoint: &Checkpoint,
) -> Result<GossipResponse, Bt2XError> {
    let response = reqwest::Client::new()
        .post(server_url.join("/listen").unwrap())
        .json(current_checkpoint)
        .send()
        .await
        .map_err(Bt2XError::GossipingCheckpointsFailed)?;

    response
        .json::<GossipResponse>()
        .await
        .map_err(Bt2XError::DeserializingGossipResponseFailed)
}

#[cfg(test)]
mod test_parse {
    use super::*;
    use hex_literal::hex;
    use sigstore::crypto::CosignVerificationKey;

    #[test]
    fn test_parse_checkpoint() {
        let checkpoint = "rekor.sigstore.dev - 2605736670972794746\n16895256\n/pOURNyljCZ3+Se0BHOmRJfTix2FC32SbGpRcMlUdwI=\nTimestamp: 1684488982407313166\n\n— rekor.sigstore.dev wNI9ajBEAiALqNNUxhyD9Ja38iUUMWNNI7mNGZO0qGrmDsdVLhxXxwIgBqn7Dnjqr2INJJ/VAovLgNBORFa5rRIwPQUcIska7n4=\n";
        let expected = Checkpoint {
            root_hash: hex!("fe939444dca58c2677f927b40473a64497d38b1d850b7d926c6a5170c9547702"),
            tree_size: 16895256,
            key_fingerprint: hex!("c0d23d6a"),
            timestamp: 1684488982407313166,
            identity: "rekor.sigstore.dev".to_string(),
            tree_id: 2605736670972794746,
            sig: From::from(hex!("304402200ba8d354c61c83f496b7f2251431634d23b98d1993b4a86ae60ec7552e1c57c7022006a9fb0e78eaaf620d249fd5028bcb80d04e4456b9ad12303d051c22c91aee7e")),
        };
        let rekor_key = CosignVerificationKey::from_pem(
            b"-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE2G2Y+2tabdTV5BcGiBIx0a9fAFwr\nkBbmLSGtks4L3qX6yYY0zufBnhC8Ur/iy55GhWP/9A/bY2LhC30M9+RYtw==\n-----END PUBLIC KEY-----",
            &Default::default(),
        ).expect("failed to parse rekor key");

        let output: Checkpoint = checkpoint.parse().unwrap();
        assert_eq!(output, expected);
        assert_eq!(output.to_signed_note(), checkpoint);
        output.verify_signature(&rekor_key).unwrap();
    }
}
