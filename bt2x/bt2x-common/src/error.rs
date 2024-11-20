use std::str::FromStr;

use thiserror::Error;

use crate::{gossip::Checkpoint, merkle::verify::ProofError};

#[derive(Error, Debug)]
pub enum Bt2XError {
    #[error("failed to verify the SCT of a certificate {0:?}")]
    SctValidationFailed(sct::Error),
    #[error("certificate does not contain the required extensions for SCT validation")]
    CertificateIsMissingCtExtensions,
    #[error("failed to fetch a log info entry from the Rekor log: {0:?}")]
    FailedToFetchLogInfo(
        sigstore::rekor::apis::Error<sigstore::rekor::apis::tlog_api::GetLogInfoError>,
    ),
    #[error("could not parse the provided log checkpoint {0:?}")]
    FailedToParseLogCheckpoint(<Checkpoint as FromStr>::Err),
    #[error("failed to verify the provided log checkpoint")]
    CheckpointSignatureValidationFailed,
    #[error("failed to fetch a log proof from the Rekor log: {0:?}")]
    FailedToFetchLogProof(
        sigstore::rekor::apis::Error<sigstore::rekor::apis::tlog_api::GetLogProofError>,
    ),
    #[error("sending checkpoint failed {0:?}")]
    GossipingCheckpointsFailed(reqwest::Error),
    #[error("sending checkpoint failed {0:?}")]
    DeserializingGossipResponseFailed(reqwest::Error),
    #[error("error during I/O {0:?}")]
    IoError(#[from] std::io::Error),
    #[error("error while interacting with OCI registry {0:?}")]
    OciError(#[from] oci_distribution::errors::OciDistributionError),
    #[error("reference is required to have a digest {0:?}")]
    MissingDigestInOciReference(sigstore::registry::OciReference),
    #[error("container image is missing the required layers")]
    MissingContainerImageLayers,
    #[error("failure during TUF update {0:?}")]
    TufError(tuf_no_std::TufError),
    #[error("serialization to JSON failed {0:?}")]
    JsonSerializationError(serde_json::Error),
    #[error("deserialization from JSON failed {0:?}")]
    JsonDeserializationError(serde_json::Error),
    #[error("hex decode failed {0:?}")]
    HexDecodingError(hex::FromHexError),
    #[error("internal error {0:?}")]
    InternalError(String),
    #[error("hash length not equal to 32 bytes")]
    InvalidHashLength,
    #[error("inclusion proof failed {0:?}")]
    InclusionProofFailed(ProofError),
    #[error("consistency proof failed {0:?}")]
    ConsistencyProofFailed(ProofError),
    #[error("failed to decode PEM key")]
    PemKeyDecodingError,
}
