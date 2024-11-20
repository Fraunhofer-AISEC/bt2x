#[derive(Debug, PartialEq, Copy, Clone)]
pub enum TufError {
    // fewer signatures than threshold of old root -> arbitrary software attack possible
    OldRootThresholdNotReached,
    // fewer signatures than threshold of new root -> arbitrary software attack possible
    ThresholdNotReached,
    // new version number has to be exactly N+1 for old root with version number N -> roll back attack
    InvalidNewVersionNumber,
    // the client was not able to persistently store a new root file
    CouldNotPersistRootMetadata,
    //  The expiration timestamp in the trusted root metadata file MUST be higher than the fixed update start time
    // -> freeze attack
    ExpiredRootFile,
    ExpiredTimestampFile,
    ExpiredSnapshotFile,
    ExpiredTargetsFile,
    // A fast-forward attack happens when attackers arbitrarily increase the version numbers of: (1) the timestamp metadata, (2) the snapshot metadata, and / or (3) the targets, or a delegated targets, metadata file in the snapshot metadata.
    PotentialFastForwardAttack,
    // could not fetch new data
    FetchError,
    InvalidSignature,
    DecodingSignatureFailed,
    DecodingPublicKeyFailed,
    InternalError,
    DecodingError,
    EncodingError,
    // could not find keys for a role
    MissingSnapshotKeys,
    MissingTargetsKeys,
    MissingTimestampKeys,
    MissingSnapshotFile,
    MissingTargetsFile,
    MissingTimestampFile,
    MissingRootKeys,
    NoSupportedHash,
    MissingTargetMetadata,
    InvalidHash,
    InvalidTargetsInSnapshot,
    InvalidLength,
    NotEnoughSpace,
    InvalidUtcTimestamp,
}
