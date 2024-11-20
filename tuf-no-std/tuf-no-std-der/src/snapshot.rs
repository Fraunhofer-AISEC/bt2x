use crate::{Hash, HashRef, SpecVersion, SpecVersionRef, Version};
use alloc::vec::Vec;
use core::fmt::Debug;
use der::asn1::{BitString, BitStringRef, SequenceOf, UtcTime};
use der::Sequence;

/// DER encoding of a TUF snapshot file.
/// [Refer to the TUF specification.](https://theupdateframework.github.io/specification/latest/#file-formats-snapshot)
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct Snapshot {
    pub expires: UtcTime,
    pub meta: Vec<SnapshotMeta>,
    pub spec_version: SpecVersion,
    pub version: Version,
}

/// [Refer to the TUF specification](https://theupdateframework.github.io/specification/latest/#metafiles).
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct SnapshotMeta {
    /// Identifier/metapath of the file.
    pub metapath: BitString,
    pub length: u64,
    /// Version of the file specified in this struct.
    pub version: Version,
    /// Hashes of the file.
    pub hashes: Vec<Hash>,
}

/// Borrowed version of [Snapshot].
/// [Refer to the TUF specification.](https://theupdateframework.github.io/specification/latest/#file-formats-snapshot)
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct SnapshotRef<'a> {
    pub expires: UtcTime,
    pub meta: SequenceOf<SnapshotMetaRef<'a>, 1>,
    pub spec_version: SpecVersionRef<'a>,
    pub version: Version,
}

/// Borrowed version of [SnapshotMeta].
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct SnapshotMetaRef<'a> {
    /// Identifier/metapath of the file.
    pub metapath: BitStringRef<'a>,
    pub length: u64,
    /// Version of the file specified in this struct.
    pub version: Version,
    /// Hashes of the file. Hard coded to size 1 to reduce stack usage.
    pub hashes: SequenceOf<HashRef<'a>, 1>,
}
