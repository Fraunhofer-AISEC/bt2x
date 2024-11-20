use crate::snapshot::{SnapshotMeta, SnapshotMetaRef};
use crate::{SpecVersion, SpecVersionRef};
use core::fmt::Debug;
use der::asn1::UtcTime;
use der::Sequence;
use tuf_no_std_common::Version;

/// DER encoding of the TUF Timestamp format.
/// [Refer to the TUF specification.](https://theupdateframework.github.io/specification/latest/#file-formats-timestamp)
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct Timestamp {
    pub expires: UtcTime,
    pub meta: SnapshotMeta,
    pub spec_version: SpecVersion,
    pub version: Version,
}

/// Borrowed version of [Timestamp].
/// [Refer to the TUF specification.](https://theupdateframework.github.io/specification/latest/#file-formats-timestamp)
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct TimestampRef<'a> {
    pub expires: UtcTime,
    pub meta: SnapshotMetaRef<'a>,
    pub spec_version: SpecVersionRef<'a>,
    pub version: Version,
}
