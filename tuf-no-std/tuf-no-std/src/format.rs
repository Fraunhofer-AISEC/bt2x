use crate::role::root::TufRoot;
use crate::role::targets::TufTargets;
use crate::role::{DecodeRole, RoleUpdate, SignedFile, TufSnapshot, TufTimestamp};
#[cfg(feature = "der")]
use spki::SubjectPublicKeyInfoRef;
#[cfg(feature = "der")]
use tuf_no_std_der::{
    root::RootRef,
    snapshot::SnapshotRef,
    targets::TargetsRef,
    timestamp::TimestampRef,
    {SignedRef, TufDer},
};

/// Trait used to abstract a file format that can be used to implement TUF.
/// An important constraint is that it has to support canonical encoding.
pub trait TufFormat<'a> {
    type Root: TufRoot + RoleUpdate + DecodeRole<'a> + SignedFile + Clone;
    type Timestamp: TufTimestamp + DecodeRole<'a> + RoleUpdate + SignedFile + Clone;
    type Snapshot: TufSnapshot + DecodeRole<'a> + RoleUpdate + SignedFile + Clone;
    type Targets: TufTargets + DecodeRole<'a> + RoleUpdate + SignedFile + Clone;
    type Key;
}

#[cfg(feature = "der")]
impl<'a> TufFormat<'a> for TufDer {
    type Root = SignedRef<'a, RootRef<'a>>;
    type Timestamp = SignedRef<'a, TimestampRef<'a>>;
    type Snapshot = SignedRef<'a, SnapshotRef<'a>>;
    type Targets = SignedRef<'a, TargetsRef<'a, 4, 0>>;
    type Key = SubjectPublicKeyInfoRef<'a>;
}
