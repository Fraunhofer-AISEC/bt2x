use crate::{Role, RoleRef, SpecVersion, SpecVersionRef};
use alloc::vec::Vec;
use core::fmt::Debug;
use der::asn1::{SequenceOf, UtcTime};
use der::referenced::OwnedToRef;
use der::Sequence;
use spki::{SubjectPublicKeyInfoOwned, SubjectPublicKeyInfoRef};
use tuf_no_std_common::Version;

/// DER encoding of a TUF root file.
#[derive(Debug, Eq, PartialEq, Sequence, Clone)]
pub struct Root {
    /// Not implemented, refer to the [TUF specification section on consistent snapshots](https://theupdateframework.github.io/specification/latest/#consistent-snapshots).
    pub consistent_snapshot: bool,
    pub expires: UtcTime,
    // Keys sorted by key ID.
    pub keys: Vec<SubjectPublicKeyInfoOwned>,
    /// Roles sorted by name.
    pub roles: Vec<Role>,
    /// Version of the TUF spec.
    pub spec_version: SpecVersion,
    /// Version of the root file.
    pub version: Version,
}

/// Borrowed version of [Root].
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct RootRef<'a> {
    /// Not implemented, refer to the [TUF specification section on consistent snapshots](https://theupdateframework.github.io/specification/latest/#consistent-snapshots).
    pub consistent_snapshot: bool,
    pub expires: UtcTime,
    // Keys sorted by key ID.
    pub keys: SequenceOf<SubjectPublicKeyInfoRef<'a>, 7>,
    // sorted by name
    pub roles: SequenceOf<RoleRef<'a>, 4>,
    /// Version of the TUF spec.
    pub spec_version: SpecVersionRef<'a>,
    /// Version of the root file.
    pub version: Version,
}

impl OwnedToRef for Root {
    type Borrowed<'a> = RootRef<'a> where Self: 'a;

    fn owned_to_ref(&self) -> Self::Borrowed<'_> {
        let mut keys: SequenceOf<SubjectPublicKeyInfoRef, 7> = Default::default();
        let mut roles: SequenceOf<RoleRef, 4> = Default::default();
        self.keys
            .iter()
            .for_each(|k| keys.add(k.owned_to_ref()).unwrap());
        self.roles
            .iter()
            .for_each(|r| roles.add(r.owned_to_ref()).unwrap());
        RootRef {
            consistent_snapshot: self.consistent_snapshot,
            expires: self.expires,
            keys,
            roles,
            spec_version: self.spec_version.owned_to_ref(),
            version: self.version,
        }
    }
}
