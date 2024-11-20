use crate::{Hash, HashRef, Length, SpecVersion, SpecVersionRef, Version};
use alloc::vec::Vec;
use core::fmt::Debug;
use der::asn1::{BitString, BitStringRef, SequenceOf, UtcTime};
use der::{Any, AnyRef, Sequence};

pub type TargetPath = BitString;
pub type TargetPathRef<'a> = BitStringRef<'a>;

/// DER encoding of the TUF targets file format.
/// [Refer to the TUF specification.](https://theupdateframework.github.io/specification/latest/#file-formats-targets)
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct Targets {
    pub expires: UtcTime,
    pub spec_version: SpecVersion,
    /// Version of this targets file.
    pub version: Version,
    /// Targets specified in this targets file.
    pub targets: Vec<Target>,
    /// Delegations are not implemented.
    pub delegations: Vec<Delegation>,
}

/// Borrowed version of [Targets].
/// [Refer to the TUF specification.](https://theupdateframework.github.io/specification/latest/#file-formats-targets)
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct TargetsRef<'a, const N_TARGETS: usize, const N_DELEGATIONS: usize> {
    pub expires: UtcTime,
    pub spec_version: SpecVersionRef<'a>,
    /// Version of this targets file.
    pub version: Version,
    /// Targets specified in this targets file.
    pub targets: SequenceOf<TargetRef<'a>, N_TARGETS>,
    /// Delegations are not implemented.
    pub delegations: SequenceOf<Delegation, N_DELEGATIONS>,
}

pub type Delegation = ();
pub type DelegationRef<'a> = ();

#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct Target {
    /// Used to identify the target file.
    pub name: TargetPath,
    /// The inner part of the data, containing the actual information.
    pub value: TargetValue,
}

/// Borrowed version of [Target].
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct TargetRef<'a> {
    /// Used to identify the target file.
    pub metapath: TargetPathRef<'a>,
    /// Used to identify the target file.
    pub value: TargetValueRef<'a>,
}

/// Information about a target file.
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct TargetValue {
    pub hashes: Vec<Hash>,
    pub length: Option<Length>,
    pub custom: Option<Custom>,
}

/// Borrowed version of [TargetValue].
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct TargetValueRef<'a> {
    // not using usize because the traits are not implemented for it
    pub hashes: SequenceOf<HashRef<'a>, 2>,
    pub length: Option<Length>,
    pub custom: Option<CustomRef<'a>>,
}

/// [Refer to the TUF specification](https://theupdateframework.github.io/specification/latest/#custom).
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct Custom {
    pub name: BitString,
    pub value: Any,
}

/// Borrowed version of [Custom].
/// [Refer to the TUF specification](https://theupdateframework.github.io/specification/latest/#custom).
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct CustomRef<'a> {
    pub name: BitStringRef<'a>,
    pub value: AnyRef<'a>,
}
