#![cfg_attr(not(test), no_std)]
extern crate alloc;

pub mod common;
pub mod constants;
pub mod crypto;
pub mod error;
pub mod remote;
pub mod storage;

use der::asn1::BitStringRef;
pub use error::TufError;

pub type Version = u32;

#[derive(Debug, Clone)]
pub enum RoleType {
    Root,
    Snapshot,
    Targets,
    Timestamp,
}

impl<'a> PartialEq<BitStringRef<'a>> for RoleType {
    fn eq(&self, other: &BitStringRef<'a>) -> bool {
        let name = match self {
            RoleType::Root => "root",
            RoleType::Snapshot => "snapshot",
            RoleType::Targets => "targets",
            RoleType::Timestamp => "timestamp",
        };
        &BitStringRef::from_bytes(name.as_bytes()).unwrap() == other
    }
}

#[cfg(test)]
mod test {
    use der::asn1::BitStringRef;

    use crate::RoleType;

    #[test]
    fn test_eq() {
        assert_eq!(RoleType::Root, BitStringRef::from_bytes(b"root").unwrap());
        assert_eq!(
            RoleType::Snapshot,
            BitStringRef::from_bytes(b"snapshot").unwrap()
        );
        assert_eq!(
            RoleType::Targets,
            BitStringRef::from_bytes(b"targets").unwrap()
        );
        assert_eq!(
            RoleType::Timestamp,
            BitStringRef::from_bytes(b"timestamp").unwrap()
        );
        assert_ne!(RoleType::Root, BitStringRef::from_bytes(b"a").unwrap());
        assert_ne!(RoleType::Timestamp, BitStringRef::from_bytes(b"a").unwrap());
        assert_ne!(RoleType::Targets, BitStringRef::from_bytes(b"a").unwrap());
        assert_ne!(RoleType::Snapshot, BitStringRef::from_bytes(b"a").unwrap());
    }
}
