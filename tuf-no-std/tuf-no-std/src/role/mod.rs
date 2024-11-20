pub mod root;
pub mod snapshot;
pub mod targets;
pub mod timestamp;

use tuf_no_std_common::{RoleType, TufError, Version};

use crate::canonical::{EncodeCanonically, EncodingError};
use crate::role::targets::TufTargets;
use core::fmt::Debug;
use der::asn1::UtcTime;
use der::{Decode, Encode};
use sha2::{Digest, Sha256};
use tuf_no_std_der::{SignatureRef, SignedRef};

/// Trait for easy access to a constant that specifies the role.
pub trait TufRole {
    const TYPE: RoleType;
}

/// Trait to abstract the decoding of a TUF role.
pub trait DecodeRole<'a>: Sized {
    fn decode_role(input: &'a [u8]) -> Result<Self, TufError>;
}

/// Trait to extract information that is required to update a TUF role.
pub trait RoleUpdate: TufRole + EncodeCanonically {
    fn version(&self) -> Version;
    fn expires(&self) -> UtcTime;
}

/// Trait to abstract signatures within TUF files.
pub trait TufSignature {
    /// Extract the raw signature.
    fn raw_sig(&self) -> &[u8];
    /// Return the ID of the key that was used to create the signature.
    fn keyid(&self) -> [u8; 32];
}

/// Trait used to abstract signed files.
pub trait SignedFile {
    type Signature: TufSignature;
    type Signed: EncodeCanonically;

    /// Return the signatures of this file.
    fn get_signatures(&self) -> serde_json_core::heapless::Vec<&Self::Signature, 16>;
    /// Return the part of the file that is used to create signatures.
    fn get_signed(&self) -> &Self::Signed;
}

/// Trait used to abstract operations of a TUF timestamp file.
pub trait TufTimestamp {
    /// Extract the version of the snapshot file specified in this timestamp file.
    fn snapshot_version(&self) -> Version;
    /// Extract the expiration date of the snapshot file specified in this timestamp file.
    fn snapshot_expires(&self) -> UtcTime;
    /// Extract the hash of the snapshot file specified in this timestamp file.
    fn snapshot_hash(&self) -> [u8; 32];
}

/// Trait used to abstract operations of a TUF snapshot file.
pub trait TufSnapshot: EncodeCanonically {
    /// Extract the hash of the targets file specified in this snapshot file.
    fn targets_hash(&self) -> [u8; 32];
    /// Calculate the hash of this snapshot file.
    fn snapshot_hash(&self) -> Result<[u8; 32], TufError> {
        let mut buf = [0u8; 8096];
        self.encode_canonically(&mut buf)
            .map(|encoded| Sha256::new().chain_update(encoded).finalize().into())
            .map_err(|_| TufError::EncodingError)
    }
    /// Extract the version of the targets file specified in this snapshot file.
    fn targets_version(&self) -> Version;
}

impl<'a, T> DecodeRole<'a> for T
where
    T: Decode<'a> + TufRole,
{
    fn decode_role(input: &'a [u8]) -> Result<Self, TufError> {
        Decode::from_der(input).map_err(|_| TufError::DecodingError)
    }
}

impl<'a, T> RoleUpdate for SignedRef<'a, T>
where
    T: RoleUpdate + Debug + Eq + PartialEq + Decode<'a> + Encode,
{
    fn version(&self) -> Version {
        self.signed.version()
    }
    fn expires(&self) -> UtcTime {
        self.signed.expires()
    }
}

impl<'a, T> TufRole for SignedRef<'a, T>
where
    T: TufRole + Debug + Eq + PartialEq + Decode<'a> + Encode,
{
    const TYPE: RoleType = T::TYPE;
}

impl<'a, T> TufTimestamp for SignedRef<'a, T>
where
    T: TufTimestamp + Debug + Eq + PartialEq + Decode<'a> + Encode,
{
    fn snapshot_version(&self) -> Version {
        self.signed.snapshot_version()
    }

    fn snapshot_expires(&self) -> UtcTime {
        self.signed.snapshot_expires()
    }

    fn snapshot_hash(&self) -> [u8; 32] {
        self.signed.snapshot_hash()
    }
}

impl<'a, T> EncodeCanonically for SignedRef<'a, T>
where
    T: Debug + Decode<'a> + Encode + Eq + PartialEq + RoleUpdate,
{
    fn encode_canonically<'o>(&self, out: &'o mut [u8]) -> Result<&'o [u8], EncodingError> {
        match self.signed.encode_to_slice(out) {
            Ok(data) => Ok(data),
            Err(err) => {
                panic!("{err:?}")
            }
        }
    }
}

impl<'a, T> TufSnapshot for SignedRef<'a, T>
where
    T: TufSnapshot + Debug + Eq + PartialEq + Decode<'a> + Encode + RoleUpdate,
{
    fn targets_hash(&self) -> [u8; 32] {
        self.signed.targets_hash()
    }

    fn targets_version(&self) -> Version {
        self.signed.targets_version()
    }
}

impl<'a, T> TufTargets for SignedRef<'a, T> where
    T: TufTargets + Debug + Eq + PartialEq + Decode<'a> + Encode
{
}

impl<'a, T> SignedFile for SignedRef<'a, T>
where
    T: EncodeCanonically + Debug + Eq + PartialEq + Decode<'a> + Encode,
{
    type Signature = SignatureRef<'a>;
    type Signed = T;

    fn get_signatures(&self) -> serde_json_core::heapless::Vec<&Self::Signature, 16> {
        self.signatures.iter().collect()
    }

    fn get_signed(&self) -> &Self::Signed {
        &self.signed
    }
}
