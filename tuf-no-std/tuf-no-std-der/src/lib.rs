#![cfg_attr(not(test), no_std)]
extern crate alloc;

use ::signature::DigestVerifier;
use alloc::vec::Vec;
use const_oid::db::rfc5912::ID_SHA_256;
use const_oid::ObjectIdentifier;
use core::fmt::Debug;
use core::marker::PhantomData;
use der::asn1::{BitString, BitStringRef, SequenceOf, UtcTime};
use der::{Decode, Encode, Sequence};
use spki::{
    AlgorithmIdentifier, AlgorithmIdentifierOwned, AlgorithmIdentifierRef,
    SubjectPublicKeyInfoOwned, SubjectPublicKeyInfoRef,
};
use tuf_no_std_common::{TufError, Version};

pub mod role;
pub mod root;
pub mod signature;
pub mod snapshot;
pub mod targets;
pub mod timestamp;

use crate::root::{Root, RootRef};
use der::referenced::OwnedToRef;
#[cfg(feature = "dilithium3")]
use oqs::sig::Algorithm::Dilithium3;

use sha2::digest::Digest;
use tuf_no_std_common::common::Threshold;
#[cfg(feature = "dilithium3")]
use tuf_no_std_common::crypto::composite_spki::{CompositePublicKeyRef, CompositeSignatureRef};
use tuf_no_std_common::crypto::sign::SigningKey;

pub type KeyId = BitString;

pub type RawSignature = BitString;
pub type SpecVersion = BitString;
pub type KeyIdRef<'a> = BitStringRef<'a>;
pub type RawSignatureRef<'a> = BitStringRef<'a>;
pub type SpecVersionRef<'a> = BitStringRef<'a>;
pub type Scheme = AlgorithmIdentifierOwned;
pub type SchemeRef<'a> = AlgorithmIdentifierRef<'a>;
pub type KeyVal = SubjectPublicKeyInfoOwned;
pub type KeyValRef<'a> = SubjectPublicKeyInfoRef<'a>;
pub type DateTime = UtcTime;
pub type ConsistentSnapshot = bool;
/// Not using usize because the traits are not implemented for it
pub type Length = u64;

/// DER encoded signature.
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct Signature {
    /// SHA256 digest of the canonical form of the key.
    pub keyid: KeyId,
    /// Canonical encoding of the signature.
    pub sig: RawSignature,
}

/// Borrowed version of [Signature].
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct SignatureRef<'a> {
    /// SHA256 digest of the canonical form of the key.
    pub keyid: KeyIdRef<'a>,
    /// Canonical encoding of the signature.
    pub sig: RawSignatureRef<'a>,
}

impl OwnedToRef for Signature {
    type Borrowed<'a>  = SignatureRef<'a> where Self: 'a;

    fn owned_to_ref(&self) -> Self::Borrowed<'_> {
        SignatureRef {
            sig: self.sig.owned_to_ref(),
            keyid: self.keyid.owned_to_ref(),
        }
    }
}

/// Encoding of a TUF role key.
#[derive(Debug, Eq, PartialEq, Sequence)]
pub struct Key {
    /// The OID of the key type.
    keytype: ObjectIdentifier,
    /// SPKI encoding of the public key.
    keyval: KeyVal,
    /// Algorithm identifier of the signature scheme.
    scheme: Scheme,
}

/// Borrowed version of [Key].
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct KeyRef<'a> {
    /// The OID of the key type.
    keytype: ObjectIdentifier,
    /// SPKI encoding of the public key.
    keyval: KeyValRef<'a>,
    /// Algorithm identifier of the signature scheme.
    scheme: SchemeRef<'a>,
}

impl<'a> KeyRef<'a> {
    /// Key hashes are calculated from the DER encoded SPKI.
    pub fn key_hash(&self) -> [u8; 32] {
        self.keyval.fingerprint_bytes().unwrap()
    }
}

pub fn verify(spki: &SubjectPublicKeyInfoRef<'_>, msg: &[u8], sig: &[u8]) -> Result<(), TufError> {
    match spki.algorithm.oid {
        #[cfg(feature = "ed25519")]
        const_oid::db::rfc8410::ID_ED_25519 => {
            use ::signature::Verifier;
            let key = ed25519_dalek::VerifyingKey::try_from(spki.clone())
                .map_err(|_| TufError::DecodingPublicKeyFailed)?;
            let sig = sig
                .try_into()
                .map_err(|_| TufError::DecodingSignatureFailed)
                .map(ed25519::Signature::from_bytes)?;
            key.verify(msg, &sig)
                .map_err(|_| TufError::InvalidSignature)
        }
        #[cfg(feature = "rsa")]
        const_oid::db::rfc5912::ID_RSASSA_PSS => {
            use ::signature::Verifier;
            let sig =
                rsa::pss::Signature::try_from(sig).or(Err(TufError::DecodingSignatureFailed))?;
            rsa::RsaPublicKey::try_from(spki.clone())
                .map(Into::<rsa::pss::VerifyingKey<sha2::Sha256>>::into)
                .map_err(|_| TufError::DecodingPublicKeyFailed)
                .and_then(|k| k.verify(msg, &sig).map_err(|_| TufError::InvalidSignature))
        }
        #[cfg(feature = "ecdsa")]
        const_oid::db::rfc5912::ID_EC_PUBLIC_KEY => {
            let key = p256::ecdsa::VerifyingKey::try_from(spki.clone())
                .map_err(|_| TufError::DecodingPublicKeyFailed)?;
            let mut hasher = <sha2::Sha256 as Digest>::new();
            Digest::update(&mut hasher, msg);
            let sig = p256::ecdsa::Signature::from_bytes(sig.into())
                .map_err(|_| TufError::DecodingSignatureFailed)?;
            key.verify_digest(hasher, &sig)
                .or(Err(TufError::InvalidSignature))?;
            Ok(())
        }
        #[cfg(all(feature = "ecdsa", feature = "dilithium3"))]
        tuf_no_std_common::constants::ID_DILITHIUM3_ECDSA_P256_SHA256 => {
            let sigs = CompositeSignatureRef::<2>::from_der(sig).map_err(|_| ())?;
            let d3 = oqs::sig::Sig::new(Dilithium3).unwrap();
            let ecdsa_sig = sigs
                .iter()
                .find_map(|s| p256::ecdsa::Signature::from_der(s.raw_bytes()).ok())
                .ok_or(())?;
            let dilithium3_sig = sigs
                .iter()
                .find_map(|s| d3.signature_from_bytes(s.raw_bytes()))
                .ok_or(())?;

            let spkis = spki
                .subject_public_key
                .as_bytes()
                .ok_or(())
                .and_then(|bytes| CompositePublicKeyRef::<2>::from_der(bytes).map_err(|_| ()))?;

            spkis
                .iter()
                .find(|spki| spki.algorithm.oid == const_oid::db::rfc5912::ECDSA_WITH_SHA_256)
                .ok_or(())
                .and_then(|spki| p256::ecdsa::VerifyingKey::try_from(spki.clone()).map_err(|_| ()))
                .and_then(|key| {
                    let mut hasher = <sha2::Sha256 as Digest>::new();
                    Digest::update(&mut hasher, msg);
                    key.verify_digest(hasher, &ecdsa_sig).or(Err(()))?;
                    Ok(())
                })?;

            spkis
                .iter()
                .find(|spki| spki.algorithm.oid == tuf_no_std_common::constants::ID_DILITHIUM3)
                .and_then(|spki| d3.public_key_from_bytes(spki.subject_public_key.raw_bytes()))
                .ok_or(())
                .and_then(|key| d3.verify(msg, dilithium3_sig, key).map_err(|_| ()))?;
            Ok(())
        }
        _ => {
            unimplemented!(
                "algorithm with OID {:?} is not implemented or activated",
                spki.algorithm.oid
            )
        }
    }
}

impl OwnedToRef for Key {
    type Borrowed<'a> = KeyRef<'a> where Self: 'a;

    fn owned_to_ref(&self) -> Self::Borrowed<'_> {
        KeyRef {
            keytype: self.keytype,
            keyval: self.keyval.owned_to_ref(),
            scheme: self.scheme.owned_to_ref(),
        }
    }
}

/// DER encoding of a TUF role.
#[derive(Debug, Eq, PartialEq, Sequence, Clone)]
pub struct Role {
    /// The name of the role, e.g. "root".
    pub name: BitString,
    /// A collection of [KeyId]s that specify which keys are associated with this role.
    pub keyids: Vec<KeyId>,
    /// The signature threshold that needs to be reached for validity.
    pub threshold: Threshold,
}

impl OwnedToRef for Role {
    type Borrowed<'a> = RoleRef<'a> where Self: 'a;

    fn owned_to_ref(&self) -> Self::Borrowed<'_> {
        let keyids = self.keyids.iter().fold(SequenceOf::new(), |mut acc, a| {
            acc.add(OwnedToRef::owned_to_ref(a)).expect("failed to add");
            acc
        });
        RoleRef {
            name: self.name.owned_to_ref(),
            keyids,
            threshold: self.threshold,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct RoleRef<'a> {
    pub name: BitStringRef<'a>,
    pub keyids: SequenceOf<KeyIdRef<'a>, 5>,
    pub threshold: Threshold,
}

/// DER encoding of a Hash
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct Hash {
    pub algorithm: AlgorithmIdentifierOwned,
    pub value: BitString,
}

impl Hash {
    pub fn from_sha256_bytes(bytes: &[u8; 32]) -> Self {
        Hash {
            algorithm: AlgorithmIdentifier {
                oid: const_oid::db::rfc5912::ID_SHA_256,
                parameters: None,
            },
            value: BitString::from_bytes(bytes).expect("failed to encode"),
        }
    }
    /// Returns `Some` if this is a SHA-256 hash.
    pub fn sha256(&self) -> Option<&[u8; 32]> {
        if self.algorithm.oid != ID_SHA_256 {
            return None;
        }
        self.value
            .as_bytes()
            .and_then(|b| TryFrom::try_from(b).ok())
    }
}

impl<'a> HashRef<'a> {
    /// Returns `Some` if this is a SHA-256 hash.
    pub fn sha256(&self) -> Option<&[u8; 32]> {
        if self.algorithm.oid != ID_SHA_256 {
            return None;
        }
        self.value
            .as_bytes()
            .and_then(|b| TryFrom::try_from(b).ok())
    }
}

/// Borrowed version of [Hash].
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct HashRef<'a> {
    pub algorithm: AlgorithmIdentifierRef<'a>,
    pub value: BitStringRef<'a>,
}

/// A signed TUF file.
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct Signed<'a, T: Debug + Eq + PartialEq + Decode<'a> + Encode> {
    pub signatures: Vec<Signature>,
    pub signed: T,
    pub _phantom: PhantomData<&'a ()>,
}

impl<'a, T> Signed<'a, T>
where
    T: Debug + Eq + PartialEq + Decode<'a> + Encode,
{
    /// Creates a signed object using the given signing keys from the data in `signed`.
    pub fn from_signed(signed: T, signing_keys: &[SigningKey]) -> Result<Signed<'a, T>, TufError> {
        let mut buf = [0u8; 2048];
        let encoded = signed
            .encode_to_slice(&mut buf)
            .map_err(|_| TufError::EncodingError)?;
        let signatures = signing_keys
            .iter()
            .map(|key| {
                key.sign(encoded).map(|sig| Signature {
                    keyid: key
                        .key_id()
                        .map(|key_id| BitString::from_bytes(&key_id).unwrap())
                        .unwrap(),
                    sig: BitString::from_bytes(&sig.to_vec()).unwrap(),
                })
            })
            .collect::<Result<Vec<_>, TufError>>()?;
        Ok(Signed {
            signatures,
            _phantom: Default::default(),
            signed,
        })
    }

    pub fn encode_as_file<'o>(&self, out: &'o mut [u8]) -> Result<&'o [u8], TufError> {
        self.encode_to_slice(out)
            .map_err(|_| TufError::EncodingError)
    }
}

/// Borrowed version of [SignedRef].
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct SignedRef<'a, T: Debug + Eq + PartialEq + Decode<'a> + Encode> {
    pub signatures: SequenceOf<SignatureRef<'a>, 5>,
    pub signed: T,
}

impl<'a, T> SignedRef<'a, T>
where
    T: Debug + Eq + PartialEq + Decode<'a> + Encode,
{
    pub fn encode_as_file<'o>(&self, out: &'o mut [u8]) -> Result<&'o [u8], TufError> {
        self.encode_to_slice(out)
            .map_err(|_| TufError::EncodingError)
    }
}

/// Enum for signature schemes.
#[derive(Clone, Debug)]
pub enum SigningScheme {
    Ed25519,
    RsassaPss,
    EcdsaSha256,
    Dilithium3EcdsaP256Sha256,
}

/// Enum for key types.
#[derive(Clone, Debug)]
pub enum KeyType {
    Ed25519,
    Ecdsa,
    Dilithium3EcdsaP256Sha256,
    Rsa,
}

/// Get signing schemes from algorithm identifiers.
impl From<SigningScheme> for AlgorithmIdentifierOwned {
    fn from(value: SigningScheme) -> Self {
        match value {
            SigningScheme::Ed25519 => AlgorithmIdentifier {
                oid: const_oid::db::rfc8410::ID_ED_25519,
                parameters: None,
            },
            // This might need parameters.
            SigningScheme::RsassaPss => AlgorithmIdentifier {
                oid: const_oid::db::rfc5912::ID_RSASSA_PSS,
                parameters: None,
            },
            SigningScheme::EcdsaSha256 => AlgorithmIdentifier {
                oid: const_oid::db::rfc5912::ECDSA_WITH_SHA_256,
                parameters: None,
            },
            SigningScheme::Dilithium3EcdsaP256Sha256 => AlgorithmIdentifier {
                oid: tuf_no_std_common::constants::ID_DILITHIUM3_ECDSA_P256_SHA256,
                parameters: None,
            },
        }
    }
}

/// Get a key type from an OID that specifies the key type.
/// The relationship is usually specified in the standardization of the key type.
impl From<KeyType> for ObjectIdentifier {
    fn from(value: KeyType) -> Self {
        match value {
            KeyType::Ed25519 => const_oid::db::rfc8410::ID_ED_25519,
            KeyType::Ecdsa => const_oid::db::rfc5912::SECP_256_R_1,
            KeyType::Dilithium3EcdsaP256Sha256 => {
                tuf_no_std_common::constants::ID_DILITHIUM3_ECDSA_P256_SHA256
            }
            KeyType::Rsa => const_oid::db::rfc5912::RSA_ENCRYPTION,
        }
    }
}

impl<'b> OwnedToRef for Signed<'b, Root> {
    type Borrowed<'a> = SignedRef<'a, RootRef<'a>> where Self: 'a;

    fn owned_to_ref(&self) -> Self::Borrowed<'_> {
        let mut sigs = SequenceOf::new();
        for sig in self.signatures.iter() {
            sigs.add(sig.owned_to_ref()).unwrap()
        }
        SignedRef {
            signatures: sigs,
            signed: self.signed.owned_to_ref(),
        }
    }
}
pub struct TufDer();

#[cfg(test)]
mod test {
    use crate::{Key, KeyType, SigningScheme};
    use der::referenced::OwnedToRef;
    use der::Decode;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;
    use spki::{EncodePublicKey, SubjectPublicKeyInfoOwned};

    #[test]
    fn test_key_hash() {
        let mut csprng = OsRng;

        let root_key: SigningKey = SigningKey::generate(&mut csprng);
        let root_pub_spki = SubjectPublicKeyInfoOwned::from_der(
            root_key
                .verifying_key()
                .to_public_key_der()
                .unwrap()
                .as_bytes(),
        )
        .unwrap();
        let root_key_id = root_pub_spki.fingerprint_bytes().unwrap();
        let key = Key {
            keytype: KeyType::Ed25519.into(),
            keyval: root_pub_spki,
            scheme: SigningScheme::Ed25519.into(),
        };

        assert_eq!(root_key_id, key.owned_to_ref().key_hash(),)
    }
}
