use crate::TufError;
use crate::TufError::InternalError;
use alloc::vec::Vec;
use der::Decode;
use p256::ecdsa;
use signature::Signer;
use spki::{EncodePublicKey, SubjectPublicKeyInfoOwned, SubjectPublicKeyInfoRef};

#[derive(Debug, Clone)]
pub enum SigningKey {
    #[cfg(feature = "ed25519")]
    Ed25519Dalek(ed25519_dalek::SigningKey),
    #[cfg(feature = "ecdsa")]
    Ecdsa(ecdsa::SigningKey),
}
#[derive(Debug, Clone)]
pub enum Cipher {
    #[cfg(feature = "ed25519")]
    Ed25519Dalek,
    #[cfg(feature = "ecdsa")]
    Ecdsa,
}

#[derive(Debug)]
pub enum RawSignature {
    #[cfg(feature = "ed25519")]
    Ed25519Dalek(ed25519_dalek::Signature),
    #[cfg(feature = "ecdsa")]
    Ecdsa(ecdsa::Signature),
}

impl RawSignature {
    pub fn to_vec(&self) -> Vec<u8> {
        match self {
            #[cfg(feature = "ed25519")]
            RawSignature::Ed25519Dalek(sig) => sig.to_vec(),
            #[cfg(feature = "ecdsa")]
            RawSignature::Ecdsa(sig) => sig.to_bytes().to_vec(),
        }
    }
}

#[cfg(feature = "sign")]
impl SigningKey {
    #[cfg(feature = "rand")]
    pub fn new(cipher: Cipher) -> Self {
        match cipher {
            #[cfg(feature = "ed25519")]
            Cipher::Ed25519Dalek => {
                Self::Ed25519Dalek(ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng))
            }
            #[cfg(feature = "ecdsa")]
            Cipher::Ecdsa => Self::Ecdsa(p256::ecdsa::SigningKey::random(&mut rand_core::OsRng)),
        }
    }

    pub fn sign(&self, msg: &[u8]) -> Result<RawSignature, TufError> {
        match self {
            #[cfg(feature = "ed25519")]
            SigningKey::Ed25519Dalek(key) => Ok(RawSignature::Ed25519Dalek(key.sign(msg))),
            #[cfg(feature = "ecdsa")]
            SigningKey::Ecdsa(key) => Ok(RawSignature::Ecdsa(key.sign(msg))),
        }
    }
    pub fn key_id(&self) -> Result<[u8; 32], TufError> {
        match self {
            #[cfg(feature = "ed25519")]
            SigningKey::Ed25519Dalek(key) => key
                .verifying_key()
                .to_public_key_der()
                .map_err(|_| TufError::EncodingError)
                .and_then(|d| {
                    SubjectPublicKeyInfoRef::from_der(d.as_bytes())
                        .map_err(|_| InternalError)
                        .and_then(|spki| spki.fingerprint_bytes().map_err(|_| InternalError))
                }),
            #[cfg(feature = "ecdsa")]
            SigningKey::Ecdsa(key) => key
                .verifying_key()
                .to_public_key_der()
                .map_err(|_| TufError::EncodingError)
                .and_then(|d| {
                    SubjectPublicKeyInfoRef::from_der(d.as_bytes())
                        .map_err(|_| InternalError)
                        .and_then(|spki| spki.fingerprint_bytes().map_err(|_| InternalError))
                }),
        }
    }
    pub fn as_spki(&self) -> Result<SubjectPublicKeyInfoOwned, TufError> {
        let pubkey_der = match self {
            #[cfg(feature = "ed25519")]
            SigningKey::Ed25519Dalek(key) => {
                key.verifying_key().to_public_key_der().unwrap().into_vec()
            }
            #[cfg(feature = "ecdsa")]
            SigningKey::Ecdsa(key) => key.verifying_key().to_public_key_der().unwrap().into_vec(),
        };
        TryFrom::try_from(pubkey_der.as_slice()).map_err(|_| TufError::DecodingError)
    }
}
