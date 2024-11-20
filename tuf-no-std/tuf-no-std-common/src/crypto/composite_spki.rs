use der::{AnyRef, Decode, Encode, FixedTag, Length, Reader, Tag, Writer};

pub(crate) struct PkComposite {}

use crate::constants::*;
use crate::crypto::Dilithium3VerificationKey;
use der::asn1::{BitStringRef, SequenceOf};
#[cfg(feature = "dilithium3")]
use oqs::sig::Algorithm::Dilithium3;
use signature::digest::Digest;
use signature::{DigestVerifier, Error, Verifier};
use spki::{SubjectPublicKeyInfo, SubjectPublicKeyInfoRef};

pub type CompositeSubjectPublicKeyInfoRef<'a, const N: usize> =
    SubjectPublicKeyInfo<AnyRef<'a>, CompositePublicKeyRef<'a, N>>;
pub type CompositePublicKeyRef<'a, const N: usize> = SequenceOf<SubjectPublicKeyInfoRef<'a>, N>;

#[cfg(feature = "composite")]
pub enum CompositeVerificationKey {
    #[cfg(all(feature = "dilithium3", feature = "ecdsa"))]
    Dilithium3EcdsaP256Sha256 {
        k1: p256::ecdsa::VerifyingKey,
        k2: Dilithium3VerificationKey,
    },
}
#[cfg(feature = "composite")]
pub type CompositeSignatureRef<'a, const N: usize> = SequenceOf<BitStringRef<'a>, N>;
#[cfg(feature = "composite")]
impl<'a> TryFrom<CompositeSubjectPublicKeyInfoRef<'a, 2>> for CompositeVerificationKey {
    type Error = ();

    fn try_from(value: CompositeSubjectPublicKeyInfoRef<'a, 2>) -> Result<Self, Self::Error> {
        match value.algorithm.oid {
            id if id == ID_DILITHIUM3_ECDSA_P256_SHA256 => {
                let ecdsa_key = value
                    .subject_public_key
                    .iter()
                    .find(|k| k.algorithm.oid == const_oid::db::rfc5912::ID_EC_PUBLIC_KEY)
                    .ok_or(())
                    .and_then(|k| p256::ecdsa::VerifyingKey::try_from(k.clone()).or(Err(())))?;
                let dilithium3_key = value
                    .subject_public_key
                    .iter()
                    .find(|k| k.algorithm.oid == ID_DILITHIUM3)
                    .ok_or(())
                    .and_then(|k| {
                        k.subject_public_key.as_bytes().ok_or(()).and_then(|b| {
                            oqs::sig::Sig::new(Dilithium3)
                                .unwrap()
                                .public_key_from_bytes(b)
                                .ok_or(())
                                .map(|k| k.to_owned())
                        })
                    })?;
                Ok(Self::Dilithium3EcdsaP256Sha256 {
                    k1: ecdsa_key,
                    k2: Dilithium3VerificationKey(dilithium3_key),
                })
            }
            _ => return Err(()),
        }
    }
}

#[cfg(test)]
mod test {
    use der::asn1::{BitStringRef, SequenceOf};
    use der::{AnyRef, Decode, DecodePem, Encode, EncodePem};
    use rand_core::OsRng;
    use spki::{
        AlgorithmIdentifier, EncodePublicKey, SubjectPublicKeyInfo, SubjectPublicKeyInfoRef,
    };

    use crate::constants::*;
    use crate::crypto::composite_spki::{
        CompositeSubjectPublicKeyInfoRef, CompositeVerificationKey,
    };
    use oqs::*;

    #[test]
    fn test() {
        let signing_key = p256::ecdsa::SigningKey::random(&mut OsRng); // Serialize with `::to_bytes()`
        let pubkey = p256::ecdsa::VerifyingKey::from(signing_key);

        let der = pubkey.to_public_key_der().unwrap();
        let spki = spki::SubjectPublicKeyInfoRef::from_der(der.as_ref()).unwrap();
        let mut keys = SequenceOf::new();
        keys.add(spki.clone()).unwrap();

        oqs::init(); // Important: initialize liboqs
        let sigalg = sig::Sig::new(sig::Algorithm::Dilithium3).unwrap();
        // A's long-term secrets
        let (a_sig_pk, a_sig_sk) = sigalg.keypair().unwrap();
        let pk_bytes = a_sig_pk.as_ref();

        keys.add(SubjectPublicKeyInfo {
            algorithm: AlgorithmIdentifier {
                oid: ID_DILITHIUM3,
                parameters: None,
            },
            subject_public_key: BitStringRef::from_bytes(pk_bytes).unwrap(),
        })
        .unwrap();

        let spki_new = CompositeSubjectPublicKeyInfoRef::<2> {
            algorithm: AlgorithmIdentifier {
                oid: ID_DILITHIUM3_ECDSA_P256_SHA256,
                parameters: None,
            },
            subject_public_key: keys,
        };
        let composite_der = spki_new.to_pem(Default::default()).unwrap();
        eprintln!("{:#?}", composite_der.len());
        let key = CompositeVerificationKey::try_from(spki_new).expect("failed to get key");
    }
}
