#![no_std]
//! A `no-std` implementation to run verification of Sigstore/Cosign style signatures.
//!
//! ## Signature Format
//!
//! At a top level the signature has the following modification to the [Cosign format](https://github.com/sigstore/cosign/blob/8defb0e72baa6c0385f4097723a3574e6d0406d0/specs/SIGNATURE_SPEC.md).
//! ```json
//! {
//!     "SignedEntryTimestamp": "<B64-encoded SET>",
//!     "Payload": "<B64-encoded BundlePayload>"
//! }
//! ```
//!
//! This has the following benefits:
//! - We can separate the parsing into multiple steps,
//!   and do not have to deserialize and re-serialize multiple times to verify signatures.
//! - Decoding the B64 strings gives us the strings we need to verify signatures on, we can do so and then parse it.
//!
//!
//! The [BundlePayload] follows the regular format, meaning we only use a very minor modification to the original specification.
//! ## Example
//!
//! This example verifies:
//! - that the binary was correctly signed with a Fulcio signing certificate,
//! - it was entered into the Rekor log within 10 minutes,
//! - the signing certificate was issued to `foo@example.org` based on being authenticated by the OIDC provider `issuer.example.org`.
//!
//! ```ignore
//! let signature = include_bytes!("bundle.json");
//! let binary = include_bytes!("example.bin");
//! let rekor_pub_key = include_bytes!("rekor_pub.pem");
//! let fulcio_crt = include_bytes!("fulcio_crt.pem");
//!
//! bt2x_embedded::verify_bt(
//!     rekor_pub_key,
//!     fulcio_crt,
//!     signature,
//!     binary,
//!     &[("foo@example.org", "issuer.example.org")],
//! ).expect("failed to verify binary");
//! ```

// #[cfg(test)]
// #[macro_use]
// extern crate std;
// extern crate alloc;

// use embedded_alloc::Heap;
//
// #[global_allocator]
// static HEAP: Heap = Heap::empty();

//pub mod models;

const MAX_CERT_SIZE: usize = 4096;
const MAX_SIGNATURE_SIZE: usize = 128;
const MAX_PAYLOAD_SIZE: usize = 4096;
const MAX_PUBKEY_SIZE: usize = 1024;

/// 'Compact' version of a cosign bundle, which is optimized to eliminate the need for a JSON encoder.
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Bundle<'a> {
    /// Base64 encoded SET.
    pub signed_entry_timestamp: &'a str,
    /// Base64 encoded [BundlePayload].
    pub payload: &'a str,
}

/// Cosign Bundle Payload.
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BundlePayload<'a> {
    /// Base64 encoded [BundleBody].
    pub body: &'a str,
    /// The timestamp of when the bundle was presented to the log. Has to be within ten minutes of the creation of a Fulcio signing cert.
    pub integrated_time: u64,
    /// The index of the entry in the log.
    pub log_index: u32,
    /// The ID of the log entry.
    #[serde(rename = "logID")]
    pub log_id: &'a str,
}

#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
#[serde(bound(deserialize = "'de: 'a"))]
pub struct BundleBody<'a> {
    pub kind: Kind,
    pub api_version: &'a str,
    pub spec: HashedRekordObj<'a>,
}

#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
#[serde(bound(deserialize = "'de: 'a"))]
pub struct HashedRekordObj<'a> {
    pub data: HashRekordData<'a>,
    pub signature: Signature<'a>,
}

#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(bound(deserialize = "'de: 'a"))]
pub struct HashRekordData<'a> {
    pub hash: Hash<'a>,
}

#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Hash<'a> {
    pub algorithm: HashAlgorithm,
    pub value: &'a str,
}

#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HashAlgorithm {
    Sha256,
}

#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Signature<'a> {
    pub format: Option<SignatureFormat>,
    pub content: &'a str,
    pub public_key: PublicKey<'a>,
}

#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicKey<'a> {
    pub content: &'a str,
}

#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum SignatureFormat {
    //Pgp,
    //Minisign,
    X509,
    //Ssh,
}

#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    HashedRekord,
}

pub struct FuncResult<'a> {
    pub integrated_time: u32,
    pub log_index: u32,
    pub log_id: &'a str,
    pub body: BundleBody<'a>,
}

pub type EcdsaP256Sha256Asn1Signature = p256::ecdsa::Signature;
pub type EcdsaP256Key = p256::ecdsa::VerifyingKey;

use core::fmt::Debug;
use p256::ecdsa::signature::DigestVerifier;
pub use serde_json_core::de::Error as SerdeDeserializationError;
pub use sha2::{Digest, Sha256};

#[derive(Debug)]
pub enum VerificationError {
    /// Failed to deserialize the [Bundle]
    DeserializationFailedBundle(serde_json_core::de::Error),
    /// Failed to deserialize the [BundlePayload].
    DeserializationFailedBundlePayload,
    /// Failed to deserialize the [BundleBody].
    DeserializationFailedBundleBody,
    SetVerificationFailed,
    ParsingPubKeyFailed,
    ParsingSignatureFailed,
    DecodingB64Failed,
    DecodingHexFailed,
    /// Hash in the bundle does not matched the calculated hash.
    HashDifferent,
    /// The signing cert is not trusted.
    UntrustedCert,
    /// Failed to PEM decode a certificate.
    ParsingCertFailedPem(pem_rfc7468::Error),
    /// Failed to DER decode a certificate.
    ParsingCertFailedDer(der::Error),
    /// Log timestamp is not within the validity period.
    TimestampNotInValidity,
    /// Pubkey type is not supported.
    UnsupportedPubKey,
    InvalidSignatureSet,
    InvalidSignatureCertificate,
    InvalidSignature,
    ErrorThatIndicatesImplementationError,
    OutOfBufferSpace,
    /// Signing certificate identity is does not match a trusted identity.
    SubjectIdentityMismatch,
}

#[derive(Debug)]
pub enum SignedObject<'a, H: Digest + Debug> {
    Blob(&'a [u8]),
    Digest(H),
}

impl<'a, H: Digest + Debug> From<&'a [u8]> for SignedObject<'a, H> {
    fn from(value: &'a [u8]) -> Self {
        SignedObject::Blob(value)
    }
}

impl<'a> From<Sha256> for SignedObject<'a, Sha256> {
    fn from(value: Sha256) -> Self {
        SignedObject::Digest(value)
    }
}

fn parse_cert<'a>(
    pem: &[u8],
    output: &'a mut [u8],
) -> Result<CertificateRef<'a>, VerificationError> {
    let (_, decoded) =
        pem_rfc7468::decode(pem, output).map_err(VerificationError::ParsingCertFailedPem)?;

    <CertificateRef as Decode>::from_der(decoded).map_err(VerificationError::ParsingCertFailedDer)
}

/// Verify that PEM encoded signing certificate was signed by the root CA.
fn verify_signing_cert<'a>(
    root_cert: &[u8],
    pem_signing: &[u8],
    output_buf: &'a mut [u8],
) -> Result<CertificateRef<'a>, VerificationError> {
    // Load root cert.
    let mut root_cert_buf = [0_u8; MAX_CERT_SIZE];
    let root_cert = parse_cert(root_cert, root_cert_buf.as_mut_slice())?;

    // Load signing cert.
    let signing_cert = parse_cert(pem_signing, output_buf)?;
    let mut tbs_encoding_buf = [0_u8; MAX_CERT_SIZE];

    // Encode the signing cert as a TBS, which is the part of the certificate that is signed.
    let tbs_encoded = signing_cert
        .tbs_certificate
        .encode_to_slice(tbs_encoding_buf.as_mut_slice())
        .map_err(|_| VerificationError::ErrorThatIndicatesImplementationError)?;

    // Load the CA key.
    let spki = root_cert.tbs_certificate.subject_public_key_info;
    let pubkey =
        ecdsa::VerifyingKey::try_from(spki).map_err(|_| VerificationError::ParsingPubKeyFailed)?;

    // Verify that the certificate was signed by the CA.
    verify_signature(
        signing_cert.signature.raw_bytes(),
        tbs_encoded.into(),
        &pubkey,
    )
    .map_err(|_| VerificationError::InvalidSignatureCertificate)?;

    Ok(signing_cert)
}

fn verify_signature(
    signature: &[u8],
    msg: SignedObject<'_, Sha256>,
    verifying_key: &VerifyingKey,
) -> Result<(), VerificationError> {
    // create a Sha256 object
    let hasher = match msg {
        SignedObject::Blob(blob) => <Sha256 as Digest>::new().chain_update(blob),
        SignedObject::Digest(hasher) => hasher,
    };

    let signature = ecdsa::Signature::from_der(signature)
        .map_err(|_| VerificationError::ParsingSignatureFailed)?;
    verifying_key
        .verify_digest(hasher, &signature)
        .map(|_| ())
        .map_err(|_| VerificationError::InvalidSignature)
}

/// Verifies the binary in `msg`, which can be either a &[u8] or calculated `Sha256` hash.
/// The `rekor_pub_key` is PEM encoded key of the Rekor server that signed the entry timestamp.
/// The parameter `root_cert` is the PEM encoded root certificate of the Fulcio CA that issues the signing certificates.
/// The signature is provided via the `bundle` parameter, it has to be formatted in a modified cosign bundle format, refer to the [Bundle struct](Bundle) for more information.
pub fn verify_bt<'a, 'b>(
    rekor_pub_key: &[u8],
    root_cert: &[u8],
    bundle: &'a [u8],
    msg: impl Into<SignedObject<'b, Sha256>>,
    subject_identities: &[(&str, &str)],
) -> Result<Bundle<'a>, VerificationError> {
    // decode the bundle
    let (bundle, _) = serde_json_core::from_slice::<Bundle>(bundle)
        .map_err(VerificationError::DeserializationFailedBundle)?;

    // Decode the SET from Base64 to the raw signature.
    let mut set_buf = [0_u8; MAX_SIGNATURE_SIZE];
    let set_decoded = Base64::decode(
        bundle.signed_entry_timestamp.as_bytes(),
        set_buf.as_mut_slice(),
    )
    .map_err(|_| VerificationError::ErrorThatIndicatesImplementationError)?;

    // Decode the payload of the bundle from Base64 to JSOn.
    let mut payload_buf = [0_u8; MAX_PAYLOAD_SIZE];
    let payload_decoded = Base64::decode(bundle.payload.as_bytes(), payload_buf.as_mut_slice())
        .map_err(|_| VerificationError::DecodingB64Failed)?;

    // Decode the Rekor public key.
    let mut pem_decode_buf = [0_u8; MAX_PUBKEY_SIZE];
    let (_, decoded) = pem_rfc7468::decode(rekor_pub_key, pem_decode_buf.as_mut_slice())
        .map_err(|_| VerificationError::ParsingPubKeyFailed)?;
    let spki = spki::SubjectPublicKeyInfoRef::from_der(decoded)
        .map_err(|_| VerificationError::ParsingPubKeyFailed)?;
    let rekor_pub_key =
        ecdsa::VerifyingKey::try_from(spki).map_err(|_| VerificationError::ParsingPubKeyFailed)?;

    // Verify that the signature was presented to the Rekor log by verifying that the payload was signed by the log with its public key.
    verify_signature(set_decoded, payload_decoded.into(), &rekor_pub_key)
        .map_err(|_| InvalidSignatureSet)?;

    // Decode the payload JSON.
    let (payload, _) = serde_json_core::from_slice::<BundlePayload>(payload_decoded)
        .map_err(|_| VerificationError::DeserializationFailedBundlePayload)?;

    // Extract the Base64 encoded body of the bundle.
    let mut body_buf = [0_u8; 4096];
    let body_decoded = Base64::decode(payload.body.as_bytes(), body_buf.as_mut_slice())
        .map_err(|_| VerificationError::DecodingB64Failed)?;

    // Decode the JSON bundle body.
    let (body, _) = serde_json_core::from_slice::<BundleBody>(body_decoded)
        .map_err(|_| VerificationError::DeserializationFailedBundleBody)?;

    // Decode hash from Rekor Entry
    let mut given_digest = [0_u8; 32];
    hex::decode_to_slice(body.spec.data.hash.value, &mut given_digest)
        .map_err(|_| VerificationError::DecodingHexFailed)?;

    // Base64 decode the signing cert.
    let mut cert_buf = [0_u8; MAX_CERT_SIZE];
    let cert_decoded = Base64::decode(
        body.spec.signature.public_key.content.as_bytes(),
        cert_buf.as_mut_slice(),
    )
    .map_err(|_| VerificationError::DecodingB64Failed)?;

    // Load the certificate and verify that it was issued by the trusted Fulcio instance.
    let mut cert_pem_decode_buf = [0_u8; MAX_CERT_SIZE];
    let signing_cert =
        verify_signing_cert(root_cert, cert_decoded, cert_pem_decode_buf.as_mut_slice())?;
    if signing_cert
        .tbs_certificate
        .validity
        .not_after
        .to_unix_duration()
        .as_secs()
        < payload.integrated_time
        || signing_cert
            .tbs_certificate
            .validity
            .not_before
            .to_unix_duration()
            .as_secs()
            > payload.integrated_time
    {
        return Err(VerificationError::TimestampNotInValidity);
    }
    // Verify that the subject that requested the signing certificate is trusted.
    verify_subject_identities(&signing_cert, subject_identities)
        .map_err(|_| VerificationError::SubjectIdentityMismatch)?;

    // Extract the public key from the signing certificate.
    let spki = signing_cert.tbs_certificate.subject_public_key_info;
    let pubkey =
        ecdsa::VerifyingKey::try_from(spki).map_err(|_| VerificationError::ParsingPubKeyFailed)?;

    // Decode the signature.
    let mut signature_buf = [0_u8; MAX_SIGNATURE_SIZE];
    let signature_decoded = Base64::decode(
        body.spec.signature.content.as_bytes(),
        signature_buf.as_mut_slice(),
    )
    .map_err(|_| VerificationError::DecodingB64Failed)?;

    // Verify the signature of the binary.
    verify_signature(signature_decoded, msg.into(), &pubkey)
        .map_err(|_| VerificationError::InvalidSignature)?;
    Ok(bundle)
}

use base64ct::{Base64, Encoding};
use der::asn1::{BitStringRef, IntRef, ObjectIdentifier, OctetStringRef, SequenceOf, SetOf};
//use base64::{Engine as _, alphabet, engine::{self, general_purpose}};
use der::{
    AnyRef, Decode, DecodeValue, Encode, EncodeValue, ErrorKind, FixedTag, Header, Length, Reader,
    Sequence, Tag, ValueOrd, Writer,
};

use p256::ecdsa;
use p256::ecdsa::VerifyingKey;
//use p256::ecdsa::VerifyingKey;
use crate::VerificationError::InvalidSignatureSet;
use pkcs8::SubjectPublicKeyInfoRef;
use spki::AlgorithmIdentifierRef;
use x509_cert::time::Validity;
use x509_cert::Version;
//use spki::DecodePublicKey;

#[derive(Clone, Debug, Sequence, ValueOrd)]
struct CertificateRef<'a> {
    pub tbs_certificate: TbsCertificateRef<'a>,
    pub signature_algorithm: AlgorithmIdentifierRef<'a>,
    pub signature: BitStringRef<'a>,
}

const N_TBS_EXT: usize = 10;
const N_TBS_RDN_SEQ: usize = 10;
const N_TBS_RDN: usize = 5;

#[derive(Clone, Debug, Sequence, ValueOrd)]
#[allow(missing_docs)]
struct TbsCertificateRef<'a> {
    /// The certificate version
    ///
    /// Note that this value defaults to Version 1 per the RFC. However,
    /// fields such as `issuer_unique_id`, `subject_unique_id` and `extensions`
    /// require later versions. Care should be taken in order to ensure
    /// standards compliance.
    #[asn1(context_specific = "0", default = "Default::default")]
    pub version: Version,

    pub serial_number: SerialNumberRef<'a>,
    pub signature: AlgorithmIdentifierRef<'a>,
    pub issuer: NameRef<'a, N_TBS_RDN, N_TBS_RDN_SEQ>,
    pub validity: Validity,
    pub subject: NameRef<'a, N_TBS_RDN, N_TBS_RDN_SEQ>,
    pub subject_public_key_info: SubjectPublicKeyInfoRef<'a>,

    #[asn1(context_specific = "1", tag_mode = "IMPLICIT", optional = "true")]
    pub issuer_unique_id: Option<BitStringRef<'a>>,

    #[asn1(context_specific = "2", tag_mode = "IMPLICIT", optional = "true")]
    pub subject_unique_id: Option<BitStringRef<'a>>,

    #[asn1(context_specific = "3", tag_mode = "EXPLICIT", optional = "true")]
    pub extensions: Option<Extensions<'a, N_TBS_EXT>>,
}

type NameRef<'a, const N_RDN: usize, const N_RDN_SEQ: usize> = RdnSequence<'a, N_RDN, N_RDN_SEQ>;

#[derive(Clone, Debug, Default)]
struct RdnSequence<'a, const N_RDN: usize, const N_RDN_SEQ: usize>(
    pub SequenceOf<RelativeDistinguishedName<'a, N_RDN>, N_RDN_SEQ>,
);
impl_newtype_generics!(
    RdnSequence<'a, N_IMPL1, N_IMPL2>,
    SequenceOf<RelativeDistinguishedName<'a, N_IMPL1>, N_IMPL2>,
    N_IMPL1,
    N_IMPL2
);

#[derive(Clone, Debug, Default)]
struct RelativeDistinguishedName<'a, const N: usize>(pub SetOf<AttributeTypeAndValue<'a>, N>);
impl_newtype_generics!(
    RelativeDistinguishedName<'a, N_IMPL1>,
    SetOf<AttributeTypeAndValue<'a>, N_IMPL1>,
    N_IMPL1
);

type Extensions<'a, const N: usize> = SequenceOf<ExtensionRef<'a>, N>;

#[derive(Clone, Debug, Sequence, ValueOrd)]
pub struct ExtensionRef<'a> {
    pub extn_id: ObjectIdentifier,

    #[asn1(default = "bool::default")]
    pub critical: bool,

    pub extn_value: OctetStringRef<'a>,
}

#[derive(Clone, Debug, Sequence, ValueOrd)]
#[allow(missing_docs)]
struct AttributeTypeAndValue<'a> {
    pub oid: AttributeType,
    pub value: AttributeValue<'a>,
}

type AttributeType = ObjectIdentifier;

type AttributeValue<'a> = AnyRef<'a>;

#[derive(Clone, Debug, ValueOrd)]
struct SerialNumberRef<'a> {
    inner: IntRef<'a>,
}

impl<'a> SerialNumberRef<'a> {
    const MAX_DECODE_LEN: Length = Length::new(21);
}

impl<'a> EncodeValue for SerialNumberRef<'a> {
    fn value_len(&self) -> DerResult<Length> {
        self.inner.value_len()
    }

    fn encode_value(&self, writer: &mut impl Writer) -> DerResult<()> {
        self.inner.encode_value(writer)
    }
}

impl<'a> DecodeValue<'a> for SerialNumberRef<'a> {
    fn decode_value<R: Reader<'a>>(reader: &mut R, header: Header) -> DerResult<Self> {
        let inner = IntRef::<'a>::decode_value(reader, header)?;

        if inner.len() > SerialNumberRef::MAX_DECODE_LEN {
            return Err(ErrorKind::Overlength.into());
        }

        Ok(Self { inner })
    }
}

impl<'a> FixedTag for SerialNumberRef<'a> {
    const TAG: Tag = <IntRef<'a> as FixedTag>::TAG;
}

type DerResult<T> = Result<T, der::Error>;

fn verify_subject_identities(
    cert: &CertificateRef<'_>,
    subject_identities: &[(&str, &str)],
) -> Result<(), ()> {
    let extensions = cert.tbs_certificate.extensions.as_ref().ok_or(())?;
    let issuer_ext = extensions
        .iter()
        .find(|&ext| ext.extn_id == ISSUER_OID)
        .ok_or(())?;
    let subject_ext = extensions
        .iter()
        .find(|&ext| ext.extn_id == SUBJECT_ALT_NAME_OID)
        .ok_or(())?;
    subject_identities
        .iter()
        .find(|(subject, issuer)| {
            let issuer = OctetStringRef::new(issuer.as_bytes()).expect("failed to parse");
            // first 4 bytes contain encoding specific data, skip them
            issuer == issuer_ext.extn_value
                && &subject_ext.extn_value.as_bytes()[4..] == subject.as_bytes()
        })
        .ok_or(())?;
    Ok(())
}

pub const ISSUER_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.57264.1.1");
pub const SUBJECT_ALT_NAME_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.17");
#[macro_export]
macro_rules! impl_newtype_generics {
    ($newtype:ty, $inner:ty, $( $i:ident ),+) => {
        #[allow(unused_lifetimes)]
        impl<'a, $( const $i: usize ),*> From<$inner> for $newtype {
            #[inline]
            fn from(value: $inner) -> Self {
                Self(value)
            }
        }

        #[allow(unused_lifetimes)]
        impl<'a, $( const $i: usize ),*> From<$newtype> for $inner {
            #[inline]
            fn from(value: $newtype) -> Self {
                value.0
            }
        }

        #[allow(unused_lifetimes)]
        impl<'a, $( const $i: usize ),*> AsRef<$inner> for $newtype {
            #[inline]
            fn as_ref(&self) -> &$inner {
                &self.0
            }
        }

        #[allow(unused_lifetimes)]
        impl<'a, $( const $i: usize ),*> AsMut<$inner> for $newtype {
            #[inline]
            fn as_mut(&mut self) -> &mut $inner {
                &mut self.0
            }
        }

        #[allow(unused_lifetimes)]
        impl<'a, $( const $i: usize ),*> ::der::FixedTag for $newtype {
            const TAG: ::der::Tag = <$inner as ::der::FixedTag>::TAG;
        }

        impl<'a, $( const $i: usize ),*> ::der::DecodeValue<'a> for $newtype {
            fn decode_value<R: ::der::Reader<'a>>(
                decoder: &mut R,
                header: ::der::Header,
            ) -> ::der::Result<Self> {
                Ok(Self(<$inner as ::der::DecodeValue>::decode_value(
                    decoder, header,
                )?))
            }
        }

        #[allow(unused_lifetimes)]
        impl<'a, $( const $i: usize ),*> ::der::EncodeValue for $newtype {
            fn encode_value(&self, encoder: &mut impl ::der::Writer) -> ::der::Result<()> {
                self.0.encode_value(encoder)
            }

            fn value_len(&self) -> ::der::Result<::der::Length> {
                self.0.value_len()
            }
        }

        #[allow(unused_lifetimes)]
        impl<'a, $( const $i: usize ),*> ::der::ValueOrd for $newtype {
            fn value_cmp(&self, other: &Self) -> ::der::Result<::core::cmp::Ordering> {
                self.0.value_cmp(&other.0)
            }
        }
    };
}
