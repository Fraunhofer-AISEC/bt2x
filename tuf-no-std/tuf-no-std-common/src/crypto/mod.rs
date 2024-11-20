#[cfg(feature = "dilithium3")]
pub mod composite_spki;
pub mod sign;

#[cfg(feature = "dilithium3")]
use oqs::sig::PublicKeyRef;
use sha2::digest::Output;
use sha2::{Digest, Sha256};

// Disable this lint because there is not point in an Err type.
#[allow(clippy::result_unit_err)]
pub fn verify_sha256(hash: impl AsRef<[u8]>, data: impl AsRef<[u8]>) -> Result<(), ()> {
    let decoded = hash.as_ref().into();
    verify_sha256_impl(decoded, data.as_ref())
}

fn verify_sha256_impl(hash: &Output<Sha256>, data: impl AsRef<[u8]>) -> Result<(), ()> {
    let output = <Sha256 as Digest>::new().chain_update(data).finalize();
    if hash == &output {
        Ok(())
    } else {
        Err(())
    }
}

#[cfg(feature = "dilithium3")]
fn from_pem_oqs<'o>(
    pem: &[u8],
    out: &'o mut [u8],
    algo: oqs::sig::Algorithm,
) -> Result<PublicKeyRef<'o>, ()> {
    let scheme = oqs::sig::Sig::new(algo).or(Err(()))?;
    let Ok((_label, data)) = pem_rfc7468::decode(pem, out) else {
        return Err(()); // PEM decoding error
    };
    let Ok((s, k)) = scheme.keypair() else {
        panic!()
    };
    scheme.public_key_from_bytes(data).ok_or(())
}

#[cfg(feature = "dilithium3")]
pub struct Dilithium3VerificationKey(pub(crate) oqs::sig::PublicKey);

#[cfg(feature = "dilithium3")]
impl<'a> Verifier<oqs::sig::SignatureRef<'a>> for Dilithium3VerificationKey {
    fn verify(&self, msg: &[u8], signature: &oqs::sig::SignatureRef) -> Result<(), Error> {
        oqs::sig::Sig::new(oqs::sig::Algorithm::Dilithium3)
            .or(Err(Default::default()))
            .and_then(|alg| {
                alg.verify(msg, signature, &self.0)
                    .or(Err(Default::default()))
            })
    }
}
