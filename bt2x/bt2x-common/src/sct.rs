use digest::FixedOutput;
use p256::ecdsa::VerifyingKey as P256VerifyingKey;
use sct::{verify_sct, Log};
use sha2::{Digest, Sha256};
use spki::{DecodePublicKey, EncodePublicKey, ObjectIdentifier};
use std::time::UNIX_EPOCH;
use x509_cert::der::{DecodePem, Encode};

use crate::error::Bt2XError;

const CT_PRECERT_SCTS_OID: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.11129.2.4.2");

pub fn validate_sct_pem(cert_pem: &[u8], ctlog_keys: &[&[u8]]) -> Result<(), Bt2XError> {
    let cert = x509_cert::Certificate::from_pem(cert_pem).expect("failed to parse cert");
    let sct = cert
        .tbs_certificate
        .extensions
        .as_ref()
        .ok_or(Bt2XError::CertificateIsMissingCtExtensions)?
        .iter()
        .find(|e| e.extn_id == CT_PRECERT_SCTS_OID)
        .ok_or(Bt2XError::CertificateIsMissingCtExtensions)?;
    let ctlog_keys = ctlog_keys
        .iter()
        .map(|&b| {
            P256VerifyingKey::from_public_key_pem(std::str::from_utf8(b).unwrap())
                .expect("failed to parse key")
        })
        .map(|key| {
            let key_der = key.to_public_key_der().unwrap().as_bytes().to_vec();
            let key_id: [u8; 32] = Sha256::new().chain_update(&key_der).finalize_fixed().into();
            (key_der, key_id, "".to_string())
        })
        .collect::<Vec<_>>();

    let ctlogs = ctlog_keys
        .iter()
        .map(|(key, key_id, s)| Log {
            description: s,
            url: s,
            operated_by: s,
            key: key.as_slice(),
            id: *key_id,
            max_merge_delay: 0,
        })
        .collect::<Vec<_>>();
    verify_sct(
        cert.to_der().unwrap().as_slice(),
        sct.extn_value.as_bytes(),
        std::time::SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs(),
        ctlogs.iter().collect::<Vec<_>>().as_slice(),
    )
    .map(|_| ())
    .map_err(Bt2XError::SctValidationFailed)
}
