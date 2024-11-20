use const_oid::ObjectIdentifier;

pub const PEM_KEY_MAX_SIZE: usize = 1024;
pub const PEM_ECDSA_KEY_MAX_SIZE: usize = 130;

pub const DER_DILITHIUM3_ECDSA_P256_SHA256_KEY_MAX_SIZE: usize = 2090;
pub const PEM_DILITHIUM3_ECDSA_P256_SHA256_KEY_MAX_SIZE: usize = 2884;
// https://github.com/IETF-Hackathon/pqc-certificates/blob/master/docs/oid_mapping.md
pub const ID_DILITHIUM3_ECDSA_P256_SHA256: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.114027.80.5.1.2");
pub const ID_DILITHIUM3: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.2.267.12.6.5");

pub const ID_COMPOSITE_KEY_OID: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.114027.80.4.1");
