use crate::canonical::EncodeCanonically;
use crate::role::{DecodeRole, RoleUpdate, SignedFile, TufRole, TufSignature};
use core::cmp::max;
use core::num::NonZeroU64;
use core::ops::Add;
use der::asn1::UtcTime;
use der::{Decode, Encode};
use serde_json_core::heapless::FnvIndexMap;
use spki::SubjectPublicKeyInfoRef;
use tuf_no_std_common::common::Threshold;
use tuf_no_std_common::remote::TufTransport;
#[cfg(feature = "async")]
use tuf_no_std_common::remote::TufTransportAsync;
use tuf_no_std_common::storage::TufStorage;
use tuf_no_std_common::TufError::*;
use tuf_no_std_common::{RoleType, TufError, Version};
use tuf_no_std_der::root::{Root, RootRef};
use tuf_no_std_der::{verify, SignedRef};

/// A trait that represents all the operations that can be done with a root file on the client side.
pub trait TufRoot: TufRole + SignedFile + EncodeCanonically {
    type Key;
    /// Verify that the role was signed by the root.
    fn verify_role<T>(&self, role: &T) -> Result<(), TufError>
    where
        T: TufRole + EncodeCanonically + SignedFile,
    {
        let mut buf = [0u8; 4096];
        let msg = role
            .get_signed()
            .encode_canonically(&mut buf)
            .map_err(|_| TufError::EncodingError)?;
        let threshold = self.role_threshold(T::TYPE);

        let mut role_keys = self.role_keys(T::TYPE).expect("failed to get role keys");
        let reached = role.get_signatures().iter().fold(0, |acc, sig| {
            let raw_sig = sig.raw_sig();
            let key_id = sig.keyid();

            // Using remove ensures each key is only used to create a single signature.
            let Some(key) = role_keys.remove(&key_id) else {
                return acc;
            };
            Self::verify_signature(&key, msg, raw_sig)
                .map(|_| 1)
                .unwrap_or(0)
                .add(acc)
        });

        if reached < threshold {
            return Err(ThresholdNotReached);
        }
        Ok(())
    }

    /// Verify that the other root is signed by this root.
    fn verify_root(&self, other: &Self) -> Result<(), TufError> {
        let mut buf = [0u8; 4096];
        let msg = other
            .get_signed()
            .encode_canonically(&mut buf)
            .map_err(|_| TufError::EncodingError)?;
        let threshold = max(
            self.role_threshold(RoleType::Root),
            self.role_threshold(RoleType::Root),
        );
        // Use the key specified in this file.
        let role_keys = self
            .role_keys(RoleType::Root)
            .expect("failed to get role keys");
        // Signatures are specified in the other file!
        let reached = other.get_signatures().iter().fold(0, |acc, sig| {
            let raw_sig = sig.raw_sig();
            let key_id = sig.keyid();

            let Some(key) = role_keys.get(&key_id) else {
                return acc;
            };
            Self::verify_signature(key, msg, raw_sig)
                .map(|_| 1)
                .unwrap_or(0)
                .add(acc)
        });

        if reached < threshold {
            return Err(ThresholdNotReached);
        }
        Ok(())
    }

    /// Extract the signing threshold for the given role.
    fn role_threshold(&self, role: RoleType) -> Threshold;

    /// Return the keys for a given role.
    fn role_keys(&self, role: RoleType) -> Option<FnvIndexMap<[u8; 32], Self::Key, 8>>;

    /// Verify the signature of the message with the role keys.
    fn verify_signature(key: &Self::Key, msg: &[u8], sig: &[u8]) -> Result<(), TufError>;
}

impl<'a> TufRole for RootRef<'a> {
    const TYPE: RoleType = RoleType::Root;
}

impl<'a> EncodeCanonically for RootRef<'a> {
    fn encode_canonically<'o>(
        &self,
        out: &'o mut [u8],
    ) -> Result<&'o [u8], crate::canonical::EncodingError> {
        self.encode_to_slice(out)
            .map_err(|_| crate::canonical::EncodingError::BufferTooSmall)
    }
}

impl<'a> RoleUpdate for RootRef<'a> {
    fn version(&self) -> Version {
        self.version
    }

    fn expires(&self) -> UtcTime {
        self.expires
    }
}

impl<'a> TufRoot for SignedRef<'a, RootRef<'a>> {
    type Key = SubjectPublicKeyInfoRef<'a>;

    fn role_threshold(&self, role: RoleType) -> Threshold {
        self.signed
            .roles
            .iter()
            .find(|r| role == r.name)
            .map(|r| r.threshold)
            .expect("did not find role")
    }

    fn role_keys(&self, role: RoleType) -> Option<FnvIndexMap<[u8; 32], Self::Key, 8>> {
        // Get the role.
        let role = self.signed.roles.iter().find(|&r| role == r.name)?;
        // Collect the matching keys.
        let mut result = FnvIndexMap::new();
        for key_id in role.keyids.iter() {
            let key_id = key_id
                .as_bytes()
                .expect("failed to convert to bytes")
                .try_into()
                .expect("failed to convert to sized array");
            let key = self
                .signed
                .keys
                .iter()
                .find(|key| key.fingerprint_bytes().unwrap().as_slice() == key_id)
                .expect("failed to calculate fingerprint");
            result
                .insert(key_id, key.clone())
                .expect("failed to insert key");
        }
        Some(result)
    }

    fn verify_signature(key: &Self::Key, msg: &[u8], sig: &[u8]) -> Result<(), TufError> {
        verify(key, msg, sig).map_err(|_| TufError::InvalidSignature)
    }
}

impl TufRole for Root {
    const TYPE: RoleType = RoleType::Root;
}

/// Verify that the new root is valid given the old root. Returns the new root if successful.
pub(crate) fn update_root_step<'a, 'b>(
    old_root: &SignedRef<'b, RootRef<'b>>,
    new_root: &'a [u8],
) -> Result<SignedRef<'a, RootRef<'a>>, TufError> {
    let next_root = SignedRef::<RootRef>::from_der(new_root).expect("failed to parse next root");
    // verify signatures
    // FIXME: old_root does not know the signatures from the new root and therefore cannot verify it.
    old_root.verify_root(&next_root)?;
    next_root.verify_role(&next_root)?;
    // check for a rollback attack (5.3.5)
    if next_root.version() != old_root.version().saturating_add(1) && old_root != &next_root {
        return Err(InvalidNewVersionNumber);
    }
    Ok(next_root)
}

/// Refer to the [TUF specification section on updating the root role](https://theupdateframework.github.io/specification/latest/#update-root) for more information
pub fn update_root<S, T>(
    remote: &mut T,
    storage: &mut S,
    max_fetches: u32,
    update_start: &UtcTime,
) -> Result<(), TufError>
where
    S: TufStorage,
    T: TufTransport,
{
    let mut fetches_left = max_fetches;
    //let mut new_root_buf = [0u8; 8096];

    let mut buf = [0u8; 2048];
    let initial_root = storage.current_root_copy(&mut buf);
    let initial_root_decoded = SignedRef::<RootRef>::decode_role(initial_root)?;
    let next_version = NonZeroU64::new(initial_root_decoded.signed.version as u64 + 1)
        .ok_or(TufError::InternalError)?;
    loop {
        if fetches_left == 0 {
            break;
        }
        let mut buf = [0u8; 2048];
        let Ok(next_root) = remote.fetch_root(next_version, &mut buf) else {
            break;
        };
        fetches_left -= 1;
        let current_root = storage
            .current_uncommitted_root()
            .and_then(|root| SignedRef::<RootRef>::decode_role(root).ok())
            .unwrap_or(initial_root_decoded.clone());
        update_root_step(&current_root, next_root)?;
        storage.persist_root(next_root)?;
    }

    let Some(new_root) = storage.current_uncommitted_root() else {
        // assume no new root
        return Ok(());
    };
    let new_root = SignedRef::<RootRef>::decode_role(new_root)?;
    if &new_root.expires() < update_start {
        return Err(ExpiredRootFile);
    }
    // delete timestamp or snapshot metadata when keys are rotated (5.3.11)
    let delete_timestamp =
        if let Some(timestamp_keys_old) = initial_root_decoded.role_keys(RoleType::Timestamp) {
            let timestamp_keys_new = new_root
                .role_keys(RoleType::Timestamp)
                .ok_or(MissingTimestampKeys)?;

            timestamp_keys_new
                .into_iter()
                .any(|(key_id, _)| !timestamp_keys_old.contains_key(&key_id))
        } else {
            false
        };
    let delete_snapshot =
        if let Some(snapshot_keys_old) = initial_root_decoded.role_keys(RoleType::Snapshot) {
            let snapshot_keys_new = new_root
                .role_keys(RoleType::Snapshot)
                .ok_or(MissingSnapshotKeys)?;

            snapshot_keys_new
                .into_iter()
                .any(|(key_id, _)| !snapshot_keys_old.contains_key(&key_id))
        } else {
            false
        };
    // this is handled here because of borrowing rules
    if delete_timestamp {
        storage.delete_timestamp_metadata();
    };
    if delete_snapshot {
        storage.delete_snapshot_metadata();
    };

    storage.commit_root()
}

/// Refer to the [TUF specification section on updating the root role](https://theupdateframework.github.io/specification/latest/#update-root) for more information
#[cfg(feature = "async")]
pub async fn update_root_async<S, T>(
    remote: &mut T,
    storage: &mut S,
    max_fetches: u32,
    update_start: &UtcTime,
) -> Result<(), TufError>
where
    S: TufStorage,
    T: TufTransportAsync,
{
    let mut fetches_left = max_fetches;
    //let mut new_root_buf = [0u8; 8096];

    let mut buf = [0u8; 2048];
    let initial_root = storage.current_root_copy(&mut buf);
    let initial_root_decoded = SignedRef::<RootRef>::decode_role(initial_root)?;
    let next_version = NonZeroU64::new(initial_root_decoded.signed.version as u64 + 1)
        .ok_or(TufError::InternalError)?;
    loop {
        if fetches_left == 0 {
            break;
        }
        let mut buf = [0u8; 2048];
        let Ok(next_root) = remote.fetch_root(next_version, &mut buf).await else {
            break;
        };
        fetches_left -= 1;
        let current_root = storage
            .current_uncommitted_root()
            .and_then(|root| SignedRef::<RootRef>::decode_role(root).ok())
            .unwrap_or(initial_root_decoded.clone());
        update_root_step(&current_root, next_root)?;
        storage.persist_root(next_root)?;
    }

    let Some(new_root) = storage.current_uncommitted_root() else {
        // assume no new root
        return Ok(());
    };
    let new_root = SignedRef::<RootRef>::decode_role(new_root)?;
    if &new_root.expires() < update_start {
        return Err(ExpiredRootFile);
    }
    // delete timestamp or snapshot metadata when keys are rotated (5.3.11)
    let delete_timestamp =
        if let Some(timestamp_keys_old) = initial_root_decoded.role_keys(RoleType::Timestamp) {
            let timestamp_keys_new = new_root
                .role_keys(RoleType::Timestamp)
                .ok_or(MissingTimestampKeys)?;

            timestamp_keys_new
                .into_iter()
                .any(|(key_id, _)| !timestamp_keys_old.contains_key(&key_id))
        } else {
            false
        };
    let delete_snapshot =
        if let Some(snapshot_keys_old) = initial_root_decoded.role_keys(RoleType::Snapshot) {
            let snapshot_keys_new = new_root
                .role_keys(RoleType::Snapshot)
                .ok_or(MissingSnapshotKeys)?;

            snapshot_keys_new
                .into_iter()
                .any(|(key_id, _)| !snapshot_keys_old.contains_key(&key_id))
        } else {
            false
        };
    // this is handled here because of borrowing rules
    if delete_timestamp {
        storage.delete_timestamp_metadata();
    };
    if delete_snapshot {
        storage.delete_snapshot_metadata();
    };

    storage.commit_root()
}

#[cfg(test)]
mod test {
    use crate::builder::RootBuilder;
    use crate::utils::spki_from_signing_key;
    use alloc::vec;
    use der::asn1::BitString;
    use der::{Decode, Encode};
    use ed25519_dalek::SigningKey;
    use rand_core::OsRng;
    use tuf_no_std_common::crypto::sign::RawSignature;
    use tuf_no_std_der::{Signed, SignedRef};

    use crate::role::root::{update_root_step, TufRoot};
    use der::referenced::OwnedToRef;
    use ed25519::Signature;
    use tuf_no_std_common::crypto::sign::SigningKey::Ed25519Dalek;
    use tuf_no_std_der::root::RootRef;

    #[test]
    fn test_root_update_step_valid() {
        let mut csprng = OsRng;

        let root_key_old = Ed25519Dalek(SigningKey::generate(&mut csprng));
        let root_pub_spki = root_key_old.as_spki().unwrap();

        let old_root = RootBuilder::default()
            .with_role_and_key("root", &[root_pub_spki], 1)
            .with_expiration_utc(2030, 1, 1, 0, 0, 0)
            .with_version(1)
            .build();

        let signed_old = Signed::from_signed(old_root, &[root_key_old.clone()]).unwrap();

        let root_key_new = Ed25519Dalek(SigningKey::generate(&mut csprng));
        let root_pub_spki = root_key_new.as_spki().unwrap();

        let root_new = RootBuilder::default()
            .with_role_and_key("root", &[root_pub_spki], 1)
            .with_expiration_utc(2030, 1, 1, 0, 0, 0)
            .with_version(2)
            .build();

        let signed_new = Signed::from_signed(root_new, &[root_key_old, root_key_new]).unwrap();
        let signed_new = signed_new.to_der().unwrap();
        update_root_step(&signed_old.owned_to_ref(), &signed_new).expect("failed to verify");
    }

    /// Test if using the same root again is accepted.
    #[test]
    fn test_root_update_step_valid_self() {
        let mut csprng = OsRng;

        let root_key_old = Ed25519Dalek(SigningKey::generate(&mut csprng));
        let root_pub_spki = spki_from_signing_key(&root_key_old);

        let old_root = RootBuilder::default()
            .with_role_and_key("root", &[root_pub_spki], 1)
            .with_expiration_utc(2030, 1, 1, 0, 0, 0)
            .with_version(1)
            .build();

        let signed_old = Signed::from_signed(old_root, &[root_key_old.clone()]).unwrap();

        update_root_step(
            &signed_old.owned_to_ref(),
            signed_old.to_der().unwrap().as_slice(),
        )
        .expect("failed to verify");
    }

    #[test]
    fn test_root_update_step_invalid_version_too_low() {
        let mut csprng = OsRng;

        let root_key_old = Ed25519Dalek(SigningKey::generate(&mut csprng));
        let root_pub_spki = spki_from_signing_key(&root_key_old);

        let old_root = RootBuilder::default()
            .with_role_and_key("root", &[root_pub_spki], 1)
            .with_expiration_utc(2030, 1, 1, 0, 0, 0)
            .with_version(1)
            .build();

        let signed_old = Signed::from_signed(old_root, &[root_key_old.clone()]).unwrap();

        let root_key_new = Ed25519Dalek(SigningKey::generate(&mut csprng));
        let root_pub_spki = spki_from_signing_key(&root_key_new);

        let root_new = RootBuilder::default()
            .with_role_and_key("root", &[root_pub_spki], 1)
            .with_expiration_utc(2030, 1, 1, 0, 0, 0)
            .with_version(1)
            .build();

        let signed_new = Signed::from_signed(root_new, &[root_key_old, root_key_new]).unwrap();
        let signed_new = signed_new.to_der().unwrap();
        update_root_step(&signed_old.owned_to_ref(), &signed_new)
            .expect_err("this should not be accepted");
    }

    #[test]
    fn test_root_update_step_threshold_not_reached() {
        let mut csprng = OsRng;

        let root_key_old_1 = Ed25519Dalek(SigningKey::generate(&mut csprng));
        let root_pub_spki_1 = spki_from_signing_key(&root_key_old_1);

        let root_key_old_2 = Ed25519Dalek(SigningKey::generate(&mut csprng));
        let root_pub_spki_2 = spki_from_signing_key(&root_key_old_2);

        let old_root = RootBuilder::default()
            .with_role_and_key("root", &[root_pub_spki_1, root_pub_spki_2], 2)
            .with_expiration_utc(2030, 1, 1, 0, 0, 0)
            .with_version(1)
            .build();

        let signed_old =
            Signed::from_signed(old_root, &[root_key_old_1.clone(), root_key_old_2.clone()])
                .unwrap();

        let root_key_new_1 = Ed25519Dalek(SigningKey::generate(&mut csprng));
        let root_pub_spki_1 = spki_from_signing_key(&root_key_new_1);

        let root_key_new_2 = Ed25519Dalek(SigningKey::generate(&mut csprng));
        let root_pub_spki_2 = spki_from_signing_key(&root_key_new_2);

        let root_new = RootBuilder::default()
            .with_role_and_key("root", &[root_pub_spki_1, root_pub_spki_2], 2)
            .with_expiration_utc(2030, 1, 1, 0, 0, 0)
            .with_version(2)
            .build();

        // Case: threshold not reached for new root
        let signed_new = Signed::from_signed(
            root_new.clone(),
            &[
                root_key_old_1.clone(),
                root_key_old_2,
                root_key_new_1.clone(),
            ],
        )
        .unwrap();
        let signed_new = signed_new.to_der().unwrap();
        update_root_step(&signed_old.owned_to_ref(), &signed_new)
            .expect_err("accepted root where new file does not meet threshold");

        // Case: threshold not reached for old root
        let signed_new = Signed::from_signed(
            root_new.clone(),
            &[
                root_key_old_1.clone(),
                root_key_new_1.clone(),
                root_key_new_2.clone(),
            ],
        )
        .unwrap();
        let signed_new = signed_new.to_der().unwrap();
        update_root_step(&signed_old.owned_to_ref(), &signed_new)
            .expect_err("accepted root where new file does not meet threshold");

        // Case: keys are reused
        let signed_new = Signed::from_signed(
            root_new,
            &[
                root_key_old_1.clone(),
                root_key_old_1.clone(),
                root_key_new_1.clone(),
                root_key_new_1.clone(),
            ],
        )
        .unwrap();
        let signed_new = signed_new.to_der().unwrap();
        update_root_step(&signed_old.owned_to_ref(), &signed_new)
            .expect_err("accepted root where signing keys contributed multiple signatures");
    }

    #[test]
    fn test_root_update_step_invald_version_too_high() {
        let mut csprng = OsRng;

        let root_key_old = Ed25519Dalek(SigningKey::generate(&mut csprng));
        let root_pub_spki = spki_from_signing_key(&root_key_old);

        let old_root = RootBuilder::default()
            .with_role_and_key("root", &[root_pub_spki], 1)
            .with_expiration_utc(2030, 1, 1, 0, 0, 0)
            .with_version(1)
            .build();

        let signed_old = Signed::from_signed(old_root, &[root_key_old.clone()]).unwrap();

        let root_key_new = Ed25519Dalek(SigningKey::generate(&mut csprng));
        let root_pub_spki = spki_from_signing_key(&root_key_new);

        let root_new = RootBuilder::default()
            .with_role_and_key("root", &[root_pub_spki], 1)
            .with_expiration_utc(2030, 1, 1, 0, 0, 0)
            .with_version(1)
            .build();

        let signed_new = Signed::from_signed(root_new, &[root_key_old, root_key_new]).unwrap();
        let signed_new = signed_new.to_der().unwrap();
        update_root_step(&signed_old.owned_to_ref(), &signed_new)
            .expect_err("this should not be accepted");
    }

    /// Tests for failure when the new root is signed by a random key instead of the new key.
    #[test]
    fn test_root_update_step_invald_sig() {
        let mut csprng = OsRng;

        let root_key_old = Ed25519Dalek(SigningKey::generate(&mut csprng));
        let root_pub_spki = spki_from_signing_key(&root_key_old);

        let old_root = RootBuilder::default()
            .with_role_and_key("root", &[root_pub_spki], 1)
            .with_expiration_utc(2030, 1, 1, 0, 0, 0)
            .with_version(1)
            .build();

        let signed_old = Signed::from_signed(old_root, &[root_key_old.clone()]).unwrap();

        let root_key_new = Ed25519Dalek(SigningKey::generate(&mut csprng));
        let root_pub_spki = spki_from_signing_key(&root_key_new);

        let root_new = RootBuilder::default()
            .with_role_and_key("root", &[root_pub_spki], 1)
            .with_expiration_utc(2030, 1, 1, 0, 0, 0)
            .with_version(2)
            .build();

        let root_key_random = Ed25519Dalek(SigningKey::generate(&mut csprng));

        let signed_new = Signed::from_signed(root_new, &[root_key_old, root_key_random]).unwrap();
        let signed_new = signed_new.to_der().unwrap();
        update_root_step(&signed_old.owned_to_ref(), &signed_new).expect_err("expected failure");
    }

    #[test]
    fn test_root_update_step_invald_duplicate_sig_old_root() {
        let mut csprng = OsRng;

        let root_key_old = Ed25519Dalek(SigningKey::generate(&mut csprng));
        let root_pub_spki = spki_from_signing_key(&root_key_old);

        let old_root = RootBuilder::default()
            .with_role_and_key("root", &[root_pub_spki], 1)
            .with_expiration_utc(2030, 1, 1, 0, 0, 0)
            .with_version(1)
            .build();

        let signed_old = Signed::from_signed(old_root, &[root_key_old.clone()]).unwrap();

        let root_key_new = Ed25519Dalek(SigningKey::generate(&mut csprng));
        let root_pub_spki = spki_from_signing_key(&root_key_new);

        let root_new = RootBuilder::default()
            .with_role_and_key("root", &[root_pub_spki], 1)
            .with_expiration_utc(2030, 1, 1, 0, 0, 0)
            .with_version(2)
            .build();

        let signed_new =
            Signed::from_signed(root_new, &[root_key_old.clone(), root_key_old.clone()]).unwrap();
        let signed_new = signed_new.to_der().unwrap();
        update_root_step(&signed_old.owned_to_ref(), &signed_new).expect_err("expected failure");
    }

    /// Tests if a root is accepted despite the previous root not having signed it.
    #[test]
    fn test_root_update_step_invalid_no_sig_old_root() {
        let mut csprng = OsRng;

        let root_key_old = Ed25519Dalek(SigningKey::generate(&mut csprng));
        let root_pub_spki = spki_from_signing_key(&root_key_old);

        let old_root = RootBuilder::default()
            .with_role_and_key("root", &[root_pub_spki], 1)
            .with_expiration_utc(2030, 1, 1, 0, 0, 0)
            .with_version(1)
            .build();

        let signed_old = Signed::from_signed(old_root, &[root_key_old.clone()]).unwrap();

        let root_key_new = Ed25519Dalek(SigningKey::generate(&mut csprng));
        let root_pub_spki = spki_from_signing_key(&root_key_new);

        let root_new = RootBuilder::default()
            .with_role_and_key("root", &[root_pub_spki], 1)
            .with_expiration_utc(2030, 1, 1, 0, 0, 0)
            .with_version(2)
            .build();

        let signed_new = Signed::from_signed(root_new, &[root_key_new]).unwrap();
        let signed_new = signed_new.to_der().unwrap();
        update_root_step(&signed_old.owned_to_ref(), &signed_new).expect_err("expected failure");
    }

    /// Tests if a root is accepted despite the new root not having signed it.
    #[test]
    fn test_root_update_step_invalid_no_sig_new_root() {
        let mut csprng = OsRng;

        let root_key_old = Ed25519Dalek(SigningKey::generate(&mut csprng));
        let root_pub_spki = spki_from_signing_key(&root_key_old);

        let old_root = RootBuilder::default()
            .with_role_and_key("root", &[root_pub_spki], 1)
            .with_expiration_utc(2030, 1, 1, 0, 0, 0)
            .with_version(1)
            .build();

        let signed_old = Signed::from_signed(old_root, &[root_key_old.clone()]).unwrap();

        let root_key_new = Ed25519Dalek(SigningKey::generate(&mut csprng));
        let root_pub_spki = spki_from_signing_key(&root_key_new);

        let root_new = RootBuilder::default()
            .with_role_and_key("root", &[root_pub_spki], 1)
            .with_expiration_utc(2030, 1, 1, 0, 0, 0)
            .with_version(2)
            .build();

        let signed_new = Signed::from_signed(root_new, &[root_key_old]).unwrap();
        let signed_new = signed_new.to_der().unwrap();
        update_root_step(&signed_old.owned_to_ref(), &signed_new).expect_err("expected failure");
    }

    /// Tests if a root is accepted despite no root not having signed it.
    #[test]
    fn test_root_update_step_invalid_no_sig() {
        let mut csprng = OsRng;

        let root_key_old = Ed25519Dalek(SigningKey::generate(&mut csprng));
        let root_pub_spki = spki_from_signing_key(&root_key_old);

        let old_root = RootBuilder::default()
            .with_role_and_key("root", &[root_pub_spki], 1)
            .with_expiration_utc(2030, 1, 1, 0, 0, 0)
            .with_version(1)
            .build();

        let signed_old = Signed::from_signed(old_root, &[root_key_old.clone()]).unwrap();

        let root_key_new = Ed25519Dalek(SigningKey::generate(&mut csprng));
        let root_pub_spki = spki_from_signing_key(&root_key_new);

        let root_new = RootBuilder::default()
            .with_role_and_key("root", &[root_pub_spki], 1)
            .with_expiration_utc(2030, 1, 1, 0, 0, 0)
            .with_version(2)
            .build();

        let signed_new = Signed::from_signed(root_new, &[]).unwrap();
        let signed_new = signed_new.to_der().unwrap();
        update_root_step(&signed_old.owned_to_ref(), &signed_new).expect_err("expected failure");
    }

    #[test]
    fn test_root() {
        let mut csprng = OsRng;

        let root_key = Ed25519Dalek(SigningKey::generate(&mut csprng));
        let root_pub_spki = spki_from_signing_key(&root_key);
        let root_key_id = root_pub_spki.fingerprint_bytes().unwrap();

        let timestamp_key = Ed25519Dalek(SigningKey::generate(&mut csprng));
        let timestamp_pub_spki = spki_from_signing_key(&timestamp_key);

        let snapshot_key = Ed25519Dalek(SigningKey::generate(&mut csprng));
        let snapshot_pub_spki = spki_from_signing_key(&snapshot_key);

        let targets_key = Ed25519Dalek(SigningKey::generate(&mut csprng));
        let targets_pub_spki = spki_from_signing_key(&targets_key);

        let root = RootBuilder::default()
            .consistent_snapshot(false)
            .with_expiration_utc(2030, 1, 1, 0, 0, 0)
            .with_role_and_key("root", &[root_pub_spki], 1)
            .with_role_and_key("targets", &[targets_pub_spki], 1)
            .with_role_and_key("timestamp", &[timestamp_pub_spki], 1)
            .with_role_and_key("snapshot", &[snapshot_pub_spki], 1)
            .build();

        let encoded_root = root.to_der().unwrap();
        let RawSignature::Ed25519Dalek(signature) = root_key.sign(&encoded_root).unwrap() else {
            unreachable!()
        };
        let signature = tuf_no_std_der::Signature {
            keyid: BitString::from_bytes(root_key_id.as_slice()).unwrap(),
            sig: BitString::from_bytes(&signature.to_bytes()).unwrap(),
        };
        let signed = Signed {
            signed: root,
            signatures: vec![signature],
            _phantom: Default::default(),
        };
        let decoded_root: RootRef = Decode::from_der(&encoded_root).unwrap();
        let Ed25519Dalek(root_key) = root_key else {
            unreachable!()
        };
        root_key
            .verify(
                &decoded_root.to_der().unwrap(),
                &Signature::from_bytes(
                    signed.signatures[0]
                        .sig
                        .as_bytes()
                        .unwrap()
                        .try_into()
                        .unwrap(),
                ),
            )
            .unwrap();
        let signed = signed.owned_to_ref();
        let decoded_root = SignedRef {
            signatures: signed.signatures.clone(),
            signed: decoded_root,
        };
        decoded_root.verify_role(&signed).unwrap();
    }

    #[cfg(test)]
    mod test_update_root {
        use crate::builder::RootBuilder;
        use crate::utils::{MockStorage, MockTransport};
        use alloc::vec;
        use core::num::NonZeroU64;
        use der::asn1::UtcTime;
        use der::{DateTime, Encode};
        use ed25519_dalek::SigningKey;
        use rand_core::OsRng;
        use tuf_no_std_common::crypto::sign::SigningKey::Ed25519Dalek;
        use tuf_no_std_der::Signed;

        use crate::role::root::{update_root, update_root_async};

        use super::spki_from_signing_key;

        #[test]
        fn test_update_root() {
            let mut csprng = OsRng;

            let old_root_key = Ed25519Dalek(SigningKey::generate(&mut csprng));

            let root_pub_spki = spki_from_signing_key(&old_root_key);

            let old_root = RootBuilder::default()
                .with_role_and_key("root", &[root_pub_spki], 1)
                .with_expiration_utc(2023, 1, 1, 1, 1, 1)
                .with_version(1)
                .build();

            let signing_keys = vec![old_root_key.clone()];
            let signed_old = Signed::from_signed(old_root, &signing_keys).unwrap();
            let root_key_new = Ed25519Dalek(SigningKey::generate(&mut csprng));

            let root_pub_spki = spki_from_signing_key(&root_key_new);

            let root_new = RootBuilder::default()
                .with_role_and_key("root", &[root_pub_spki], 1)
                .with_expiration_utc(2023, 1, 1, 1, 1, 1)
                .with_version(2)
                .build();

            let signing_keys = vec![root_key_new, old_root_key];
            let signed_new = Signed::from_signed(root_new, &signing_keys).unwrap();
            //eprintln!("{signed_new:#?}");
            let signed_new = signed_new.to_der();
            let signed_new = signed_new.as_ref().unwrap().as_slice();
            let mut transport = MockTransport::<_, &[u8]> {
                roots: heapless::FnvIndexMap::from_iter([
                    (NonZeroU64::new(1).unwrap(), signed_old.to_der().unwrap()),
                    (NonZeroU64::new(2).unwrap(), signed_new.to_vec()),
                ]),
                timestamp: vec![],
                snapshot: vec![],
                targets: vec![],
                target_files: Default::default(),
            };
            let mut storage = MockStorage {
                root: signed_old.to_der().unwrap(),
                uncommitted_root: None,
                timestamp: None,
                snapshot: None,
                targets: None,
            };
            update_root(
                &mut transport,
                &mut storage,
                1,
                &UtcTime::from_date_time(DateTime::new(2023, 1, 1, 1, 1, 1).unwrap()).unwrap(),
            )
            .expect("rejected correct update");
            let mut storage = MockStorage {
                root: signed_old.to_der().unwrap(),
                uncommitted_root: None,
                timestamp: None,
                snapshot: None,
                targets: None,
            };
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(async {
                    update_root_async(
                        &mut transport,
                        &mut storage,
                        1,
                        &UtcTime::from_date_time(DateTime::new(2023, 1, 1, 1, 1, 1).unwrap())
                            .unwrap(),
                    )
                    .await
                    .expect("rejected correct update");
                });
        }

        #[test]
        fn test_update_root_expired() {
            let mut csprng = OsRng;

            let old_root_key = Ed25519Dalek(SigningKey::generate(&mut csprng));

            let root_pub_spki = spki_from_signing_key(&old_root_key);

            let old_root = RootBuilder::default()
                .with_role_and_key("root", &[root_pub_spki], 1)
                .with_expiration_utc(2023, 1, 1, 1, 1, 1)
                .with_version(1)
                .build();

            let signing_keys = vec![old_root_key.clone()];
            let signed_old = Signed::from_signed(old_root, &signing_keys).unwrap();
            let root_key_new = Ed25519Dalek(SigningKey::generate(&mut csprng));

            let root_pub_spki = spki_from_signing_key(&root_key_new);

            let root_new = RootBuilder::default()
                .with_role_and_key("root", &[root_pub_spki], 1)
                .with_expiration_utc(2000, 1, 1, 1, 1, 1)
                .with_version(2)
                .build();

            let signing_keys = vec![root_key_new, old_root_key];
            let signed_new = Signed::from_signed(root_new, &signing_keys).unwrap();
            //eprintln!("{signed_new:#?}");
            let signed_new = signed_new.to_der();
            let signed_new = signed_new.as_ref().unwrap().as_slice();
            let mut transport = MockTransport::<_, &[u8]> {
                roots: heapless::FnvIndexMap::from_iter([
                    (NonZeroU64::new(1).unwrap(), signed_old.to_der().unwrap()),
                    (NonZeroU64::new(2).unwrap(), signed_new.to_vec()),
                ]),
                timestamp: vec![],
                snapshot: vec![],
                targets: vec![],
                target_files: Default::default(),
            };
            let mut storage = MockStorage {
                root: signed_old.to_der().unwrap(),
                uncommitted_root: None,
                timestamp: None,
                snapshot: None,
                targets: None,
            };
            update_root(
                &mut transport,
                &mut storage,
                1,
                &UtcTime::from_date_time(DateTime::new(2023, 1, 1, 1, 1, 1).unwrap()).unwrap(),
            )
            .expect_err("accepted expired root");

            let mut storage = MockStorage {
                root: signed_old.to_der().unwrap(),
                uncommitted_root: None,
                timestamp: None,
                snapshot: None,
                targets: None,
            };
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(async {
                    update_root_async(
                        &mut transport,
                        &mut storage,
                        1,
                        &UtcTime::from_date_time(DateTime::new(2023, 1, 1, 1, 1, 1).unwrap())
                            .unwrap(),
                    )
                    .await
                    .expect_err("accepted expired root");
                });
        }
        #[test]
        fn test_update_root_role_key_rotation() {
            let mut csprng = OsRng;

            let old_root_key = Ed25519Dalek(SigningKey::generate(&mut csprng));

            let root_pub_spki = spki_from_signing_key(&old_root_key);
            let ts_key = Ed25519Dalek(SigningKey::generate(&mut csprng));
            let ts_pub_spki = spki_from_signing_key(&ts_key);
            let snap_key = Ed25519Dalek(SigningKey::generate(&mut csprng));
            let snap_pub_spki = spki_from_signing_key(&snap_key);

            let old_root = RootBuilder::default()
                .with_role_and_key("root", &[root_pub_spki], 1)
                .with_role_and_key("snapshot", &[snap_pub_spki], 1)
                .with_role_and_key("timestamp", &[ts_pub_spki], 1)
                .with_expiration_utc(2023, 1, 1, 1, 1, 1)
                .with_version(1)
                .build();

            let signing_keys = vec![old_root_key.clone()];
            let signed_old = Signed::from_signed(old_root, &signing_keys).unwrap();
            let root_key_new = Ed25519Dalek(SigningKey::generate(&mut csprng));

            let root_pub_spki = spki_from_signing_key(&root_key_new);

            let ts_key = Ed25519Dalek(SigningKey::generate(&mut csprng));
            let ts_pub_spki = spki_from_signing_key(&ts_key);
            let snap_key = Ed25519Dalek(SigningKey::generate(&mut csprng));
            let snap_pub_spki = spki_from_signing_key(&snap_key);

            let root_new = RootBuilder::default()
                .with_role_and_key("root", &[root_pub_spki], 1)
                .with_role_and_key("snapshot", &[snap_pub_spki], 1)
                .with_role_and_key("timestamp", &[ts_pub_spki], 1)
                .with_expiration_utc(2023, 1, 1, 1, 1, 1)
                .with_version(2)
                .build();

            let signing_keys = vec![root_key_new, old_root_key];
            let signed_new = Signed::from_signed(root_new, &signing_keys).unwrap();
            //eprintln!("{signed_new:#?}");
            let signed_new = signed_new.to_der();
            let signed_new = signed_new.as_ref().unwrap().as_slice();
            let mut transport = MockTransport::<_, &[u8]> {
                roots: heapless::FnvIndexMap::from_iter([
                    (NonZeroU64::new(1).unwrap(), signed_old.to_der().unwrap()),
                    (NonZeroU64::new(2).unwrap(), signed_new.to_vec()),
                ]),
                timestamp: vec![],
                snapshot: vec![],
                targets: vec![],
                target_files: Default::default(),
            };
            let mut storage = MockStorage {
                root: signed_old.to_der().unwrap(),
                uncommitted_root: None,
                timestamp: Some(Default::default()),
                snapshot: Some(Default::default()),
                targets: None,
            };
            assert!(
                storage.snapshot.is_some(),
                "likely implementation error within the test"
            );
            assert!(
                storage.timestamp.is_some(),
                "likely implementation error within the test"
            );
            update_root(
                &mut transport,
                &mut storage,
                1,
                &UtcTime::from_date_time(DateTime::new(2023, 1, 1, 1, 1, 1).unwrap()).unwrap(),
            )
            .expect("rejected correct update");
            assert!(storage.snapshot.is_none(), "failed to delete snapshots");
            assert!(storage.timestamp.is_none(), "failed to delete timestamps");

            let mut storage = MockStorage {
                root: signed_old.to_der().unwrap(),
                uncommitted_root: None,
                timestamp: Some(Default::default()),
                snapshot: Some(Default::default()),
                targets: None,
            };
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(async {
                    update_root_async(
                        &mut transport,
                        &mut storage,
                        1,
                        &UtcTime::from_date_time(DateTime::new(2023, 1, 1, 1, 1, 1).unwrap())
                            .unwrap(),
                    )
                    .await
                    .expect("rejected correct update");
                });
            assert!(storage.snapshot.is_none(), "failed to delete snapshots");
            assert!(storage.timestamp.is_none(), "failed to delete timestamps");
        }
    }
}
