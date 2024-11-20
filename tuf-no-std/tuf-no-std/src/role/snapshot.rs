use crate::canonical::{EncodeCanonically, EncodingError};
use crate::role::root::TufRoot;
use crate::role::{DecodeRole, RoleUpdate, TufRole, TufSnapshot, TufTimestamp};
use der::asn1::{BitStringRef, UtcTime};
use der::Encode;
use tuf_no_std_common::crypto::verify_sha256;
use tuf_no_std_common::remote::TufTransport;
#[cfg(feature = "async")]
use tuf_no_std_common::remote::TufTransportAsync;
use tuf_no_std_common::storage::TufStorage;
use tuf_no_std_common::TufError::InvalidNewVersionNumber;
use tuf_no_std_common::{RoleType, TufError, Version};
use tuf_no_std_der::root::RootRef;
use tuf_no_std_der::snapshot::{Snapshot, SnapshotRef};
use tuf_no_std_der::timestamp::TimestampRef;
use tuf_no_std_der::SignedRef;
impl<'a> TufRole for SnapshotRef<'a> {
    const TYPE: RoleType = RoleType::Snapshot;
}

impl<'a> EncodeCanonically for SnapshotRef<'a> {
    fn encode_canonically<'o>(&self, out: &'o mut [u8]) -> Result<&'o [u8], EncodingError> {
        self.encode_to_slice(out)
            .map_err(|_| EncodingError::BufferTooSmall)
    }
}

impl EncodeCanonically for Snapshot {
    fn encode_canonically<'o>(&self, out: &'o mut [u8]) -> Result<&'o [u8], EncodingError> {
        self.encode_to_slice(out)
            .map_err(|_| EncodingError::BufferTooSmall)
    }
}

impl<'a> RoleUpdate for SnapshotRef<'a> {
    fn version(&self) -> Version {
        self.version
    }

    fn expires(&self) -> UtcTime {
        self.expires
    }
}

impl<'a> TufSnapshot for SnapshotRef<'a> {
    fn targets_hash(&self) -> [u8; 32] {
        self.meta
            .iter()
            .find(|f| f.metapath == BitStringRef::from_bytes(b"targets.der").unwrap())
            .and_then(|h| h.hashes.get(0))
            .and_then(|h| TryFrom::try_from(h.value.raw_bytes()).ok())
            .expect("failed to find hash")
    }

    fn targets_version(&self) -> Version {
        self.meta
            .iter()
            .find(|f| f.metapath == BitStringRef::from_bytes(b"targets.der").unwrap())
            .map(|h| h.version)
            .expect("failed to find metapath")
    }
}

fn verify_snapshot(
    root: &[u8],
    timestamp: &[u8],
    snapshot_new: &[u8],
    snapshot_old: Option<&[u8]>,
    update_start: &UtcTime,
) -> Result<(), TufError> {
    let root = SignedRef::<RootRef>::decode_role(root)?;
    let timestamp_decoded = SignedRef::<TimestampRef>::decode_role(timestamp)?;
    let snapshot_new_decoded = SignedRef::<SnapshotRef>::decode_role(snapshot_new)?;

    // 5.5.2
    verify_sha256(timestamp_decoded.snapshot_hash(), snapshot_new)
        .map_err(|_| TufError::InvalidHash)?;

    // 5.5.3
    root.verify_role(&snapshot_new_decoded)?;

    // 5.5.4
    if timestamp_decoded.snapshot_version() != snapshot_new_decoded.version() {
        return Err(InvalidNewVersionNumber);
    }
    // 5.5.5 Ensure every targets metadata file still exists
    //       and the old version numbers are less or equal to the old one.
    if let Some(snapshot_old) = snapshot_old {
        let snapshot_old = SignedRef::<SnapshotRef>::decode_role(snapshot_old)?;

        snapshot_old
            .signed
            .meta
            .iter()
            .all(|t_old| {
                snapshot_new_decoded
                    .signed
                    .meta
                    .iter()
                    .find(|t_new| t_new.metapath == t_old.metapath)
                    .map(|t_new| t_new.version >= t_old.version)
                    .unwrap_or(false)
            })
            .then_some(())
            .ok_or(TufError::InvalidTargetsInSnapshot)?;
    }
    if timestamp_decoded.snapshot_version() != snapshot_new_decoded.version() {
        return Err(TufError::InvalidNewVersionNumber);
    }

    if &snapshot_new_decoded.expires() < update_start {
        return Err(TufError::ExpiredSnapshotFile);
    }
    Ok(())
}

pub(crate) fn update_snapshot<S, T>(
    remote: &mut T,
    storage: &mut S,
    update_start: &UtcTime,
) -> Result<(), TufError>
where
    S: TufStorage,
    T: TufTransport,
{
    let current_root = storage.current_root();
    let timestamp = storage
        .current_timestamp()
        .ok_or(TufError::MissingTimestampFile)?;
    let snapshot_old = storage.current_snapshot();
    let mut buf = [0u8; 512];
    let snapshot_new = remote
        .fetch_snapshot(&mut buf)
        .map_err(|_| TufError::FetchError)?;
    verify_snapshot(
        current_root,
        timestamp,
        snapshot_new,
        snapshot_old,
        update_start,
    )?;
    storage.persist_snapshot(snapshot_new)?;
    Ok(())
}

#[cfg(feature = "async")]
pub async fn update_snapshot_async<S, T>(
    remote: &mut T,
    storage: &mut S,
    update_start: &UtcTime,
) -> Result<(), TufError>
where
    S: TufStorage,
    T: TufTransportAsync,
{
    let current_root = storage.current_root();
    let timestamp = storage
        .current_timestamp()
        .ok_or(TufError::MissingTimestampFile)?;
    let snapshot_old = storage.current_snapshot();
    let mut buf = [0u8; 512];
    let snapshot_new = remote
        .fetch_snapshot(&mut buf)
        .await
        .map_err(|_| TufError::FetchError)?;
    verify_snapshot(
        current_root,
        timestamp,
        snapshot_new,
        snapshot_old,
        update_start,
    )?;
    storage.persist_snapshot(snapshot_new)?;
    Ok(())
}

#[cfg(test)]
mod test {
    use core::num::NonZeroU64;

    use crate::builder::{RootBuilder, SnapshotBuilder, TargetsBuilder, TimestampBuilder};
    use crate::utils::{spki_from_signing_key, MockStorage, MockTransport};
    use der::asn1::BitString;
    use der::{DateTime, Encode};
    use ed25519_dalek::SigningKey;
    use rand_core::OsRng;
    use tuf_no_std_common::crypto::sign::SigningKey::Ed25519Dalek;
    use tuf_no_std_der::Signed;

    use super::{update_snapshot, verify_snapshot};

    #[test]
    fn test_verify_snapshot() {
        let mut csprng = OsRng;

        let root_key = Ed25519Dalek(SigningKey::generate(&mut csprng));
        let root_pub_spki = spki_from_signing_key(&root_key);

        let timestamp_key = Ed25519Dalek(SigningKey::generate(&mut csprng));
        let timestamp_pub_spki = spki_from_signing_key(&timestamp_key);

        let targets_key = Ed25519Dalek(SigningKey::generate(&mut csprng));
        let targets_pub_spki = spki_from_signing_key(&targets_key);

        let snapshot_key = Ed25519Dalek(SigningKey::generate(&mut csprng));
        let snapshot_pub_spki = spki_from_signing_key(&snapshot_key);

        let root = RootBuilder::default()
            .with_role_and_key("root", &[root_pub_spki], 1)
            .with_role_and_key("targets", &[targets_pub_spki], 1)
            .with_role_and_key("snapshot", &[snapshot_pub_spki], 1)
            .with_role_and_key("timestamp", &[timestamp_pub_spki], 1)
            .with_expiration_utc(2030, 1, 1, 0, 0, 0)
            .with_version(1)
            .build();

        let signed_root = Signed::from_signed(root, &[root_key]).unwrap();
        let targets = TargetsBuilder::default()
            .with_expiration_utc(2030, 1, 1, 0, 0, 0)
            .with_version(1)
            .build();
        let signed_targets = Signed::from_signed(targets, &[(targets_key.clone())]).unwrap();

        let snapshot = SnapshotBuilder::default()
            .with_expiration_utc(2030, 1, 1, 0, 0, 0)
            .with_version(1)
            .with_meta(b"targets.der", &signed_targets.to_der().unwrap(), 1)
            .build();
        let signed_snapshot =
            Signed::from_signed(snapshot.clone(), &[(snapshot_key.clone())]).unwrap();

        let timestamp = TimestampBuilder::default()
            .with_expiration_utc(2030, 1, 1, 0, 0, 0)
            .with_version(1)
            .with_snapshot("snapshot.der", &signed_snapshot)
            .build();
        let signed_timestamp = Signed::from_signed(timestamp, &[(timestamp_key.clone())]).unwrap();

        // Case: valid
        verify_snapshot(
            &signed_root.to_der().unwrap(),
            &signed_timestamp.to_der().unwrap(),
            &signed_snapshot.to_der().unwrap(),
            None,
            &DateTime::new(2023, 1, 1, 0, 0, 0)
                .unwrap()
                .try_into()
                .unwrap(),
        )
        .expect("failed to verify valid snapshot file");

        // Case: expired
        verify_snapshot(
            &signed_root.to_der().unwrap(),
            &signed_timestamp.to_der().unwrap(),
            &signed_snapshot.to_der().unwrap(),
            None,
            &DateTime::new(2040, 1, 1, 0, 0, 0)
                .unwrap()
                .try_into()
                .unwrap(),
        )
        .expect_err("accepted expired snapshot");

        // Case: mismatched hash
        let snapshot = SnapshotBuilder::default()
            .with_expiration_utc(2030, 1, 1, 0, 0, 0)
            .with_version(1)
            .with_meta(b"targets.der", &signed_targets.to_der().unwrap(), 1)
            .build();
        let signed_snapshot =
            Signed::from_signed(snapshot.clone(), &[(snapshot_key.clone())]).unwrap();

        let mut timestamp = TimestampBuilder::default()
            .with_expiration_utc(2030, 1, 1, 0, 0, 0)
            .with_version(1)
            .with_snapshot("snapshot.der", &signed_snapshot)
            .build();

        // modify hash
        timestamp.meta.hashes[0].value = BitString::from_bytes(&[0u8; 32]).unwrap();
        let signed_timestamp = Signed::from_signed(timestamp, &[(timestamp_key.clone())]).unwrap();

        verify_snapshot(
            &signed_root.to_der().unwrap(),
            &signed_timestamp.to_der().unwrap(),
            &signed_snapshot.to_der().unwrap(),
            None,
            &DateTime::new(2023, 1, 1, 0, 0, 0)
                .unwrap()
                .try_into()
                .unwrap(),
        )
        .expect_err("accepted snapshot with invalid hash");

        // Case: valid step
        let snapshot_old = SnapshotBuilder::default()
            .with_expiration_utc(2030, 1, 1, 0, 0, 0)
            .with_version(1)
            .with_meta(b"targets.der", &signed_targets.to_der().unwrap(), 1)
            .build();
        let signed_snapshot_old =
            Signed::from_signed(snapshot_old.clone(), &[(snapshot_key.clone())]).unwrap();

        let snapshot_new = SnapshotBuilder::default()
            .with_expiration_utc(2030, 1, 1, 0, 0, 0)
            .with_version(2)
            .with_meta(b"targets.der", &signed_targets.to_der().unwrap(), 1)
            .build();
        let signed_snapshot_new =
            Signed::from_signed(snapshot_new.clone(), &[(snapshot_key.clone())]).unwrap();

        let timestamp_new = TimestampBuilder::default()
            .with_expiration_utc(2030, 1, 1, 0, 0, 0)
            .with_version(1)
            .with_snapshot("snapshot.der", &signed_snapshot_new)
            .build();
        let signed_timestamp_new =
            Signed::from_signed(timestamp_new, &[(timestamp_key.clone())]).unwrap();

        verify_snapshot(
            &signed_root.to_der().unwrap(),
            &signed_timestamp_new.to_der().unwrap(),
            &signed_snapshot_new.to_der().unwrap(),
            Some(&signed_snapshot_old.to_der().unwrap()),
            &DateTime::new(2023, 1, 1, 0, 0, 0)
                .unwrap()
                .try_into()
                .unwrap(),
        )
        .expect("rejected valid snapshot");

        // Case: version number does not match timestamps file
        let snapshot_new = SnapshotBuilder::default()
            .with_expiration_utc(2030, 1, 1, 0, 0, 0)
            .with_version(1)
            .with_meta(b"targets.der", &signed_targets.to_der().unwrap(), 1)
            .build();
        let signed_snapshot_new =
            Signed::from_signed(snapshot_new.clone(), &[(snapshot_key.clone())]).unwrap();

        let mut timestamp_new = TimestampBuilder::default()
            .with_expiration_utc(2030, 1, 1, 0, 0, 0)
            .with_version(1)
            .with_snapshot("snapshot.der", &signed_snapshot_new)
            .build();
        // Modify version number in timestamp file
        timestamp_new.meta.version = 0;
        let signed_timestamp_new =
            Signed::from_signed(timestamp_new, &[(timestamp_key.clone())]).unwrap();

        verify_snapshot(
            &signed_root.to_der().unwrap(),
            &signed_timestamp_new.to_der().unwrap(),
            &signed_snapshot_new.to_der().unwrap(),
            None,
            &DateTime::new(2023, 1, 1, 0, 0, 0)
                .unwrap()
                .try_into()
                .unwrap(),
        )
        .expect_err("accepted snapshot file with lower version number");
    }

    #[test]
    fn test_verify_snapshot_threshold() {
        let mut csprng = OsRng;

        let root_key = Ed25519Dalek(SigningKey::generate(&mut csprng));
        let root_pub_spki = spki_from_signing_key(&root_key);

        let timestamp_key = Ed25519Dalek(SigningKey::generate(&mut csprng));
        let timestamp_pub_spki = spki_from_signing_key(&timestamp_key);

        let targets_key = Ed25519Dalek(SigningKey::generate(&mut csprng));
        let targets_pub_spki = spki_from_signing_key(&targets_key);

        let snapshot_key_1 = Ed25519Dalek(SigningKey::generate(&mut csprng));
        let snapshot_pub_spki_1 = spki_from_signing_key(&snapshot_key_1);
        let snapshot_key_2 = Ed25519Dalek(SigningKey::generate(&mut csprng));
        let snapshot_pub_spki_2 = spki_from_signing_key(&snapshot_key_2);

        let root = RootBuilder::default()
            .with_role_and_key("root", &[root_pub_spki], 1)
            .with_role_and_key("targets", &[targets_pub_spki], 1)
            .with_role_and_key("snapshot", &[snapshot_pub_spki_1, snapshot_pub_spki_2], 2)
            .with_role_and_key("timestamp", &[timestamp_pub_spki], 1)
            .with_expiration_utc(2030, 1, 1, 0, 0, 0)
            .with_version(1)
            .build();

        let signed_root = Signed::from_signed(root, &[root_key]).unwrap();
        let targets = TargetsBuilder::default()
            .with_expiration_utc(2030, 1, 1, 0, 0, 0)
            .with_version(1)
            .build();
        let signed_targets = Signed::from_signed(targets, &[(targets_key.clone())]).unwrap();

        let snapshot = SnapshotBuilder::default()
            .with_expiration_utc(2030, 1, 1, 0, 0, 0)
            .with_version(1)
            .with_meta(b"targets.der", &signed_targets.to_der().unwrap(), 1)
            .build();
        let signed_snapshot = Signed::from_signed(
            snapshot.clone(),
            &[snapshot_key_1.clone(), snapshot_key_2.clone()],
        )
        .unwrap();

        let timestamp = TimestampBuilder::default()
            .with_expiration_utc(2030, 1, 1, 0, 0, 0)
            .with_version(1)
            .with_snapshot("snapshot.der", &signed_snapshot)
            .build();
        let signed_timestamp = Signed::from_signed(timestamp, &[(timestamp_key.clone())]).unwrap();

        // Case: valid
        verify_snapshot(
            &signed_root.to_der().unwrap(),
            &signed_timestamp.to_der().unwrap(),
            &signed_snapshot.to_der().unwrap(),
            None,
            &DateTime::new(2023, 1, 1, 0, 0, 0)
                .unwrap()
                .try_into()
                .unwrap(),
        )
        .expect("failed to verify valid snapshot file");

        // Case: signing keys are reused
        let signed_snapshot = Signed::from_signed(
            snapshot.clone(),
            &[snapshot_key_2.clone(), snapshot_key_2.clone()],
        )
        .unwrap();

        let timestamp = TimestampBuilder::default()
            .with_expiration_utc(2030, 1, 1, 0, 0, 0)
            .with_version(1)
            .with_snapshot("snapshot.der", &signed_snapshot)
            .build();
        let signed_timestamp = Signed::from_signed(timestamp, &[(timestamp_key.clone())]).unwrap();

        // Case: valid
        verify_snapshot(
            &signed_root.to_der().unwrap(),
            &signed_timestamp.to_der().unwrap(),
            &signed_snapshot.to_der().unwrap(),
            None,
            &DateTime::new(2023, 1, 1, 0, 0, 0)
                .unwrap()
                .try_into()
                .unwrap(),
        )
        .expect_err("accepted snapshot file with reused keys");

        // Case: untrusted keys are used
        let signed_snapshot = Signed::from_signed(
            snapshot.clone(),
            &[
                Ed25519Dalek(SigningKey::generate(&mut csprng)),
                Ed25519Dalek(SigningKey::generate(&mut csprng)),
            ],
        )
        .unwrap();

        let timestamp = TimestampBuilder::default()
            .with_expiration_utc(2030, 1, 1, 0, 0, 0)
            .with_version(1)
            .with_snapshot("snapshot.der", &signed_snapshot)
            .build();
        let signed_timestamp = Signed::from_signed(timestamp, &[(timestamp_key.clone())]).unwrap();

        // Case: valid
        verify_snapshot(
            &signed_root.to_der().unwrap(),
            &signed_timestamp.to_der().unwrap(),
            &signed_snapshot.to_der().unwrap(),
            None,
            &DateTime::new(2023, 1, 1, 0, 0, 0)
                .unwrap()
                .try_into()
                .unwrap(),
        )
        .expect_err("accepted snapshot file with invalid signatures");
    }

    #[test]
    fn test_verify_snapshot_targets_metadata() {
        let mut csprng = OsRng;

        let root_key = Ed25519Dalek(SigningKey::generate(&mut csprng));
        let root_pub_spki = spki_from_signing_key(&root_key);

        let timestamp_key = Ed25519Dalek(SigningKey::generate(&mut csprng));
        let timestamp_pub_spki = spki_from_signing_key(&timestamp_key);

        let targets_key = Ed25519Dalek(SigningKey::generate(&mut csprng));
        let targets_pub_spki = spki_from_signing_key(&targets_key);

        let snapshot_key = Ed25519Dalek(SigningKey::generate(&mut csprng));
        let snapshot_pub_spki = spki_from_signing_key(&snapshot_key);

        let root = RootBuilder::default()
            .with_role_and_key("root", &[root_pub_spki], 1)
            .with_role_and_key("targets", &[targets_pub_spki], 1)
            .with_role_and_key("snapshot", &[snapshot_pub_spki], 1)
            .with_role_and_key("timestamp", &[timestamp_pub_spki], 1)
            .with_expiration_utc(2030, 1, 1, 0, 0, 0)
            .with_version(1)
            .build();

        let signed_root = Signed::from_signed(root, &[root_key]).unwrap();
        let targets = TargetsBuilder::default()
            .with_expiration_utc(2030, 1, 1, 0, 0, 0)
            .with_version(1)
            .build();
        let signed_targets = Signed::from_signed(targets, &[(targets_key.clone())]).unwrap();

        let snapshot_old = SnapshotBuilder::default()
            .with_expiration_utc(2030, 1, 1, 0, 0, 0)
            .with_version(1)
            .with_meta(b"targets.der", &signed_targets.to_der().unwrap(), 1)
            .build();
        let signed_snapshot_old =
            Signed::from_signed(snapshot_old.clone(), &[(snapshot_key.clone())]).unwrap();

        let snapshot_new = SnapshotBuilder::default()
            .with_expiration_utc(2030, 1, 1, 0, 0, 0)
            .with_version(2)
            .with_meta(b"targets.der", &signed_targets.to_der().unwrap(), 0)
            .build();
        let signed_snapshot_new =
            Signed::from_signed(snapshot_new.clone(), &[(snapshot_key.clone())]).unwrap();

        let timestamp = TimestampBuilder::default()
            .with_expiration_utc(2030, 1, 1, 0, 0, 0)
            .with_version(1)
            .with_snapshot("snapshot.der", &signed_snapshot_new)
            .build();
        let signed_timestamp = Signed::from_signed(timestamp, &[(timestamp_key.clone())]).unwrap();

        // Case: invalid version for target in new snapshot file
        verify_snapshot(
            &signed_root.to_der().unwrap(),
            &signed_timestamp.to_der().unwrap(),
            &signed_snapshot_new.to_der().unwrap(),
            Some(&signed_snapshot_old.to_der().unwrap()),
            &DateTime::new(2023, 1, 1, 0, 0, 0)
                .unwrap()
                .try_into()
                .unwrap(),
        )
        .expect_err("accepted snapshot file with invalid targets version number");

        let snapshot_old = SnapshotBuilder::default()
            .with_expiration_utc(2030, 1, 1, 0, 0, 0)
            .with_version(1)
            .with_meta(b"targets.der", &signed_targets.to_der().unwrap(), 1)
            .build();
        let signed_snapshot_old =
            Signed::from_signed(snapshot_old.clone(), &[(snapshot_key.clone())]).unwrap();

        let snapshot_new = SnapshotBuilder::default()
            .with_expiration_utc(2030, 1, 1, 0, 0, 0)
            .with_version(2)
            .build();
        let signed_snapshot_new =
            Signed::from_signed(snapshot_new.clone(), &[(snapshot_key.clone())]).unwrap();

        let timestamp = TimestampBuilder::default()
            .with_expiration_utc(2030, 1, 1, 0, 0, 0)
            .with_version(1)
            .with_snapshot("snapshot.der", &signed_snapshot_new)
            .build();
        let signed_timestamp = Signed::from_signed(timestamp, &[(timestamp_key.clone())]).unwrap();

        // Case: invalid version for target in new snapshot file
        verify_snapshot(
            &signed_root.to_der().unwrap(),
            &signed_timestamp.to_der().unwrap(),
            &signed_snapshot_new.to_der().unwrap(),
            Some(&signed_snapshot_old.to_der().unwrap()),
            &DateTime::new(2023, 1, 1, 0, 0, 0)
                .unwrap()
                .try_into()
                .unwrap(),
        )
        .expect_err("accepted snapshot file with missing targets metadata");
    }

    #[test]
    fn test_update_snapshot() {
        let mut csprng = OsRng;

        let root_key = Ed25519Dalek(SigningKey::generate(&mut csprng));
        let root_pub_spki = spki_from_signing_key(&root_key);

        let timestamp_key = Ed25519Dalek(SigningKey::generate(&mut csprng));
        let timestamp_pub_spki = spki_from_signing_key(&timestamp_key);

        let targets_key = Ed25519Dalek(SigningKey::generate(&mut csprng));
        let targets_pub_spki = spki_from_signing_key(&targets_key);

        let snapshot_key = Ed25519Dalek(SigningKey::generate(&mut csprng));
        let snapshot_pub_spki = spki_from_signing_key(&snapshot_key);

        let root = RootBuilder::default()
            .with_role_and_key("root", &[root_pub_spki], 1)
            .with_role_and_key("targets", &[targets_pub_spki], 1)
            .with_role_and_key("snapshot", &[snapshot_pub_spki], 1)
            .with_role_and_key("timestamp", &[timestamp_pub_spki], 1)
            .with_expiration_utc(2030, 1, 1, 0, 0, 0)
            .with_version(1)
            .build();

        let signed_root = Signed::from_signed(root, &[root_key]).unwrap();
        let root_encoded = signed_root.to_der().unwrap();
        let targets = TargetsBuilder::default()
            .with_expiration_utc(2030, 1, 1, 0, 0, 0)
            .with_version(1)
            .build();
        let signed_targets = Signed::from_signed(targets, &[(targets_key.clone())]).unwrap();
        let targets_encoded = signed_targets.to_der().unwrap();

        let snapshot = SnapshotBuilder::default()
            .with_expiration_utc(2030, 1, 1, 0, 0, 0)
            .with_version(1)
            .with_meta(b"targets.der", &signed_targets.to_der().unwrap(), 1)
            .build();
        let signed_snapshot =
            Signed::from_signed(snapshot.clone(), &[(snapshot_key.clone())]).unwrap();
        let snapshot_encoded = signed_snapshot.to_der().unwrap();

        let timestamp = TimestampBuilder::default()
            .with_expiration_utc(2030, 1, 1, 0, 0, 0)
            .with_version(1)
            .with_snapshot("snapshot.der", &signed_snapshot)
            .build();
        let signed_timestamp = Signed::from_signed(timestamp, &[(timestamp_key.clone())]).unwrap();
        let timestamp_encoded = signed_timestamp.to_der().unwrap();

        let mut transport = MockTransport::<_, &[u8]> {
            roots: heapless::FnvIndexMap::from_iter([(
                NonZeroU64::new(1).unwrap(),
                root_encoded.clone(),
            )]),
            timestamp: timestamp_encoded.clone(),
            snapshot: snapshot_encoded.clone(),
            targets: snapshot_encoded.clone(),
            target_files: Default::default(),
        };
        let storage = MockStorage {
            root: root_encoded.clone(),
            uncommitted_root: None,
            timestamp: Some(timestamp_encoded.clone()),
            snapshot: None,
            targets: Some(targets_encoded.clone()),
        };

        // Case: valid
        let mut storage_test = storage.clone();
        update_snapshot(
            &mut transport,
            &mut storage_test,
            &DateTime::new(2023, 1, 1, 0, 0, 0)
                .unwrap()
                .try_into()
                .unwrap(),
        )
        .expect("failed to verify snapshot file");
        assert_eq!(storage_test.root, root_encoded);
        assert_eq!(storage_test.timestamp, Some(timestamp_encoded.clone()));
        assert_eq!(storage_test.snapshot, Some(snapshot_encoded.clone()));
        assert_eq!(storage_test.targets, Some(targets_encoded.clone()));

        // Case: expired
        let mut storage_test = storage.clone();
        update_snapshot(
            &mut transport,
            &mut storage_test,
            &DateTime::new(2040, 1, 1, 0, 0, 0)
                .unwrap()
                .try_into()
                .unwrap(),
        )
        .expect_err("accepted expired snapshot file");
        assert_eq!(storage_test.root, root_encoded);
        assert_eq!(storage_test.timestamp, Some(timestamp_encoded.clone()));
        assert_eq!(storage_test.snapshot, None);
        assert_eq!(storage_test.targets, Some(targets_encoded.clone()));

        // Case: mismatched hash
        let snapshot = SnapshotBuilder::default()
            .with_expiration_utc(2030, 1, 1, 0, 0, 0)
            .with_version(1)
            .with_meta(b"targets.der", &signed_targets.to_der().unwrap(), 1)
            .build();
        let signed_snapshot =
            Signed::from_signed(snapshot.clone(), &[(snapshot_key.clone())]).unwrap();

        let mut timestamp = TimestampBuilder::default()
            .with_expiration_utc(2030, 1, 1, 0, 0, 0)
            .with_version(1)
            .with_snapshot("snapshot.der", &signed_snapshot)
            .build();

        // modify hash
        timestamp.meta.hashes[0].value = BitString::from_bytes(&[0u8; 32]).unwrap();
        let signed_timestamp = Signed::from_signed(timestamp, &[(timestamp_key.clone())]).unwrap();
        let timestamp_encoded = signed_timestamp.to_der().unwrap();

        let mut storage_test = storage.clone();
        storage_test.timestamp = Some(timestamp_encoded.clone());

        update_snapshot(
            &mut transport,
            &mut storage_test,
            &DateTime::new(2040, 1, 1, 0, 0, 0)
                .unwrap()
                .try_into()
                .unwrap(),
        )
        .expect_err("accepted snapshot with invalid hash");
        assert_eq!(storage_test.root, root_encoded);
        assert_eq!(storage_test.timestamp, Some(timestamp_encoded.clone()));
        assert_eq!(storage_test.snapshot, None);
        assert_eq!(storage_test.targets, Some(targets_encoded.clone()));

        // Case: valid step
        let snapshot_old = SnapshotBuilder::default()
            .with_expiration_utc(2030, 1, 1, 0, 0, 0)
            .with_version(1)
            .with_meta(b"targets.der", &signed_targets.to_der().unwrap(), 1)
            .build();
        let signed_snapshot_old =
            Signed::from_signed(snapshot_old.clone(), &[(snapshot_key.clone())]).unwrap();

        let snapshot_new = SnapshotBuilder::default()
            .with_expiration_utc(2030, 1, 1, 0, 0, 0)
            .with_version(2)
            .with_meta(b"targets.der", &signed_targets.to_der().unwrap(), 1)
            .build();
        let signed_snapshot_new =
            Signed::from_signed(snapshot_new.clone(), &[(snapshot_key.clone())]).unwrap();

        let timestamp_new = TimestampBuilder::default()
            .with_expiration_utc(2030, 1, 1, 0, 0, 0)
            .with_version(1)
            .with_snapshot("snapshot.der", &signed_snapshot_new)
            .build();
        let signed_timestamp =
            Signed::from_signed(timestamp_new, &[(timestamp_key.clone())]).unwrap();

        let timestamp_encoded = signed_timestamp.to_der().unwrap();
        let snapshot_encoded_old = signed_snapshot_old.to_der().unwrap();
        let snapshot_encoded_new = signed_snapshot_new.to_der().unwrap();

        let mut transport = MockTransport::<_, &[u8]> {
            roots: heapless::FnvIndexMap::from_iter([(
                NonZeroU64::new(1).unwrap(),
                root_encoded.clone(),
            )]),
            timestamp: timestamp_encoded.clone(),
            snapshot: snapshot_encoded_new.clone(),
            targets: snapshot_encoded.clone(),
            target_files: Default::default(),
        };
        let mut storage = MockStorage {
            root: root_encoded.clone(),
            uncommitted_root: None,
            timestamp: Some(timestamp_encoded.clone()),
            snapshot: Some(snapshot_encoded_old.clone()),
            targets: Some(targets_encoded.clone()),
        };
        update_snapshot(
            &mut transport,
            &mut storage,
            &DateTime::new(2023, 1, 1, 0, 0, 0)
                .unwrap()
                .try_into()
                .unwrap(),
        )
        .expect("rejected valid snapshot");
        assert_eq!(storage.root, root_encoded);
        assert_eq!(storage.timestamp, Some(timestamp_encoded.clone()));
        assert_eq!(storage.snapshot, Some(snapshot_encoded_new.clone()));
        assert_eq!(storage.targets, Some(targets_encoded.clone()));

        // Case: version number does not match timestamps file
        let snapshot_new = SnapshotBuilder::default()
            .with_expiration_utc(2030, 1, 1, 0, 0, 0)
            .with_version(1)
            .with_meta(b"targets.der", &signed_targets.to_der().unwrap(), 1)
            .build();
        let signed_snapshot_new =
            Signed::from_signed(snapshot_new.clone(), &[(snapshot_key.clone())]).unwrap();

        let mut timestamp_new = TimestampBuilder::default()
            .with_expiration_utc(2030, 1, 1, 0, 0, 0)
            .with_version(1)
            .with_snapshot("snapshot.der", &signed_snapshot_new)
            .build();
        // Modify version number in timestamp file
        timestamp_new.meta.version = 0;
        let signed_timestamp =
            Signed::from_signed(timestamp_new, &[(timestamp_key.clone())]).unwrap();

        let timestamp_encoded = signed_timestamp.to_der().unwrap();
        let snapshot_encoded_new = signed_snapshot_new.to_der().unwrap();

        let mut transport = MockTransport::<_, &[u8]> {
            roots: heapless::FnvIndexMap::from_iter([(
                NonZeroU64::new(1).unwrap(),
                root_encoded.clone(),
            )]),
            timestamp: timestamp_encoded.clone(),
            snapshot: snapshot_encoded_new.clone(),
            targets: snapshot_encoded.clone(),
            target_files: Default::default(),
        };
        let mut storage = MockStorage {
            root: root_encoded.clone(),
            uncommitted_root: None,
            timestamp: Some(timestamp_encoded.clone()),
            snapshot: Some(snapshot_encoded_old.clone()),
            targets: Some(targets_encoded.clone()),
        };
        update_snapshot(
            &mut transport,
            &mut storage,
            &DateTime::new(2023, 1, 1, 0, 0, 0)
                .unwrap()
                .try_into()
                .unwrap(),
        )
        .expect_err("accepted snapshot file with lower version number");
        assert_eq!(storage.root, root_encoded);
        assert_eq!(storage.timestamp, Some(timestamp_encoded.clone()));
        assert_eq!(storage.snapshot, Some(snapshot_encoded_old.clone()));
        assert_eq!(storage.targets, Some(targets_encoded.clone()));
    }
}
