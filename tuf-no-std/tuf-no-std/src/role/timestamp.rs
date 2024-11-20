use crate::canonical::{EncodeCanonically, EncodingError};
use crate::role::root::TufRoot;
use crate::role::{DecodeRole, RoleUpdate, TufRole, TufTimestamp};
use der::asn1::UtcTime;
use der::Encode;
use tuf_no_std_common::remote::TufTransport;
#[cfg(feature = "async")]
use tuf_no_std_common::remote::TufTransportAsync;
use tuf_no_std_common::storage::TufStorage;
use tuf_no_std_common::TufError::{ExpiredTimestampFile, InvalidNewVersionNumber};
use tuf_no_std_common::{RoleType, TufError, Version};
use tuf_no_std_der::root::RootRef;
use tuf_no_std_der::timestamp::TimestampRef;
use tuf_no_std_der::SignedRef;

impl<'a> TufRole for TimestampRef<'a> {
    const TYPE: RoleType = RoleType::Timestamp;
}

impl<'a> EncodeCanonically for TimestampRef<'a> {
    fn encode_canonically<'o>(&self, out: &'o mut [u8]) -> Result<&'o [u8], EncodingError> {
        self.encode_to_slice(out)
            .map_err(|_| EncodingError::BufferTooSmall)
    }
}

impl<'a> RoleUpdate for TimestampRef<'a> {
    fn version(&self) -> Version {
        self.version
    }

    fn expires(&self) -> UtcTime {
        self.expires
    }
}

impl<'a> TufTimestamp for TimestampRef<'a> {
    fn snapshot_version(&self) -> Version {
        self.meta.version
    }

    fn snapshot_expires(&self) -> UtcTime {
        self.expires
    }

    fn snapshot_hash(&self) -> [u8; 32] {
        self.meta
            .hashes
            .get(0)
            .expect("expected at least one hash")
            .value
            .as_bytes()
            .and_then(|h| TryInto::try_into(h).ok())
            .unwrap()
    }
}

pub(crate) fn verify_timestamp<'a>(
    root: &[u8],
    timestamp_old: Option<&'a [u8]>,
    timestamp_new: &'a [u8],
    update_start: &UtcTime,
) -> Result<&'a [u8], TufError> {
    let root = SignedRef::<RootRef>::decode_role(root)?;
    let timestamp_new_decoded = SignedRef::<TimestampRef>::decode_role(timestamp_new)?;

    root.verify_role(&timestamp_new_decoded)?;

    if let Some(timestamp_old) = timestamp_old {
        let timestamp_old_decoded = SignedRef::<TimestampRef>::decode_role(timestamp_old)?;
        if timestamp_new_decoded.version() < timestamp_old_decoded.version() {
            return Err(InvalidNewVersionNumber);
        }
        if timestamp_new_decoded.snapshot_version() < timestamp_old_decoded.snapshot_version() {
            return Err(InvalidNewVersionNumber);
        }
        // From the TUF spec: 'In case [the version numbers] are equal,
        // discard the new timestamp metadata and abort the update cycle.
        // This is normal and it shouldn’t raise any error.'
        if timestamp_new_decoded.version() == timestamp_old_decoded.version() {
            return Ok(timestamp_old);
        }
    }

    if &timestamp_new_decoded.expires() < update_start {
        return Err(ExpiredTimestampFile);
    }
    Ok(timestamp_new)
}

pub(crate) fn update_timestamp<S, T>(
    remote: &mut T,
    storage: &mut S,
    update_start: &UtcTime,
) -> Result<(), TufError>
where
    S: TufStorage,
    T: TufTransport,
{
    let current_root = storage.current_root();
    let mut buf = [0u8; 512];
    let timestamp_old = storage.current_timestamp_copy(&mut buf);
    let mut buf = [0u8; 512];
    let timestamp = remote
        .fetch_timestamp(&mut buf)
        .map_err(|_| TufError::FetchError)?;
    let timestamp = verify_timestamp(current_root, timestamp_old, timestamp, update_start)?;
    storage.persist_timestamp(timestamp)?;
    Ok(())
}

#[cfg(feature = "async")]
pub(crate) async fn update_timestamp_async<S, T>(
    remote: &mut T,
    storage: &mut S,
    update_start: &UtcTime,
) -> Result<(), TufError>
where
    S: TufStorage,
    T: TufTransportAsync,
{
    let current_root = storage.current_root();
    let mut buf = [0u8; 512];
    let timestamp_old = storage.current_timestamp_copy(&mut buf);
    let mut buf = [0u8; 512];
    let timestamp_new = remote
        .fetch_timestamp(&mut buf)
        .await
        .map_err(|_| TufError::FetchError)?;
    let timestamp = verify_timestamp(current_root, timestamp_old, timestamp_new, update_start)?;
    storage.persist_timestamp(timestamp)?;
    Ok(())
}

#[cfg(test)]
mod test {
    use crate::builder::{RootBuilder, SnapshotBuilder, TargetsBuilder, TimestampBuilder};
    use crate::role::timestamp::verify_timestamp;
    use crate::utils::{build_role, spki_from_signing_key, MockStorage, MockTransport};
    use alloc::vec;
    use anyhow::anyhow;
    use der::asn1::{BitString, UtcTime};
    use der::referenced::OwnedToRef;
    use der::{DateTime, Encode};
    use ed25519_dalek::SigningKey;
    use rand_core::OsRng;
    use tuf_no_std_common::crypto::sign::SigningKey::Ed25519Dalek;
    use tuf_no_std_der::root::Root;
    use tuf_no_std_der::Signed;

    use super::update_timestamp;

    #[test]
    fn test_verify_timestamp() {
        let mut csprng = OsRng;

        let root_key = Ed25519Dalek(SigningKey::generate(&mut csprng));
        let root_pub_spki = spki_from_signing_key(&root_key);

        let timestamp_key = Ed25519Dalek(SigningKey::generate(&mut csprng));
        let timestamp_pub_spki = spki_from_signing_key(&timestamp_key);

        let snapshot_key = Ed25519Dalek(SigningKey::generate(&mut csprng));
        let snapshot_pub_spki = spki_from_signing_key(&snapshot_key);

        let targets_key = Ed25519Dalek(SigningKey::generate(&mut csprng));
        let targets_pub_spki = spki_from_signing_key(&targets_key);

        let root = RootBuilder::default()
            .with_version(1)
            .with_expiration_utc(2023, 1, 1, 1, 0, 0)
            .with_role_and_key("root", &[root_pub_spki], 1)
            .with_role_and_key("snapshot", &[snapshot_pub_spki], 1)
            .with_role_and_key("targets", &[targets_pub_spki], 1)
            .with_role_and_key("timestamp", &[timestamp_pub_spki], 1)
            .build();

        let signed_root = Signed::from_signed(root, &[root_key]).unwrap();

        let targets = TargetsBuilder::default()
            .with_expiration_utc(2030, 1, 1, 0, 0, 0)
            .with_version(1)
            .build();

        let signed_targets = Signed::from_signed(targets, &[targets_key.clone()]).unwrap();

        let mut buf = [0u8; 4096];
        let encoded_targets = signed_targets.encode_to_slice(&mut buf).unwrap();

        let snapshot = SnapshotBuilder::default()
            .with_expiration_utc(2030, 1, 1, 0, 0, 0)
            .with_meta(b"targets.der", encoded_targets, 1)
            .with_version(1)
            .build();

        let signed_snapshot =
            Signed::from_signed(snapshot.clone(), &[snapshot_key.clone()]).unwrap();

        let timestamp = TimestampBuilder::default()
            .with_expiration_utc(2030, 1, 1, 0, 0, 0)
            .with_snapshot("snapshot.der", &signed_snapshot)
            .with_version(1)
            .build();

        let signed_timestamp = Signed::from_signed(timestamp, &[timestamp_key]).unwrap();

        verify_timestamp(
            &signed_root.to_der().unwrap(),
            None,
            &signed_timestamp.to_der().unwrap(),
            &DateTime::new(2023, 1, 1, 0, 0, 0)
                .unwrap()
                .try_into()
                .unwrap(),
        )
        .expect("failed to verify");
        verify_timestamp(
            &signed_root.to_der().unwrap(),
            None,
            &signed_timestamp.to_der().unwrap(),
            &DateTime::new(2031, 1, 1, 0, 0, 0)
                .unwrap()
                .try_into()
                .unwrap(),
        )
        .expect_err("accepted expired timestamp");
    }

    #[test]
    fn test_verify_timestamp_threshold_not_reached() {
        let mut csprng = OsRng;

        let root_key = Ed25519Dalek(SigningKey::generate(&mut csprng));
        let root_pub_spki = spki_from_signing_key(&root_key);

        let timestamp_key_1 = Ed25519Dalek(SigningKey::generate(&mut csprng));
        let timestamp_pub_spki_1 = spki_from_signing_key(&timestamp_key_1);
        let timestamp_key_2 = Ed25519Dalek(SigningKey::generate(&mut csprng));
        let timestamp_pub_spki_2 = spki_from_signing_key(&timestamp_key_2);
        let snapshot_key = Ed25519Dalek(SigningKey::generate(&mut csprng));
        let snapshot_pub_spki = spki_from_signing_key(&snapshot_key);

        let targets_key = Ed25519Dalek(SigningKey::generate(&mut csprng));
        let targets_pub_spki = spki_from_signing_key(&targets_key);

        let mut keys = vec![
            root_pub_spki.clone(),
            targets_pub_spki.clone(),
            timestamp_pub_spki_1.clone(),
            timestamp_pub_spki_2.clone(),
            snapshot_pub_spki.clone(),
        ];

        keys.sort_by_key(|k| k.owned_to_ref().fingerprint_bytes().unwrap());
        let root = Root {
            consistent_snapshot: true,
            expires: DateTime::new(2030, 1, 1, 0, 0, 0)
                .map_err(|err| anyhow!("failed to create DateTime {err:?}"))
                .and_then(|d| {
                    UtcTime::from_date_time(d)
                        .map_err(|err| anyhow!("failed to create UtcTime {err:?}"))
                })
                .expect("could not create date"),
            keys,
            roles: vec![
                build_role("root", &[root_pub_spki], 1),
                build_role("snapshot", &[snapshot_pub_spki], 1),
                build_role("targets", &[targets_pub_spki], 1),
                build_role(
                    "timestamp",
                    &[timestamp_pub_spki_1, timestamp_pub_spki_2],
                    2,
                ),
            ],
            spec_version: BitString::from_bytes(b"1.0").unwrap(),
            version: 1,
        };
        let signed_root = Signed::from_signed(root, &[root_key]).unwrap();

        let targets = TargetsBuilder::default()
            .with_expiration_utc(2030, 1, 1, 0, 0, 0)
            .with_version(1)
            .build();

        let signed_targets = Signed::from_signed(targets, &[targets_key.clone()]).unwrap();

        let mut buf = [0u8; 4096];
        let encoded_targets = signed_targets.encode_to_slice(&mut buf).unwrap();

        let snapshot = SnapshotBuilder::default()
            .with_expiration_utc(2030, 1, 1, 0, 0, 0)
            .with_meta(b"targets.der", encoded_targets, 1)
            .with_version(1)
            .build();

        let signed_snapshot =
            Signed::from_signed(snapshot.clone(), &[snapshot_key.clone()]).unwrap();

        let timestamp = TimestampBuilder::default()
            .with_expiration_utc(2030, 1, 1, 0, 0, 0)
            .with_snapshot("snapshot.der", &signed_snapshot)
            .with_version(1)
            .build();

        let signed_timestamp = Signed::from_signed(
            timestamp.clone(),
            &[
                Ed25519Dalek(SigningKey::generate(&mut csprng)),
                Ed25519Dalek(SigningKey::generate(&mut csprng)),
            ],
        )
        .unwrap();
        verify_timestamp(
            &signed_root.to_der().unwrap(),
            None,
            &signed_timestamp.to_der().unwrap(),
            &DateTime::new(2023, 1, 1, 0, 0, 0)
                .unwrap()
                .try_into()
                .unwrap(),
        )
        .expect_err("accepted timestamp signed by unknown keys");

        let signed_timestamp = Signed::from_signed(timestamp.clone(), &[]).unwrap();
        verify_timestamp(
            &signed_root.to_der().unwrap(),
            None,
            &signed_timestamp.to_der().unwrap(),
            &DateTime::new(2023, 1, 1, 0, 0, 0)
                .unwrap()
                .try_into()
                .unwrap(),
        )
        .expect_err("accepted timestamp without any signatures");

        let signed_timestamp =
            Signed::from_signed(timestamp.clone(), &[timestamp_key_1.clone()]).unwrap();
        verify_timestamp(
            &signed_root.to_der().unwrap(),
            None,
            &signed_timestamp.to_der().unwrap(),
            &DateTime::new(2023, 1, 1, 0, 0, 0)
                .unwrap()
                .try_into()
                .unwrap(),
        )
        .expect_err("accepted timestamp without meeting threshold");

        let signed_timestamp = Signed::from_signed(
            timestamp,
            &[timestamp_key_1.clone(), timestamp_key_1.clone()],
        )
        .unwrap();

        verify_timestamp(
            &signed_root.to_der().unwrap(),
            None,
            &signed_timestamp.to_der().unwrap(),
            &DateTime::new(2023, 1, 1, 0, 0, 0)
                .unwrap()
                .try_into()
                .unwrap(),
        )
        .expect_err("accepted timestamp with duplicate signatures threshold");
    }

    #[test]
    fn test_update_timestamp_version_number() {
        let mut csprng = OsRng;

        let root_key = Ed25519Dalek(SigningKey::generate(&mut csprng));
        let root_pub_spki = spki_from_signing_key(&root_key);

        let timestamp_key = Ed25519Dalek(SigningKey::generate(&mut csprng));
        let timestamp_pub_spki = spki_from_signing_key(&timestamp_key);
        let snapshot_key = Ed25519Dalek(SigningKey::generate(&mut csprng));
        let snapshot_pub_spki = spki_from_signing_key(&snapshot_key);

        let targets_key = Ed25519Dalek(SigningKey::generate(&mut csprng));
        let targets_pub_spki = spki_from_signing_key(&targets_key);

        let mut keys = vec![
            root_pub_spki.clone(),
            targets_pub_spki.clone(),
            timestamp_pub_spki.clone(),
            snapshot_pub_spki.clone(),
        ];

        keys.sort_by_key(|k| k.owned_to_ref().fingerprint_bytes().unwrap());
        let root = Root {
            consistent_snapshot: true,
            expires: DateTime::new(2030, 1, 1, 0, 0, 0)
                .map_err(|err| anyhow!("failed to create DateTime {err:?}"))
                .and_then(|d| {
                    UtcTime::from_date_time(d)
                        .map_err(|err| anyhow!("failed to create UtcTime {err:?}"))
                })
                .expect("could not create date"),
            keys,
            roles: vec![
                build_role("root", &[root_pub_spki], 1),
                build_role("snapshot", &[snapshot_pub_spki], 1),
                build_role("targets", &[targets_pub_spki], 1),
                build_role("timestamp", &[timestamp_pub_spki], 1),
            ],
            spec_version: BitString::from_bytes(b"1.0").unwrap(),
            version: 1,
        };
        let signed_root = Signed::from_signed(root, &[root_key]).unwrap();

        let targets = TargetsBuilder::default()
            .with_expiration_utc(2030, 1, 1, 0, 0, 0)
            .with_version(1)
            .build();

        let signed_targets = Signed::from_signed(targets, &[targets_key.clone()]).unwrap();

        let mut buf = [0u8; 4096];
        let encoded_targets = signed_targets.encode_to_slice(&mut buf).unwrap();

        let snapshot = SnapshotBuilder::default()
            .with_expiration_utc(2030, 1, 1, 0, 0, 0)
            .with_meta(b"targets.der", encoded_targets, 1)
            .with_version(1)
            .build();

        let signed_snapshot =
            Signed::from_signed(snapshot.clone(), &[snapshot_key.clone()]).unwrap();

        let timestamp = TimestampBuilder::default()
            .with_expiration_utc(2030, 1, 1, 0, 0, 0)
            .with_snapshot("snapshot.der", &signed_snapshot)
            .with_version(1)
            .build();

        let signed_timestamp_old =
            Signed::from_signed(timestamp.clone(), &[timestamp_key.clone()]).unwrap();

        let timestamp = TimestampBuilder::default()
            .with_expiration_utc(2031, 1, 1, 0, 0, 0)
            .with_snapshot("snapshot.der", &signed_snapshot)
            .with_version(1)
            .build();

        let signed_timestamp_new =
            Signed::from_signed(timestamp.clone(), &[timestamp_key.clone()]).unwrap();
        let mut transport = MockTransport::<_, &[u8]> {
            roots: Default::default(),
            timestamp: signed_timestamp_new.to_der().unwrap(),
            snapshot: vec![],
            targets: vec![],
            target_files: Default::default(),
        };
        let mut storage = MockStorage {
            root: signed_root.to_der().unwrap(),
            uncommitted_root: None,
            timestamp: Some(signed_timestamp_old.to_der().unwrap()),
            snapshot: Some(signed_snapshot.to_der().unwrap()),
            targets: Some(signed_targets.to_der().unwrap()),
        };
        update_timestamp(
            &mut transport,
            &mut storage,
            &UtcTime::from_date_time(DateTime::new(2030, 1, 1, 0, 0, 0).unwrap()).unwrap(),
        )
        .expect("this should succeed");
        assert_eq!(
            signed_timestamp_old.to_der().unwrap(),
            storage.timestamp.unwrap(),
            "expected no update to the timestamp"
        );

        // Case: version number is lower than the previous one
        let timestamp = TimestampBuilder::default()
            .with_expiration_utc(2031, 1, 1, 0, 0, 0)
            .with_snapshot("snapshot.der", &signed_snapshot)
            .with_version(0)
            .build();

        let signed_timestamp_new =
            Signed::from_signed(timestamp.clone(), &[timestamp_key.clone()]).unwrap();
        let mut transport = MockTransport::<_, &[u8]> {
            roots: Default::default(),
            timestamp: signed_timestamp_new.to_der().unwrap(),
            snapshot: vec![],
            targets: vec![],
            target_files: Default::default(),
        };
        let mut storage = MockStorage {
            root: signed_root.to_der().unwrap(),
            uncommitted_root: None,
            timestamp: Some(signed_timestamp_old.to_der().unwrap()),
            snapshot: Some(signed_snapshot.to_der().unwrap()),
            targets: Some(signed_targets.to_der().unwrap()),
        };
        update_timestamp(
            &mut transport,
            &mut storage,
            &UtcTime::from_date_time(DateTime::new(2030, 1, 1, 0, 0, 0).unwrap()).unwrap(),
        )
        .expect_err("this should fail");

        // Case: version number of the snapshot metadata file in the trusted timestamp metadata file
        //       not less or equal to the one in the new timestamp.
        let snapshot = SnapshotBuilder::default()
            .with_expiration_utc(2030, 1, 1, 0, 0, 0)
            .with_meta(b"targets.der", encoded_targets, 1)
            .with_version(0)
            .build();

        let signed_snapshot =
            Signed::from_signed(snapshot.clone(), &[snapshot_key.clone()]).unwrap();

        let timestamp = TimestampBuilder::default()
            .with_expiration_utc(2031, 1, 1, 0, 0, 0)
            .with_snapshot("snapshot.der", &signed_snapshot)
            .with_version(2)
            .build();

        let signed_timestamp_new =
            Signed::from_signed(timestamp.clone(), &[timestamp_key.clone()]).unwrap();
        assert_eq!(signed_timestamp_new.signed.meta.version, 0);
        let mut transport = MockTransport::<_, &[u8]> {
            roots: Default::default(),
            timestamp: signed_timestamp_new.to_der().unwrap(),
            snapshot: vec![],
            targets: vec![],
            target_files: Default::default(),
        };
        let mut storage = MockStorage {
            root: signed_root.to_der().unwrap(),
            uncommitted_root: None,
            timestamp: Some(signed_timestamp_old.to_der().unwrap()),
            snapshot: Some(signed_snapshot.to_der().unwrap()),
            targets: Some(signed_targets.to_der().unwrap()),
        };
        update_timestamp(
            &mut transport,
            &mut storage,
            &UtcTime::from_date_time(DateTime::new(2030, 1, 1, 0, 0, 0).unwrap()).unwrap(),
        )
        .expect_err("this should fail");
    }
}
