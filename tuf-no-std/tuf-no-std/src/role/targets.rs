use crate::canonical::{EncodeCanonically, EncodingError};
use crate::format::TufFormat;
use crate::role::root::TufRoot;
use crate::role::{DecodeRole, RoleUpdate, TufRole, TufSnapshot};
use der::asn1::{BitStringRef, UtcTime};
use der::Encode;
use tuf_no_std_common::crypto::verify_sha256;
use tuf_no_std_common::remote::TufTransport;
#[cfg(feature = "async")]
use tuf_no_std_common::remote::TufTransportAsync;
use tuf_no_std_common::storage::TufStorage;
use tuf_no_std_common::TufError::{ExpiredTargetsFile, InvalidNewVersionNumber};
use tuf_no_std_common::{RoleType, TufError, Version};
use tuf_no_std_der::targets::{Targets, TargetsRef};
use tuf_no_std_der::{HashRef, TufDer};

pub trait TufTargets {}

impl<'a> TufRole for TargetsRef<'a, 4, 0> {
    const TYPE: RoleType = RoleType::Targets;
}

impl<'a> EncodeCanonically for TargetsRef<'a, 4, 0> {
    fn encode_canonically<'o>(&self, out: &'o mut [u8]) -> Result<&'o [u8], EncodingError> {
        self.encode_to_slice(out)
            .map_err(|_| EncodingError::BufferTooSmall)
    }
}

impl EncodeCanonically for Targets {
    fn encode_canonically<'o>(&self, out: &'o mut [u8]) -> Result<&'o [u8], EncodingError> {
        self.encode_to_slice(out)
            .map_err(|_| EncodingError::BufferTooSmall)
    }
}

impl<'a> RoleUpdate for TargetsRef<'a, 4, 0> {
    fn version(&self) -> Version {
        self.version
    }

    fn expires(&self) -> UtcTime {
        self.expires
    }
}

impl<'a> TufTargets for TargetsRef<'a, 4, 0> {}

pub(crate) fn verify_targets<'a>(
    root: &'a [u8],
    snapshot: &'a [u8],
    targets_new: &'a [u8],
    update_start: &UtcTime,
) -> Result<(), TufError> {
    let root_decoded = <TufDer as TufFormat>::Root::decode_role(root)?;
    let snapshot_decoded = <TufDer as TufFormat>::Snapshot::decode_role(snapshot)?;
    let targets_new_decoded = <TufDer as TufFormat>::Targets::decode_role(targets_new)?;

    verify_sha256(snapshot_decoded.targets_hash(), targets_new)
        .map_err(|_| TufError::InvalidHash)?;
    root_decoded.verify_role(&targets_new_decoded)?;
    if targets_new_decoded.version() != snapshot_decoded.targets_version() {
        return Err(InvalidNewVersionNumber);
    }
    if &targets_new_decoded.expires() < update_start {
        return Err(ExpiredTargetsFile);
    }
    Ok(())
}

pub(crate) fn update_targets<S, T>(
    remote: &mut T,
    storage: &mut S,
    update_start: &UtcTime,
) -> Result<(), TufError>
where
    S: TufStorage,
    T: TufTransport,
{
    let current_root = storage.current_root();
    let snapshot = storage
        .current_snapshot()
        .ok_or(TufError::MissingSnapshotFile)?;

    let mut buf = [0u8; 512];
    let targets_new = remote
        .fetch_targets(&mut buf)
        .map_err(|_| TufError::FetchError)?;
    verify_targets(current_root, snapshot, targets_new, update_start)?;
    storage.persist_targets(targets_new)?;
    Ok(())
}

#[cfg(feature = "async")]
pub(crate) async fn update_targets_async<S, T>(
    remote: &mut T,
    storage: &mut S,
    update_start: &UtcTime,
) -> Result<(), TufError>
where
    S: TufStorage,
    T: TufTransportAsync,
{
    let current_root = storage.current_root();
    let snapshot = storage
        .current_snapshot()
        .ok_or(TufError::MissingSnapshotFile)?;

    let mut buf = [0u8; 512];
    let targets_new = remote
        .fetch_targets(&mut buf)
        .await
        .map_err(|_| TufError::FetchError)?;
    verify_targets(current_root, snapshot, targets_new, update_start)?;
    storage.persist_targets(targets_new)?;
    Ok(())
}

pub(crate) fn verify_target_file(
    targets: &[u8],
    target_file_metapath: &[u8],
    target_file: &[u8],
) -> Result<(), TufError> {
    // 5.7.1 Verify the desired target against its targets metadata.

    let targets_decoded = <TufDer as TufFormat>::Targets::decode_role(targets)?;
    let target_file_metapath =
        BitStringRef::from_bytes(target_file_metapath).or(Err(TufError::InternalError))?;
    let metadata = &targets_decoded
        .signed
        .targets
        .iter()
        .find(|t| t.metapath == target_file_metapath)
        .ok_or(TufError::MissingTargetMetadata)?
        .value;
    if metadata
        .length
        .map(|l| l != target_file.len() as u64)
        .unwrap_or(false)
    {
        return Err(TufError::InvalidLength);
    }
    let expected_hash = metadata
        .hashes
        .iter()
        .find_map(HashRef::sha256)
        .ok_or(TufError::NoSupportedHash)?;
    verify_sha256(expected_hash, target_file).map_err(|_| TufError::InvalidHash)?;
    Ok(())
}

#[cfg(test)]
mod test {

    use der::asn1::BitString;
    use der::{DateTime, Encode};
    use ed25519_dalek::SigningKey;
    use rand_core::OsRng;
    use tuf_no_std_common::crypto::sign::SigningKey::Ed25519Dalek;
    use tuf_no_std_der::Signed;

    use crate::builder::{RootBuilder, SnapshotBuilder, TargetsBuilder};
    use crate::utils::spki_from_signing_key;

    use super::{verify_target_file, verify_targets};

    #[test]
    fn test_verify_targets() {
        let target_file = "Hello World!";
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
            .with_target(b"hello-world.txt", target_file.as_bytes())
            .build();
        let signed_targets = Signed::from_signed(targets, &[(targets_key.clone())]).unwrap();

        let snapshot = SnapshotBuilder::default()
            .with_expiration_utc(2030, 1, 1, 0, 0, 0)
            .with_version(1)
            .with_meta(b"targets.der", &signed_targets.to_der().unwrap(), 1)
            .build();
        let signed_snapshot =
            Signed::from_signed(snapshot.clone(), &[(snapshot_key.clone())]).unwrap();

        // Case: valid file
        verify_targets(
            &signed_root.to_der().unwrap(),
            &signed_snapshot.to_der().unwrap(),
            &signed_targets.to_der().unwrap(),
            &DateTime::new(2023, 1, 1, 0, 0, 0)
                .unwrap()
                .try_into()
                .unwrap(),
        )
        .expect("failed to verify valid snapshot file");

        // Case: expired
        verify_targets(
            &signed_root.to_der().unwrap(),
            &signed_snapshot.to_der().unwrap(),
            &signed_targets.to_der().unwrap(),
            &DateTime::new(2040, 1, 1, 0, 0, 0)
                .unwrap()
                .try_into()
                .unwrap(),
        )
        .expect_err("failed to reject expired snapshot file");
        verify_target_file(
            &signed_targets.to_der().unwrap(),
            b"hello-world.txt",
            target_file.as_bytes(),
        )
        .expect("failed to verify targets file");

        let mut snapshot = SnapshotBuilder::default()
            .with_expiration_utc(2030, 1, 1, 0, 0, 0)
            .with_version(1)
            .with_meta(b"targets.der", &signed_targets.to_der().unwrap(), 1)
            .build();
        snapshot.meta[0].hashes[0].value = BitString::from_bytes(&[0u8; 32]).unwrap();

        let signed_snapshot =
            Signed::from_signed(snapshot.clone(), &[(snapshot_key.clone())]).unwrap();
        verify_targets(
            &signed_root.to_der().unwrap(),
            &signed_snapshot.to_der().unwrap(),
            &signed_targets.to_der().unwrap(),
            &DateTime::new(2023, 1, 1, 0, 0, 0)
                .unwrap()
                .try_into()
                .unwrap(),
        )
        .expect_err("accepted invalid targets file");

        // Case: version number does not match snapshot
        let mut snapshot = SnapshotBuilder::default()
            .with_expiration_utc(2030, 1, 1, 0, 0, 0)
            .with_version(1)
            .with_meta(b"targets.der", &signed_targets.to_der().unwrap(), 1)
            .build();
        snapshot.meta[0].version = 0;

        let signed_snapshot =
            Signed::from_signed(snapshot.clone(), &[(snapshot_key.clone())]).unwrap();
        verify_targets(
            &signed_root.to_der().unwrap(),
            &signed_snapshot.to_der().unwrap(),
            &signed_targets.to_der().unwrap(),
            &DateTime::new(2023, 1, 1, 0, 0, 0)
                .unwrap()
                .try_into()
                .unwrap(),
        )
        .expect_err("accepted invalid targets file");
    }

    #[test]
    fn test_verify_targets_threshold() {
        let mut csprng = OsRng;

        let root_key = Ed25519Dalek(SigningKey::generate(&mut csprng));
        let root_pub_spki = spki_from_signing_key(&root_key);

        let timestamp_key = Ed25519Dalek(SigningKey::generate(&mut csprng));
        let timestamp_pub_spki = spki_from_signing_key(&timestamp_key);

        let targets_key_1 = Ed25519Dalek(SigningKey::generate(&mut csprng));
        let targets_pub_spki_1 = spki_from_signing_key(&targets_key_1);
        let targets_key_2 = Ed25519Dalek(SigningKey::generate(&mut csprng));
        let targets_pub_spki_2 = spki_from_signing_key(&targets_key_2);

        let snapshot_key = Ed25519Dalek(SigningKey::generate(&mut csprng));
        let snapshot_pub_spki = spki_from_signing_key(&snapshot_key);

        let root = RootBuilder::default()
            .with_role_and_key("root", &[root_pub_spki], 1)
            .with_role_and_key("targets", &[targets_pub_spki_1, targets_pub_spki_2], 2)
            .with_role_and_key("snapshot", &[snapshot_pub_spki], 1)
            .with_role_and_key("timestamp", &[timestamp_pub_spki], 1)
            .with_expiration_utc(2030, 1, 1, 0, 0, 0)
            .with_version(1)
            .build();

        let signed_root = Signed::from_signed(root, &[root_key]).unwrap();

        // Case: valid, meets threshold
        let targets = TargetsBuilder::default()
            .with_expiration_utc(2030, 1, 1, 0, 0, 0)
            .with_version(1)
            .build();
        let signed_targets =
            Signed::from_signed(targets, &[targets_key_1.clone(), targets_key_2.clone()]).unwrap();

        let snapshot = SnapshotBuilder::default()
            .with_expiration_utc(2030, 1, 1, 0, 0, 0)
            .with_version(1)
            .with_meta(b"targets.der", &signed_targets.to_der().unwrap(), 1)
            .build();
        let signed_snapshot =
            Signed::from_signed(snapshot.clone(), &[(snapshot_key.clone())]).unwrap();

        verify_targets(
            &signed_root.to_der().unwrap(),
            &signed_snapshot.to_der().unwrap(),
            &signed_targets.to_der().unwrap(),
            &DateTime::new(2023, 1, 1, 0, 0, 0)
                .unwrap()
                .try_into()
                .unwrap(),
        )
        .expect("failed to verify valid snapshot file");

        // Case: Does not meet threshold.
        let targets = TargetsBuilder::default()
            .with_expiration_utc(2030, 1, 1, 0, 0, 0)
            .with_version(1)
            .build();
        let signed_targets = Signed::from_signed(targets, &[targets_key_1.clone()]).unwrap();

        let snapshot = SnapshotBuilder::default()
            .with_expiration_utc(2030, 1, 1, 0, 0, 0)
            .with_version(1)
            .with_meta(b"targets.der", &signed_targets.to_der().unwrap(), 1)
            .build();
        let signed_snapshot =
            Signed::from_signed(snapshot.clone(), &[(snapshot_key.clone())]).unwrap();

        verify_targets(
            &signed_root.to_der().unwrap(),
            &signed_snapshot.to_der().unwrap(),
            &signed_targets.to_der().unwrap(),
            &DateTime::new(2023, 1, 1, 0, 0, 0)
                .unwrap()
                .try_into()
                .unwrap(),
        )
        .expect_err("accepted targets file that does not have enough signatures");

        // Case: Does not meet threshold, keys are reused.
        let targets = TargetsBuilder::default()
            .with_expiration_utc(2030, 1, 1, 0, 0, 0)
            .with_version(1)
            .build();
        let signed_targets =
            Signed::from_signed(targets, &[targets_key_1.clone(), targets_key_1.clone()]).unwrap();

        let snapshot = SnapshotBuilder::default()
            .with_expiration_utc(2030, 1, 1, 0, 0, 0)
            .with_version(1)
            .with_meta(b"targets.der", &signed_targets.to_der().unwrap(), 1)
            .build();
        let signed_snapshot =
            Signed::from_signed(snapshot.clone(), &[(snapshot_key.clone())]).unwrap();

        verify_targets(
            &signed_root.to_der().unwrap(),
            &signed_snapshot.to_der().unwrap(),
            &signed_targets.to_der().unwrap(),
            &DateTime::new(2023, 1, 1, 0, 0, 0)
                .unwrap()
                .try_into()
                .unwrap(),
        )
        .expect_err("accepted targets file that reused keys to meet threshold");

        // Case: signatures from keys not specified for the role.
        let targets = TargetsBuilder::default()
            .with_expiration_utc(2030, 1, 1, 0, 0, 0)
            .with_version(1)
            .build();
        let signed_targets = Signed::from_signed(
            targets,
            &[
                Ed25519Dalek(SigningKey::generate(&mut csprng)),
                Ed25519Dalek(SigningKey::generate(&mut csprng)),
            ],
        )
        .unwrap();

        let snapshot = SnapshotBuilder::default()
            .with_expiration_utc(2030, 1, 1, 0, 0, 0)
            .with_version(1)
            .with_meta(b"targets.der", &signed_targets.to_der().unwrap(), 1)
            .build();
        let signed_snapshot =
            Signed::from_signed(snapshot.clone(), &[(snapshot_key.clone())]).unwrap();

        verify_targets(
            &signed_root.to_der().unwrap(),
            &signed_snapshot.to_der().unwrap(),
            &signed_targets.to_der().unwrap(),
            &DateTime::new(2023, 1, 1, 0, 0, 0)
                .unwrap()
                .try_into()
                .unwrap(),
        )
        .expect_err("accepted targets file that used untrusted keys");
    }
}
