use der::asn1::UtcTime;
use der::{DateTime, Decode, Encode};
use rand_core::OsRng;
use std::collections::BTreeMap;
use std::num::NonZeroU64;
use tuf_no_std::builder::{RootBuilder, SnapshotBuilder, TargetsBuilder, TimestampBuilder};
use tuf_no_std_common::crypto::sign::SigningKey;
use tuf_no_std_common::remote::{TransportError, TufTransport};
use tuf_no_std_common::storage::TufStorage;
use tuf_no_std_common::TufError;
use tuf_no_std_der::root::Root;
use tuf_no_std_der::snapshot::Snapshot;
use tuf_no_std_der::targets::Targets;
use tuf_no_std_der::timestamp::Timestamp;
use tuf_no_std_der::Signed;

fn gen_key() -> SigningKey {
    let mut csprng = OsRng;
    let key = ed25519_dalek::SigningKey::generate(&mut csprng);

    SigningKey::Ed25519Dalek(key)
}

#[test]
fn test_out_timestamp() {
    Signed::<Timestamp>::from_der(include_bytes!("../../out/1.timestamp.der"))
        .expect("failed to parse timestamp");
}

#[test]
fn test_out_root() {
    Signed::<Root>::from_der(include_bytes!("../../out/1.root.der")).expect("failed to parse root");
}

#[test]
fn test_out_snapshot() {
    Signed::<Snapshot>::from_der(include_bytes!("../../out/1.snapshot.der"))
        .expect("failed to parse snapshot");
}

#[test]
fn test_out_targets() {
    Signed::<Targets>::from_der(include_bytes!("../../out/1.targets.der"))
        .expect("failed to parse targets");
}

#[test]
fn test() {
    let target_file = b"Hello World!";

    let root_key = gen_key();
    let timestamp_key = gen_key();
    let snapshot_key = gen_key();
    let targets_key = gen_key();

    let root = RootBuilder::default()
        .with_role_and_key("root", &[root_key.as_spki().unwrap()], 1)
        .with_role_and_key("timestamp", &[timestamp_key.as_spki().unwrap()], 1)
        .with_role_and_key("targets", &[targets_key.as_spki().unwrap()], 1)
        .with_role_and_key("snapshot", &[snapshot_key.as_spki().unwrap()], 1)
        .with_version(1)
        .with_expiration_utc(2030, 1, 1, 1, 1, 1)
        .build();

    let targets = TargetsBuilder::default()
        .with_expiration_utc(2030, 1, 1, 1, 1, 1)
        .with_version(1)
        .with_target(b"hello.txt", target_file)
        .build();

    let signed_root = Signed::from_signed(root, &[root_key]).unwrap();
    let targets_signed = Signed::from_signed(targets.clone(), &[targets_key]).unwrap();

    let mut buf = [0u8; 4096];
    let targets_signed_encoded = targets_signed.encode_as_file(&mut buf).unwrap();
    let snapshot = SnapshotBuilder::default()
        .with_expiration_utc(2030, 1, 1, 1, 1, 1)
        .with_version(1)
        .with_meta(b"targets.der", targets_signed_encoded, targets.version)
        .build();

    let signed_snapshot = Signed::from_signed(snapshot, &[snapshot_key]).unwrap();
    let timestamp = TimestampBuilder::default()
        .with_expiration_utc(2030, 1, 1, 1, 1, 1)
        .with_snapshot("snapshot.der", &signed_snapshot)
        .with_version(1)
        .build();

    let signed_timestamp = Signed::from_signed(timestamp, &[timestamp_key]).unwrap();

    let signed_root_encoded = signed_root.to_der().unwrap();
    let signed_timestamp_encoded = signed_timestamp.to_der().unwrap();
    let signed_snapshot_encoded = signed_snapshot.to_der().unwrap();
    let signed_targets_encoded = targets_signed.to_der().unwrap();

    let mut storage = MockStorage {
        root: signed_root_encoded.to_vec(),
        uncommitted_root: None,
        timestamp: None,
        snapshot: None,
        targets: None,
    };
    let mut transport = MockTransport {
        roots: BTreeMap::from([(NonZeroU64::new(1).unwrap(), signed_root_encoded.to_vec())]),
        timestamp: signed_timestamp_encoded.to_vec(),
        snapshot: signed_snapshot_encoded.to_vec(),
        targets: signed_targets_encoded.to_vec(),
        target_files: BTreeMap::from([("hello.txt".to_string(), target_file.to_vec())]),
    };
    tuf_no_std::update_repo(
        &mut storage,
        &mut transport,
        10,
        &UtcTime::from_date_time(DateTime::new(2023, 1, 1, 0, 0, 0).unwrap()).unwrap(),
    )
    .expect("failed to verify valid repo");

    let mut buf = [0u8; 2048];
    let output = tuf_no_std::fetch_and_verify_target_file(
        &mut storage,
        &mut transport,
        b"hello.txt",
        &mut buf,
    )
    .expect("failed to fetch and verify file");
    assert_eq!(output, target_file);
}

// impl TufRepo for Repo {}

#[derive(Default, Clone)]
struct MockStorage {
    pub root: Vec<u8>,
    pub uncommitted_root: Option<Vec<u8>>,
    pub timestamp: Option<Vec<u8>>,
    pub snapshot: Option<Vec<u8>>,
    pub targets: Option<Vec<u8>>,
}

impl TufStorage for MockStorage {
    fn delete_timestamp_metadata(&mut self) {
        self.timestamp = None
    }

    fn delete_snapshot_metadata(&mut self) {
        self.snapshot = None
    }

    fn persist_root(&mut self, data: &[u8]) -> Result<(), TufError> {
        self.uncommitted_root = Some(data.to_vec());
        Ok(())
    }

    fn persist_timestamp(&mut self, data: &[u8]) -> Result<(), TufError> {
        self.timestamp = Some(data.to_vec());
        Ok(())
    }

    fn persist_snapshot(&mut self, data: &[u8]) -> Result<(), TufError> {
        self.snapshot = Some(data.to_vec());
        Ok(())
    }

    fn persist_targets(&mut self, data: &[u8]) -> Result<(), TufError> {
        self.targets = Some(data.to_vec());
        Ok(())
    }

    fn commit_root(&mut self) -> Result<(), TufError> {
        //self.root = self.uncommitted_root.as_ref().expect("missing new root").clone();
        //self.uncommitted_root = None;
        Ok(())
    }

    fn current_root(&self) -> &[u8] {
        &self.root
    }

    fn current_root_copy<'o>(&self, out: &'o mut [u8]) -> &'o [u8] {
        out[..self.root.len()].copy_from_slice(self.root.as_slice());
        &out[..self.root.len()]
    }

    fn current_uncommitted_root_copy<'o>(&self, out: &'o mut [u8]) -> Option<&'o [u8]> {
        match self.uncommitted_root.as_ref() {
            None => None,
            Some(root) => {
                out[..root.len()].copy_from_slice(root.as_slice());
                Some(&out[..root.len()])
            }
        }
    }

    fn current_uncommitted_root(&self) -> Option<&[u8]> {
        self.uncommitted_root.as_ref().map(AsRef::as_ref)
    }

    fn current_timestamp(&self) -> Option<&[u8]> {
        self.timestamp.as_ref().map(AsRef::as_ref)
    }

    fn current_timestamp_copy<'o>(&self, out: &'o mut [u8]) -> Option<&'o [u8]> {
        match self.timestamp.as_ref() {
            None => None,
            Some(root) => {
                out[..root.len()].copy_from_slice(root.as_slice());
                Some(&out[..root.len()])
            }
        }
    }

    fn current_snapshot(&self) -> Option<&[u8]> {
        self.snapshot.as_ref().map(AsRef::as_ref)
    }

    fn current_snapshot_copy<'o>(&self, out: &'o mut [u8]) -> Option<&'o [u8]> {
        match self.snapshot.as_ref() {
            None => None,
            Some(root) => {
                out[..root.len()].copy_from_slice(root.as_slice());
                Some(&out[..root.len()])
            }
        }
    }

    fn current_targets(&self) -> Option<&[u8]> {
        self.targets.as_ref().map(AsRef::as_ref)
    }
}

#[derive(Default, Clone)]
pub struct MockTransport {
    pub roots: BTreeMap<NonZeroU64, Vec<u8>>,
    pub timestamp: Vec<u8>,
    pub snapshot: Vec<u8>,
    pub targets: Vec<u8>,
    pub target_files: BTreeMap<String, Vec<u8>>,
}

fn check_size_and_copy<'o>(src: &[u8], out: &'o mut [u8]) -> Result<&'o [u8], TransportError> {
    if out.len() < src.len() {
        return Err(TransportError::FetchError);
    }
    let (out_buf, _) = out.split_at_mut(src.len());
    out_buf.copy_from_slice(src);
    Ok(out_buf)
}

impl TufTransport for MockTransport {
    fn fetch_root<'o>(
        &self,
        version: NonZeroU64,
        out: &'o mut [u8],
    ) -> Result<&'o [u8], TransportError> {
        let root_file = self.roots.get(&version).ok_or(TransportError::FetchError)?;
        check_size_and_copy(root_file.as_slice(), out)
    }

    fn fetch_timestamp<'o>(&self, out: &'o mut [u8]) -> Result<&'o [u8], TransportError> {
        check_size_and_copy(self.timestamp.as_slice(), out)
    }

    fn fetch_snapshot<'o>(&self, out: &'o mut [u8]) -> Result<&'o [u8], TransportError> {
        check_size_and_copy(self.snapshot.as_slice(), out)
    }

    fn fetch_targets<'o>(&self, out: &'o mut [u8]) -> Result<&'o [u8], TransportError> {
        check_size_and_copy(self.targets.as_slice(), out)
    }

    fn fetch_target_file<'o>(
        &self,
        metapath: &[u8],
        out: &'o mut [u8],
    ) -> Result<&'o [u8], TransportError> {
        self.target_files
            .iter()
            .find(|(p, _)| p.as_bytes() == metapath)
            .ok_or(TransportError::FetchError)
            .and_then(|(_, f)| check_size_and_copy(f.as_slice(), out))
    }
}
