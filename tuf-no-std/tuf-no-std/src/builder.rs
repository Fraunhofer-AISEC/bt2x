use der::asn1::{BitString, UtcTime};
use der::{DateTime, Encode};
use sha2::{Digest, Sha256};
use spki::SubjectPublicKeyInfo;
use tuf_no_std_common::Version;
use tuf_no_std_der::targets::TargetValue;
use tuf_no_std_der::Signed;
#[cfg(feature = "der")]
use tuf_no_std_der::{
    root::Root,
    snapshot::{Snapshot, SnapshotMeta},
    targets::{Delegation, Target, Targets},
    timestamp::Timestamp,
    {Hash, Role},
};

pub struct RootBuilder {
    root: Root,
}

impl Default for RootBuilder {
    fn default() -> Self {
        RootBuilder {
            root: Root {
                consistent_snapshot: false,
                expires: UtcTime::from_date_time(DateTime::new(1970, 1, 1, 0, 0, 0).unwrap())
                    .unwrap(),
                keys: Default::default(),
                roles: Default::default(),
                spec_version: BitString::from_bytes(b"1.0").unwrap(),
                version: 0,
            },
        }
    }
}

impl RootBuilder {
    /// Set the expiration date of the root role to this [UTC date](https://en.wikipedia.org/wiki/Coordinated_Universal_Time).
    pub fn with_expiration_utc(
        mut self,
        year: u16,
        month: u8,
        day: u8,
        hour: u8,
        minutes: u8,
        seconds: u8,
    ) -> Self {
        self.root.expires = UtcTime::from_date_time(
            DateTime::new(year, month, day, hour, minutes, seconds).unwrap(),
        )
        .unwrap();
        self
    }

    /// Add add a role to the root file.
    pub fn with_role(mut self, role: Role) -> Self {
        self.root.roles.push(role);
        self
    }

    /// Add a key to the root file.
    pub fn with_key(mut self, key: SubjectPublicKeyInfo<der::Any, BitString>) -> Self {
        self.root.keys.push(key);
        self
    }

    /// Add a root role that has the given key. Useful to add roles with a single key.
    pub fn with_role_and_key(
        self,
        role: &str,
        keys: &[SubjectPublicKeyInfo<der::Any, BitString>],
        threshold: u8,
    ) -> Self {
        let key_ids = keys
            .iter()
            .map(|key| key.fingerprint_bytes().unwrap())
            .map(|key_id| BitString::from_bytes(key_id.as_slice()).unwrap())
            .collect();

        let builder = self.with_role(Role {
            name: BitString::from_bytes(role.as_bytes()).unwrap(),
            keyids: key_ids,
            threshold,
        });
        keys.iter()
            .fold(builder, |builder, key| builder.with_key(key.clone()))
    }

    /// Set the version of the root file.
    pub fn with_version(mut self, version: u32) -> Self {
        self.root.version = version;
        self
    }

    /// Set the flag whether [consistent snapshots](https://theupdateframework.github.io/specification/latest/#consistent-snapshots) are enabled.
    pub fn consistent_snapshot(mut self, consistent_snapshots: bool) -> Self {
        self.root.consistent_snapshot = consistent_snapshots;
        self
    }

    /// Return the constructed root file..
    pub fn build(self) -> Root {
        self.root
    }
}

pub struct TimestampBuilder {
    inner: Timestamp,
}

impl Default for TimestampBuilder {
    fn default() -> Self {
        TimestampBuilder {
            inner: Timestamp {
                expires: UtcTime::from_date_time(DateTime::new(1970, 1, 1, 0, 0, 0).unwrap())
                    .unwrap(),
                meta: SnapshotMeta {
                    metapath: BitString::from_bytes(b"snapshot.der").unwrap(),
                    length: 0,
                    version: 0,
                    hashes: Default::default(),
                },
                spec_version: BitString::from_bytes(b"1.0").unwrap(),
                version: 0,
            },
        }
    }
}

impl TimestampBuilder {
    /// Add a snapshot file to the timestamp file.
    pub fn with_snapshot(mut self, metapath: &str, snapshot: &Signed<Snapshot>) -> Self {
        let encoded_snapshot = snapshot.to_der().unwrap();
        let hash = Hash::from_sha256_bytes(
            &<Sha256 as Digest>::new()
                .chain_update(encoded_snapshot)
                .finalize()
                .into(),
        );
        let length = snapshot
            .encoded_len()
            .expect("failed to get encoded length");
        self.inner.meta.metapath = BitString::from_bytes(metapath.as_bytes()).unwrap();
        self.inner.meta.length = Into::<u32>::into(length).into();
        self.inner.meta.hashes = [hash].to_vec();
        self.inner.meta.version = snapshot.signed.version;
        self
    }

    /// Set the expiration date of the timestamp role to this [UTC date](https://en.wikipedia.org/wiki/Coordinated_Universal_Time).
    pub fn with_expiration_utc(
        mut self,
        year: u16,
        month: u8,
        day: u8,
        hour: u8,
        minutes: u8,
        seconds: u8,
    ) -> Self {
        self.inner.expires = UtcTime::from_date_time(
            DateTime::new(year, month, day, hour, minutes, seconds).unwrap(),
        )
        .unwrap();
        self
    }

    /// Set the version of the timestamp file. Has to increase between iterations.
    pub fn with_version(mut self, version: Version) -> Self {
        self.inner.version = version;
        self
    }

    /// Finish the construction.
    pub fn build(self) -> Timestamp {
        self.inner
    }
}

pub struct SnapshotBuilder {
    inner: Snapshot,
}

impl Default for SnapshotBuilder {
    fn default() -> Self {
        SnapshotBuilder {
            inner: Snapshot {
                expires: UtcTime::from_date_time(DateTime::new(1970, 1, 1, 0, 0, 0).unwrap())
                    .unwrap(),
                meta: Default::default(),
                spec_version: BitString::from_bytes(b"1.0").unwrap(),
                version: 0,
            },
        }
    }
}

impl SnapshotBuilder {
    /// Set the expiration date of the snapshot role to this [UTC date](https://en.wikipedia.org/wiki/Coordinated_Universal_Time).
    pub fn with_expiration_utc(
        mut self,
        year: u16,
        month: u8,
        day: u8,
        hour: u8,
        minutes: u8,
        seconds: u8,
    ) -> Self {
        self.inner.expires = UtcTime::from_date_time(
            DateTime::new(year, month, day, hour, minutes, seconds).unwrap(),
        )
        .unwrap();
        self
    }

    /// Set the version of the snapshot file. Has to increase between iterations.
    pub fn with_version(mut self, version: Version) -> Self {
        self.inner.version = version;
        self
    }
    pub fn with_meta(mut self, metapath: &[u8], data: &[u8], version: Version) -> Self {
        let hash = &<Sha256 as Digest>::new()
            .chain_update(data)
            .finalize()
            .into();
        self.inner.meta.push(SnapshotMeta {
            metapath: BitString::from_bytes(metapath).unwrap(),
            hashes: [Hash::from_sha256_bytes(hash)].to_vec(),
            length: data.len() as u64,
            version,
        });

        self
    }
    pub fn build(self) -> Snapshot {
        self.inner
    }
}

pub struct TargetsBuilder {
    inner: Targets,
}

impl Default for TargetsBuilder {
    fn default() -> Self {
        TargetsBuilder {
            inner: Targets {
                expires: UtcTime::from_date_time(DateTime::new(1970, 1, 1, 0, 0, 0).unwrap())
                    .unwrap(),
                spec_version: BitString::from_bytes(b"1.0").unwrap(),
                version: 0,
                targets: Default::default(),
                delegations: Default::default(),
            },
        }
    }
}

impl TargetsBuilder {
    /// Add target file to the targets role.
    pub fn with_target(mut self, name: &[u8], target_file: &[u8]) -> Self {
        let hash = &<Sha256 as Digest>::new()
            .chain_update(target_file)
            .finalize()
            .into();
        let target = Target {
            name: BitString::from_bytes(name).unwrap(),
            value: TargetValue {
                length: Some(target_file.len() as u64),
                hashes: [Hash::from_sha256_bytes(hash)].to_vec(),
                custom: None,
            },
        };
        self.inner.targets.push(target);
        self
    }

    /// Delegations are not implemented.
    pub fn with_delegation(self, _delegation: Delegation) -> Self {
        unimplemented!("delegations are not implemented")
    }

    /// Set the expiration date of the targets role to this [UTC date](https://en.wikipedia.org/wiki/Coordinated_Universal_Time).
    pub fn with_expiration_utc(
        mut self,
        year: u16,
        month: u8,
        day: u8,
        hour: u8,
        minutes: u8,
        seconds: u8,
    ) -> Self {
        self.inner.expires = UtcTime::from_date_time(
            DateTime::new(year, month, day, hour, minutes, seconds).unwrap(),
        )
        .unwrap();
        self
    }

    /// Set the version of the targets file. Has to increase between iterations.
    pub fn with_version(mut self, version: Version) -> Self {
        self.inner.version = version;
        self
    }

    /// Finish the construction.
    pub fn build(self) -> Targets {
        self.inner
    }
}

#[cfg(test)]
mod test {
    use crate::builder::RootBuilder;
    use alloc::vec;
    use der::asn1::{BitString, UtcTime};
    use der::Decode;
    use ed25519_dalek::SigningKey;
    use rand_core::OsRng;
    use spki::{EncodePublicKey, SubjectPublicKeyInfoOwned};
    use tuf_no_std_der::root::Root;
    use tuf_no_std_der::Role;

    #[test]
    fn test_root_builder() {
        let mut csprng = OsRng;
        let root_key: SigningKey = SigningKey::generate(&mut csprng);
        let root_pub_spki = SubjectPublicKeyInfoOwned::from_der(
            root_key
                .verifying_key()
                .to_public_key_der()
                .unwrap()
                .as_bytes(),
        )
        .unwrap();
        let root_key_id = root_pub_spki.fingerprint_bytes().unwrap();

        let output = RootBuilder::default()
            .with_key(root_pub_spki.clone())
            .with_role(Role {
                name: BitString::from_bytes(b"root").unwrap(),
                keyids: vec![BitString::from_bytes(&root_key_id).unwrap()],
                threshold: 1,
            })
            .with_expiration_utc(2023, 1, 1, 1, 1, 1)
            .with_version(1)
            .build();

        let expected = Root {
            consistent_snapshot: false,
            expires: UtcTime::from_date_time(der::DateTime::new(2023, 1, 1, 1, 1, 1).unwrap())
                .unwrap(),
            keys: vec![root_pub_spki],
            roles: vec![Role {
                keyids: vec![BitString::from_bytes(&root_key_id).unwrap()],
                threshold: 1,
                name: BitString::from_bytes(b"root").unwrap(),
            }],
            spec_version: BitString::from_bytes(b"1.0").unwrap(),
            version: 1,
        };
        assert_eq!(expected, output);
    }
}
