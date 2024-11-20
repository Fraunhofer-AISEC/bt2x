use crate::TufError;

/// A trait to abstract file storage for TUF.
pub trait TufStorage {
    /// Delete currently stored timestamp metadata.
    fn delete_timestamp_metadata(&mut self);
    /// Delete currently stored snapshot metadata.
    fn delete_snapshot_metadata(&mut self);
    /// Persistently store the provided root file. This does overwrite the previous root file, this happens when it is committed.
    fn persist_root(&mut self, data: &[u8]) -> Result<(), TufError>;
    /// Persistently store the provided timestamp file.
    fn persist_timestamp(&mut self, data: &[u8]) -> Result<(), TufError>;
    /// Persistently store the provided snapshot file.
    fn persist_snapshot(&mut self, data: &[u8]) -> Result<(), TufError>;
    /// Persistently store the provided targets file.
    fn persist_targets(&mut self, data: &[u8]) -> Result<(), TufError>;
    /// Update the root file to the last root file that was persisted.
    fn commit_root(&mut self) -> Result<(), TufError>;
    fn current_root(&self) -> &[u8];
    fn current_root_copy<'o>(&self, out: &'o mut [u8]) -> &'o [u8];
    fn current_uncommitted_root_copy<'o>(&self, out: &'o mut [u8]) -> Option<&'o [u8]>;
    fn current_uncommitted_root(&self) -> Option<&[u8]>;
    fn current_timestamp(&self) -> Option<&[u8]>;
    fn current_timestamp_copy<'o>(&self, out: &'o mut [u8]) -> Option<&'o [u8]>;
    fn current_snapshot(&self) -> Option<&[u8]>;
    fn current_snapshot_copy<'o>(&self, out: &'o mut [u8]) -> Option<&'o [u8]>;
    fn current_targets(&self) -> Option<&[u8]>;
}

pub enum StorageState {
    Empty,
    NonEmpty(usize),
}
/*
pub struct StackStorage<'a, const N: usize> {
    buf: [[u8; N]; 5],
    ref_storage: RefStorage<'a>,
}

impl<'a, const N: usize> StackStorage<'a, N> {
    pub fn new(buf: &'a mut [u8; N]) -> Self {
        let (root, rest) = buf.split_at_mut(N / 5);
        let (uncommitted_root, rest) = rest.split_at_mut(N / 5);
        let (timestamp, rest) = rest.split_at_mut(N / 5);
        let (snapshot, rest) = rest.split_at_mut(N / 5);
        let (targets, _) = rest.split_at_mut(N / 5);
        StackStorage {
            buf: [[0u8; N]; 5],
            ref_storage: RefStorage {
                root: (0, root),
                uncommitted_root: (StorageState::Empty, uncommitted_root),
                timestamp: (StorageState::Empty, timestamp),
                snapshot: (StorageState::Empty, snapshot),
                targets: (StorageState::Empty, targets),
            },
        }
    }
}

impl<'a, const N: usize> Storage<'a> for StackStorage<'a, N> {
    fn delete_timestamp_metadata(&mut self) {
        self.ref_storage.delete_timestamp_metadata()
    }
    fn delete_snapshot_metadata(&mut self) {
        self.ref_storage.delete_snapshot_metadata()
    }
    fn persist_root(&mut self, data: &[u8]) -> Result<(), RootVerificationError> {
        self.ref_storage.persist_root(data)
    }
    fn persist_timestamp(&mut self, data: &[u8]) -> Result<(), RootVerificationError> {
        self.ref_storage.persist_timestamp(data)
    }
    fn persist_snapshot(&mut self, data: &[u8]) -> Result<(), RootVerificationError> {
        self.ref_storage.persist_snapshot(data)
    }
    fn persist_targets(&mut self, data: &[u8]) -> Result<(), RootVerificationError> {
        self.ref_storage.persist_targets(data)
    }
    fn commit_root(&mut self) -> Result<(), RootVerificationError> {
        self.ref_storage.commit_root()
    }
    fn current_root<'o>(&self, out: &'o mut [u8]) -> &'o [u8] {
        self.ref_storage.current_root(out)
    }
    fn current_uncommitted_root<'o>(&self, out: &'o mut [u8]) -> Option<&'o [u8]> {
        self.ref_storage.current_uncommitted_root(out)
    }
    fn current_timestamp<'o>(&self, out: &'o mut [u8]) -> Option<&'o [u8]> {
        self.ref_storage.current_timestamp(out)
    }
    fn current_snapshot<'o>(&self, out: &'o mut [u8]) -> Option<&'o [u8]> {
        self.ref_storage.current_snapshot(out)
    }
}

pub struct RefStorage<'a> {
    root: (usize, &'a mut [u8]),
    uncommitted_root: (StorageState, &'a mut [u8]),
    timestamp: (StorageState, &'a mut [u8]),
    snapshot: (StorageState, &'a mut [u8]),
    targets: (StorageState, &'a mut [u8]),
}

impl<'a> RefStorage<'a> {
    fn persist(dst: &mut (StorageState, &'a mut [u8]), src: &[u8]) -> Result<(), ()> {
        if src.len() > dst.1.len() {
            return Err(());
        }
        dst.1[..src.len()].copy_from_slice(src);
        dst.0 = StorageState::NonEmpty(src.len());
        Ok(())
    }
}

impl<'a> Storage for RefStorage<'a> {
    fn delete_timestamp_metadata(&mut self) {
        self.timestamp.1.zeroize();
        self.timestamp.0 = StorageState::Empty;
    }

    fn delete_snapshot_metadata(&mut self) {
        self.snapshot.1.zeroize();
        self.snapshot.0 = StorageState::Empty;
    }

    fn persist_root(&mut self, data: &[u8]) -> Result<(), RootVerificationError> {
        RefStorage::persist(&mut self.uncommitted_root, data)
            .map_err(|_| CouldNotPersistRootMetadata)
    }

    fn persist_timestamp(&mut self, data: &[u8]) -> Result<(), RootVerificationError> {
        RefStorage::persist(&mut self.timestamp, data).map_err(|_| CouldNotPersistRootMetadata)
    }

    fn persist_snapshot(&mut self, data: &[u8]) -> Result<(), RootVerificationError> {
        RefStorage::persist(&mut self.snapshot, data).map_err(|_| CouldNotPersistRootMetadata)
    }

    fn persist_targets(&mut self, data: &[u8]) -> Result<(), RootVerificationError> {
        RefStorage::persist(&mut self.targets, data).map_err(|_| CouldNotPersistRootMetadata)
    }

    fn commit_root(&mut self) -> Result<(), RootVerificationError> {
        let (StorageState::NonEmpty(size), data) = &self.uncommitted_root else {
            return Ok(());
        };
        if self.root.1.len() < *size {
            return Err(NotEnoughSpace);
        }
        self.root.1.zeroize();
        self.root.0 = *size;
        self.root.1[0..*size].copy_from_slice(data);
        Ok(())
    }

    fn current_root<'o>(&self, out: &'o mut [u8]) -> &'o [u8] {
        let out = &mut out[..self.root.0];
        let src = &self.root.1[..self.root.0];
        out.copy_from_slice(src);
        out
    }

    fn current_uncommitted_root<'o>(&self, out: &'o mut [u8]) -> Option<&'o [u8]> {
        let (StorageState::NonEmpty(size), data) = &self.uncommitted_root else {
            return None;
        };
        let out = &mut out[..*size];
        let src = &data[..*size];
        out.copy_from_slice(src);
        Some(out)
    }

    fn current_timestamp<'o>(&self, out: &'o mut [u8]) -> Option<&'o [u8]> {
        let (StorageState::NonEmpty(size), data) = &self.timestamp else {
            return None;
        };
        let out = &mut out[..*size];
        let src = &data[..*size];
        out.copy_from_slice(src);
        Some(out)
    }

    fn current_snapshot<'o>(&self, out: &'o mut [u8]) -> Option<&'o [u8]> {
        let (StorageState::NonEmpty(size), data) = &self.timestamp else {
            return None;
        };
        let out = &mut out[..*size];
        let src = &data[..*size];
        out.copy_from_slice(src);
        Some(out)
    }
}
*/
