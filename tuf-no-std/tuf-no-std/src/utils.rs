#[cfg(any(test, feature = "memory-transport"))]
use der::asn1::BitString;
#[cfg(any(test, feature = "memory-transport"))]
use spki::SubjectPublicKeyInfoOwned;
#[cfg(any(test, feature = "memory-transport"))]
use tuf_no_std_common::common::Threshold;
#[cfg(any(test, feature = "memory-transport"))]
use tuf_no_std_der::{KeyId, Role};

#[cfg(any(test, feature = "memory-transport"))]
use alloc::vec::Vec;
#[cfg(any(test, feature = "memory-transport"))]
use core::num::NonZeroU64;

#[cfg(any(test, feature = "memory-transport"))]
use tuf_no_std_common::remote::TufTransport;

use tuf_no_std_common::storage::TufStorage;
use tuf_no_std_common::TufError;

#[cfg(test)]
pub(crate) fn spki_from_signing_key(
    key: &tuf_no_std_common::crypto::sign::SigningKey,
) -> SubjectPublicKeyInfoOwned {
    key.as_spki().unwrap()
}

#[cfg(test)]
pub(crate) fn build_role(
    name: &str,
    spkis: &[SubjectPublicKeyInfoOwned],
    threshold: Threshold,
) -> Role {
    Role {
        keyids: spkis
            .iter()
            .map(|spki| KeyId::from_bytes(spki.fingerprint_bytes().unwrap().as_slice()).unwrap())
            .collect(),
        threshold,
        name: BitString::from_bytes(name.as_bytes()).unwrap(),
    }
}

#[cfg(test)]
#[derive(Default, Clone)]
pub(crate) struct MockStorage {
    pub root: Vec<u8>,
    pub uncommitted_root: Option<Vec<u8>>,
    pub timestamp: Option<Vec<u8>>,
    pub snapshot: Option<Vec<u8>>,
    pub targets: Option<Vec<u8>>,
}

#[cfg(test)]
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
        let data = self.timestamp.as_deref()?;
        let out = &mut out[..data.len()];
        out.copy_from_slice(data);
        Some(out)
    }

    fn current_snapshot(&self) -> Option<&[u8]> {
        self.snapshot.as_ref().map(AsRef::as_ref)
    }

    fn current_snapshot_copy<'o>(&self, out: &'o mut [u8]) -> Option<&'o [u8]> {
        let data = self.snapshot.as_deref()?;
        let out = &mut out[..data.len()];
        out.copy_from_slice(data);
        Some(out)
    }

    fn current_targets(&self) -> Option<&[u8]> {
        self.targets.as_ref().map(AsRef::as_ref)
    }
}

#[cfg(any(test, feature = "memory-transport"))]
#[derive(Default, Clone)]
pub struct MockTransport<V: Sized, K> {
    pub roots: heapless::FnvIndexMap<NonZeroU64, V, 2>,
    pub timestamp: V,
    pub snapshot: V,
    pub targets: V,
    pub target_files: heapless::FnvIndexMap<K, V, 8>,
}

#[cfg(any(test, feature = "memory-transport"))]
fn check_size_and_copy<'o>(
    src: &[u8],
    out: &'o mut [u8],
) -> Result<&'o [u8], tuf_no_std_common::remote::TransportError> {
    if out.len() < src.len() {
        return Err(tuf_no_std_common::remote::TransportError::FetchError);
    }
    let (out_buf, _) = out.split_at_mut(src.len());
    out_buf.copy_from_slice(src);
    Ok(out_buf)
}

#[cfg(any(test, feature = "memory-transport"))]
impl<V: Sized + AsRef<[u8]>, K: AsRef<[u8]>> TufTransport for MockTransport<V, K> {
    fn fetch_root<'o>(
        &self,
        version: NonZeroU64,
        out: &'o mut [u8],
    ) -> Result<&'o [u8], tuf_no_std_common::remote::TransportError> {
        let root_file = self
            .roots
            .get(&version)
            .ok_or(tuf_no_std_common::remote::TransportError::FetchError)?;
        check_size_and_copy(root_file.as_ref(), out)
    }

    fn fetch_timestamp<'o>(
        &self,
        out: &'o mut [u8],
    ) -> Result<&'o [u8], tuf_no_std_common::remote::TransportError> {
        check_size_and_copy(self.timestamp.as_ref(), out)
    }

    fn fetch_snapshot<'o>(
        &self,
        out: &'o mut [u8],
    ) -> Result<&'o [u8], tuf_no_std_common::remote::TransportError> {
        check_size_and_copy(self.snapshot.as_ref(), out)
    }

    fn fetch_targets<'o>(
        &self,
        out: &'o mut [u8],
    ) -> Result<&'o [u8], tuf_no_std_common::remote::TransportError> {
        check_size_and_copy(self.targets.as_ref(), out)
    }

    fn fetch_target_file<'o>(
        &self,
        metapath: &[u8],
        out: &'o mut [u8],
    ) -> Result<&'o [u8], tuf_no_std_common::remote::TransportError> {
        self.target_files
            .iter()
            .find(|(p, _)| p.as_ref() == metapath)
            .ok_or(tuf_no_std_common::remote::TransportError::FetchError)
            .and_then(|(_, f)| check_size_and_copy(f.as_ref(), out))
    }
}

#[cfg(all(feature = "async", any(test, feature = "memory-transport")))]
impl<V: Sized + AsRef<[u8]>, K: AsRef<[u8]>> tuf_no_std_common::remote::TufTransportAsync
    for MockTransport<V, K>
{
    async fn fetch_root<'o>(
        &self,
        version: NonZeroU64,
        out: &'o mut [u8],
    ) -> Result<&'o [u8], tuf_no_std_common::remote::TransportError> {
        <Self as TufTransport>::fetch_root(self, version, out)
    }

    async fn fetch_timestamp<'o>(
        &self,
        out: &'o mut [u8],
    ) -> Result<&'o [u8], tuf_no_std_common::remote::TransportError> {
        <Self as TufTransport>::fetch_timestamp(self, out)
    }

    async fn fetch_snapshot<'o>(
        &self,
        out: &'o mut [u8],
    ) -> Result<&'o [u8], tuf_no_std_common::remote::TransportError> {
        <Self as TufTransport>::fetch_snapshot(self, out)
    }

    async fn fetch_targets<'o>(
        &self,
        out: &'o mut [u8],
    ) -> Result<&'o [u8], tuf_no_std_common::remote::TransportError> {
        <Self as TufTransport>::fetch_targets(self, out)
    }

    async fn fetch_target_file<'o>(
        &self,
        metapath: &[u8],
        out: &'o mut [u8],
    ) -> Result<&'o [u8], tuf_no_std_common::remote::TransportError> {
        <Self as TufTransport>::fetch_target_file(self, metapath, out)
    }
}

/// In-memory implementation for TUF storage. Stores the files for the root, timestamp, snapshot and targets roles.
pub struct MemoryStorage {
    pub root: heapless::Vec<u8, 2048>,
    pub uncommitted_root: Option<heapless::Vec<u8, 2048>>,
    pub timestamp: Option<heapless::Vec<u8, 512>>,
    pub snapshot: Option<heapless::Vec<u8, 512>>,
    pub targets: Option<heapless::Vec<u8, 512>>,
}

fn try_copy_from_slice(src: impl AsRef<[u8]>, dst: &mut [u8]) -> Result<&[u8], ()> {
    let src = src.as_ref();
    if dst.len() < src.len() {
        return Err(());
    }
    let dst = &mut dst[..src.len()];
    dst.copy_from_slice(src);
    Ok(dst)
}

impl TufStorage for MemoryStorage {
    fn delete_timestamp_metadata(&mut self) {
        self.timestamp = None;
    }

    fn delete_snapshot_metadata(&mut self) {
        self.snapshot = None;
    }

    fn persist_root(&mut self, data: &[u8]) -> Result<(), crate::common::TufError> {
        self.uncommitted_root = Some(
            heapless::Vec::<_, 2048>::from_slice(data)
                .map_err(|_| TufError::CouldNotPersistRootMetadata)?,
        );
        Ok(())
    }

    fn persist_timestamp(&mut self, data: &[u8]) -> Result<(), crate::common::TufError> {
        self.timestamp = Some(
            heapless::Vec::<_, 512>::from_slice(data)
                .map_err(|_| TufError::CouldNotPersistRootMetadata)?,
        );
        Ok(())
    }

    fn persist_snapshot(&mut self, data: &[u8]) -> Result<(), crate::common::TufError> {
        self.snapshot = Some(
            heapless::Vec::<_, 512>::from_slice(data)
                .map_err(|_| TufError::CouldNotPersistRootMetadata)?,
        );
        Ok(())
    }

    fn persist_targets(&mut self, data: &[u8]) -> Result<(), crate::common::TufError> {
        self.targets = Some(
            heapless::Vec::<_, 512>::from_slice(data)
                .map_err(|_| TufError::CouldNotPersistRootMetadata)?,
        );
        Ok(())
    }

    fn commit_root(&mut self) -> Result<(), crate::common::TufError> {
        self.root = self
            .uncommitted_root
            .take()
            .ok_or(TufError::InternalError)?;
        Ok(())
    }

    fn current_root(&self) -> &[u8] {
        self.root.as_ref()
    }

    fn current_root_copy<'o>(&self, out: &'o mut [u8]) -> &'o [u8] {
        try_copy_from_slice(&self.root, out).expect("this should be replaced with a Result")
    }

    fn current_uncommitted_root_copy<'o>(&self, out: &'o mut [u8]) -> Option<&'o [u8]> {
        self.uncommitted_root
            .as_ref()
            .and_then(|data| try_copy_from_slice(data, out).ok())
    }

    fn current_uncommitted_root(&self) -> Option<&[u8]> {
        self.uncommitted_root.as_ref().map(AsRef::as_ref)
    }

    fn current_timestamp(&self) -> Option<&[u8]> {
        self.timestamp.as_ref().map(AsRef::as_ref)
    }

    fn current_timestamp_copy<'o>(&self, out: &'o mut [u8]) -> Option<&'o [u8]> {
        self.timestamp
            .as_ref()
            .and_then(|data| try_copy_from_slice(data, out).ok())
    }

    fn current_snapshot(&self) -> Option<&[u8]> {
        self.snapshot.as_ref().map(AsRef::as_ref)
    }

    fn current_snapshot_copy<'o>(&self, out: &'o mut [u8]) -> Option<&'o [u8]> {
        self.snapshot
            .as_ref()
            .and_then(|data| try_copy_from_slice(data, out).ok())
    }

    fn current_targets(&self) -> Option<&[u8]> {
        self.targets.as_ref().map(AsRef::as_ref)
    }
}

#[cfg(test)]
mod test {
    use super::try_copy_from_slice;

    #[test]
    fn test_try_copy_from_slice() {
        let src = [1, 2];
        let mut dst_0 = [0u8; 0];
        let mut dst_1 = [0u8; 1];
        let mut dst_2 = [0u8; 2];
        let mut dst_3 = [0u8; 3];
        let mut dst_4 = [0u8; 4];
        assert_eq!(try_copy_from_slice(src, &mut dst_0), Err(()));
        assert_eq!(try_copy_from_slice(src, &mut dst_1), Err(()));
        assert_eq!(try_copy_from_slice(src, &mut dst_2), Ok([1, 2].as_slice()));
        assert_eq!(try_copy_from_slice(src, &mut dst_3), Ok([1, 2].as_slice()));
        assert_eq!(try_copy_from_slice(src, &mut dst_4), Ok([1, 2].as_slice()));
    }
}
