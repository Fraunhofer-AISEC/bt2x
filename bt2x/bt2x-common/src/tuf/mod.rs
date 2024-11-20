use crate::error::Bt2XError;
use crate::sigstore_config::TufTargetNames;
use core::str;
use std::fs::OpenOptions;
use std::io::Read;
use std::path::{Path, PathBuf};
use tuf_no_std::remote::TransportError;
use tuf_no_std::utils::MemoryStorage;
use tuf_no_std::TufTransport;
use url::Url;

#[derive(Debug)]
pub struct SigstoreKeys {
    pub rekor_key: Vec<u8>,
    pub fulcio_cert: Vec<u8>,
    pub ctlog_key: Vec<u8>,
}

pub async fn load_tuf_filesystem(
    root: &Path,
    metadata_base_path: &Url,
    _targets_base_path: &Url,
    target_names: &TufTargetNames,
) -> Result<SigstoreKeys, Bt2XError> {
    let root = std::fs::read(root).expect("failed to read a root file at the providedd path");
    let mut storage = MemoryStorage {
        root: tuf_no_std::heapless::Vec::from_slice(&root).expect("root file > 2048 bytes"),
        snapshot: None,
        targets: None,
        timestamp: None,
        uncommitted_root: None,
    };
    let repository_path = metadata_base_path
        .to_file_path()
        .expect("did not provide a file path");
    let mut transport = FilesystemTransport { repository_path };
    let update_start = chrono::Utc::now().signed_duration_since(chrono::DateTime::UNIX_EPOCH);
    let update_start = update_start
        .to_std()
        .expect("failed to convert update start to std data type");
    let update_start = tuf_no_std::UtcTime::from_unix_duration(update_start)
        .expect("could not create update start timestamp");
    tuf_no_std::update_repo(&mut storage, &mut transport, 100, update_start)
        .map_err(Bt2XError::TufError)?;

    let mut rekor_buf = [0u8; 1024];
    let mut fulcio_buf = [0u8; 1024];
    let mut ctlog_buf = [0u8; 1024];
    let rekor_key = tuf_no_std::fetch_and_verify_target_file(
        &mut storage,
        &mut transport,
        target_names.rekor.as_bytes(),
        &mut rekor_buf,
    )
    .map_err(Bt2XError::TufError)?;
    let fulcio_crt = tuf_no_std::fetch_and_verify_target_file(
        &mut storage,
        &mut transport,
        target_names.fulcio.as_bytes(),
        &mut fulcio_buf,
    )
    .map_err(Bt2XError::TufError)?;
    let ctlog_key = tuf_no_std::fetch_and_verify_target_file(
        &mut storage,
        &mut transport,
        target_names.ctlog.as_bytes(),
        &mut ctlog_buf,
    )
    .map_err(Bt2XError::TufError)?;

    Ok(SigstoreKeys {
        ctlog_key: ctlog_key.to_vec(),
        fulcio_cert: fulcio_crt.to_vec(),
        rekor_key: rekor_key.to_vec(),
    })
}

#[derive(Debug)]
pub struct FilesystemTransport {
    repository_path: PathBuf,
}

impl FilesystemTransport {
    fn fetch_impl<'o>(
        &self,
        path: &PathBuf,
        out: &'o mut [u8],
    ) -> Result<&'o [u8], tuf_no_std::remote::TransportError> {
        OpenOptions::new()
            .read(true)
            .open(path)
            .map_err(|_| TransportError::FetchError)
            .and_then(|mut f| f.read(out).map_err(|_| TransportError::FetchError))
            .map(|n| &out[..n])
    }
}

impl TufTransport for FilesystemTransport {
    fn fetch_root<'o>(
        &self,
        version: std::num::NonZeroU64,
        out: &'o mut [u8],
    ) -> Result<&'o [u8], tuf_no_std::remote::TransportError> {
        self.fetch_impl(
            &self.repository_path.join(format!("{version}.root.der")),
            out,
        )
    }

    fn fetch_timestamp<'o>(
        &self,
        out: &'o mut [u8],
    ) -> Result<&'o [u8], tuf_no_std::remote::TransportError> {
        self.fetch_impl(&self.repository_path.join("1.timestamp.der"), out)
    }

    fn fetch_snapshot<'o>(
        &self,
        out: &'o mut [u8],
    ) -> Result<&'o [u8], tuf_no_std::remote::TransportError> {
        self.fetch_impl(&self.repository_path.join("1.snapshot.der"), out)
    }

    fn fetch_targets<'o>(
        &self,
        out: &'o mut [u8],
    ) -> Result<&'o [u8], tuf_no_std::remote::TransportError> {
        self.fetch_impl(&self.repository_path.join("1.targets.der"), out)
    }

    fn fetch_target_file<'o>(
        &self,
        metapath: &[u8],
        out: &'o mut [u8],
    ) -> Result<&'o [u8], tuf_no_std::remote::TransportError> {
        let metapath = PathBuf::from(str::from_utf8(metapath).unwrap());
        if metapath.is_absolute() {
            panic!("provided absolute path")
        }
        self.fetch_impl(&self.repository_path.join("targets").join(metapath), out)
    }
}
