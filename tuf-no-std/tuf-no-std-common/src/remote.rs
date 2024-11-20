use core::num::NonZeroU64;

#[derive(Debug, Clone)]
pub enum TransportError {
    /// Failed to fetch the specific file. For instance, if it was not present there.
    FetchError,
    /// Failed to connect to the remote host.
    ConnectError,
}

/// Trait that is used represent the communication with a remote TUF repository.
pub trait TufTransport {
    fn fetch_root<'o>(
        &self,
        version: NonZeroU64,
        out: &'o mut [u8],
    ) -> Result<&'o [u8], TransportError>;
    /// Fetches the most recent timestamp provided by the remote.
    fn fetch_timestamp<'o>(&self, out: &'o mut [u8]) -> Result<&'o [u8], TransportError>;
    /// Fetches the most recent snapshot provided by the remote.
    fn fetch_snapshot<'o>(&self, out: &'o mut [u8]) -> Result<&'o [u8], TransportError>;
    /// Fetches the most recent targets provided by the remote.
    fn fetch_targets<'o>(&self, out: &'o mut [u8]) -> Result<&'o [u8], TransportError>;
    /// Fetches the target file with the name provided in `metapath`.
    fn fetch_target_file<'o>(
        &self,
        metapath: &[u8],
        out: &'o mut [u8],
    ) -> Result<&'o [u8], TransportError>;
}

/// Async version of the trait `TufTransport` trait that is used represent the communication with a remote TUF repository.
#[allow(async_fn_in_trait)]
#[cfg(feature = "async")]
pub trait TufTransportAsync {
    /// Fetches the root file with the given version number.
    async fn fetch_root<'o>(
        &self,
        version: NonZeroU64,
        out: &'o mut [u8],
    ) -> Result<&'o [u8], TransportError>;
    /// Fetches the most recent timestamp provided by the remote.
    async fn fetch_timestamp<'o>(&self, out: &'o mut [u8]) -> Result<&'o [u8], TransportError>;
    /// Fetches the most recent snapshot provided by the remote.
    async fn fetch_snapshot<'o>(&self, out: &'o mut [u8]) -> Result<&'o [u8], TransportError>;
    /// Fetches the most recent targets provided by the remote.
    async fn fetch_targets<'o>(&self, out: &'o mut [u8]) -> Result<&'o [u8], TransportError>;
    /// Fetches the target file with the name provided in `metapath`.
    async fn fetch_target_file<'o>(
        &self,
        metapath: &[u8],
        out: &'o mut [u8],
    ) -> Result<&'o [u8], TransportError>;
}
