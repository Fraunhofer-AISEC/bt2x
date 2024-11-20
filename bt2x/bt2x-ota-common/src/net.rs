use embassy_net::driver::Driver;
use embassy_net::tcp::TcpSocket;
use embassy_net::{IpEndpoint, Stack};

#[cfg(feature = "defmt")]
use defmt::error;
use embassy_time::Duration;
use embedded_storage::nor_flash::NorFlash;
#[cfg(feature = "log")]
use log::{debug, error, info, warn};
use sha2::Digest;
#[cfg(feature = "tracing")]
use tracing::error;
use tuf_no_std::common::remote::{TransportError, TufTransportAsync};

use crate::TufMessage;

/// Implementation for the networking functionality required for TUF and BT²X for embassy_net implementations.
pub struct Transport<'a, D: Driver> {
    /// The address of the remote server.
    pub server: IpEndpoint,
    /// The network stack that is used to communicate with the remote host.
    pub network_stack: &'a Stack<D>,
}

impl<'a, D: Driver> Transport<'a, D> {
    /// Fetch the TUF role with the specified version number.
    async fn fetch_role<'o>(
        &self,
        version: Option<core::num::NonZeroU64>,
        out: &'o mut [u8],
        role: TufMessage,
    ) -> Result<&'o [u8], TransportError> {
        let mut rx_buffer = [0; 4096];
        let mut tx_buffer = [0; 4096];
        let mut socket = TcpSocket::new(self.network_stack, &mut rx_buffer, &mut tx_buffer);
        socket.set_timeout(Some(Duration::from_secs(10)));
        socket
            .connect(self.server)
            .await
            .map_err(|_| TransportError::ConnectError)?;
        let (reader, writer) = socket.split();
        let bytes_received = crate::fetch_tuf_role(reader, writer, out, role, version)
            .await
            .map_err(|err| {
                error!("had error while fetching: {:?}", err);
                TransportError::FetchError
            })?;
        socket.close();
        Ok(&out[..bytes_received])
    }
}

impl<'a, D: Driver> TufTransportAsync for Transport<'a, D> {
    async fn fetch_root<'o>(
        &self,
        version: core::num::NonZeroU64,
        out: &'o mut [u8],
    ) -> Result<&'o [u8], TransportError> {
        self.fetch_role(Some(version), out, TufMessage::Root).await
    }

    async fn fetch_timestamp<'o>(
        &self,
        out: &'o mut [u8],
    ) -> Result<&'o [u8], tuf_no_std::common::remote::TransportError> {
        self.fetch_role(None, out, TufMessage::Timestamp).await
    }

    async fn fetch_snapshot<'o>(
        &self,
        out: &'o mut [u8],
    ) -> Result<&'o [u8], tuf_no_std::common::remote::TransportError> {
        self.fetch_role(None, out, TufMessage::Snapshot).await
    }

    async fn fetch_targets<'o>(
        &self,
        out: &'o mut [u8],
    ) -> Result<&'o [u8], tuf_no_std::common::remote::TransportError> {
        self.fetch_role(None, out, TufMessage::Targets).await
    }

    async fn fetch_target_file<'o>(
        &self,
        metapath: &[u8],
        out: &'o mut [u8],
    ) -> Result<&'o [u8], tuf_no_std::common::remote::TransportError> {
        let mut rx_buffer = [0; 4096];
        let mut tx_buffer = [0; 4096];
        let mut socket = TcpSocket::new(self.network_stack, &mut rx_buffer, &mut tx_buffer);
        socket.set_timeout(Some(Duration::from_secs(10)));
        socket
            .connect(self.server)
            .await
            .map_err(|_| TransportError::ConnectError)?;
        let (reader, writer) = socket.split();
        let bytes_received = crate::fetch_tuf_file(reader, writer, out, metapath)
            .await
            .map_err(|err| {
                error!("had error while fetching: {:?}", err);
                TransportError::FetchError
            })?;
        Ok(&out[..bytes_received])
    }
}

impl<'a, D: Driver> Transport<'a, D> {
    /// Fetch the binary with the given identifier and write it to memory.
    /// This is only feasible for small binaries that fit into the RAM.
    /// In most cases you should prefer the `fetch_binary_flash` function.
    pub async fn fetch_binary<'o>(
        &self,
        identifier: &[u8],
        out: &'o mut [u8],
    ) -> Result<&'o [u8], tuf_no_std::common::remote::TransportError> {
        let mut rx_buffer = [0; 4096];
        let mut tx_buffer = [0; 4096];
        let mut socket = TcpSocket::new(self.network_stack, &mut rx_buffer, &mut tx_buffer);
        socket.set_timeout(Some(Duration::from_secs(10)));
        socket
            .connect(self.server)
            .await
            .map_err(|_| TransportError::ConnectError)?;
        let (reader, writer) = socket.split();
        let bytes_received = crate::fetch_binary(reader, writer, out, identifier)
            .await
            .map_err(|err| {
                error!("had error while fetching: {:?}", err);
                TransportError::FetchError
            })?;
        Ok(&out[..bytes_received])
    }

    /// Fetch the binary with the given identifier and write it to the flash storage.
    /// This also calculates a digest of the binary during download with the algorithm specified in `H`.
    /// On success it returns the number of bytes that were written and the digest.
    pub async fn fetch_binary_flash<H: Digest>(
        &self,
        identifier: &[u8],
        out: impl NorFlash,
    ) -> Result<(usize, H), tuf_no_std::common::remote::TransportError> {
        let mut rx_buffer = [0; 4096];
        let mut tx_buffer = [0; 4096];
        let mut socket = TcpSocket::new(self.network_stack, &mut rx_buffer, &mut tx_buffer);
        socket.set_timeout(Some(Duration::from_secs(10)));
        socket
            .connect(self.server)
            .await
            .map_err(|_| TransportError::ConnectError)?;
        let (reader, writer) = socket.split();
        let bytes_received = crate::fetch_binary_flash(reader, writer, out, identifier)
            .await
            .map_err(|err| {
                error!("had error while fetching: {:?}", err);
                TransportError::FetchError
            })?;
        Ok(bytes_received)
    }

    /// Fetches the signature for the given identifier.
    pub async fn fetch_signature<'o>(
        &self,
        identifier: &[u8],
        out: &'o mut [u8],
    ) -> Result<&'o [u8], tuf_no_std::common::remote::TransportError> {
        let mut rx_buffer = [0; 4096];
        let mut tx_buffer = [0; 4096];
        let mut socket = TcpSocket::new(self.network_stack, &mut rx_buffer, &mut tx_buffer);
        socket.set_timeout(Some(Duration::from_secs(10)));
        socket
            .connect(self.server)
            .await
            .map_err(|_| TransportError::ConnectError)?;
        let (reader, writer) = socket.split();
        let bytes_received = crate::fetch_signature(reader, writer, out, identifier)
            .await
            .map_err(|err| {
                error!("had error while fetching: {:?}", err);
                TransportError::FetchError
            })?;
        Ok(&out[..bytes_received])
    }
}
