#![cfg_attr(all(not(test), not(feature = "mock_flash")), no_std)]
//! This crate contains the client side implementation for the OTA updates.
//! It is implemented using a custom TCP-based request-response protocol.
//! It works roughly in the following way:
//! - general structure of a message is `<Header>[<Data>]`,
//! - handling the segmentation is left to TCP,
//! - the header specifies what type of message it is and what the rest of the header and message contains.
//!
//! Refer to the [Header] and the code for more information.
//!
//! ## Example
//!
//! ```ignore
//! use tuf_no_std::TufTransportAsync;
//!
//! // initialize_stack is not a real function, set up your network stack accordingly.
//! let stack = initialize_stack();
//! let mut transport = Transport {
//!     network_stack: &stack,
//!     server: IpEndpoint::new(
//!         "192.168.1.2",
//!         50000,
//!     ),
//! };
//!
//! let mut buf = [0u8; 4096];
//! let binary = transport.fetch_binary(
//!     b"binary-identifer",
//!     &mut buf,
//! ).expect("failed to fetch binary");
//!
//! ```

extern crate alloc;

pub mod flash;
pub mod net;
/// TufTransportAsync implementation for `embassy_net` network stacks.
pub use net::Transport;

use bitfield::bitfield;
use core::num::NonZeroU64;
#[cfg(feature = "defmt")]
use defmt::{debug, warn};
#[cfg(feature = "log")]
use log::{debug, error, info, warn};
#[cfg(feature = "tracing")]
use tracing::{debug, warn};

use embedded_io_async::{Read, Write};
use embedded_storage::nor_flash::NorFlash;
use sha2::Digest;

#[repr(u8)]
#[derive(Debug, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum TufMessage {
    Root = 0,
    Timestamp = 1,
    Snapshot = 2,
    Targets = 3,
    TargetFile = 4,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum MessageClass {
    Request = 0,
    Response = 1,
    Error = 2,
    Ok = 3,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum MessageType {
    Binary = 0,
    Signature = 1,
    Tuf = 2,
    Rfc3161 = 3,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum ErrorType {
    NotEnoughSpace = 1,
}

#[derive(Debug, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Error {
    Write,
    Read,
    Flush,
    WrongMsgType {
        expected: TufMessage,
        got: TufMessage,
    },
    InvalidVarIntLen(u8),
    FailedToDecodeVarInt,
    FailedToEncodeVarInt,
    OutBufTooSmall {
        supplied: usize,
        required: usize,
    },
    RemoteClosed,
    ReceivedInvalidMessage,
    InvalidMessageClass(u128),
    InvalidMessageType(u128),
    InvalidContentType(u128),
}

pub async fn fetch_tuf_role(
    reader: impl Read,
    writer: impl Write,
    out: &mut [u8],
    role: TufMessage,
    version: Option<NonZeroU64>,
) -> Result<usize, Error> {
    let version = version.unwrap_or(NonZeroU64::new(1).unwrap());
    //debug!("fetching {role:?}");

    fetch_file(
        reader,
        writer,
        out,
        MessageClass::Request,
        MessageType::Tuf,
        role as u128,
        Some(version.get() as u128),
        None,
    )
    .await
}

pub async fn fetch_file(
    mut reader: impl Read,
    mut writer: impl Write,
    out: &mut [u8],
    message_class: MessageClass,
    message_type: MessageType,
    content_type: u128,
    header_data: Option<u128>,
    body: Option<&[u8]>,
) -> Result<usize, Error> {
    let mut header = Header(0);
    header.set_message_class(message_class as u128);
    header.set_message_type(message_type as u128);
    header.set_content_type(content_type);
    if let Some(header_data) = header_data {
        header.set_header_data(header_data);
    }
    header.set_content_len(body.map(|b| b.len()).unwrap_or_default() as u128);
    debug!("content len: {}", header.content_len());

    debug!("writing request header to socket");
    writer.write(&header.0.to_be_bytes()).await.map_err(|_| {
        //error!("had error while writing: {:?}", err);
        Error::Write
    })?;

    if let Some(body) = body {
        debug!("writing request data to socket");
        writer.write(body).await.map_err(|_| {
            //error!("had error while writing: {:?}", err);
            Error::Write
        })?;
    }

    writer.flush().await.map_err(|_| {
        //error!("had error while flushing: {:?}", err);
        Error::Flush
    })?;
    debug!("flushed socket");
    let mut header = [0u8; 16];
    debug!("reading response header");
    reader.read_exact(&mut header).await.map_err(|_| {
        //error!("error while reading: {:?}", err);
        Error::Read
    })?;

    let header_response = Header(u128::from_be_bytes(header));
    match (
        header_response.message_class(),
        header_response.message_type(),
        header_response.content_type(),
    ) {
        (message_class, _, _) if message_class != MessageClass::Response as u128 => {
            return Err(Error::InvalidMessageClass(message_class));
        }
        (_, message_type_got, _) if message_type_got != message_type as u128 => {
            return Err(Error::InvalidMessageType(message_type_got));
        }
        (_, _, content_type_got) if content_type_got != content_type => {
            return Err(Error::InvalidContentType(content_type_got));
        }
        _ => {}
    }
    debug!("successfully extracted header");
    let content_len = header_response.content_len() as usize;
    let mut header_status_response = Header(0);
    if content_len > out.len() {
        header_status_response.set_message_class(MessageClass::Error as u128);
        writer
            .write(&header_status_response.0.to_be_bytes())
            .await
            .or(Err(Error::Write))?;
        writer.flush().await.or(Err(Error::Flush))?;
        return Err(Error::OutBufTooSmall {
            required: content_len,
            supplied: out.len(),
        });
    }
    header_status_response.set_message_class(MessageClass::Ok as u128);
    writer
        .write(&header_status_response.0.to_be_bytes())
        .await
        .or(Err(Error::Write))?;
    writer.flush().await.or(Err(Error::Flush))?;
    debug!("successfully sent OK");
    debug!("attemtping to receive data");
    //let mut read_buf = [0u8; 1024];
    let mut bytes_received = 0;
    loop {
        let (from, to) = (
            bytes_received,
            core::cmp::min(out.len(), bytes_received + 1024),
        );
        let read_slice = &mut out[from..to];
        match reader.read(read_slice).await {
            Ok(0) => {
                warn!("read EOF");
                return Ok(bytes_received);
            }
            Ok(n) => {
                debug!("read {} bytes", n);
                bytes_received += n;
            }
            Err(_) => {
                //warn!("read error: {:?}", e);
                return Err(Error::Read);
            }
        }
    }
}

pub async fn fetch_file_flash<H: Digest>(
    mut reader: impl Read,
    mut writer: impl Write,
    mut out: impl NorFlash,
    message_class: MessageClass,
    message_type: MessageType,
    content_type: u128,
    header_data: Option<u128>,
    body: Option<&[u8]>,
) -> Result<(usize, H), Error> {
    let mut header = Header(0);
    header.set_message_class(message_class as u128);
    header.set_message_type(message_type as u128);
    header.set_content_type(content_type);
    if let Some(header_data) = header_data {
        header.set_header_data(header_data);
    }
    header.set_content_len(body.map(|b| b.len()).unwrap_or_default() as u128);
    debug!("content len: {}", header.content_len());

    debug!("writing request header to socket");
    writer.write(&header.0.to_be_bytes()).await.map_err(|_| {
        //error!("had error while writing: {:?}", err);
        Error::Write
    })?;

    if let Some(body) = body {
        debug!("writing request data to socket");
        writer.write(body).await.map_err(|_| {
            //error!("had error while writing: {:?}", err);
            Error::Write
        })?;
    }

    writer.flush().await.map_err(|_| {
        //error!("had error while flushing: {:?}", err);
        Error::Flush
    })?;
    debug!("flushed socket");
    let mut header = [0u8; 16];
    debug!("reading response header");
    reader.read_exact(&mut header).await.map_err(|_| {
        //error!("error while reading: {:?}", err);
        Error::Read
    })?;

    let header_response = Header(u128::from_be_bytes(header));
    match (
        header_response.message_class(),
        header_response.message_type(),
        header_response.content_type(),
    ) {
        (message_class, _, _) if message_class != MessageClass::Response as u128 => {
            return Err(Error::InvalidMessageClass(message_class));
        }
        (_, message_type_got, _) if message_type_got != message_type as u128 => {
            return Err(Error::InvalidMessageType(message_type_got));
        }
        (_, _, content_type_got) if content_type_got != content_type => {
            return Err(Error::InvalidContentType(content_type_got));
        }
        _ => {}
    }
    debug!("successfully extracted header");
    let content_len = header_response.content_len() as usize;
    let mut header_status_response = Header(0);
    if content_len > out.capacity() {
        header_status_response.set_message_class(MessageClass::Error as u128);
        writer
            .write(&header_status_response.0.to_be_bytes())
            .await
            .or(Err(Error::Write))?;
        writer.flush().await.or(Err(Error::Flush))?;
        return Err(Error::OutBufTooSmall {
            required: content_len,
            supplied: out.capacity(),
        });
    }
    header_status_response.set_message_class(MessageClass::Ok as u128);
    writer
        .write(&header_status_response.0.to_be_bytes())
        .await
        .or(Err(Error::Write))?;
    writer.flush().await.or(Err(Error::Flush))?;

    let mut bytes_received = 0;
    let mut read_buf = [0u8; 1024];
    let mut hasher = H::new();
    loop {
        match reader.read(&mut read_buf).await {
            Ok(0) => {
                warn!("read EOF");
                return Ok((bytes_received, hasher));
            }
            Ok(n) => {
                debug!("read {} bytes", n);
                hasher.update(&read_buf[..n]);
                out.write(bytes_received as u32, &read_buf[..n])
                    .map_err(|_| Error::Write)?;
                bytes_received += n;
            }
            Err(_) => {
                //warn!("read error: {:?}", e);
                return Err(Error::Read);
            }
        }
    }
}

pub async fn fetch_tuf_file(
    reader: impl Read,
    writer: impl Write,
    out: &mut [u8],
    metapath: &[u8],
) -> Result<usize, Error> {
    debug!(
        "fetching tuf file at path {:?}",
        core::str::from_utf8(metapath).unwrap_or("INVALID UTF-8 PATH")
    );
    fetch_file(
        reader,
        writer,
        out,
        MessageClass::Request,
        MessageType::Tuf,
        TufMessage::TargetFile as u128,
        None,
        Some(metapath),
    )
    .await
}

pub async fn fetch_binary(
    reader: impl Read,
    writer: impl Write,
    out: &mut [u8],
    identifier: &[u8],
) -> Result<usize, Error> {
    debug!(
        "fetching binary with identifier {:?}",
        core::str::from_utf8(identifier).unwrap_or("INVALID UTF-8 PATH")
    );
    fetch_file(
        reader,
        writer,
        out,
        MessageClass::Request,
        MessageType::Binary,
        0,
        None,
        Some(identifier),
    )
    .await
}

pub async fn fetch_binary_flash<H: Digest>(
    reader: impl Read,
    writer: impl Write,
    out: impl NorFlash,
    identifier: &[u8],
) -> Result<(usize, H), Error> {
    debug!(
        "fetching binary with identifier {:?}",
        core::str::from_utf8(identifier).unwrap_or("INVALID UTF-8 PATH")
    );
    fetch_file_flash(
        reader,
        writer,
        out,
        MessageClass::Request,
        MessageType::Binary,
        0,
        None,
        Some(identifier),
    )
    .await
}

pub async fn fetch_signature(
    reader: impl Read,
    writer: impl Write,
    out: &mut [u8],
    identifier: &[u8],
) -> Result<usize, Error> {
    debug!(
        "fetching binary with identifier {:?}",
        core::str::from_utf8(identifier).unwrap_or("INVALID UTF-8 PATH")
    );
    fetch_file(
        reader,
        writer,
        out,
        MessageClass::Request,
        MessageType::Signature,
        0,
        None,
        Some(identifier),
    )
    .await
}

pub async fn send(mut reader: impl Read, mut writer: impl Write, data: &[u8]) -> Result<(), Error> {
    let mut header_out = Header(0);
    header_out.set_message_class(MessageClass::Response as u128);
    header_out.set_message_type(MessageType::Tuf as u128);
    header_out.set_content_type(TufMessage::Root as u128);
    header_out.set_content_len(data.len() as u128);

    writer
        .write(&header_out.0.to_be_bytes())
        .await
        .or(Err(Error::Write))?;
    writer.flush().await.or(Err(Error::Flush))?;

    let mut buf = [0u8; 16];
    reader.read_exact(&mut buf).await.or(Err(Error::Read))?;
    let header_in = Header(u128::from_be_bytes(buf));
    if header_in.message_class() != MessageClass::Ok as u128 {
        unimplemented!("handling error cases handling is not implemented")
    }

    for bytes in data.chunks(1024) {
        writer.write(bytes).await.or(Err(Error::Write))?;
        writer.flush().await.or(Err(Error::Flush))?;
    }
    Ok(())
}

bitfield! {
  pub struct Header(u128);
  impl Debug;
  pub message_class, set_message_class: 7, 0;
  pub message_type, set_message_type : 15, 8;
  pub content_type, set_content_type : 31, 16;
  pub header_data, set_header_data : 63, 32;
  pub content_len, set_content_len : 127, 64;
}

#[cfg(test)]
mod test {
    use alloc::borrow::ToOwned;
    use alloc::vec;
    use sha2::Sha256;

    use crate::{
        fetch_file_flash, fetch_tuf_file, fetch_tuf_role, send, Header, MessageClass, MessageType,
        TufMessage,
    };
    use embedded_storage::nor_flash::ReadNorFlash;
    use tempfile::NamedTempFile;

    async fn test_send_impl(data: &str) {
        let mut reader = vec![];

        let mut header = Header(0);
        header.set_message_class(MessageClass::Ok as u128);
        reader.extend(header.0.to_be_bytes());

        let mut writer = vec![0; data.len() + 16];

        send(reader.as_slice(), writer.as_mut_slice(), data.as_bytes())
            .await
            .expect("failed");
        eprintln!("{writer:?}");
        let header_got = Header(u128::from_be_bytes(writer[0..16].try_into().unwrap()));

        assert_eq!(
            header_got.message_class(),
            MessageClass::Response as u128,
            "wrong message class"
        );
        assert_eq!(
            header_got.message_type(),
            MessageType::Tuf as u128,
            "wrong message type"
        );
        assert_eq!(
            header_got.content_type(),
            TufMessage::Root as u128,
            "wrong content type"
        );
        let content_len = header_got.content_len() as usize;
        assert_eq!(content_len, data.len());
        assert_eq!(std::str::from_utf8(&writer[16..]).unwrap(), data);
    }

    #[tokio::test]
    async fn test_send() {
        test_send_impl("hello world").await;
    }

    async fn test_fetch_impl(data: &str) {
        let mut reader = vec![];
        let mut header = Header(0);
        header.set_message_class(MessageClass::Response as u128);
        header.set_message_type(MessageType::Tuf as u128);
        header.set_content_type(TufMessage::Root as u128);
        header.set_content_len(data.len() as u128);
        reader.extend(header.0.to_be_bytes());
        reader.extend(data.bytes());
        let mut writer = [0u8; 1024];

        let mut out_buf = [0u8; 1024];
        let n = fetch_tuf_role(
            reader.as_slice(),
            writer.as_mut_slice(),
            &mut out_buf,
            TufMessage::Root,
            None,
        )
        .await
        .expect("failed");
        let first_header = Header(u128::from_be_bytes(writer[0..16].try_into().unwrap()));
        let second_header = Header(u128::from_be_bytes(writer[16..32].try_into().unwrap()));

        eprintln!("{first_header:?}");
        assert_eq!(
            first_header.message_class(),
            MessageClass::Request as u128,
            "wrong message class"
        );
        assert_eq!(
            first_header.message_type(),
            MessageType::Tuf as u128,
            "wrong message type"
        );
        assert_eq!(
            first_header.content_type(),
            TufMessage::Root as u128,
            "wrong content type"
        );
        assert_eq!(
            second_header.message_class(),
            MessageClass::Ok as u128,
            "wrong message class"
        );
        assert_eq!(std::str::from_utf8(&out_buf[..n]).unwrap(), data);
    }

    #[tokio::test]
    async fn test_fetch() {
        test_fetch_impl("hello world").await
    }

    #[tokio::test]
    async fn test_fetch_target_file() {
        test_fetch_target_file_impl("hello.txt", "hello world").await
    }

    async fn test_fetch_target_file_impl(path: &str, data: &str) {
        let mut reader = vec![];
        let mut header = Header(0);
        header.set_message_class(MessageClass::Response as u128);
        header.set_message_type(MessageType::Tuf as u128);
        header.set_content_type(TufMessage::TargetFile as u128);
        header.set_content_len(data.len() as u128);
        reader.extend(header.0.to_be_bytes());
        reader.extend(data.bytes());
        let mut writer = [0u8; 1024];

        let mut out_buf = [0u8; 1024];
        let n = fetch_tuf_file(
            reader.as_slice(),
            writer.as_mut_slice(),
            &mut out_buf,
            path.as_bytes(),
        )
        .await
        .expect("failed");
        let first_header = Header(u128::from_be_bytes(writer[0..16].try_into().unwrap()));
        let first_content = std::str::from_utf8(&writer[16..16 + path.len()]).unwrap();

        let second_header = Header(u128::from_be_bytes(
            writer[16 + path.len()..32 + path.len()].try_into().unwrap(),
        ));

        eprintln!("{first_header:?}");
        assert_eq!(
            first_header.message_class(),
            MessageClass::Request as u128,
            "wrong message class"
        );
        assert_eq!(
            first_header.message_type(),
            MessageType::Tuf as u128,
            "wrong message type"
        );
        assert_eq!(
            first_header.content_type(),
            TufMessage::TargetFile as u128,
            "wrong content type"
        );
        assert_eq!(
            first_header.content_len(),
            path.len() as u128,
            "wrong content len"
        );
        assert_eq!(first_content, path, "wrong content");
        assert_eq!(
            second_header.message_class(),
            MessageClass::Ok as u128,
            "wrong message class"
        );
        assert_eq!(std::str::from_utf8(&out_buf[..n]).unwrap(), data);
    }

    #[tokio::test]
    async fn test_fetch_flash() {
        let writer = vec![];
        let mut header = Header(0);
        let file_content = b"Hello World!";
        header.set_message_class(MessageClass::Response as u128);
        header.set_message_type(MessageType::Binary as u128);
        header.set_header_data(file_content.len() as u128);
        let reader = [header.0.to_be_bytes().as_slice(), file_content].concat();
        let file = dbg!(NamedTempFile::new().expect("failed to create tempfile"));
        let mut flash_writer = crate::flash::mock_flash::FsWriter(file.path().to_owned());
        let path = b"hello-world.txt";
        fetch_file_flash::<Sha256>(
            reader.as_slice(),
            writer,
            &mut flash_writer,
            MessageClass::Request,
            MessageType::Binary,
            0,
            Some(path.len() as u128),
            Some(path),
        )
        .await
        .expect("should succeed");
        let mut out_buf = [0u8; 12];
        flash_writer
            .read(0, out_buf.as_mut_slice())
            .expect("failed to read bytes");
        assert_eq!(&out_buf, file_content);
    }
}
