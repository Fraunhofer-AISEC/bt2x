mod cli;

use crate::cli::Args;
use anyhow::{anyhow, Context, Result};
use bt2x_ota_common::{Header, MessageClass, MessageType, TufMessage};
use clap::Parser;
use path_clean::PathClean;
use std::error::Error;
use std::fs::OpenOptions;
use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader, BufWriter};
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, info};
use tracing_subscriber::filter::Targets;
use tracing_subscriber::prelude::*;

#[derive(Debug, Clone)]
struct Storage {
    pub(crate) repository_path: PathBuf,
    pub(crate) binaries_path: PathBuf,
    pub(crate) signatures_path: PathBuf,
}

impl Storage {
    pub fn tuf_root(&self, version: u64) -> Result<Vec<u8>> {
        info!("handling fetching root with version {version:?}");
        std::fs::read(self.repository_path.join(format!("{version}.root.der")))
            .context("failed to read file")
    }
    pub fn tuf_timestamp(&self, version: Option<u64>) -> Result<Vec<u8>> {
        let version = version.unwrap_or(1);
        info!("handling fetching timestamp with version {version:?}");
        std::fs::read(
            self.repository_path
                .join(format!("{version}.timestamp.der")),
        )
        .context("failed to read file")
    }
    pub fn tuf_snapshot(&self, version: Option<u64>) -> Result<Vec<u8>> {
        let version = version.unwrap_or(1);
        info!("handling fetching snapshot with version {version:?}");
        std::fs::read(self.repository_path.join(format!("{version}.snapshot.der")))
            .context("failed to read file")
    }
    pub fn tuf_targets(&self, version: Option<u64>) -> Result<Vec<u8>> {
        let version = version.unwrap_or(1);
        info!("handling fetching targets with version {version:?}");
        std::fs::read(self.repository_path.join(format!("{version}.targets.der")))
            .context("failed to read file")
    }
    pub fn tuf_target(&self, metapath: &str) -> Result<Vec<u8>> {
        info!("handling fetching target with path {metapath:?}");
        let metapath_clean = PathBuf::from(metapath).clean();
        let file_path = self.repository_path.join("targets").join(metapath_clean);
        if !file_path.starts_with(&self.repository_path) {
            return Err(anyhow!(
                "requested path {file_path:?}is not within directory"
            ));
        }
        std::fs::read(file_path).context("failed to read file")
    }

    pub fn binary(&self, metapath: &str) -> Result<(u64, impl std::io::Read)> {
        let metapath_clean = PathBuf::from(metapath).clean();
        OpenOptions::new()
            .read(true)
            .open(self.binaries_path.join(metapath_clean))
            .context("failed to open binary")
            .map(|f| {
                let size = f.metadata().as_ref().unwrap().size();
                (size, std::io::BufReader::new(f))
            })
    }
    pub fn signature(&self, metapath: &str) -> Result<(u64, impl std::io::Read)> {
        OpenOptions::new()
            .read(true)
            .open(self.signatures_path.join(metapath))
            .context("failed to open signature")
            .map(|f| {
                let size = f.metadata().as_ref().unwrap().size();
                (size, std::io::BufReader::new(f))
            })
    }
}

async fn handle_client(
    sock: &mut TcpStream,
    storage: &Storage,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut buf = [0u8; 16];
    sock.read_exact(&mut buf).await?;
    let header = Header(u128::from_be_bytes(buf));
    debug!("got header: {header:?}");
    match (header.message_class(), header.message_type()) {
        (c_class, m_type)
            if (c_class, m_type) == (MessageClass::Request as u128, MessageType::Tuf as u128) =>
        {
            debug!("handling tuf");
            handle_tuf(sock, header, storage).await?
        }

        (c_class, m_type)
            if (c_class, m_type)
                == (MessageClass::Request as u128, MessageType::Binary as u128) =>
        {
            debug!("handling binary");
            handle_binary(sock, header, storage).await?
        }
        (c_class, m_type)
            if (c_class, m_type)
                == (
                    MessageClass::Request as u128,
                    MessageType::Signature as u128,
                ) =>
        {
            debug!("handling signature");
            handle_signature(sock, header, storage).await?
        }
        (c_class, m_type)
            if (c_class, m_type)
                == (MessageClass::Request as u128, MessageType::Rfc3161 as u128) =>
        {
            debug!("handling tuf");
            handle_rfc3161(sock, header, storage).await?
        }
        _ => {
            unimplemented!();
        }
    }
    Ok(())
}

async fn handle_tuf(stream: &mut TcpStream, header: Header, storage: &Storage) -> Result<()> {
    let (data, role) = match header.content_type() {
        c_type if c_type == TufMessage::Root as u128 => (
            storage.tuf_root(header.header_data() as u64)?,
            TufMessage::Root,
        ),
        c_type if c_type == TufMessage::Targets as u128 => {
            (storage.tuf_targets(None)?, TufMessage::Targets)
        }
        c_type if c_type == TufMessage::Snapshot as u128 => {
            (storage.tuf_snapshot(None)?, TufMessage::Snapshot)
        }
        c_type if c_type == TufMessage::Timestamp as u128 => {
            (storage.tuf_timestamp(None)?, TufMessage::Timestamp)
        }
        c_type if c_type == TufMessage::TargetFile as u128 => {
            let mut buf = vec![0; header.content_len() as usize];
            stream
                .read_exact(&mut buf)
                .await
                .context("could not read path from socket")?;
            debug!("{buf:x?}");
            let path = std::str::from_utf8(&buf).context("provided path was not valid UTF-8")?;
            debug!("got path: {path:?}");
            (storage.tuf_target(path)?, TufMessage::TargetFile)
        }
        _ => unimplemented!(),
    };
    debug!("handling {role:?}");
    send(stream, &data, role).await
}

async fn handle_signature(stream: &mut TcpStream, header: Header, storage: &Storage) -> Result<()> {
    let (read, write) = stream.split();
    let mut reader = BufReader::new(read);
    let mut writer = BufWriter::new(write);

    let mut path = [0u8; 256];
    let content_len = header.content_len() as usize;
    reader.read_exact(&mut path[..content_len]).await?;
    let path = std::str::from_utf8(&path[..content_len])?;
    let (data_len, mut data) = storage.signature(path)?;

    let mut header_out = Header(0);
    header_out.set_message_class(MessageClass::Response as u128);
    header_out.set_message_type(MessageType::Signature as u128);
    header_out.set_content_len(data_len as u128);

    writer.write_all(&header_out.0.to_be_bytes()).await?;
    writer.flush().await?;
    info!("sent header");
    let mut buf = [0u8; 16];
    reader.read_exact(&mut buf).await?;
    let header_in = Header(u128::from_be_bytes(buf));
    if header_in.message_class() != MessageClass::Ok as u128 {
        return Err(anyhow!("got message != Ok from remote"));
    }
    info!("sending data");
    loop {
        use std::io::Read;
        let mut buf = [0u8; 1024];
        let bytes_read = data.read(&mut buf)?;
        if bytes_read == 0 {
            break;
        }
        let mut buf = &buf[..bytes_read];
        debug!("sending {} bytes", buf.len());
        loop {
            if buf.is_empty() {
                break;
            }
            let bytes_sent = writer.write(buf).await?;
            debug!("sent {bytes_sent} bytes");
            buf = &buf[bytes_sent..];
            writer.flush().await?;
        }
    }
    info!("sending data finished");
    Ok(())
}

async fn handle_binary(stream: &mut TcpStream, header: Header, storage: &Storage) -> Result<()> {
    let (read, write) = stream.split();
    let mut reader = BufReader::new(read);
    let mut writer = BufWriter::new(write);

    let mut path = [0u8; 256];
    let content_len = header.content_len() as usize;
    reader.read_exact(&mut path[..content_len]).await?;
    let path = std::str::from_utf8(&path[..content_len])?;
    info!("client requested binary at: {path}");
    let (data_len, mut data) = storage.binary(path)?;

    let mut header_out = Header(0);
    header_out.set_message_class(MessageClass::Response as u128);
    header_out.set_message_type(MessageType::Binary as u128);
    header_out.set_content_len(data_len as u128);

    writer.write_all(&header_out.0.to_be_bytes()).await?;
    writer.flush().await?;
    info!("sent header");
    let mut buf = [0u8; 16];
    reader.read_exact(&mut buf).await?;
    let header_in = Header(u128::from_be_bytes(buf));
    if header_in.message_class() != MessageClass::Ok as u128 {
        return Err(anyhow!("got message != Ok from remote"));
    }
    info!("sending data");
    loop {
        use std::io::Read;
        let mut buf = [0u8; 1024];
        let bytes_read = data.read(&mut buf)?;
        if bytes_read == 0 {
            break;
        }
        let mut buf = &buf[..bytes_read];
        debug!("sending {} bytes", buf.len());
        loop {
            if buf.is_empty() {
                break;
            }
            let bytes_sent = writer.write(buf).await?;
            debug!("sent {bytes_sent} bytes");
            buf = &buf[bytes_sent..];
            writer.flush().await?;
        }
    }
    info!("sending data finished");
    Ok(())
}

#[allow(unused_variables)]
async fn handle_rfc3161(stream: &mut TcpStream, header: Header, storage: &Storage) -> Result<()> {
    unimplemented!()
}

async fn send(stream: &mut TcpStream, data: &[u8], role: TufMessage) -> Result<()> {
    let mut header_out = Header(0);
    header_out.set_message_class(MessageClass::Response as u128);
    header_out.set_message_type(MessageType::Tuf as u128);
    header_out.set_content_type(role as u128);
    header_out.set_content_len(data.len() as u128);
    let (read, write) = stream.split();
    let mut reader = BufReader::new(read);
    let mut writer = BufWriter::new(write);
    writer.write_all(&header_out.0.to_be_bytes()).await?;
    writer.flush().await?;
    info!("sent header");
    let mut buf = [0u8; 16];
    reader.read_exact(&mut buf).await?;
    let header_in = Header(u128::from_be_bytes(buf));
    if header_in.message_class() != MessageClass::Ok as u128 {
        return Err(anyhow!("got message != Ok from remote"));
    }
    info!("sending data");
    for bytes in data.chunks(1024) {
        debug!("sending {} bytes", bytes.len());
        let n = writer.write(bytes).await?;
        writer.flush().await?;
        debug!("sent {n} bytes");
    }
    info!("sending data finished");
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer())
        .with(Targets::new().with_target(
            env!("CARGO_PKG_NAME").replace('-', "_"),
            tracing_core::Level::INFO,
        ))
        .init();
    let args = Args::parse();

    let storage = Storage {
        repository_path: args.repo_path,
        signatures_path: args.signatures,
        binaries_path: args.binaries,
    };
    debug!("starting TCP listener");
    let sockaddr = ("0.0.0.0", 50000);
    let listener = TcpListener::bind(sockaddr)
        .await
        .expect("failed to bind to socket");
    debug!("successfully bound to {sockaddr:?}");
    loop {
        let (mut socket, addr) = listener.accept().await?;
        debug!("got client: {addr:?}");
        match handle_client(&mut socket, &storage).await {
            Ok(_) => continue,
            Err(err) => println!("encountered error: {err:?}"),
        }
    }
}
