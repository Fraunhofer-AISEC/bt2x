mod args;
mod config;

use crate::args::Args;
use crate::config::{Config, KeyConfig, KeyKind};
use anyhow::{Context, Result};
use clap::Parser;
use der::Encode;
use std::fs::read;
use std::{
    fs,
    fs::{read_to_string, OpenOptions},
    io::Write,
};
use tuf_no_std::{
    builder::*,
    common::crypto::sign::{Cipher, SigningKey},
};
use tuf_no_std_der::{
    root::Root, snapshot::Snapshot, targets::Targets, timestamp::Timestamp, Signed,
};

fn main() -> Result<()> {
    let args = Args::parse();
    let config: Config = read_to_string(args.config)
        .context("failed to config file")
        .and_then(|s| serde_yaml::from_str(&s).context("failed to parse config file"))?;

    let root_config = &config.roles["root"];
    let timestamp_config = &config.roles["timestamp"];
    let snapshot_config = &config.roles["snapshot"];
    let targets_config = &config.roles["targets"];

    let func = |k_conf: &KeyConfig| match k_conf.kind {
        KeyKind::Ecdsa => SigningKey::new(Cipher::Ecdsa),
    };
    let root_keys = root_config.keys.iter().map(func).collect::<Vec<_>>();
    let timestamp_keys = timestamp_config.keys.iter().map(func).collect::<Vec<_>>();
    let snapshot_keys = snapshot_config.keys.iter().map(func).collect::<Vec<_>>();
    let targets_keys = targets_config.keys.iter().map(func).collect::<Vec<_>>();

    let root_keys_spki = root_keys
        .iter()
        .map(|k| k.as_spki().unwrap())
        .collect::<Vec<_>>();
    let targets_keys_spki = targets_keys
        .iter()
        .map(|k| k.as_spki().unwrap())
        .collect::<Vec<_>>();
    let snapshot_keys_spki = snapshot_keys
        .iter()
        .map(|k| k.as_spki().unwrap())
        .collect::<Vec<_>>();
    let timestamp_keys_spki = timestamp_keys
        .iter()
        .map(|k| k.as_spki().unwrap())
        .collect::<Vec<_>>();

    let root = RootBuilder::default()
        .with_expiration_utc(2030, 1, 1, 0, 0, 0)
        .with_role_and_key("root", &root_keys_spki, root_config.threshold)
        .with_role_and_key("targets", &targets_keys_spki, targets_config.threshold)
        .with_role_and_key("snapshot", &snapshot_keys_spki, snapshot_config.threshold)
        .with_role_and_key(
            "timestamp",
            &timestamp_keys_spki,
            timestamp_config.threshold,
        )
        .with_version(root_config.version)
        .build();
    let signed_root = Signed::<Root>::from_signed(root, &root_keys).unwrap();

    let root_der = signed_root.to_der().unwrap();
    let rekor_pub_pem = config
        .targets
        .get("rekor")
        .context("missing rekor target")
        .and_then(|c| read(&c.filepath).context("failed to read rekor key"))?;
    let ct_log_pub_pem = config
        .targets
        .get("ctlog")
        .context("missing rekor target")
        .and_then(|c| read(&c.filepath).context("failed to read rekor key"))?;
    let fulcio_crt_pem = config
        .targets
        .get("fulcio")
        .context("missing rekor target")
        .and_then(|c| read(&c.filepath).context("failed to read rekor key"))?;

    let targets = TargetsBuilder::default()
        .with_expiration_utc(2030, 1, 1, 0, 0, 0)
        .with_version(targets_config.version)
        .with_target(config.targets["rekor"].name.as_bytes(), &rekor_pub_pem)
        .with_target(config.targets["fulcio"].name.as_bytes(), &fulcio_crt_pem)
        .with_target(config.targets["ctlog"].name.as_bytes(), &ct_log_pub_pem)
        .build();
    let signed_targets = Signed::<Targets>::from_signed(targets, &targets_keys).unwrap();
    let targets_der = signed_targets.to_der().unwrap();

    let snapshot = SnapshotBuilder::default()
        .with_expiration_utc(2030, 1, 1, 0, 0, 0)
        .with_meta(b"targets.der", targets_der.as_slice(), 1)
        .with_version(snapshot_config.version)
        .build();
    let signed_snapshot = Signed::<Snapshot>::from_signed(snapshot, &snapshot_keys).unwrap();
    let snapshot_der = signed_snapshot.to_der().unwrap();

    let timestamp = TimestampBuilder::default()
        .with_expiration_utc(2030, 1, 1, 0, 0, 0)
        .with_snapshot("snapshot.der", &signed_snapshot)
        .with_version(snapshot_config.version)
        .build();
    let signed_timestamp = Signed::<Timestamp>::from_signed(timestamp, &timestamp_keys).unwrap();
    let timestamp_der = signed_timestamp.to_der().unwrap();
    let out_dir = config.out;
    fs::create_dir_all(out_dir.join("targets")).expect("failed to create dir 'out/targets' dir");
    [
        (out_dir.join("1.root.der"), root_der.as_slice()),
        (out_dir.join("1.targets.der"), targets_der.as_slice()),
        (out_dir.join("1.timestamp.der"), timestamp_der.as_slice()),
        (out_dir.join("1.snapshot.der"), snapshot_der.as_slice()),
        (out_dir.join("targets/rekor.pub"), rekor_pub_pem.as_slice()),
        (
            out_dir.join("targets/fulcio.crt.pem"),
            fulcio_crt_pem.as_slice(),
        ),
        (out_dir.join("targets/ctlog.pub"), ct_log_pub_pem.as_slice()),
    ]
    .into_iter()
    .for_each(|(p, f)| {
        OpenOptions::new()
            .write(true)
            .truncate(true)
            .create(true)
            .open(&p)
            .unwrap_or_else(|_| panic!("failed to open file at path: {p:?}"))
            .write_all(f)
            .expect("failed to write to file");
    });
    Ok(())
}
