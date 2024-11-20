use clap::Parser;
use embassy_executor::{Executor, Spawner};
use std::cmp::min;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;
use std::process::exit;

use embassy_net::{Config, IpEndpoint, Ipv4Address, Ipv4Cidr, Stack, StackResources};
use embassy_net_tuntap::TunTapDevice;

use bt2x_embedded::{verify_bt, Digest, Sha256};
use bt2x_ota_common::net::Transport;
use heapless::Vec;
use log::*;
use rand_core::{OsRng, RngCore};
use static_cell::StaticCell;
use tuf_no_std::utils::TufStorage;
use tuf_no_std::{DateTime, UtcTime};

use bt2x_ota_common::flash::mock_flash::ReadNorFlash;

const TUF_ROOT: &[u8] = include_bytes!("../../build/1.root.der");

#[derive(Parser)]
#[clap(version = "1.0")]
struct Opts {
    /// TAP device name
    #[clap(long, default_value = "tap0")]
    tap: String,
    /// use a static IP instead of DHCP
    #[clap(long)]
    static_ip: bool,
}

#[embassy_executor::task]
async fn net_task(stack: &'static Stack<TunTapDevice>) -> ! {
    stack.run().await
}

#[embassy_executor::task]
async fn main_task(spawner: Spawner) {
    let opts: Opts = Opts::parse();

    // Init network device
    let device = TunTapDevice::new(&opts.tap).unwrap();

    // Choose between dhcp or static ip
    let config = if opts.static_ip {
        Config::ipv4_static(embassy_net::StaticConfigV4 {
            address: Ipv4Cidr::new(Ipv4Address::new(192, 168, 69, 2), 24),
            dns_servers: Vec::new(),
            gateway: Some(Ipv4Address::new(192, 168, 69, 1)),
        })
    } else {
        Config::dhcpv4(Default::default())
    };
    // Generate random seed
    let mut seed = [0; 8];
    OsRng.fill_bytes(&mut seed);
    let seed = u64::from_le_bytes(seed);

    // Init network stack
    static STACK: StaticCell<Stack<TunTapDevice>> = StaticCell::new();
    static RESOURCES: StaticCell<StackResources<3>> = StaticCell::new();
    let stack = &*STACK.init(Stack::new(
        device,
        config,
        RESOURCES.init(StackResources::<3>::new()),
        seed,
    ));

    // Launch network task
    spawner.spawn(net_task(stack)).unwrap();

    let mut storage = TufStorage {
        root: TUF_ROOT.try_into().unwrap(),
        uncommitted_root: Default::default(),
        snapshot: Default::default(),
        timestamp: Default::default(),
        targets: Default::default(),
    };

    let mut transport = Transport {
        network_stack: &stack,
        server: IpEndpoint::new("192.168.69.100".parse().unwrap(), 50000),
    };
    let update_start =
        UtcTime::from_date_time(DateTime::new(2024, 1, 1, 0, 0, 0).unwrap()).unwrap();
    debug!("starting repo update");
    tuf_no_std::update_repo_async(&mut storage, &mut transport, 4, update_start)
        .await
        .expect("failed to update repo");
    debug!("repo update complete");
    let mut rekor_pem = [0u8; 4096];
    debug!("fetching rekor.pem");
    let rekor_pem = tuf_no_std::fetch_and_verify_target_file_async(
        &mut storage,
        &mut transport,
        b"rekor.pub",
        &mut rekor_pem,
    )
    .await
    .unwrap();
    debug!("fetching fulcio.pem");
    let mut fulcio_pem = [0u8; 4096];
    let fulcio_pem = tuf_no_std::fetch_and_verify_target_file_async(
        &mut storage,
        &mut transport,
        b"fulcio.crt.pem",
        &mut fulcio_pem,
    )
    .await
    .unwrap();
    debug!("fetching binary");
    let mut flash = bt2x_ota_common::flash::mock_flash::FsWriter(PathBuf::from("flash-test"));
    let (_, hasher) = transport
        .fetch_binary_flash::<Sha256>(b"pi-pico-bin", &mut flash)
        .await
        .unwrap();

    debug!("fetching signature");
    let mut signature_buf = [0u8; 4096];
    let bundle = transport
        .fetch_signature(b"pi-pico-bin.canonical.json", &mut signature_buf)
        .await
        .unwrap();
    OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open("pi-pico-bin.canonical.json")
        .unwrap()
        .write_all(bundle)
        .unwrap();
    debug!("verifying bundle");
    verify_bt(
        rekor_pem,
        fulcio_pem,
        bundle,
        hasher,
        &[(env!("GITHUB_EMAIL"), "http://dex-idp:8888/")],
    )
    .unwrap();
    exit(0)
}

static EXECUTOR: StaticCell<Executor> = StaticCell::new();

fn main() {
    env_logger::builder()
        .filter_level(log::LevelFilter::Debug)
        .filter_module("async_io", log::LevelFilter::Info)
        .format_timestamp_nanos()
        .init();
    info!("logging set up");
    let executor = EXECUTOR.init(Executor::new());
    executor.run(|spawner| {
        spawner.spawn(main_task(spawner)).unwrap();
    });
}
