//! This example uses the RP Pico W board Wifi chip (cyw43).
//! Connects to specified Wifi network and creates a TCP endpoint on port 1234.

#![no_std]
#![no_main]
#![feature(type_alias_impl_trait)]
#![feature(async_fn_in_trait)]
#![feature(impl_trait_in_assoc_type)]
#![allow(stable_features, unknown_lints, async_fn_in_trait)]

use bt2x_embedded::{verify_bt, Sha256};
use bt2x_ota_common::net::Transport;
use cyw43_pio::PioSpi;
// use defmt::*;
use embassy_boot_rp::{AlignedBuffer, BlockingFirmwareUpdater, FirmwareUpdaterConfig};
use embassy_executor::Spawner;
use embassy_net::tcp::client::{TcpClient, TcpClientState};
use embassy_net::{IpEndpoint, Ipv4Address, Ipv4Cidr, Stack, StackResources};
use embassy_rp::bind_interrupts;
use embassy_rp::clocks::RoscRng;
use embassy_rp::flash::Flash;
use embassy_rp::gpio::{Level, Output};
use embassy_rp::peripherals::{DMA_CH0, PIO0};
use embassy_rp::pio::{InterruptHandler, Pio};
use embassy_rp::watchdog::Watchdog;
use embassy_sync::blocking_mutex::Mutex;
use embassy_time::{Duration, Instant, Timer};
use rand::RngCore;
use reqwless::request::{Method, RequestBuilder};
//use embedded_io_async::Write as AsyncIoWrite;
use core::cell::RefCell;
use static_cell::StaticCell;
use tuf_no_std::utils::MemoryStorage;
use tuf_no_std::{DateTime, UtcTime};
use {defmt_rtt as _, panic_probe as _};

use embedded_alloc::Heap;

use p256::pkcs8::DecodePublicKey;
use signature::DigestVerifier;

bind_interrupts!(struct Irqs {
    PIO0_IRQ_0 => InterruptHandler<PIO0>;
});

const WIFI_NETWORK: &str = env!("WIFI_NETWORK");
const WIFI_PASSWORD: &str = env!("WIFI_PASSWORD");
const OTA_SERVER_PORT: &str = env!("OTA_SERVER_PORT");
const OTA_SERVER_HOST: &str = env!("OTA_SERVER_HOST");
const TUF_ROOT: &[u8] = include_bytes!("../../../build/1.root.der");
const FLASH_SIZE: usize = 2 * 1024 * 1024;

const DUMMY_KEY: &[u8] = include_bytes!("key.der");
const DUMMY_SIGNATURE: &[u8] = include_bytes!("sig.der");

#[embassy_executor::task]
async fn wifi_task(
    runner: cyw43::Runner<'static, Output<'static>, PioSpi<'static, PIO0, 0, DMA_CH0>>,
) -> ! {
    runner.run().await
}

#[embassy_executor::task]
async fn net_task(stack: &'static Stack<cyw43::NetDriver<'static>>) -> ! {
    stack.run().await
}

#[embassy_executor::main]
async fn main(spawner: Spawner) {
    let p = embassy_rp::init(Default::default());
    {
        use core::mem::MaybeUninit;
        const HEAP_SIZE: usize = 1024;
        static mut HEAP_MEM: [MaybeUninit<u8>; HEAP_SIZE] = [MaybeUninit::uninit(); HEAP_SIZE];
        unsafe { HEAP.init(HEAP_MEM.as_ptr() as usize, HEAP_SIZE) }
    }
    let mut watchdog = Watchdog::new(p.WATCHDOG);
    watchdog.start(Duration::from_secs(8));

    //let fw = include_bytes!("../firmware/43439A0.bin");
    //let clm = include_bytes!("../firmware/43439A0_clm.bin");

    // To make flashing faster for development, you may want to flash the firmwares independently
    // at hardcoded addresses, instead of baking them into the program with `include_bytes!`:
    //     probe-rs download 43439A0.bin --binary-format bin --chip RP2040 --base-address 0x10110000
    //     probe-rs download 43439A0_clm.bin --binary-format bin --chip RP2040 --base-address 0x10150000
    let fw = unsafe { core::slice::from_raw_parts(0x10110000 as *const u8, 230321) };
    let clm = unsafe { core::slice::from_raw_parts(0x10150000 as *const u8, 4752) };

    let pwr = Output::new(p.PIN_23, Level::Low);
    let cs = Output::new(p.PIN_25, Level::High);
    let mut pio = Pio::new(p.PIO0, Irqs);
    let spi = PioSpi::new(
        &mut pio.common,
        pio.sm0,
        pio.irq0,
        cs,
        p.PIN_24,
        p.PIN_29,
        p.DMA_CH0,
    );

    static STATE: StaticCell<cyw43::State> = StaticCell::new();
    let state = STATE.init(cyw43::State::new());
    let (net_device, mut control, runner) = cyw43::new(state, pwr, spi, fw).await;
    spawner.spawn(wifi_task(runner)).unwrap();

    control.init(clm).await;
    control
        .set_power_management(cyw43::PowerManagementMode::PowerSave)
        .await;
    watchdog.feed();
    //let config = Config::dhcpv4(Default::default());
    let config = embassy_net::Config::ipv4_static(embassy_net::StaticConfigV4 {
        address: Ipv4Cidr::new(Ipv4Address::new(192, 168, 0, 100), 24),
        dns_servers: Default::default(),
        gateway: Some(Ipv4Address::new(192, 168, 0, 1)),
    });

    let mut rng = RoscRng;
    // Generate random seed
    let seed = rng.next_u64();

    // Init network stack
    static STACK: StaticCell<Stack<cyw43::NetDriver<'static>>> = StaticCell::new();
    static RESOURCES: StaticCell<StackResources<2>> = StaticCell::new();
    let stack = &*STACK.init(Stack::new(
        net_device,
        config,
        RESOURCES.init(StackResources::<2>::new()),
        seed,
    ));
    spawner.spawn(net_task(stack)).unwrap();
    watchdog.feed();
    loop {
        //control.join_open(WIFI_NETWORK).await;
        match control.join_wpa2(WIFI_NETWORK, WIFI_PASSWORD).await {
            Ok(_) => break,
            Err(err) => {
                panic!("join failed with status={}", err.status);
            }
        }
    }

    // Wait for DHCP, not necessary when using static IP
    //info!("waiting for DHCP...");
    while !stack.is_config_up() {
        control.gpio_set(0, true).await;
        Timer::after_millis(20).await;
        watchdog.feed();
        control.gpio_set(0, false).await;
    }

    let mut storage = MemoryStorage {
        root: TUF_ROOT.try_into().unwrap(),
        uncommitted_root: Default::default(),
        snapshot: Default::default(),
        timestamp: Default::default(),
        targets: Default::default(),
    };

    let mut transport = Transport {
        network_stack: &stack,
        server: IpEndpoint::new(
            OTA_SERVER_HOST.parse().unwrap(),
            OTA_SERVER_PORT.parse().unwrap(),
        ),
    };
    watchdog.feed();

    let update_start =
        UtcTime::from_date_time(DateTime::new(2024, 1, 1, 0, 0, 0).unwrap()).unwrap();
    let start_total = Instant::now();
    tuf_no_std::update_repo_async(&mut storage, &mut transport, 4, update_start)
        .await
        .expect("failed to update repo");
    let duration_update_repo = start_total.elapsed();
    watchdog.feed();

    let start_fetch_sigstore_keys = Instant::now();
    let mut rekor_pem = [0u8; 4096];
    let rekor_pem = tuf_no_std::fetch_and_verify_target_file_async(
        &mut storage,
        &mut transport,
        b"rekor.pub",
        &mut rekor_pem,
    )
    .await
    .unwrap();
    watchdog.feed();
    let mut fulcio_pem = [0u8; 4096];
    let fulcio_pem = tuf_no_std::fetch_and_verify_target_file_async(
        &mut storage,
        &mut transport,
        b"fulcio.crt.pem",
        &mut fulcio_pem,
    )
    .await
    .unwrap();
    let duration_fetch_sigstore_keys = start_fetch_sigstore_keys.elapsed();

    watchdog.feed();
    let start_fetch_signature = Instant::now();
    let mut bundle = [0u8; 4096];
    let bundle = transport
        .fetch_signature(b"pi-pico-bin.canonical.json", &mut bundle)
        .await
        .unwrap();
    let duration_fetch_signature = start_fetch_signature.elapsed();

    watchdog.feed();

    let flash = Flash::<_, _, FLASH_SIZE>::new_blocking(p.FLASH);
    let flash = Mutex::new(RefCell::new(flash));

    let config = FirmwareUpdaterConfig::from_linkerfile_blocking(&flash, &flash);
    let mut aligned = AlignedBuffer([0; 1]);
    let mut updater = BlockingFirmwareUpdater::new(config, &mut aligned.0);
    let mut dfu = updater.prepare_update().unwrap();

    control.gpio_set(0, true).await;
    let start_fetch_binary = Instant::now();
    watchdog.feed();
    let (n, hasher) = transport
        .fetch_binary_flash::<Sha256>(b"pi-pico-bin", &mut dfu)
        .await
        .unwrap();
    watchdog.feed();
    let duration_fetch_binary = start_fetch_binary.elapsed();
    watchdog.feed();

    let start_verify_binary = Instant::now();
    match verify_bt(
        rekor_pem,
        fulcio_pem,
        bundle,
        hasher.clone(),
        &[(env!("GITHUB_EMAIL"), "http://dex-idp:8888/")],
    ) {
        Ok(_) => {}
        Err(err) => loop {
            watchdog.feed();
            Timer::after_millis(100).await;
            control.gpio_set(0, true).await;
            Timer::after_millis(100).await;
            control.gpio_set(0, false).await;
        },
    }
    let duration_verify_binary = start_verify_binary.elapsed();
    watchdog.feed();

    let start_verification_naive = Instant::now();
    let verifying_key = p256::ecdsa::VerifyingKey::from_public_key_der(DUMMY_KEY).unwrap();
    let signature = p256::ecdsa::DerSignature::from_bytes(DUMMY_SIGNATURE).unwrap();
    let _ = verifying_key.verify_digest(hasher, &signature); // result does not matter for performance
    let duration_verification_naive = start_verification_naive.elapsed();
    watchdog.feed();

    let end = Instant::now();
    let benchmark_data = BenchmarkData {
        start_time: Some(start_total.as_ticks()),
        end_time: Some(end.as_ticks()),
        binary_size: Some(n),
        fetch_target_files: Some(duration_fetch_sigstore_keys.into()),
        update_repo: Some(duration_update_repo.into()),
        fetch_signature: Some(duration_fetch_signature.into()),
        fetch_binary: Some(duration_fetch_binary.into()),
        verify_binary: Some(duration_verify_binary.into()),
        verify_binary_naive: Some(duration_verification_naive.into()),
    };
    watchdog.feed();
    let mut serialize_buf = [0u8; 2048];
    let n = serde_json_core::to_slice(&benchmark_data, &mut serialize_buf)
        .expect("failed to serialize");
    watchdog.feed();
    let data = &serialize_buf[..n];
    let client_state = TcpClientState::<1, 1024, 1024>::new();
    let tcp_client = TcpClient::new(stack, &client_state);
    let dns_client = embassy_net::dns::DnsSocket::new(stack);
    let mut http_client = reqwless::client::HttpClient::new(&tcp_client, &dns_client);
    let url = concat!("http://", env!("OTA_SERVER_HOST"), ":8080/");
    // for non-TLS requests, use this instead:
    // let mut http_client = HttpClient::new(&tcp_client, &dns_client);
    // let url = "http://worldtimeapi.org/api/timezone/Europe/Berlin";
    watchdog.feed();
    let mut request = match http_client.request(Method::POST, &url).await {
        Ok(req) => req,
        Err(e) => {
            return; // handle the error
        }
    };
    watchdog.feed();
    let mut rx_buffer = [0; 8192];
    let response = request
        .body(data)
        .send(&mut rx_buffer)
        .await
        .unwrap()
        .body()
        .read_to_end()
        .await
        .unwrap();

    watchdog.feed();
    control.gpio_set(0, true).await;
    let Ok(_) = updater.mark_updated() else {
        loop {
            watchdog.feed();
            Timer::after_millis(200).await;
            control.gpio_set(0, true).await;
            Timer::after_millis(200).await;
            control.gpio_set(0, false).await;
        }
    };

    Timer::after_millis(3000).await;
    watchdog.feed();
    Timer::after_millis(3000).await;
    watchdog.feed();
    control.gpio_set(0, false).await;
    cortex_m::peripheral::SCB::sys_reset();
}

#[global_allocator]
static HEAP: Heap = Heap::empty();

#[derive(serde::Deserialize, serde::Serialize, Debug, Default)]
struct BenchmarkData {
    start_time: Option<u64>,
    end_time: Option<u64>,
    binary_size: Option<usize>,
    fetch_target_files: Option<core::time::Duration>,
    update_repo: Option<core::time::Duration>,
    fetch_signature: Option<core::time::Duration>,
    fetch_binary: Option<core::time::Duration>,
    verify_binary: Option<core::time::Duration>,
    verify_binary_naive: Option<core::time::Duration>,
}
