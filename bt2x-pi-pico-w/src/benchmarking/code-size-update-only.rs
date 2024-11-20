//! This example uses the RP Pico W board Wifi chip (cyw43).
//! Connects to specified Wifi network and creates a TCP endpoint on port 1234.

#![no_std]
#![no_main]
#![feature(type_alias_impl_trait)]
#![feature(async_fn_in_trait)]
#![feature(impl_trait_in_assoc_type)]
#![allow(stable_features, unknown_lints, async_fn_in_trait)]

use bt2x_embedded::Sha256;
use bt2x_ota_common::net::Transport;
use cyw43_pio::PioSpi;
// use defmt::*;
use embassy_boot_rp::{AlignedBuffer, BlockingFirmwareUpdater, FirmwareUpdaterConfig};
use embassy_executor::Spawner;
use embassy_net::{Config, IpEndpoint, Stack, StackResources};
use embassy_rp::bind_interrupts;
use embassy_rp::clocks::RoscRng;
use embassy_rp::flash::Flash;
use embassy_rp::gpio::{Level, Output};
use embassy_rp::peripherals::{DMA_CH0, PIO0};
use embassy_rp::pio::{InterruptHandler, Pio};
use embassy_rp::watchdog::Watchdog;
use embassy_sync::blocking_mutex::Mutex;
use embassy_time::{Duration, Timer};
use rand::RngCore;
//use embedded_io_async::Write as AsyncIoWrite;
use core::cell::RefCell;
use static_cell::StaticCell;
use {defmt_rtt as _, panic_probe as _};

use embedded_alloc::Heap;

bind_interrupts!(struct Irqs {
    PIO0_IRQ_0 => InterruptHandler<PIO0>;
});

// Dummy values
const WIFI_NETWORK: &str = "the network";
const WIFI_PASSWORD: &str = "the password";
const OTA_SERVER_PORT: &str = "5000";
const OTA_SERVER_HOST: &str = "127.0.0.1";
const FLASH_SIZE: usize = 2 * 1024 * 1024;

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
    let config = Config::dhcpv4(Default::default());
    //let config = embassy_net::Config::ipv4_static(embassy_net::StaticConfigV4 {
    //    address: Ipv4Cidr::new(Ipv4Address::new(192, 168, 69, 2), 24),
    //    dns_servers: Vec::new(),
    //    gateway: Some(Ipv4Address::new(192, 168, 69, 1)),
    //});

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

    let transport = Transport {
        network_stack: stack,
        server: IpEndpoint::new(
            OTA_SERVER_HOST.parse().unwrap(),
            OTA_SERVER_PORT.parse().unwrap(),
        ),
    };

    watchdog.feed();

    let flash = Flash::<_, _, FLASH_SIZE>::new_blocking(p.FLASH);
    let flash = Mutex::new(RefCell::new(flash));

    let config = FirmwareUpdaterConfig::from_linkerfile_blocking(&flash, &flash);
    let mut aligned = AlignedBuffer([0; 1]);
    let mut updater = BlockingFirmwareUpdater::new(config, &mut aligned.0);
    let mut dfu = updater.prepare_update().unwrap();
    watchdog.feed();

    control.gpio_set(0, true).await;
    let (_, _) = transport
        .fetch_binary_flash::<Sha256>(b"pi-pico-bin", &mut dfu)
        .await
        .unwrap();
    control.gpio_set(0, false).await;
    Timer::after_millis(100).await;
    control.gpio_set(0, true).await;

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
    watchdog.feed();
    Timer::after_millis(2000).await;
    watchdog.feed();
    Timer::after_millis(2000).await;
    watchdog.feed();
    control.gpio_set(0, false).await;
    cortex_m::peripheral::SCB::sys_reset();
}

#[global_allocator]
static HEAP: Heap = Heap::empty();
