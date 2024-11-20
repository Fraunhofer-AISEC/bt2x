# BT²X Example on a Pi Pico W

This folder contains the source code for the Pi Pico W example. The `main.rs` file contains the updater and the `blinky.rs` file contains the dummy program.

The WiFi drivers are in the `firmware` directory. The binaries used for benchmarking are in the `src/benchmarking` directory.

## Building/Flashing

### Environment variables

The example application requires a network connection via WiFi.

To configure the network connection create a `.env` file and source it, it has to set the correct environment variables. It has the following variables:
- `WIFI_NETWORK`
- `WIFI_PASSWORD`
- `OTA_SERVER_PORT`: TCP port of the OTA server, set it to `50000`.
- `OTA_SERVER_HOST`: the network address of the host running the docker setup.
- `GITHUB_EMAIL`: the email address that was used to sign the firmware.


### Flashing

If you have [probe-rs](https://probe.rs/docs/getting-started/installation/) installed and the Pico W is correctly wired to a debug probe you can run the following command to flash binaries.

```sh
cargo flash --release  --bin=<BINARY NAME> --chip RP2040
```
#### Flashing the Bootloader

To run the code you need to flash the bootloader, it is put at the beginning of the flash.
The other applications are flashed at addresses that succeed it, refer to respective `memory.x` files for more details.+

You only need to run this command **once**, assuming you do not overwrite the part of the flash that stores the bootloader.

```sh
cargo flash --manifest-path ../pico-w-bootloader/Cargo.toml --release --chip RP2040
```

#### Flashing the Updater

```sh
cargo flash --release  --bin=pico-w-updater --chip RP2040
```

#### WiFi Drivers

You also need to flash the WiFi drivers once. If you overwrite the addresses where the drivers are stored you need to flash them again. However, this should not happen with the examples from this repository.

```sh
probe-rs download 43439A0.bin --binary-format bin --chip RP2040 --base-address 0x10110000
probe-rs download 43439A0_clm.bin --binary-format bin --chip RP2040 --base-address 0x10150000
```