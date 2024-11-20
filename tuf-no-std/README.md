# tuf-no-std

- proof-of-concept `no-std` Rust implementation for TUF based on the DER format
- attempts to adhere to the TUF specification as far as possible
- possible that some aspects of the code fail to do so

## Project Structure

The project is divided into the following modules.
- `tuf-no-std`: most of the logic resides here, some of the code could be split into the other crates.
- `tuf-no-cli`: tool to create a TUF repo, not very flexible; also serves as an example on how to use the builders from the `tuf-no-std` crate.
- `tuf-no-common`: crate common functionalities such as error types, traits, constants, etc. that need to be available to other non-top level modules.
- `tuf-no-der`: TUF data structures for the DER format.

## Building the Docs

To view the documentation within the code (RustDocs) run the following command:

```sh
cargo doc --open
```
