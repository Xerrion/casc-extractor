# casc-extractor

[![CI](https://github.com/Xerrion/casc-extractor/actions/workflows/ci.yml/badge.svg)](https://github.com/Xerrion/casc-extractor/actions/workflows/ci.yml)
[![crates.io](https://img.shields.io/crates/v/casc-lib.svg)](https://crates.io/crates/casc-lib)
[![docs.rs](https://docs.rs/casc-lib/badge.svg)](https://docs.rs/casc-lib)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

## Overview

A pure Rust CLI tool and library for reading World of Warcraft CASC (Content Addressable Storage Container) archives. Built from scratch with no external CASC library dependencies - every layer of the extraction pipeline is implemented natively in Rust.

## Features

- **BLTE decoding** - supports N (plain), Z (zlib), and 4 (LZ4) compression modes
- **TACT encryption** - Salsa20 and ARC4 decryption with configurable key stores
- **LZ4 sub-block decompression** - handles chunked BLTE frames with LZ4 compression
- **Parallel extraction** - multi-threaded file extraction powered by rayon
- **Metadata indexing** - generates JSONL and CSV metadata indexes during extraction
- **Glob filtering** - extract or list only files matching a glob pattern
- **Listfile integration** - automatic community listfile download for FDID-to-path mapping
- **Multi-product support** - works with retail, classic, and anniversary WoW installations

## Installation

Install the CLI tool:

```sh
cargo install casc-cli
```

Add the library to your project:

```sh
cargo add casc-lib
```

## CLI Usage

The binary is called `casc-extractor` and provides four subcommands:

### Extract all files

```sh
casc-extractor extract "E:\World of Warcraft" -o ./extracted -p wow
```

Extract with filtering, checksum verification, and encrypted file skipping:

```sh
casc-extractor extract "E:\World of Warcraft" -o ./extracted -p wow \
    --filter "world/maps/**" --verify --skip-encrypted -j 8
```

### List files

```sh
casc-extractor list "E:\World of Warcraft" -p wow --filter "interface/icons/*"
```

### Show storage info

```sh
casc-extractor info "E:\World of Warcraft" -p wow
```

### Extract a single file by FileDataID

```sh
casc-extractor get 136235 -i "E:\World of Warcraft" -o icon.blp -p wow
```

## Library Usage

```rust
use casc_lib::extract::{CascStorage, OpenConfig, list_files};
use casc_lib::root::flags::LocaleFlags;

// Open a CASC storage directory
let config = OpenConfig {
    install_dir: "E:\\World of Warcraft".into(),
    product: Some("wow".into()),
    keyfile: None,
    listfile: None,
    output_dir: None,
};
let storage = CascStorage::open(&config)?;

// Read a file by FileDataID
let data = storage.read_by_fdid(136235, LocaleFlags::EN_US)?;
println!("Read {} bytes", data.len());

// List all files matching a filter
let files = list_files(&storage, LocaleFlags::EN_US.0, Some("interface/icons/*"));
for (fdid, path) in &files {
    println!("{}\t{}", fdid, path);
}
```

## Supported Products

| Product           | Flag                | Description                      |
|-------------------|---------------------|----------------------------------|
| Retail            | `wow`               | The War Within, current live     |
| Classic           | `wow_classic`       | Current classic expansion        |
| Classic Era       | `wow_classic_era`   | Vanilla Classic (1.x)            |
| Anniversary       | `wow_anniversary`   | 20th Anniversary edition         |
| Retail PTR        | `wowt`              | Public Test Realm                |
| Classic PTR       | `wow_classic_ptr`   | Classic PTR                      |

Any product present in `.build.info` is supported. Use `casc-extractor info <path>` to list installed products.

Pass the product flag with `-p` on the CLI, or set it via `OpenConfig::product` in the library.

## Building from Source

```sh
git clone https://github.com/Xerrion/casc-extractor.git
cd casc-extractor
cargo build --release
```

The compiled binary will be at `target/release/casc-extractor` (or `casc-extractor.exe` on Windows).

## Project Structure

```
casc-extractor/
  crates/
    casc-lib/    # Core library - BLTE, TACT, encoding, root, storage
    casc-cli/    # CLI binary wrapping casc-lib with clap
  Cargo.toml     # Workspace root
```

## License

Licensed under the [MIT License](LICENSE).
