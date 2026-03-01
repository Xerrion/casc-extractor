# casc-lib

Pure Rust library for reading World of Warcraft CASC (Content Addressable Storage Container) archives.

This crate implements the full CASC extraction pipeline - from parsing `.build.info` and index files through BLTE decoding and TACT decryption - with no external CASC library dependencies.

## Features

- BLTE container decoding (N/Z/4 compression modes)
- TACT encryption support (Salsa20 + ARC4)
- LZ4 sub-block decompression
- Encoding and root file parsing (Legacy, MFST V1, MFST V2)
- Parallel extraction with rayon
- JSONL/CSV metadata index generation
- Community listfile integration (FDID-to-path mapping)
- Supports retail, classic, and anniversary WoW installations

## Usage

Add to your `Cargo.toml`:

```sh
cargo add casc-lib
```

### Open storage and read a file by FileDataID

```rust
use casc_lib::extract::{CascStorage, OpenConfig};
use casc_lib::root::flags::LocaleFlags;

let config = OpenConfig {
    install_dir: "E:\\World of Warcraft".into(),
    product: Some("wow".into()),
    keyfile: None,
    listfile: None,
    output_dir: None,
};
let storage = CascStorage::open(&config)?;

let data = storage.read_by_fdid(136235, LocaleFlags::EN_US)?;
println!("Read {} bytes", data.len());
```

### Iterate root entries

```rust
use casc_lib::root::flags::LocaleFlags;

for (fdid, entry) in storage.root.iter_all() {
    if entry.locale_flags.matches(LocaleFlags::EN_US) {
        println!("FDID {} -> CKey {}", fdid, hex::encode(entry.ckey));
    }
}
```

### List files with glob filtering

```rust
use casc_lib::extract::list_files;

let files = list_files(&storage, LocaleFlags::EN_US.0, Some("interface/icons/*"));
for (fdid, path) in &files {
    println!("{}\t{}", fdid, path);
}
```

## Documentation

Full API docs are available on [docs.rs](https://docs.rs/casc-lib).

## License

Licensed under the [MIT License](../../LICENSE).
