//! Pure Rust library for reading Blizzard CASC (Content Addressable Storage Container) archives.
//!
//! CASC is the file storage format used by World of Warcraft (and other Blizzard titles) to
//! bundle game data on disk. This crate provides the building blocks to open a local CASC
//! installation, resolve file identifiers, and extract raw file content.
//!
//! # Architecture
//!
//! The extraction pipeline follows this path:
//!
//! 1. **Config** - parse `.build.info`, build config, and CDN config to discover keys and paths.
//! 2. **Storage** - open `data.NNN` archives and their `.idx` index files.
//! 3. **Encoding** - load the encoding file that maps content keys (CKeys) to encoding keys (EKeys).
//! 4. **Root** - load the root file that maps file data IDs (FDIDs) to CKeys.
//! 5. **BLTE** - decode the BLTE container (decompress, decrypt) to get raw file bytes.
//!
//! # Quick Start
//!
//! ```no_run
//! use casc_lib::extract::pipeline::{CascStorage, OpenConfig};
//! use casc_lib::root::flags::LocaleFlags;
//!
//! let config = OpenConfig {
//!     install_dir: "E:\\World of Warcraft".into(),
//!     product: None,
//!     keyfile: None,
//!     listfile: None,
//!     output_dir: None,
//! };
//! let storage = CascStorage::open(&config)?;
//! let data = storage.read_by_fdid(136235, LocaleFlags::EN_US)?;
//! # Ok::<(), casc_lib::error::CascError>(())
//! ```

/// BLTE (Binary Large Table Entry) container decoding, compression, and encryption.
pub mod blte;
/// CASC configuration file parsers (`.build.info`, build config, CDN config).
pub mod config;
/// Encoding file parser - maps content keys (CKeys) to encoding keys (EKeys).
pub mod encoding;
/// Error types and the crate-wide [`Result`](error::Result) alias.
pub mod error;
/// High-level extraction pipeline for opening CASC storage and reading files.
pub mod extract;
/// Community listfile download and parsing (FDID to filename mapping).
pub mod listfile;
/// Root file parser - maps file data IDs (FDIDs) to content keys (CKeys).
pub mod root;
/// Low-level data archive and index file access.
pub mod storage;
/// Shared I/O and hashing utilities.
pub mod util;
