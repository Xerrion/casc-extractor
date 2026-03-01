//! Core CASC extraction pipeline.
//!
//! Provides [`CascStorage`] - a facade that bootstraps all CASC components
//! (build info, build config, index, data store, encoding, root, listfile,
//! and key store) from a WoW install directory - and the extraction functions
//! [`extract_all`], [`extract_single_file`], and [`list_files`].

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use rayon::ThreadPoolBuilder;
use rayon::prelude::*;

use crate::blte::decoder::decode_blte_with_keys;
use crate::blte::encryption::TactKeyStore;
use crate::config::build_config::{BuildConfig, config_path, parse_build_config};
use crate::config::build_info::{BuildInfo, parse_build_info};
use crate::encoding::parser::EncodingFile;
use crate::error::{CascError, Result};
use crate::listfile::downloader::load_or_download;
use crate::listfile::parser::Listfile;
use crate::root::flags::LocaleFlags;
use crate::root::parser::{RootEntry, RootFile, RootFormat};
use crate::storage::data::DataStore;
use crate::storage::index::CascIndex;

use super::metadata::{ExtractionStats, MetadataEntry, MetadataWriter};

// ---------------------------------------------------------------------------
// Configuration types
// ---------------------------------------------------------------------------

/// Configuration for opening CASC storage.
pub struct OpenConfig {
    /// Path to the WoW install directory (the folder containing `.build.info`).
    pub install_dir: PathBuf,
    /// Filter by product name (e.g. "wow", "wow_classic").
    pub product: Option<String>,
    /// Optional custom keyfile path.
    pub keyfile: Option<PathBuf>,
    /// Optional custom listfile path.
    pub listfile: Option<PathBuf>,
    /// Directory for listfile cache and other output.
    pub output_dir: Option<PathBuf>,
}

/// Extraction configuration.
pub struct ExtractionConfig {
    /// Directory where extracted files are written.
    pub output_dir: PathBuf,
    /// Raw locale bitmask used to filter root entries (e.g. `0x2` for enUS).
    pub locale: u32,
    /// Number of rayon worker threads for parallel extraction.
    pub threads: usize,
    /// When `true`, verify extracted file checksums against their CKey.
    pub verify: bool,
    /// When `true`, skip files marked with the `ENCRYPTED` content flag.
    pub skip_encrypted: bool,
    /// Optional glob pattern to filter files by listfile path.
    pub filter: Option<String>,
    /// When `true`, disable writing metadata files (JSONL, CSV, summary).
    pub no_metadata: bool,
}

/// High-level storage info.
pub struct StorageInfo {
    /// Build name string from the build config (e.g. `"WOW-12345patch1.2.3"`).
    pub build_name: String,
    /// Product identifier from `.build.info` (e.g. `"wow"`, `"wow_classic"`).
    pub product: String,
    /// Client version string (e.g. `"12.0.1.66192"`).
    pub version: String,
    /// Number of entries in the encoding table.
    pub encoding_entries: usize,
    /// Total number of root file entries across all blocks.
    pub root_entries: usize,
    /// Detected root file format as a display string (`"Legacy"`, `"MfstV1"`, `"MfstV2"`).
    pub root_format: String,
    /// Number of entries in the CASC index.
    pub index_entries: usize,
    /// Number of entries in the loaded listfile.
    pub listfile_entries: usize,
}

// ---------------------------------------------------------------------------
// Central CASC storage facade
// ---------------------------------------------------------------------------

/// Central CASC storage facade that bootstraps all components and provides
/// file read methods.
pub struct CascStorage {
    pub build_info: BuildInfo,
    pub build_config: BuildConfig,
    pub index: CascIndex,
    pub data: DataStore,
    pub encoding: EncodingFile,
    pub root: RootFile,
    pub listfile: Listfile,
    pub keystore: TactKeyStore,
}

impl CascStorage {
    /// Bootstrap all CASC components from an install directory.
    ///
    /// See [`OpenConfig`] for configuration options.
    pub fn open(config: &OpenConfig) -> Result<Self> {
        // 1. Read .build.info from install_dir (NOT Data/)
        let build_info_path = config.install_dir.join(".build.info");
        let build_info_content = std::fs::read_to_string(&build_info_path)?;
        let all_entries = parse_build_info(&build_info_content)?;

        // 2. Filter by product or take first active entry
        let build_info = select_build_info(&all_entries, config.product.as_deref())?;

        // 3. Read build config
        let data_dir = config.install_dir.join("Data");
        let config_rel = config_path(&build_info.build_key);
        let config_file = data_dir.join(&config_rel);
        let config_content = std::fs::read_to_string(&config_file)?;
        let build_config = parse_build_config(&config_content)?;

        // 4. Load CascIndex from Data/data/
        let data_data_dir = data_dir.join("data");
        let index = CascIndex::load(&data_data_dir)?;

        // 5. Open DataStore from Data/data/
        let data_store = DataStore::open(&data_data_dir)?;

        // 6. Set up keystore
        let mut keystore = TactKeyStore::with_known_keys();
        if let Some(ref keyfile_path) = config.keyfile {
            let custom = TactKeyStore::load_keyfile(keyfile_path)?;
            keystore.merge(&custom);
        }

        // 7. Bootstrap encoding file
        let encoding = bootstrap_encoding(&build_config, &index, &data_store, &keystore)?;

        // 8. Bootstrap root file
        let root = bootstrap_root(&build_config, &encoding, &index, &data_store, &keystore)?;

        // 9. Load listfile
        let listfile = load_listfile(config)?;

        Ok(Self {
            build_info,
            build_config,
            index,
            data: data_store,
            encoding,
            root,
            listfile,
            keystore,
        })
    }

    /// Read a file by its content key (CKey).
    pub fn read_by_ckey(&self, ckey: &[u8; 16]) -> Result<Vec<u8>> {
        let enc_entry = self
            .encoding
            .find_ekey(ckey)
            .ok_or_else(|| CascError::KeyNotFound {
                key_type: "CKey".into(),
                hash: hex::encode(ckey),
            })?;

        let ekey = &enc_entry.ekeys[0];
        let idx_entry = self
            .index
            .find(ekey)
            .ok_or_else(|| CascError::KeyNotFound {
                key_type: "EKey".into(),
                hash: hex::encode(ekey),
            })?;

        let blte_data = self.data.read_raw(
            idx_entry.archive_number,
            idx_entry.archive_offset,
            idx_entry.size,
        )?;

        decode_blte_with_keys(blte_data, Some(&self.keystore))
    }

    /// Read a file by FileDataID and locale.
    pub fn read_by_fdid(&self, fdid: u32, locale: LocaleFlags) -> Result<Vec<u8>> {
        let root_entry =
            self.root
                .find_by_fdid(fdid, locale)
                .ok_or_else(|| CascError::KeyNotFound {
                    key_type: "FDID".into(),
                    hash: format!("{} (locale {})", fdid, locale),
                })?;

        self.read_by_ckey(&root_entry.ckey)
    }

    /// Return high-level statistics about the loaded storage.
    pub fn info(&self) -> StorageInfo {
        let root_format = match self.root.format() {
            RootFormat::Legacy => "Legacy",
            RootFormat::MfstV1 => "MfstV1",
            RootFormat::MfstV2 => "MfstV2",
        };

        StorageInfo {
            build_name: self.build_config.build_name.clone(),
            product: self.build_info.product.clone(),
            version: self.build_info.version.clone(),
            encoding_entries: self.encoding.len(),
            root_entries: self.root.len(),
            root_format: root_format.to_string(),
            index_entries: self.index.len(),
            listfile_entries: self.listfile.len(),
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Select the appropriate BuildInfo entry by product filter or take first active.
fn select_build_info(entries: &[BuildInfo], product: Option<&str>) -> Result<BuildInfo> {
    if entries.is_empty() {
        return Err(CascError::InvalidFormat("no entries in .build.info".into()));
    }

    let selected = match product {
        Some(p) => entries
            .iter()
            .find(|e| e.active && e.product == p)
            .or_else(|| entries.iter().find(|e| e.product == p)),
        None => entries.iter().find(|e| e.active),
    };

    selected.cloned().ok_or_else(|| {
        let filter_desc = product
            .map(|p| format!("product '{p}'"))
            .unwrap_or_else(|| "active".into());
        CascError::InvalidFormat(format!(
            "no matching entry in .build.info for {filter_desc}"
        ))
    })
}

/// Bootstrap the encoding file from the build config.
fn bootstrap_encoding(
    build_config: &BuildConfig,
    index: &CascIndex,
    data: &DataStore,
    keystore: &TactKeyStore,
) -> Result<EncodingFile> {
    let ekey_bytes = hex_to_bytes(&build_config.encoding_ekey)?;

    let idx_entry = index
        .find(&ekey_bytes)
        .ok_or_else(|| CascError::KeyNotFound {
            key_type: "encoding EKey".into(),
            hash: build_config.encoding_ekey.clone(),
        })?;

    let blte_data = data.read_entry(
        idx_entry.archive_number,
        idx_entry.archive_offset,
        idx_entry.size,
    )?;

    let raw_data = decode_blte_with_keys(blte_data, Some(keystore))?;
    EncodingFile::parse(&raw_data)
}

/// Bootstrap the root file via encoding lookup.
fn bootstrap_root(
    build_config: &BuildConfig,
    encoding: &EncodingFile,
    index: &CascIndex,
    data: &DataStore,
    keystore: &TactKeyStore,
) -> Result<RootFile> {
    let root_ckey = hex_to_16(&build_config.root_ckey)?;

    let enc_entry = encoding
        .find_ekey(&root_ckey)
        .ok_or_else(|| CascError::KeyNotFound {
            key_type: "root CKey".into(),
            hash: build_config.root_ckey.clone(),
        })?;

    let ekey = &enc_entry.ekeys[0];
    let idx_entry = index.find(ekey).ok_or_else(|| CascError::KeyNotFound {
        key_type: "root EKey".into(),
        hash: hex::encode(ekey),
    })?;

    let blte_data = data.read_entry(
        idx_entry.archive_number,
        idx_entry.archive_offset,
        idx_entry.size,
    )?;

    let raw_data = decode_blte_with_keys(blte_data, Some(keystore))?;
    RootFile::parse(&raw_data)
}

/// Load the listfile from a custom path or via download.
fn load_listfile(config: &OpenConfig) -> Result<Listfile> {
    if let Some(ref path) = config.listfile {
        return Listfile::load(path);
    }

    let output_dir = config
        .output_dir
        .clone()
        .unwrap_or_else(|| std::env::temp_dir().join("casc-extractor"));

    load_or_download(&output_dir)
}

/// Decode a hex string to a `Vec<u8>`.
fn hex_to_bytes(hex_str: &str) -> Result<Vec<u8>> {
    hex::decode(hex_str)
        .map_err(|e| CascError::InvalidFormat(format!("invalid hex string '{}': {}", hex_str, e)))
}

/// Decode a hex string to a `[u8; 16]` array.
fn hex_to_16(hex_str: &str) -> Result<[u8; 16]> {
    let bytes = hex_to_bytes(hex_str)?;
    if bytes.len() < 16 {
        return Err(CascError::InvalidFormat(format!(
            "hex string too short for 16-byte key: '{}'",
            hex_str
        )));
    }
    let mut arr = [0u8; 16];
    arr.copy_from_slice(&bytes[..16]);
    Ok(arr)
}

/// Compute the output path for a FileDataID, using the listfile for naming.
///
/// If the listfile has a path for the FDID, the path is normalized
/// (backslashes replaced with forward slashes) and sanitized against
/// path traversal. Unknown files go to `output_dir/unknown/<fdid>.dat`.
pub fn output_path(output_dir: &Path, fdid: u32, listfile: &Listfile) -> PathBuf {
    match listfile.path(fdid) {
        Some(path) => {
            let normalized = path.replace('\\', "/");
            // Prevent path traversal
            let safe = normalized.trim_start_matches('/').trim_start_matches("../");
            output_dir.join(safe)
        }
        None => output_dir.join("unknown").join(format!("{}.dat", fdid)),
    }
}

// ---------------------------------------------------------------------------
// Extraction functions
// ---------------------------------------------------------------------------

/// Extract all matching files from CASC storage into the output directory.
///
/// Files are filtered by locale and an optional glob pattern, deduplicated by
/// FDID, sorted by archive/offset for sequential I/O, then extracted in
/// parallel via a rayon thread pool.
pub fn extract_all(
    storage: &CascStorage,
    config: &ExtractionConfig,
    progress_cb: Option<&(dyn Fn(u64, u64) + Sync)>,
) -> Result<ExtractionStats> {
    // 1. Collect entries: iterate root, filter by locale
    let locale_filter = LocaleFlags(config.locale);
    let mut entries: Vec<(u32, &RootEntry)> = storage
        .root
        .iter_all()
        .filter(|(_, entry)| entry.locale_flags.matches(locale_filter))
        .collect();

    // 2. Deduplicate by FDID (keep first matching entry per FDID)
    let mut seen = std::collections::HashSet::new();
    entries.retain(|(fdid, _)| seen.insert(*fdid));

    // 3. Apply glob filter if present
    if let Some(ref pattern) = config.filter {
        entries.retain(|(fdid, _)| match storage.listfile.path(*fdid) {
            Some(path) => glob_matches(pattern, path),
            None => false, // unknown files don't match glob
        });
    }

    let total = entries.len() as u64;

    // 4. Sort by archive+offset for sequential I/O
    let mut sortable: Vec<(u32, &RootEntry, u32, u64)> = entries
        .iter()
        .map(|(fdid, re)| {
            let (archive, offset) = storage
                .encoding
                .find_ekey(&re.ckey)
                .and_then(|ee| storage.index.find(&ee.ekeys[0]))
                .map(|ie| (ie.archive_number, ie.archive_offset))
                .unwrap_or((u32::MAX, u64::MAX));
            (*fdid, *re, archive, offset)
        })
        .collect();
    sortable.sort_by_key(|&(_, _, archive, offset)| (archive, offset));

    // 5. Create output directory
    std::fs::create_dir_all(&config.output_dir)?;

    // 6. Create metadata writer (unless disabled)
    let metadata = if !config.no_metadata {
        let build_name = &storage.build_config.build_name;
        let product = &storage.build_info.product;
        Some(MetadataWriter::new(
            &config.output_dir,
            build_name,
            product,
        )?)
    } else {
        None
    };

    // 7. Set up thread pool
    let pool = ThreadPoolBuilder::new()
        .num_threads(config.threads)
        .build()
        .map_err(|e| CascError::InvalidFormat(format!("failed to create thread pool: {}", e)))?;

    // 8. Parallel extraction
    let completed = AtomicU64::new(0);

    pool.install(|| {
        sortable.par_iter().for_each(|(fdid, root_entry, _, _)| {
            let result = extract_one(storage, config, *fdid, root_entry);

            if let Some(ref meta) = metadata {
                let entry = make_metadata_entry(*fdid, root_entry, &result, &storage.listfile);
                let _ = meta.record(&entry);
            }

            let done = completed.fetch_add(1, Ordering::Relaxed) + 1;
            if let Some(cb) = progress_cb {
                cb(done, total);
            }
        });
    });

    // 9. Finish metadata
    if let Some(meta) = metadata {
        meta.finish()
    } else {
        Ok(ExtractionStats::default())
    }
}

/// List all files in the root that match the given locale and optional glob
/// filter. Returns `(FileDataID, path)` pairs sorted by FDID.
pub fn list_files(storage: &CascStorage, locale: u32, filter: Option<&str>) -> Vec<(u32, String)> {
    let locale_filter = LocaleFlags(locale);
    let mut seen = std::collections::HashSet::new();

    let mut result: Vec<(u32, String)> = storage
        .root
        .iter_all()
        .filter(|(_, entry)| entry.locale_flags.matches(locale_filter))
        .filter(|(fdid, _)| seen.insert(*fdid))
        .filter(|(fdid, _)| match filter {
            Some(pat) => match storage.listfile.path(*fdid) {
                Some(path) => glob_matches(pat, path),
                None => false,
            },
            None => true,
        })
        .map(|(fdid, _)| {
            let path = storage.listfile.path(fdid).unwrap_or("unknown").to_string();
            (fdid, path)
        })
        .collect();

    result.sort_by_key(|(fdid, _)| *fdid);
    result
}

/// Extract a single file by FDID or path string to the given output location.
///
/// The `target` parameter is parsed as a numeric FDID first; if that fails it
/// is treated as a listfile path lookup (case-insensitive).
pub fn extract_single_file(
    storage: &CascStorage,
    target: &str,
    output: &Path,
    locale: u32,
) -> Result<u64> {
    let data = if let Ok(fdid) = target.parse::<u32>() {
        storage.read_by_fdid(fdid, LocaleFlags(locale))?
    } else {
        let fdid = storage
            .listfile
            .fdid(target)
            .ok_or_else(|| CascError::KeyNotFound {
                key_type: "path".into(),
                hash: target.into(),
            })?;
        storage.read_by_fdid(fdid, LocaleFlags(locale))?
    };

    if let Some(parent) = output.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let size = data.len() as u64;
    std::fs::write(output, &data)?;
    Ok(size)
}

// ---------------------------------------------------------------------------
// Extraction helpers (private)
// ---------------------------------------------------------------------------

/// Extract a single file from storage, returning the bytes written or an
/// error string for metadata recording.
fn extract_one(
    storage: &CascStorage,
    config: &ExtractionConfig,
    fdid: u32,
    root_entry: &RootEntry,
) -> std::result::Result<u64, String> {
    // Check if encrypted and skip if configured
    if root_entry.content_flags.0 & 0x8000000 != 0 && config.skip_encrypted {
        return Err("skipped:encrypted".into());
    }

    // Read the file data
    let data = storage
        .read_by_ckey(&root_entry.ckey)
        .map_err(|e| format!("error:{}", e))?;

    // Optional: verify MD5
    if config.verify {
        use md5::{Digest, Md5};
        let mut hasher = Md5::new();
        hasher.update(&data);
        let hash = hasher.finalize();
        if hash.as_slice() != root_entry.ckey {
            return Err(format!("error:checksum mismatch for FDID {}", fdid));
        }
    }

    // Determine output path and write
    let out_path = output_path(&config.output_dir, fdid, &storage.listfile);

    if let Some(parent) = out_path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("error:mkdir: {}", e))?;
    }

    std::fs::write(&out_path, &data).map_err(|e| format!("error:write: {}", e))?;

    Ok(data.len() as u64)
}

/// Build a [`MetadataEntry`] from extraction results for metadata recording.
fn make_metadata_entry(
    fdid: u32,
    root_entry: &RootEntry,
    result: &std::result::Result<u64, String>,
    listfile: &Listfile,
) -> MetadataEntry {
    let path = listfile
        .path(fdid)
        .map(|s| s.to_string())
        .unwrap_or_else(|| format!("unknown/{}.dat", fdid));
    let ckey_hex = hex::encode(root_entry.ckey);

    match result {
        Ok(size) => MetadataEntry {
            fdid,
            path,
            size: *size,
            ckey: ckey_hex,
            locale_flags: root_entry.locale_flags.0,
            content_flags: root_entry.content_flags.0,
            status: "ok".into(),
        },
        Err(status) => MetadataEntry {
            fdid,
            path,
            size: 0,
            ckey: ckey_hex,
            locale_flags: root_entry.locale_flags.0,
            content_flags: root_entry.content_flags.0,
            status: status.clone(),
        },
    }
}

/// Simple glob matching for WoW file paths.
///
/// Supported patterns:
/// - `dir/**` - matches all files recursively under `dir/`
/// - `*.ext` - matches any file ending with `.ext`
/// - `dir/*` - matches files directly inside `dir/` (not recursive)
/// - `prefix*` or `dir/prefix*` - matches files starting with prefix
/// - exact path - literal match
///
/// All matching is case-insensitive with forward-slash normalization.
fn glob_matches(pattern: &str, path: &str) -> bool {
    let pattern = pattern.to_lowercase().replace('\\', "/");
    let path = path.to_lowercase().replace('\\', "/");

    if pattern.ends_with("/**") {
        let prefix = &pattern[..pattern.len() - 3];
        return path.starts_with(&format!("{}/", prefix)) || path == *prefix;
    }
    if pattern.starts_with("*.") {
        let suffix = &pattern[1..]; // e.g. ".m2"
        return path.ends_with(suffix);
    }
    if pattern.ends_with("/*") {
        let prefix = &pattern[..pattern.len() - 2];
        return path.starts_with(&format!("{}/", prefix))
            && !path[prefix.len() + 1..].contains('/');
    }
    // Trailing wildcard: "some/prefix*" matches anything starting with "some/prefix"
    if pattern.ends_with('*') {
        let prefix = &pattern[..pattern.len() - 1];
        return path.starts_with(prefix);
    }
    // Exact match fallback
    path == pattern
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn output_path_from_listfile_hit() {
        let listfile = Listfile::parse("53;Cameras/FlyBy.m2");
        let out = PathBuf::from("/output");
        let result = output_path(&out, 53, &listfile);
        // Should use the listfile path (preserving case from listfile)
        assert!(result.to_string_lossy().contains("Cameras"));
        assert!(result.to_string_lossy().contains("FlyBy.m2"));
    }

    #[test]
    fn output_path_from_listfile_miss() {
        let listfile = Listfile::parse("");
        let out = PathBuf::from("/output");
        let result = output_path(&out, 99999, &listfile);
        assert!(result.to_string_lossy().contains("unknown"));
        assert!(result.to_string_lossy().contains("99999.dat"));
    }

    #[test]
    fn output_path_normalizes_backslashes() {
        let listfile = Listfile::parse("100;World\\Maps\\Test.adt");
        let out = PathBuf::from("/output");
        let result = output_path(&out, 100, &listfile);
        // Should not contain backslashes (on the path level)
        let s = result.to_string_lossy().replace('\\', "/");
        assert!(s.contains("World/Maps/Test.adt") || s.contains("world/maps/test.adt"));
    }

    #[test]
    fn output_path_prevents_traversal() {
        // A malicious listfile entry
        let listfile = Listfile::parse("200;../../../etc/passwd");
        let out = PathBuf::from("/output");
        let result = output_path(&out, 200, &listfile);
        // Must not escape output_dir
        assert!(result.starts_with("/output"));
    }

    #[test]
    fn extraction_config_defaults() {
        let config = ExtractionConfig {
            output_dir: PathBuf::from("/out"),
            locale: 0x2, // enUS
            threads: 4,
            verify: false,
            skip_encrypted: true,
            filter: None,
            no_metadata: false,
        };
        assert_eq!(config.locale, 0x2);
        assert!(config.skip_encrypted);
    }

    #[test]
    fn open_config_minimal() {
        let config = OpenConfig {
            install_dir: PathBuf::from("E:\\World of Warcraft"),
            product: Some("wow".into()),
            keyfile: None,
            listfile: None,
            output_dir: None,
        };
        assert_eq!(config.product, Some("wow".into()));
    }

    #[test]
    fn storage_info_fields() {
        let info = StorageInfo {
            build_name: "WOW-12345".into(),
            product: "wow".into(),
            version: "12.0.1.66192".into(),
            encoding_entries: 100000,
            root_entries: 500000,
            root_format: "MfstV2".into(),
            index_entries: 200000,
            listfile_entries: 400000,
        };
        assert_eq!(info.build_name, "WOW-12345");
        assert_eq!(info.root_entries, 500000);
    }

    #[test]
    fn hex_to_bytes_16() {
        let hex_str = "0ff1247849a5cd6049624d3a105811f8";
        let bytes = hex::decode(hex_str).unwrap();
        assert_eq!(bytes.len(), 16);
        assert_eq!(bytes[0], 0x0f);
        assert_eq!(bytes[1], 0xf1);
    }

    #[test]
    fn hex_to_16_valid() {
        let arr = hex_to_16("0ff1247849a5cd6049624d3a105811f8").unwrap();
        assert_eq!(arr[0], 0x0f);
        assert_eq!(arr[15], 0xf8);
    }

    #[test]
    fn hex_to_16_too_short() {
        assert!(hex_to_16("aabb").is_err());
    }

    #[test]
    fn hex_to_16_invalid_hex() {
        assert!(hex_to_16("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz").is_err());
    }

    #[test]
    fn select_build_info_by_product() {
        let entries = vec![
            BuildInfo {
                branch: "eu".into(),
                active: true,
                build_key: "abc".into(),
                cdn_key: "def".into(),
                cdn_path: "".into(),
                cdn_hosts: vec![],
                version: "1.0".into(),
                product: "wow".into(),
                tags: "".into(),
                keyring: "".into(),
            },
            BuildInfo {
                branch: "eu".into(),
                active: true,
                build_key: "xyz".into(),
                cdn_key: "uvw".into(),
                cdn_path: "".into(),
                cdn_hosts: vec![],
                version: "2.0".into(),
                product: "wow_classic".into(),
                tags: "".into(),
                keyring: "".into(),
            },
        ];

        let selected = select_build_info(&entries, Some("wow_classic")).unwrap();
        assert_eq!(selected.product, "wow_classic");
        assert_eq!(selected.build_key, "xyz");
    }

    #[test]
    fn select_build_info_first_active() {
        let entries = vec![
            BuildInfo {
                branch: "eu".into(),
                active: false,
                build_key: "inactive".into(),
                cdn_key: "".into(),
                cdn_path: "".into(),
                cdn_hosts: vec![],
                version: "".into(),
                product: "wow".into(),
                tags: "".into(),
                keyring: "".into(),
            },
            BuildInfo {
                branch: "eu".into(),
                active: true,
                build_key: "active".into(),
                cdn_key: "".into(),
                cdn_path: "".into(),
                cdn_hosts: vec![],
                version: "1.0".into(),
                product: "wow".into(),
                tags: "".into(),
                keyring: "".into(),
            },
        ];

        let selected = select_build_info(&entries, None).unwrap();
        assert_eq!(selected.build_key, "active");
    }

    #[test]
    fn select_build_info_empty() {
        let result = select_build_info(&[], Some("wow"));
        assert!(result.is_err());
    }

    #[test]
    fn select_build_info_no_match() {
        let entries = vec![BuildInfo {
            branch: "eu".into(),
            active: true,
            build_key: "abc".into(),
            cdn_key: "".into(),
            cdn_path: "".into(),
            cdn_hosts: vec![],
            version: "".into(),
            product: "wow".into(),
            tags: "".into(),
            keyring: "".into(),
        }];

        let result = select_build_info(&entries, Some("nonexistent"));
        assert!(result.is_err());
    }

    // Integration tests - only run with real WoW install
    #[test]
    #[ignore]
    fn open_real_casc_storage() {
        let config = OpenConfig {
            install_dir: PathBuf::from(r"E:\World of Warcraft"),
            product: Some("wow".into()),
            keyfile: None,
            listfile: None,
            output_dir: Some(std::env::temp_dir().join("casc_test_open")),
        };
        let storage = CascStorage::open(&config).unwrap();
        let info = storage.info();
        assert!(info.encoding_entries > 0);
        assert!(info.root_entries > 100000);
        println!("Build: {}", info.build_name);
        println!("Encoding entries: {}", info.encoding_entries);
        println!("Root entries: {}", info.root_entries);
    }

    #[test]
    #[ignore]
    fn read_known_file_by_fdid() {
        let config = OpenConfig {
            install_dir: PathBuf::from(r"E:\World of Warcraft"),
            product: Some("wow".into()),
            keyfile: None,
            listfile: None,
            output_dir: Some(std::env::temp_dir().join("casc_test_read")),
        };
        let storage = CascStorage::open(&config).unwrap();
        // FDID 1 should exist in virtually every WoW build
        let data = storage.read_by_fdid(1, LocaleFlags::EN_US);
        // It might fail for various reasons, but shouldn't panic
        println!("FDID 1 result: {:?}", data.is_ok());
        if let Ok(bytes) = data {
            println!("FDID 1 size: {} bytes", bytes.len());
        }
    }

    // -----------------------------------------------------------------------
    // Glob matching tests
    // -----------------------------------------------------------------------

    #[test]
    fn glob_matches_double_star() {
        assert!(glob_matches(
            "world/maps/**",
            "world/maps/azeroth/azeroth_25_25.adt"
        ));
        assert!(glob_matches("world/maps/**", "world/maps/test.wdt"));
        assert!(!glob_matches("world/maps/**", "interface/icons/test.blp"));
    }

    #[test]
    fn glob_matches_extension() {
        assert!(glob_matches("*.m2", "creature/bear/bear.m2"));
        assert!(glob_matches("*.M2", "Creature/Bear/Bear.m2")); // case insensitive
        assert!(!glob_matches("*.m2", "creature/bear/bear.skin"));
    }

    #[test]
    fn glob_matches_single_star() {
        assert!(glob_matches(
            "interface/icons/*",
            "interface/icons/test.blp"
        ));
        assert!(!glob_matches(
            "interface/icons/*",
            "interface/icons/subdir/test.blp"
        ));
    }

    #[test]
    fn glob_matches_exact() {
        assert!(glob_matches("test.txt", "test.txt"));
        assert!(!glob_matches("test.txt", "other.txt"));
    }

    // -----------------------------------------------------------------------
    // Extraction helper tests
    // -----------------------------------------------------------------------

    #[test]
    fn extract_single_file_parses_fdid() {
        // Verify the parsing logic: numeric strings are treated as FDIDs
        let target = "12345";
        assert!(target.parse::<u32>().is_ok());

        let target_path = "world/maps/test.adt";
        assert!(target_path.parse::<u32>().is_err());
    }

    #[test]
    fn make_metadata_entry_ok() {
        let listfile = Listfile::parse("42;World/Test.adt");
        let root_entry = RootEntry {
            ckey: [0xAA; 16],
            content_flags: crate::root::flags::ContentFlags(0),
            locale_flags: LocaleFlags(0x2),
            name_hash: None,
        };
        let result: std::result::Result<u64, String> = Ok(1024);
        let meta = make_metadata_entry(42, &root_entry, &result, &listfile);
        assert_eq!(meta.fdid, 42);
        assert_eq!(meta.path, "World/Test.adt");
        assert_eq!(meta.size, 1024);
        assert_eq!(meta.status, "ok");
        assert_eq!(meta.ckey, hex::encode([0xAA; 16]));
    }

    #[test]
    fn make_metadata_entry_error() {
        let listfile = Listfile::parse("");
        let root_entry = RootEntry {
            ckey: [0xBB; 16],
            content_flags: crate::root::flags::ContentFlags(0x8000000),
            locale_flags: LocaleFlags(0x2),
            name_hash: None,
        };
        let result: std::result::Result<u64, String> = Err("skipped:encrypted".into());
        let meta = make_metadata_entry(99, &root_entry, &result, &listfile);
        assert_eq!(meta.fdid, 99);
        assert_eq!(meta.path, "unknown/99.dat");
        assert_eq!(meta.size, 0);
        assert_eq!(meta.status, "skipped:encrypted");
    }

    // -----------------------------------------------------------------------
    // Integration tests - require real WoW install
    // -----------------------------------------------------------------------

    #[test]
    #[ignore]
    fn extract_all_small_filter() {
        let open_config = OpenConfig {
            install_dir: PathBuf::from(r"E:\World of Warcraft"),
            product: Some("wow".into()),
            keyfile: None,
            listfile: None,
            output_dir: Some(std::env::temp_dir().join("casc_extract_test")),
        };
        let storage = CascStorage::open(&open_config).unwrap();

        let extract_config = ExtractionConfig {
            output_dir: std::env::temp_dir().join("casc_extract_test_out"),
            locale: 0x2, // enUS
            threads: 4,
            verify: false,
            skip_encrypted: true,
            filter: Some("*.wdt".into()),
            no_metadata: false,
        };

        let stats = extract_all(&storage, &extract_config, None).unwrap();
        println!(
            "Extracted: {} success, {} errors, {} skipped",
            stats.success, stats.errors, stats.skipped
        );
        assert!(stats.total > 0);
    }
}
