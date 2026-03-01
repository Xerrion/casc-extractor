//! Integration tests against a real World of Warcraft installation.
//!
//! All tests are `#[ignore]` - run with: `cargo test -- --ignored`
//! Requires WoW installed at `E:\World of Warcraft` (or set `WOW_DIR` env var).

use std::path::PathBuf;

use casc_lib::blte::decoder::decode_blte_with_keys;
use casc_lib::blte::encryption::TactKeyStore;
use casc_lib::config::build_config::{config_path, parse_build_config};
use casc_lib::config::build_info::parse_build_info;
use casc_lib::encoding::parser::EncodingFile;
use casc_lib::extract::{
    CascStorage, ExtractionConfig, OpenConfig, extract_all, extract_single_file, list_files,
};
use casc_lib::root::flags::LocaleFlags;
use casc_lib::storage::data::DataStore;
use casc_lib::storage::index::CascIndex;

fn wow_dir() -> PathBuf {
    std::env::var("WOW_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(r"E:\World of Warcraft"))
}

fn data_dir() -> PathBuf {
    wow_dir().join("Data").join("data")
}

fn has_wow_install() -> bool {
    wow_dir().join(".build.info").exists()
}

/// Skip test gracefully if WoW is not installed.
macro_rules! require_wow {
    () => {
        if !has_wow_install() {
            eprintln!("SKIPPED: WoW install not found at {:?}", wow_dir());
            return;
        }
    };
}

// ---------------------------------------------------------------------------
// Step 9: Bootstrap tests
// ---------------------------------------------------------------------------

#[test]
#[ignore]
fn reads_real_build_info() {
    require_wow!();
    let content = std::fs::read_to_string(wow_dir().join(".build.info")).unwrap();
    let infos = parse_build_info(&content).unwrap();
    assert!(
        !infos.is_empty(),
        "Should have at least one build info entry"
    );
    for info in &infos {
        assert!(!info.build_key.is_empty(), "build_key should not be empty");
        assert!(!info.product.is_empty(), "product should not be empty");
        println!(
            "Product: {} | Version: {} | Build Key: {}",
            info.product, info.version, info.build_key
        );
    }
}

#[test]
#[ignore]
fn reads_real_build_config() {
    require_wow!();
    let content = std::fs::read_to_string(wow_dir().join(".build.info")).unwrap();
    let infos = parse_build_info(&content).unwrap();
    let info = infos
        .iter()
        .find(|i| i.product == "wow")
        .unwrap_or(&infos[0]);

    let config_file = wow_dir().join("Data").join(config_path(&info.build_key));
    let config_content = std::fs::read_to_string(&config_file).unwrap();
    let config = parse_build_config(&config_content).unwrap();

    assert!(
        !config.root_ckey.is_empty(),
        "root CKey should not be empty"
    );
    assert!(
        !config.encoding_ekey.is_empty(),
        "encoding EKey should not be empty"
    );
    assert!(
        !config.build_name.is_empty(),
        "build name should not be empty"
    );
    println!(
        "Build: {} | Root CKey: {} | Encoding EKey: {}",
        config.build_name, config.root_ckey, config.encoding_ekey
    );
}

#[test]
#[ignore]
fn loads_real_index() {
    require_wow!();
    let index = CascIndex::load(&data_dir()).unwrap();
    assert!(!index.is_empty(), "Index should have entries");
    println!("Index entries: {}", index.len());
    assert!(
        index.len() > 10000,
        "Expected >10000 index entries, got {}",
        index.len()
    );
}

#[test]
#[ignore]
fn opens_real_data_store() {
    require_wow!();
    let _store = DataStore::open(&data_dir()).unwrap();
    println!("DataStore opened successfully");
}

#[test]
#[ignore]
fn bootstraps_encoding_file() {
    require_wow!();
    let content = std::fs::read_to_string(wow_dir().join(".build.info")).unwrap();
    let infos = parse_build_info(&content).unwrap();
    let info = infos
        .iter()
        .find(|i| i.product == "wow")
        .unwrap_or(&infos[0]);

    let config_content =
        std::fs::read_to_string(wow_dir().join("Data").join(config_path(&info.build_key))).unwrap();
    let config = parse_build_config(&config_content).unwrap();

    let index = CascIndex::load(&data_dir()).unwrap();
    let store = DataStore::open(&data_dir()).unwrap();
    let keystore = TactKeyStore::with_known_keys();

    // Look up encoding EKey in index
    let ekey_bytes = hex::decode(&config.encoding_ekey).unwrap();
    let entry = index
        .find(&ekey_bytes)
        .expect("Encoding EKey not found in index");

    // Read from data store
    let blte_data = store
        .read_entry(entry.archive_number, entry.archive_offset, entry.size)
        .unwrap();

    // BLTE decode
    let raw = decode_blte_with_keys(blte_data, Some(&keystore)).unwrap();
    assert!(!raw.is_empty(), "Decoded encoding data should not be empty");

    // Parse encoding file
    let encoding = EncodingFile::parse(&raw).unwrap();
    println!("Encoding file parsed: {} entries", encoding.len());
    assert!(
        encoding.len() > 10000,
        "Expected >10000 encoding entries, got {}",
        encoding.len()
    );
}

#[test]
#[ignore]
fn bootstraps_root_file() {
    require_wow!();
    let open_config = OpenConfig {
        install_dir: wow_dir(),
        product: Some("wow".into()),
        keyfile: None,
        listfile: None,
        output_dir: Some(std::env::temp_dir().join("casc_integ_root")),
    };
    let storage = CascStorage::open(&open_config).unwrap();
    let info = storage.info();

    println!(
        "Root format: {} | Root entries: {}",
        info.root_format, info.root_entries
    );
    assert!(
        info.root_entries > 100000,
        "Expected >100000 root entries, got {}",
        info.root_entries
    );
    assert!(info.encoding_entries > 10000);
}

#[test]
#[ignore]
fn full_storage_open_and_info() {
    require_wow!();
    let open_config = OpenConfig {
        install_dir: wow_dir(),
        product: Some("wow".into()),
        keyfile: None,
        listfile: None,
        output_dir: Some(std::env::temp_dir().join("casc_integ_info")),
    };
    let storage = CascStorage::open(&open_config).unwrap();
    let info = storage.info();

    println!("=== CASC Storage Info ===");
    println!("Build:     {}", info.build_name);
    println!("Product:   {}", info.product);
    println!("Version:   {}", info.version);
    println!("Format:    {}", info.root_format);
    println!("Encoding:  {} entries", info.encoding_entries);
    println!("Root:      {} entries", info.root_entries);
    println!("Index:     {} entries", info.index_entries);
    println!("Listfile:  {} entries", info.listfile_entries);

    assert!(!info.build_name.is_empty());
    assert!(!info.product.is_empty());
}

// ---------------------------------------------------------------------------
// Step 10: Extraction tests
// ---------------------------------------------------------------------------

#[test]
#[ignore]
fn extract_known_small_file() {
    require_wow!();
    let open_config = OpenConfig {
        install_dir: wow_dir(),
        product: Some("wow".into()),
        keyfile: None,
        listfile: None,
        output_dir: Some(std::env::temp_dir().join("casc_integ_extract")),
    };
    let storage = CascStorage::open(&open_config).unwrap();

    // Try reading FDID 1 (usually exists)
    let result = storage.read_by_fdid(1, LocaleFlags::EN_US);
    match result {
        Ok(data) => {
            println!("FDID 1: {} bytes", data.len());
            assert!(!data.is_empty());
        }
        Err(e) => {
            // Some FDIDs might not exist - that's ok, just log
            println!("FDID 1 not available: {}", e);
        }
    }

    // Try a few more known FDIDs
    for fdid in [53, 100, 1000, 10000] {
        let result = storage.read_by_fdid(fdid, LocaleFlags::EN_US);
        println!(
            "FDID {}: {}",
            fdid,
            match &result {
                Ok(data) => format!("{} bytes", data.len()),
                Err(e) => format!("error: {}", e),
            }
        );
    }
}

#[test]
#[ignore]
fn extract_single_file_to_disk() {
    require_wow!();
    let out_dir = std::env::temp_dir().join("casc_integ_single");
    let _ = std::fs::remove_dir_all(&out_dir);
    std::fs::create_dir_all(&out_dir).unwrap();

    let open_config = OpenConfig {
        install_dir: wow_dir(),
        product: Some("wow".into()),
        keyfile: None,
        listfile: None,
        output_dir: Some(out_dir.clone()),
    };
    let storage = CascStorage::open(&open_config).unwrap();

    let out_file = out_dir.join("test_file.dat");
    // Try extracting by FDID
    let result = extract_single_file(&storage, "53", &out_file, 0x2);
    match result {
        Ok(size) => {
            println!("Extracted FDID 53: {} bytes", size);
            assert!(out_file.exists());
            assert!(std::fs::metadata(&out_file).unwrap().len() > 0);
        }
        Err(e) => {
            println!("Could not extract FDID 53: {} (this is acceptable)", e);
        }
    }

    let _ = std::fs::remove_dir_all(&out_dir);
}

#[test]
#[ignore]
fn list_files_returns_results() {
    require_wow!();
    let open_config = OpenConfig {
        install_dir: wow_dir(),
        product: Some("wow".into()),
        keyfile: None,
        listfile: None,
        output_dir: Some(std::env::temp_dir().join("casc_integ_list")),
    };
    let storage = CascStorage::open(&open_config).unwrap();

    let files = list_files(&storage, 0x2, None);
    println!("Total files (enUS): {}", files.len());
    assert!(
        files.len() > 100000,
        "Expected >100k files, got {}",
        files.len()
    );

    // Print first 10
    for (fdid, path) in files.iter().take(10) {
        println!("  {} -> {}", fdid, path);
    }
}

#[test]
#[ignore]
fn list_files_with_filter() {
    require_wow!();
    let open_config = OpenConfig {
        install_dir: wow_dir(),
        product: Some("wow".into()),
        keyfile: None,
        listfile: None,
        output_dir: Some(std::env::temp_dir().join("casc_integ_filter")),
    };
    let storage = CascStorage::open(&open_config).unwrap();

    let files = list_files(&storage, 0x2, Some("*.wdt"));
    println!("WDT files: {}", files.len());
    assert!(!files.is_empty(), "Should find at least some .wdt files");

    for (fdid, path) in files.iter().take(5) {
        println!("  {} -> {}", fdid, path);
        assert!(
            path.to_lowercase().ends_with(".wdt"),
            "Expected .wdt extension: {}",
            path
        );
    }
}

#[test]
#[ignore]
fn extract_batch_small_subset() {
    require_wow!();
    let out_dir = std::env::temp_dir().join("casc_integ_batch");
    let _ = std::fs::remove_dir_all(&out_dir);

    let open_config = OpenConfig {
        install_dir: wow_dir(),
        product: Some("wow".into()),
        keyfile: None,
        listfile: None,
        output_dir: Some(out_dir.clone()),
    };
    let storage = CascStorage::open(&open_config).unwrap();

    let config = ExtractionConfig {
        output_dir: out_dir.clone(),
        locale: 0x2,
        threads: 4,
        verify: false,
        skip_encrypted: true,
        filter: Some("*.wdt".into()), // Small subset - just WDT map files
        no_metadata: false,
    };

    let stats = extract_all(&storage, &config, None).unwrap();
    println!("Batch extraction results:");
    println!("  Total:   {}", stats.total);
    println!("  Success: {}", stats.success);
    println!("  Errors:  {}", stats.errors);
    println!("  Skipped: {}", stats.skipped);

    assert!(stats.total > 0, "Should have found some files");
    assert!(
        stats.success > 0,
        "Should have extracted at least some files"
    );

    // Check metadata was written
    let meta_dir = out_dir.join(".casc-meta");
    assert!(
        meta_dir.join("index.jsonl").exists(),
        "JSONL index should exist"
    );
    assert!(
        meta_dir.join("index.csv").exists(),
        "CSV index should exist"
    );
    assert!(
        meta_dir.join("summary.json").exists(),
        "Summary should exist"
    );

    // Verify summary content
    let summary = std::fs::read_to_string(meta_dir.join("summary.json")).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&summary).unwrap();
    assert!(parsed["stats"]["success"].as_u64().unwrap() > 0);

    let _ = std::fs::remove_dir_all(&out_dir);
}

#[test]
#[ignore]
fn extract_verifies_ckey_md5() {
    require_wow!();
    let open_config = OpenConfig {
        install_dir: wow_dir(),
        product: Some("wow".into()),
        keyfile: None,
        listfile: None,
        output_dir: Some(std::env::temp_dir().join("casc_integ_verify")),
    };
    let storage = CascStorage::open(&open_config).unwrap();

    // Read files and verify their CKey (MD5)
    use md5::{Digest, Md5};

    let mut verified = 0;
    for (fdid, root_entry) in storage.root.iter_all().take(100) {
        if let Ok(data) = storage.read_by_ckey(&root_entry.ckey) {
            let mut hasher = Md5::new();
            hasher.update(&data);
            let hash = hasher.finalize();

            if hash.as_slice() == root_entry.ckey {
                verified += 1;
            } else {
                println!(
                    "MISMATCH: FDID {} CKey={} MD5={}",
                    fdid,
                    hex::encode(root_entry.ckey),
                    hex::encode(hash)
                );
            }
        }
        if verified >= 10 {
            break;
        }
    }

    println!("Successfully verified {} file checksums", verified);
    assert!(
        verified > 0,
        "Should have verified at least one file checksum"
    );
}

// ---------------------------------------------------------------------------
// Root V2 block header diagnostic
// ---------------------------------------------------------------------------

#[test]
#[ignore]
fn dump_root_block_headers() {
    require_wow!();

    // --- Bootstrap: build info -> build config -> index + store + encoding ---
    let content = std::fs::read_to_string(wow_dir().join(".build.info")).unwrap();
    let infos = parse_build_info(&content).unwrap();
    let info = infos
        .iter()
        .find(|i| i.product == "wow")
        .unwrap_or(&infos[0]);

    let config_content =
        std::fs::read_to_string(wow_dir().join("Data").join(config_path(&info.build_key))).unwrap();
    let config = parse_build_config(&config_content).unwrap();

    let index = CascIndex::load(&data_dir()).unwrap();
    let store = DataStore::open(&data_dir()).unwrap();
    let keystore = TactKeyStore::with_known_keys();

    // --- Decode encoding file ---
    let enc_ekey_bytes = hex::decode(&config.encoding_ekey).unwrap();
    let enc_entry = index
        .find(&enc_ekey_bytes)
        .expect("Encoding EKey not found in index");
    let enc_blte = store
        .read_entry(
            enc_entry.archive_number,
            enc_entry.archive_offset,
            enc_entry.size,
        )
        .unwrap();
    let enc_raw = decode_blte_with_keys(enc_blte, Some(&keystore)).unwrap();
    let encoding = EncodingFile::parse(&enc_raw).unwrap();
    println!("Encoding file: {} entries", encoding.len());

    // --- Decode root file ---
    let root_ckey_bytes = hex::decode(&config.root_ckey).unwrap();
    let root_ckey_arr: [u8; 16] = root_ckey_bytes[..16].try_into().unwrap();
    let enc_mapping = encoding
        .find_ekey(&root_ckey_arr)
        .expect("Root CKey not found in encoding");
    let root_ekey = &enc_mapping.ekeys[0];
    let root_idx = index.find(root_ekey).expect("Root EKey not found in index");
    let root_blte = store
        .read_entry(
            root_idx.archive_number,
            root_idx.archive_offset,
            root_idx.size,
        )
        .unwrap();
    let root_raw = decode_blte_with_keys(root_blte, Some(&keystore)).unwrap();

    let total_size = root_raw.len();
    println!("\n===== ROOT FILE DIAGNOSTIC =====");
    println!("Root CKey:       {}", config.root_ckey);
    println!(
        "Root file size:  {} bytes ({:.2} MiB)",
        total_size,
        total_size as f64 / (1024.0 * 1024.0)
    );

    // --- Detect format ---
    if total_size < 4 {
        println!("ERROR: root file too small ({} bytes)", total_size);
        return;
    }

    // MFST_MAGIC = 0x5453464D, stored LE as bytes [4D 46 53 54] = "MFST"
    const MFST_MAGIC_LE: u32 = 0x5453464D;
    // Same constant but read as BE (file bytes "TSFM" = [54 53 46 4D])
    const MFST_MAGIC_BE: u32 = 0x4D465354;

    let magic_le = u32::from_le_bytes(root_raw[0..4].try_into().unwrap());
    let is_mfst = magic_le == MFST_MAGIC_LE || magic_le == MFST_MAGIC_BE;

    println!(
        "Magic at [0..4]: bytes=[{:02X} {:02X} {:02X} {:02X}] LE=0x{:08X}",
        root_raw[0], root_raw[1], root_raw[2], root_raw[3], magic_le
    );
    println!(
        "  MFST_MAGIC_LE=0x{:08X} match={}  MFST_MAGIC_BE=0x{:08X} match={}",
        MFST_MAGIC_LE,
        magic_le == MFST_MAGIC_LE,
        MFST_MAGIC_BE,
        magic_le == MFST_MAGIC_BE,
    );

    // Dump first 64 bytes of the root file for context
    println!("First 64 raw bytes:");
    for (i, byte) in root_raw.iter().enumerate().take(64.min(total_size)) {
        if i % 16 == 0 && i > 0 {
            println!();
        }
        print!("{:02X} ", byte);
    }
    println!("\n");

    // Determine format and block_start
    // Try both LE and BE for the header fields since the magic may be in either order
    let (format_name, version, block_start);
    if !is_mfst {
        format_name = "Legacy";
        version = 0u32;
        block_start = 0usize;
        println!("Detected: Legacy format (no MFST magic). Blocks start at offset 0.");
    } else if total_size < 12 {
        println!("ERROR: MFST header too short");
        return;
    } else {
        let field_at_4_le = u32::from_le_bytes(root_raw[4..8].try_into().unwrap());
        let field_at_4_be = u32::from_be_bytes(root_raw[4..8].try_into().unwrap());
        let field_at_8_le = u32::from_le_bytes(root_raw[8..12].try_into().unwrap());
        let field_at_8_be = u32::from_be_bytes(root_raw[8..12].try_into().unwrap());
        println!(
            "  field@4: LE={} BE={}  field@8: LE={} BE={}",
            field_at_4_le, field_at_4_be, field_at_8_le, field_at_8_be
        );

        // Check both endianness for header_size==24
        if field_at_4_le == 24 && total_size >= 24 {
            version = field_at_8_le;
            block_start = 24;
            format_name = match version {
                1 => "MfstV1",
                2 => "MfstV2",
                _ => "MfstV?",
            };
            println!(
                "Detected: {} (header_size=24 LE, version={} LE)",
                format_name, version
            );
        } else if field_at_4_be == 24 && total_size >= 24 {
            version = field_at_8_be;
            block_start = 24;
            format_name = match version {
                1 => "MfstV1",
                2 => "MfstV2",
                _ => "MfstV?",
            };
            println!(
                "Detected: {} (header_size=24 BE, version={} BE)",
                format_name, version
            );
        } else {
            // Pre-10.1.7 MFST with 12-byte header
            version = 1;
            block_start = 12;
            format_name = "MfstV1 (pre-10.1.7)";
            let total_count = field_at_4_le;
            let named_count = field_at_8_le;
            println!(
                "Detected: {} (total_count={}, named_count={})",
                format_name, total_count, named_count
            );
        }

        // Dump full MFST header
        let hdr_end = block_start.min(total_size);
        print!("MFST header [0..{}]: ", hdr_end);
        for byte in root_raw.iter().take(hdr_end) {
            print!("{:02X} ", byte);
        }
        println!();
    };

    println!(
        "Block data starts at offset: {} (0x{:X})",
        block_start, block_start
    );
    println!();

    const NUM_BLOCKS_TO_DUMP: usize = 10;

    // Choose header size and dump strategy based on format
    let is_v2 = version == 2 && format_name == "MfstV2";
    let is_v1_or_legacy = !is_v2;

    if is_v1_or_legacy {
        // V1/Legacy block header: 12 bytes
        //   num_records:   u32 (4 bytes)
        //   content_flags: u32 (4 bytes)
        //   locale_flags:  u32 (4 bytes)
        const V1_BLOCK_HEADER_SIZE: usize = 12;

        let mut pos = block_start;
        let mut block_idx = 0;

        println!("=== {} block headers (12 bytes each) ===", format_name);
        println!("{:-<100}", "");
        println!(
            "{:<6} {:<12} {:<14} {:<14} {:<10} {:<10} {:<10}",
            "Block", "num_recs", "content_flg", "locale_flg", "NoNameHash", "has_hash", "body_size"
        );
        println!("{:-<100}", "");

        while block_idx < NUM_BLOCKS_TO_DUMP && pos + V1_BLOCK_HEADER_SIZE <= total_size {
            let num_records = u32::from_le_bytes(root_raw[pos..pos + 4].try_into().unwrap());
            let content_flags = u32::from_le_bytes(root_raw[pos + 4..pos + 8].try_into().unwrap());
            let locale_flags = u32::from_le_bytes(root_raw[pos + 8..pos + 12].try_into().unwrap());

            // Sanity check: num_records should be reasonable
            if num_records > 5_000_000 {
                println!(
                    "Block {}: num_records={} (0x{:08X}) - UNREASONABLE, stopping",
                    block_idx, num_records, num_records
                );
                break;
            }

            let no_name_hash = (content_flags & (1 << 28)) != 0;
            let has_name_hash = !no_name_hash;

            let base_body = (num_records as usize) * 4 + (num_records as usize) * 16;
            let body_size = if has_name_hash {
                base_body + (num_records as usize) * 8
            } else {
                base_body
            };

            println!(
                "{:<6} {:<12} 0x{:08X}     0x{:08X}     {:<10} {:<10} {}",
                block_idx,
                num_records,
                content_flags,
                locale_flags,
                no_name_hash,
                has_name_hash,
                body_size,
            );

            // Print raw header bytes
            print!("       raw: ");
            for i in 0..V1_BLOCK_HEADER_SIZE {
                print!("{:02X} ", root_raw[pos + i]);
            }
            println!();

            pos += V1_BLOCK_HEADER_SIZE + body_size;

            // Peek at next block
            if pos + 4 <= total_size {
                let peek = u32::from_le_bytes(root_raw[pos..pos + 4].try_into().unwrap());
                print!("       next @ 0x{:X}, peek num_records={}", pos, peek);
                if peek > 0 && peek < 500_000 {
                    println!(" (plausible)");
                } else if pos == total_size {
                    println!(" (at EOF)");
                } else {
                    println!(" (SUSPICIOUS)");
                }
            } else if pos == total_size {
                println!("       next @ 0x{:X} = exact EOF", pos);
            } else {
                println!(
                    "       next @ 0x{:X} OVERSHOT by {} bytes!",
                    pos,
                    pos - total_size
                );
            }

            println!();
            block_idx += 1;
        }

        println!("{:-<100}", "");
        println!("\nAfter {} blocks:", block_idx);
        println!("  Position: 0x{:X} ({} / {} bytes)", pos, pos, total_size);
        if pos <= total_size {
            println!("  Valid: {} bytes remaining", total_size - pos);
        } else {
            println!("  OVERSHOT by {} bytes", pos - total_size);
        }
    } else {
        // V2 block header: 17 bytes each
        //   num_records:  u32 (4 bytes)
        //   locale_flags: u32 (4 bytes)
        //   field3:       u32 (4 bytes)  -- content_flags in interpretation A
        //   field4:       u32 (4 bytes)  -- unknown / part of content_flags in interp B
        //   field5_byte:  u8  (1 byte)   -- unknown / part of content_flags in interp B
        //
        // Interpretation A: content_flags = field3 only (field4/f5 are separate unknowns)
        // Interpretation B: content_flags = field3 | field4 | (field5 << 17) (current parser code)
        // Interpretation C: content_flags = field4 (field3 is something else, f5 is something else)
        const V2_BLOCK_HEADER_SIZE: usize = 17;

        // Walk blocks using EACH interpretation independently, then compare
        println!("=== MfstV2 block headers (17 bytes each) - walking with interp B ===");
        println!("{:-<140}", "");
        println!(
            "{:<5} {:>8}  {:<12} {:<12} {:<12} {:<6} | {:<12} {:<9} | {:<12} {:<9} | {:<12} {:<9}",
            "Blk",
            "num_recs",
            "locale_flg",
            "field3",
            "field4",
            "f5",
            "A:cf",
            "A:hash?",
            "B:cf",
            "B:hash?",
            "C:cf",
            "C:hash?",
        );
        println!("{:-<140}", "");

        let mut pos = block_start;
        let mut block_idx = 0;

        while block_idx < NUM_BLOCKS_TO_DUMP && pos + V2_BLOCK_HEADER_SIZE <= total_size {
            let num_records = u32::from_le_bytes(root_raw[pos..pos + 4].try_into().unwrap());
            let locale_flags = u32::from_le_bytes(root_raw[pos + 4..pos + 8].try_into().unwrap());
            let field3 = u32::from_le_bytes(root_raw[pos + 8..pos + 12].try_into().unwrap());
            let field4 = u32::from_le_bytes(root_raw[pos + 12..pos + 16].try_into().unwrap());
            let field5_byte = root_raw[pos + 16];

            if num_records > 5_000_000 {
                println!(
                    "Block {}: num_records={} (0x{:08X}) - UNREASONABLE, stopping",
                    block_idx, num_records, num_records
                );
                break;
            }

            // Interpretation A: content_flags = field3 only
            let cf_a = field3;
            let has_hash_a = (cf_a & (1 << 28)) == 0;

            // Interpretation B: content_flags = field3 | field4 | (field5 << 17) (current code)
            let cf_b = field3 | field4 | ((field5_byte as u32) << 17);
            let has_hash_b = (cf_b & (1 << 28)) == 0;

            // Interpretation C: content_flags = field4 alone
            let cf_c = field4;
            let has_hash_c = (cf_c & (1 << 28)) == 0;

            println!(
                "{:<5} {:>8}  0x{:08X}   0x{:08X}   0x{:08X}   0x{:02X}  | 0x{:08X}   {:<9} | 0x{:08X}   {:<9} | 0x{:08X}   {:<9}",
                block_idx,
                num_records,
                locale_flags,
                field3,
                field4,
                field5_byte,
                cf_a,
                if has_hash_a { "hash" } else { "NO_HASH" },
                cf_b,
                if has_hash_b { "hash" } else { "NO_HASH" },
                cf_c,
                if has_hash_c { "hash" } else { "NO_HASH" },
            );

            // Print raw header bytes
            print!("      raw: ");
            for i in 0..V2_BLOCK_HEADER_SIZE {
                print!("{:02X} ", root_raw[pos + i]);
            }
            println!();

            pos += V2_BLOCK_HEADER_SIZE;
            let body_start = pos;

            let base_body = (num_records as usize) * 4 + (num_records as usize) * 16;
            let hash_body = (num_records as usize) * 8;

            let body_a = if has_hash_a {
                base_body + hash_body
            } else {
                base_body
            };
            let body_b = if has_hash_b {
                base_body + hash_body
            } else {
                base_body
            };
            let body_c = if has_hash_c {
                base_body + hash_body
            } else {
                base_body
            };

            let next_a = body_start + body_a;
            let next_b = body_start + body_b;
            let next_c = body_start + body_c;

            println!(
                "      body @ 0x{:X}: base={} hash={} | A:{} B:{} C:{}",
                body_start, base_body, hash_body, body_a, body_b, body_c
            );

            // Helper to peek and validate
            let peek = |label: &str, offset: usize| {
                if offset + 4 <= total_size {
                    let val = u32::from_le_bytes(root_raw[offset..offset + 4].try_into().unwrap());
                    let verdict = if val > 0 && val < 500_000 {
                        "OK"
                    } else {
                        "BAD"
                    };
                    println!(
                        "      peek {}: @ 0x{:X} -> {} [{}]",
                        label, offset, val, verdict
                    );
                } else if offset == total_size {
                    println!("      peek {}: @ 0x{:X} -> EOF [OK]", label, offset);
                } else {
                    println!("      peek {}: @ 0x{:X} -> OVERSHOT [BAD]", label, offset);
                }
            };

            // Only peek unique positions
            peek("A", next_a);
            if next_b != next_a {
                peek("B", next_b);
            } else {
                println!("      peek B: same as A");
            }
            if next_c != next_a && next_c != next_b {
                peek("C", next_c);
            } else {
                println!(
                    "      peek C: same as {}",
                    if next_c == next_a { "A" } else { "B" }
                );
            }

            println!();

            // Advance using interpretation B (current parser logic) since it seems correct
            pos = next_b;
            block_idx += 1;
        }

        println!("{:-<140}", "");

        // Walk ALL blocks with each interpretation to see which reaches EOF cleanly
        println!("\n=== Full walk comparison (all blocks until EOF or error) ===");

        type InterpFn = fn(u32, u32, u8) -> u32;
        let interps: [(&str, InterpFn); 3] = [
            ("A (field3 only)", |f3, _f4, _f5| f3),
            ("B (f3|f4|f5<<17)", |f3, f4, f5| {
                f3 | f4 | ((f5 as u32) << 17)
            }),
            ("C (field4 only)", |_f3, f4, _f5| f4),
        ];

        for (label, interp_fn) in interps {
            let mut p = block_start;
            let mut blocks = 0u32;
            let mut prev_nr = 0u32;
            let mut ok = true;
            while p + V2_BLOCK_HEADER_SIZE <= total_size {
                let nr = u32::from_le_bytes(root_raw[p..p + 4].try_into().unwrap());
                if nr > 5_000_000 {
                    println!(
                        "  Interp {}: block {} @ 0x{:X} has unreasonable num_records={} (0x{:08X})",
                        label, blocks, p, nr, nr
                    );
                    // Dump the raw bytes at this position
                    print!("    raw @ 0x{:X}: ", p);
                    for i in 0..V2_BLOCK_HEADER_SIZE.min(total_size - p) {
                        print!("{:02X} ", root_raw[p + i]);
                    }
                    println!();
                    // Also show the previous block's details
                    if blocks > 0 {
                        println!(
                            "    (previous block was #{} with {} records)",
                            blocks - 1,
                            prev_nr
                        );
                    }
                    ok = false;
                    break;
                }
                let lf = u32::from_le_bytes(root_raw[p + 4..p + 8].try_into().unwrap());
                let f3 = u32::from_le_bytes(root_raw[p + 8..p + 12].try_into().unwrap());
                let f4 = u32::from_le_bytes(root_raw[p + 12..p + 16].try_into().unwrap());
                let f5 = root_raw[p + 16];
                let cf = interp_fn(f3, f4, f5);
                let has_hash = (cf & (1 << 28)) == 0;
                // Print blocks near the failure point
                if blocks >= 48 {
                    println!(
                        "    blk {:>4} @ 0x{:06X}: nr={:>6} lf=0x{:08X} f3=0x{:08X} f4=0x{:08X} f5=0x{:02X} cf=0x{:08X} hash={}",
                        blocks, p, nr, lf, f3, f4, f5, cf, has_hash
                    );
                }
                prev_nr = nr;
                p += V2_BLOCK_HEADER_SIZE;
                let base = (nr as usize) * 4 + (nr as usize) * 16;
                let body = if has_hash {
                    base + (nr as usize) * 8
                } else {
                    base
                };
                if p + body > total_size {
                    println!(
                        "  Interp {}: block {} body overruns (need {} more, only {} left), ABORT",
                        label,
                        blocks,
                        body,
                        total_size - p
                    );
                    ok = false;
                    break;
                }
                p += body;
                blocks += 1;
            }
            if ok {
                let remaining = total_size - p;
                println!(
                    "  Interp {}: {} blocks, final pos=0x{:X} ({}/{} bytes), {} remaining {}",
                    label,
                    blocks,
                    p,
                    p,
                    total_size,
                    remaining,
                    if remaining == 0 {
                        "- EXACT EOF"
                    } else if remaining < V2_BLOCK_HEADER_SIZE {
                        "- partial remainder (OK?)"
                    } else {
                        "- DATA LEFT OVER"
                    }
                );
            }
        }
    }

    println!("\n===== END DIAGNOSTIC =====");
}
