//! Root file binary parser.
//!
//! Supports three root file formats used across WoW versions:
//!
//! - **Legacy** (pre-8.2) - no header, blocks start at offset 0.
//! - **MFST V1** (8.2 - 11.0.x) - `MFST` magic header, 12-byte block headers.
//! - **MFST V2** (11.1.0+) - `MFST` magic header, 17-byte block headers with
//!   restructured content flags.
//!
//! Each root file is organized as a series of blocks, where each block shares
//! a common set of locale and content flags. Within a block, FileDataIDs are
//! stored as delta-encoded integers followed by parallel arrays of CKeys and
//! (optionally) name hashes.

use std::collections::HashMap;

use crate::error::{CascError, Result};
use crate::util::io::{read_le_i32, read_le_u32, read_le_u64};

use super::flags::{ContentFlags, LocaleFlags};

/// Magic number for MFST header.
///
/// Real WoW root files store the bytes `[54 53 46 4D]` ("TSFM"), which is
/// the string "MFST" written as a big-endian u32 (`0x5453464D`).  When read
/// back with `read_le_u32` this yields `0x4D465354`.  We check both values
/// so that hand-built test data (which writes `MFST_MAGIC_BE.to_le_bytes()`)
/// and real game files are both recognized.
const MFST_MAGIC_BE: u32 = 0x5453464D; // read_le on bytes "TSFM" -> 0x4D465354, but this is the BE interpretation
const MFST_MAGIC_LE: u32 = 0x4D465354; // what read_le_u32 actually returns for real files

/// A single root file entry mapping a CKey to flags/locale/name hash.
#[derive(Debug, Clone)]
pub struct RootEntry {
    /// Content key identifying the file data in the encoding table.
    pub ckey: [u8; 16],
    /// Content flags (platform, encryption, compression hints).
    pub content_flags: ContentFlags,
    /// Locale flags indicating which client locales this entry applies to.
    pub locale_flags: LocaleFlags,
    /// Jenkins96 name hash of the original file path, or `None` when the
    /// `NoNameHash` content flag is set.
    pub name_hash: Option<u64>,
}

/// Detected root file format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RootFormat {
    /// Pre-8.2, no MFST header - blocks start immediately.
    Legacy,
    /// 8.2+, MFST header with block format version 1.
    MfstV1,
    /// 11.1.0+, MFST header with block format version 2.
    MfstV2,
}

/// Parsed root file with FileDataID -> CKey lookup.
pub struct RootFile {
    format: RootFormat,
    /// FileDataID -> `Vec<RootEntry>` (may have multiple locale variants).
    entries: HashMap<u32, Vec<RootEntry>>,
    total_entries: usize,
}

impl RootFile {
    /// Parse a root file from raw bytes.
    pub fn parse(data: &[u8]) -> Result<Self> {
        let (format, block_start) = detect_format(data)?;

        let mut entries: HashMap<u32, Vec<RootEntry>> = HashMap::new();
        let mut total_entries: usize = 0;
        let mut pos = block_start;

        while pos < data.len() {
            let (block_entries, new_pos) = parse_block(data, pos, format)?;
            total_entries += block_entries.len();
            for (fdid, entry) in block_entries {
                entries.entry(fdid).or_default().push(entry);
            }
            pos = new_pos;
        }

        Ok(Self {
            format,
            entries,
            total_entries,
        })
    }

    /// Find the first entry for a FileDataID that matches the given locale filter.
    pub fn find_by_fdid(&self, fdid: u32, locale: LocaleFlags) -> Option<&RootEntry> {
        self.entries
            .get(&fdid)?
            .iter()
            .find(|e| e.locale_flags.matches(locale))
    }

    /// Iterate all (FileDataID, entry) pairs.
    pub fn iter_all(&self) -> impl Iterator<Item = (u32, &RootEntry)> {
        self.entries
            .iter()
            .flat_map(|(fdid, entries)| entries.iter().map(move |entry| (*fdid, entry)))
    }

    /// The detected format of this root file.
    pub fn format(&self) -> RootFormat {
        self.format
    }

    /// Total number of entries across all blocks.
    pub fn len(&self) -> usize {
        self.total_entries
    }

    /// Whether the root file contains no entries.
    pub fn is_empty(&self) -> bool {
        self.total_entries == 0
    }

    /// Number of unique FileDataIDs.
    pub fn fdid_count(&self) -> usize {
        self.entries.len()
    }
}

/// Detect the root file format and return the byte offset where blocks begin.
fn detect_format(data: &[u8]) -> Result<(RootFormat, usize)> {
    if data.len() < 4 {
        // Too short for MFST header - treat as legacy if it has any data, else empty
        if data.is_empty() {
            return Err(CascError::InvalidFormat("root file is empty".to_string()));
        }
        return Ok((RootFormat::Legacy, 0));
    }

    let magic = read_le_u32(&data[0..4]);
    if magic != MFST_MAGIC_LE && magic != MFST_MAGIC_BE {
        // No MFST header - legacy format, blocks start at offset 0
        return Ok((RootFormat::Legacy, 0));
    }

    // Has MFST magic. Determine header size.
    if data.len() < 12 {
        return Err(CascError::InvalidFormat(
            "MFST header too short".to_string(),
        ));
    }

    let field_at_4 = read_le_u32(&data[4..8]);

    // For pre-10.1.7 MFST: header is magic(4) + total_count(4) + named_count(4) = 12 bytes.
    // For 10.1.7+: offset 4 = header_size (24), offset 8 = version (1 or 2).
    // Distinguish: if field_at_4 looks like a reasonable header_size (e.g. 24),
    // it's the 10.1.7+ format. If it's a huge number, it's the old 12-byte header
    // where field_at_4 is total_file_count.
    if field_at_4 == 24 && data.len() >= 24 {
        // 10.1.7+ format with explicit header_size and version
        let version = read_le_u32(&data[8..12]);
        let format = match version {
            1 => RootFormat::MfstV1,
            2 => RootFormat::MfstV2,
            _ => {
                return Err(CascError::UnsupportedVersion(version));
            }
        };
        Ok((format, 24))
    } else {
        // Pre-10.1.7 MFST: 12-byte header (magic + total_count + named_count)
        // Block format is v1
        Ok((RootFormat::MfstV1, 12))
    }
}

/// Parse a single block from the root file data at the given position.
/// Returns the list of (FileDataID, RootEntry) pairs and the new position after the block.
fn parse_block(
    data: &[u8],
    pos: usize,
    format: RootFormat,
) -> Result<(Vec<(u32, RootEntry)>, usize)> {
    let (num_records, content_flags, locale_flags, mut pos) =
        parse_block_header(data, pos, format)?;

    if num_records == 0 {
        return Ok((Vec::new(), pos));
    }

    let num = num_records as usize;

    // Read FileDataID deltas (i32 LE each)
    let deltas_size = num * 4;
    if pos + deltas_size > data.len() {
        return Err(CascError::InvalidFormat(
            "root block: not enough data for FileDataID deltas".to_string(),
        ));
    }

    let mut fdids = Vec::with_capacity(num);
    let mut current_fdid: i64 = 0;
    for i in 0..num {
        let delta = read_le_i32(&data[pos + i * 4..]) as i64;
        if i == 0 {
            // First delta is the absolute starting FileDataID
            current_fdid = delta;
        } else {
            current_fdid = current_fdid + 1 + delta;
        }
        fdids.push(current_fdid as u32);
    }
    pos += deltas_size;

    // Read CKeys (16 bytes each)
    let ckeys_size = num * 16;
    if pos + ckeys_size > data.len() {
        return Err(CascError::InvalidFormat(
            "root block: not enough data for content keys".to_string(),
        ));
    }

    let mut ckeys = Vec::with_capacity(num);
    for i in 0..num {
        let mut ckey = [0u8; 16];
        ckey.copy_from_slice(&data[pos + i * 16..pos + i * 16 + 16]);
        ckeys.push(ckey);
    }
    pos += ckeys_size;

    // Read name hashes (u64 LE each) - only if NoNameHash flag is NOT set
    let has_name_hashes = !content_flags.has_no_name_hash();
    let mut name_hashes: Vec<Option<u64>> = Vec::with_capacity(num);

    if has_name_hashes {
        let hashes_size = num * 8;
        if pos + hashes_size > data.len() {
            return Err(CascError::InvalidFormat(
                "root block: not enough data for name hashes".to_string(),
            ));
        }
        for i in 0..num {
            name_hashes.push(Some(read_le_u64(&data[pos + i * 8..])));
        }
        pos += hashes_size;
    } else {
        name_hashes.resize(num, None);
    }

    // Assemble entries
    let mut result = Vec::with_capacity(num);
    for i in 0..num {
        result.push((
            fdids[i],
            RootEntry {
                ckey: ckeys[i],
                content_flags,
                locale_flags,
                name_hash: name_hashes[i],
            },
        ));
    }

    Ok((result, pos))
}

/// Parse a block header and return (num_records, content_flags, locale_flags, new_pos).
fn parse_block_header(
    data: &[u8],
    pos: usize,
    format: RootFormat,
) -> Result<(u32, ContentFlags, LocaleFlags, usize)> {
    match format {
        RootFormat::Legacy | RootFormat::MfstV1 => {
            // Block header v1: num_records(4) + content_flags(4) + locale_flags(4) = 12 bytes
            if pos + 12 > data.len() {
                return Err(CascError::InvalidFormat(
                    "root block header v1: not enough data".to_string(),
                ));
            }
            let num_records = read_le_u32(&data[pos..]);
            let content_flags = ContentFlags(read_le_u32(&data[pos + 4..]));
            let locale_flags = LocaleFlags(read_le_u32(&data[pos + 8..]));
            Ok((num_records, content_flags, locale_flags, pos + 12))
        }
        RootFormat::MfstV2 => {
            // Block header v2: num_records(4) + locale_flags(4) + unk1(4) + unk2(4) + unk3(1) = 17 bytes
            if pos + 17 > data.len() {
                return Err(CascError::InvalidFormat(
                    "root block header v2: not enough data".to_string(),
                ));
            }
            let num_records = read_le_u32(&data[pos..]);
            let locale_flags = LocaleFlags(read_le_u32(&data[pos + 4..]));
            let unk1 = read_le_u32(&data[pos + 8..]);
            let unk2 = read_le_u32(&data[pos + 12..]);
            let unk3 = data[pos + 16];
            // Convert to old-style content_flags
            let content_flags = ContentFlags(unk1 | unk2 | ((unk3 as u32) << 17));
            Ok((num_records, content_flags, locale_flags, pos + 17))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::root::flags::{ContentFlags, LocaleFlags};

    type RootBlockEntry = (i32, [u8; 16], Option<u64>);

    /// Build a v1 MFST root file with given blocks.
    /// Each block: (content_flags, locale_flags, entries: Vec<(fdid_delta, ckey, name_hash?)>)
    fn build_root_v1(blocks: &[(u32, u32, Vec<RootBlockEntry>)]) -> Vec<u8> {
        let total_count: u32 = blocks.iter().map(|(_, _, e)| e.len() as u32).sum();
        let named_count: u32 = blocks
            .iter()
            .filter(|(cf, _, _)| (cf & 0x10000000) == 0)
            .map(|(_, _, e)| e.len() as u32)
            .sum();

        let mut data = Vec::new();

        // MFST header (24 bytes for 10.1.7+ format)
        data.extend_from_slice(&MFST_MAGIC_BE.to_le_bytes()); // magic "MFST"
        data.extend_from_slice(&24u32.to_le_bytes()); // header_size
        data.extend_from_slice(&1u32.to_le_bytes()); // version = 1
        data.extend_from_slice(&total_count.to_le_bytes()); // total_file_count
        data.extend_from_slice(&named_count.to_le_bytes()); // named_file_count
        data.extend_from_slice(&0u32.to_le_bytes()); // padding
        assert_eq!(data.len(), 24);

        // Blocks
        for (content_flags, locale_flags, entries) in blocks {
            let num_records = entries.len() as u32;
            // Block header v1: num_records + content_flags + locale_flags
            data.extend_from_slice(&num_records.to_le_bytes());
            data.extend_from_slice(&content_flags.to_le_bytes());
            data.extend_from_slice(&locale_flags.to_le_bytes());

            // FileDataID deltas
            for (delta, _, _) in entries {
                data.extend_from_slice(&delta.to_le_bytes());
            }

            // CKeys
            for (_, ckey, _) in entries {
                data.extend_from_slice(ckey);
            }

            // Name hashes (only if NoNameHash not set)
            if (content_flags & 0x10000000) == 0 {
                for (_, _, name_hash) in entries {
                    let hash = name_hash.unwrap_or(0);
                    data.extend_from_slice(&hash.to_le_bytes());
                }
            }
        }

        data
    }

    #[test]
    fn detect_mfst_format() {
        let data = build_root_v1(&[]);
        let root = RootFile::parse(&data).unwrap();
        assert_eq!(root.format(), RootFormat::MfstV1);
    }

    #[test]
    fn parse_single_block_single_entry() {
        let ckey = [0xAA; 16];
        let blocks = vec![(0x8u32, 0x2u32, vec![(100i32, ckey, Some(0xDEADBEEF_u64))])]; // Windows, enUS
        let data = build_root_v1(&blocks);
        let root = RootFile::parse(&data).unwrap();

        assert_eq!(root.len(), 1);
        let entry = root.find_by_fdid(100, LocaleFlags::EN_US).unwrap();
        assert_eq!(entry.ckey, ckey);
        assert_eq!(entry.name_hash, Some(0xDEADBEEF));
    }

    #[test]
    fn parse_fdid_deltas_sequential() {
        let blocks = vec![(
            0x10000008u32,
            0x2u32,
            vec![
                (100i32, [0x01; 16], None), // fdid = 100
                (0i32, [0x02; 16], None),   // fdid = 101 (100 + 1 + 0)
                (0i32, [0x03; 16], None),   // fdid = 102
                (2i32, [0x04; 16], None),   // fdid = 105 (102 + 1 + 2)
            ],
        )];
        let data = build_root_v1(&blocks);
        let root = RootFile::parse(&data).unwrap();

        assert_eq!(root.len(), 4);
        assert!(root.find_by_fdid(100, LocaleFlags::ALL).is_some());
        assert!(root.find_by_fdid(101, LocaleFlags::ALL).is_some());
        assert!(root.find_by_fdid(102, LocaleFlags::ALL).is_some());
        assert!(root.find_by_fdid(103, LocaleFlags::ALL).is_none()); // gap
        assert!(root.find_by_fdid(104, LocaleFlags::ALL).is_none()); // gap
        assert!(root.find_by_fdid(105, LocaleFlags::ALL).is_some());
    }

    #[test]
    fn parse_block_with_name_hashes() {
        let blocks = vec![(
            0x8u32,
            0x2u32,
            vec![(50i32, [0xBB; 16], Some(0x1234567890ABCDEF_u64))],
        )]; // No NoNameHash flag = has name hashes
        let data = build_root_v1(&blocks);
        let root = RootFile::parse(&data).unwrap();

        let entry = root.find_by_fdid(50, LocaleFlags::ALL).unwrap();
        assert_eq!(entry.name_hash, Some(0x1234567890ABCDEF));
    }

    #[test]
    fn parse_block_without_name_hashes() {
        let blocks = vec![(0x10000008u32, 0x2u32, vec![(50i32, [0xCC; 16], None)])]; // NoNameHash flag set
        let data = build_root_v1(&blocks);
        let root = RootFile::parse(&data).unwrap();

        let entry = root.find_by_fdid(50, LocaleFlags::ALL).unwrap();
        assert_eq!(entry.name_hash, None);
    }

    #[test]
    fn parse_multiple_blocks_different_locales() {
        let blocks = vec![
            (0x8u32, 0x2u32, vec![(100i32, [0x01; 16], Some(0))]), // enUS
            (0x8u32, 0x20u32, vec![(100i32, [0x02; 16], Some(0))]), // deDE, same fdid!
        ];
        let data = build_root_v1(&blocks);
        let root = RootFile::parse(&data).unwrap();

        // Same fdid, different locales
        let en = root.find_by_fdid(100, LocaleFlags::EN_US).unwrap();
        assert_eq!(en.ckey, [0x01; 16]);

        let de = root.find_by_fdid(100, LocaleFlags::DE_DE).unwrap();
        assert_eq!(de.ckey, [0x02; 16]);
    }

    #[test]
    fn parse_locale_filter() {
        let blocks = vec![(0x8u32, 0x20u32, vec![(200i32, [0xFF; 16], Some(0))])]; // deDE only
        let data = build_root_v1(&blocks);
        let root = RootFile::parse(&data).unwrap();

        assert!(root.find_by_fdid(200, LocaleFlags::EN_US).is_none()); // not enUS
        assert!(root.find_by_fdid(200, LocaleFlags::DE_DE).is_some()); // deDE
        assert!(root.find_by_fdid(200, LocaleFlags::ALL).is_some()); // ALL matches
    }

    #[test]
    fn iter_all_entries() {
        let blocks = vec![(
            0x10000008u32,
            0x2u32,
            vec![(10i32, [0x01; 16], None), (0i32, [0x02; 16], None)],
        )];
        let data = build_root_v1(&blocks);
        let root = RootFile::parse(&data).unwrap();

        let all: Vec<_> = root.iter_all().collect();
        assert_eq!(all.len(), 2);
    }

    #[test]
    fn parse_empty_root() {
        let data = build_root_v1(&[]);
        let root = RootFile::parse(&data).unwrap();
        assert!(root.is_empty());
        assert_eq!(root.fdid_count(), 0);
    }

    #[test]
    fn detect_legacy_format() {
        // Data that doesn't start with MFST magic - should be Legacy.
        // Build a minimal legacy root with one block (block header starts at offset 0).
        let mut data = Vec::new();
        // Block header v1: num_records=1, content_flags=0x10000008, locale_flags=0x2
        data.extend_from_slice(&1u32.to_le_bytes());
        data.extend_from_slice(&0x10000008u32.to_le_bytes());
        data.extend_from_slice(&0x2u32.to_le_bytes());
        // Delta: fdid = 42
        data.extend_from_slice(&42i32.to_le_bytes());
        // CKey
        data.extend_from_slice(&[0xDD; 16]);
        // No name hashes (NoNameHash set)

        let root = RootFile::parse(&data).unwrap();
        assert_eq!(root.format(), RootFormat::Legacy);
        assert_eq!(root.len(), 1);
        assert!(root.find_by_fdid(42, LocaleFlags::ALL).is_some());
    }

    #[test]
    fn detect_pre_1017_mfst() {
        // Pre-10.1.7 MFST: 12-byte header (magic + total_count + named_count)
        let mut data = Vec::new();
        data.extend_from_slice(&MFST_MAGIC_BE.to_le_bytes()); // magic
        data.extend_from_slice(&500000u32.to_le_bytes()); // total_count (large number, not 24)
        data.extend_from_slice(&400000u32.to_le_bytes()); // named_count

        // One block after header
        data.extend_from_slice(&1u32.to_le_bytes()); // num_records
        data.extend_from_slice(&0x10000008u32.to_le_bytes()); // content_flags
        data.extend_from_slice(&0x2u32.to_le_bytes()); // locale_flags
        data.extend_from_slice(&7i32.to_le_bytes()); // delta (fdid = 7)
        data.extend_from_slice(&[0xEE; 16]); // ckey
        // No name hashes

        let root = RootFile::parse(&data).unwrap();
        assert_eq!(root.format(), RootFormat::MfstV1);
        assert_eq!(root.len(), 1);
        assert!(root.find_by_fdid(7, LocaleFlags::ALL).is_some());
    }

    #[test]
    fn mfst_v2_block_header() {
        // Build a v2 MFST root manually
        let mut data = Vec::new();
        // MFST header (24 bytes)
        data.extend_from_slice(&MFST_MAGIC_BE.to_le_bytes());
        data.extend_from_slice(&24u32.to_le_bytes()); // header_size
        data.extend_from_slice(&2u32.to_le_bytes()); // version = 2
        data.extend_from_slice(&1u32.to_le_bytes()); // total_file_count
        data.extend_from_slice(&0u32.to_le_bytes()); // named_file_count
        data.extend_from_slice(&0u32.to_le_bytes()); // padding

        // Block header v2: num_records(4) + locale_flags(4) + unk1(4) + unk2(4) + unk3(1) = 17 bytes
        data.extend_from_slice(&1u32.to_le_bytes()); // num_records = 1
        data.extend_from_slice(&0x2u32.to_le_bytes()); // locale_flags = enUS
        data.extend_from_slice(&0x8u32.to_le_bytes()); // unk1 = 0x8 (LoadOnWindows)
        data.extend_from_slice(&0x10000000u32.to_le_bytes()); // unk2 = NoNameHash
        data.push(0); // unk3 = 0

        // Delta
        data.extend_from_slice(&99i32.to_le_bytes());
        // CKey
        data.extend_from_slice(&[0xAB; 16]);
        // No name hashes (NoNameHash is set via unk2)

        let root = RootFile::parse(&data).unwrap();
        assert_eq!(root.format(), RootFormat::MfstV2);
        assert_eq!(root.len(), 1);

        let entry = root.find_by_fdid(99, LocaleFlags::EN_US).unwrap();
        assert_eq!(entry.ckey, [0xAB; 16]);
        // content_flags should be unk1 | unk2 | (unk3 << 17) = 0x8 | 0x10000000 | 0
        assert!(entry.content_flags.has(ContentFlags::LOAD_ON_WINDOWS));
        assert!(entry.content_flags.has_no_name_hash());
        assert_eq!(entry.name_hash, None);
    }

    #[test]
    fn parse_error_on_empty_data() {
        let result = RootFile::parse(&[]);
        assert!(result.is_err());
    }

    #[test]
    fn parse_error_on_truncated_block() {
        let mut data = Vec::new();
        // MFST header
        data.extend_from_slice(&MFST_MAGIC_BE.to_le_bytes());
        data.extend_from_slice(&24u32.to_le_bytes());
        data.extend_from_slice(&1u32.to_le_bytes());
        data.extend_from_slice(&1u32.to_le_bytes());
        data.extend_from_slice(&1u32.to_le_bytes());
        data.extend_from_slice(&0u32.to_le_bytes());
        // Block header claiming 1000 records but no body
        data.extend_from_slice(&1000u32.to_le_bytes());
        data.extend_from_slice(&0x8u32.to_le_bytes());
        data.extend_from_slice(&0x2u32.to_le_bytes());

        let result = RootFile::parse(&data);
        assert!(result.is_err());
    }

    #[test]
    fn fdid_count_vs_len() {
        // Two entries with same fdid but different locales = fdid_count 1, len 2
        let blocks = vec![
            (0x8u32, 0x2u32, vec![(50i32, [0x01; 16], Some(0))]),
            (0x8u32, 0x20u32, vec![(50i32, [0x02; 16], Some(0))]),
        ];
        let data = build_root_v1(&blocks);
        let root = RootFile::parse(&data).unwrap();

        assert_eq!(root.len(), 2);
        assert_eq!(root.fdid_count(), 1);
    }
}
