//! Parser for CASC `.idx` index files.
//!
//! Index files map the first 9 bytes of each encoding key (EKey) to its physical
//! location (archive number + byte offset) in the `data.NNN` archives. There are
//! 16 buckets (0x00 - 0x0F), each with a versioned `.idx` file; only the
//! highest-version file per bucket is used.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use crate::error::{CascError, Result};
use crate::util::io::{read_be_u40, read_le_u32};

/// Parsed entry from an .idx file.
#[derive(Debug, Clone, Copy)]
pub struct IndexEntry {
    /// First 9 bytes of the EKey.
    pub key: [u8; 9],
    /// Data archive number (data.NNN).
    pub archive_number: u32,
    /// Byte offset within the archive.
    pub archive_offset: u64,
    /// Total size (header + BLTE data).
    pub size: u32,
}

/// Field-size spec from an idx header.
#[derive(Debug, Clone, Copy)]
pub struct IndexSpec {
    /// Byte width of the entry size field (typically 4).
    pub size_len: u8,
    /// Byte width of the archive offset field (typically 5).
    pub offset_len: u8,
    /// Byte width of the EKey prefix stored per entry (typically 9).
    pub key_len: u8,
    /// Number of bits within the offset field devoted to the byte offset
    /// (the remaining upper bits encode the archive number).
    pub offset_bits: u8,
}

/// Complete index across all 16 buckets.
pub struct CascIndex {
    entries: HashMap<[u8; 9], IndexEntry>,
}

// ---------------------------------------------------------------------------
// Public helpers
// ---------------------------------------------------------------------------

/// Compute the bucket index (0..15) for a given EKey.
///
/// Formula: XOR bytes 0-8, then `(result & 0xF) ^ (result >> 4)`.
pub fn bucket_index(ekey: &[u8]) -> u8 {
    let i = ekey[0] ^ ekey[1] ^ ekey[2] ^ ekey[3] ^ ekey[4] ^ ekey[5] ^ ekey[6] ^ ekey[7] ^ ekey[8];
    (i & 0xF) ^ (i >> 4)
}

/// Parse the 0x28-byte idx header. Returns the [`IndexSpec`] and total
/// `entries_size` (byte length of all entries that follow the header).
pub fn parse_idx_header(data: &[u8]) -> Result<(IndexSpec, u32)> {
    if data.len() < 0x28 {
        return Err(CascError::InvalidFormat(format!(
            "idx header too short: {} bytes",
            data.len()
        )));
    }

    let version = u16::from_le_bytes([data[0x08], data[0x09]]);
    if version != 7 {
        return Err(CascError::UnsupportedVersion(version as u32));
    }

    let extra_bytes = data[0x0B];
    if extra_bytes != 0 {
        return Err(CascError::InvalidFormat(format!(
            "idx extra_bytes must be 0, got {extra_bytes}"
        )));
    }

    let spec = IndexSpec {
        size_len: data[0x0C],
        offset_len: data[0x0D],
        key_len: data[0x0E],
        offset_bits: data[0x0F],
    };

    let entries_size = read_le_u32(&data[0x20..0x24]);

    Ok((spec, entries_size))
}

/// Parse the raw entry bytes according to `spec`. Returns all entries found.
pub fn parse_idx_entries(data: &[u8], spec: &IndexSpec) -> Result<Vec<IndexEntry>> {
    let entry_len = (spec.key_len as usize) + (spec.offset_len as usize) + (spec.size_len as usize);
    if entry_len == 0 {
        return Err(CascError::InvalidFormat("idx entry length is 0".into()));
    }

    let count = data.len() / entry_len;
    let mut entries = Vec::with_capacity(count);

    for i in 0..count {
        let base = i * entry_len;
        let key_end = base + spec.key_len as usize;
        let offset_end = key_end + spec.offset_len as usize;
        let size_end = offset_end + spec.size_len as usize;

        if size_end > data.len() {
            break;
        }

        // Key (first key_len bytes of the EKey)
        let mut key = [0u8; 9];
        let copy_len = (spec.key_len as usize).min(9);
        key[..copy_len].copy_from_slice(&data[base..base + copy_len]);

        // Offset - big-endian, variable length (typically 5 bytes)
        let raw_offset = read_be_u40(&data[key_end..offset_end]);
        let offset_mask = (1u64 << spec.offset_bits) - 1;
        let archive_number = (raw_offset >> spec.offset_bits) as u32;
        let archive_offset = raw_offset & offset_mask;

        // Size - little-endian u32
        let size = read_le_u32(&data[offset_end..size_end]);

        entries.push(IndexEntry {
            key,
            archive_number,
            archive_offset,
            size,
        });
    }

    Ok(entries)
}

/// Parse an idx filename like `"0500000003.idx"` into `(bucket, version)`.
///
/// The filename is `BBVVVVVVVV.idx` where BB is the hex bucket (0x00-0x0F)
/// and VVVVVVVV is the hex version number.
pub fn parse_idx_filename(name: &str) -> Option<(u8, u32)> {
    let stem = name.strip_suffix(".idx")?;
    if stem.len() != 10 {
        return None;
    }
    let bucket = u8::from_str_radix(&stem[0..2], 16).ok()?;
    let version = u32::from_str_radix(&stem[2..10], 16).ok()?;
    if bucket > 0x0F {
        return None;
    }
    Some((bucket, version))
}

/// Scan `data_dir` for `.idx` files and select the highest-version file per
/// bucket (0-15). Returns up to 16 paths.
pub fn select_idx_files(data_dir: &Path) -> Result<Vec<PathBuf>> {
    let pattern = data_dir.join("*.idx");
    let pattern_str = pattern.to_string_lossy().to_string();

    let mut best: HashMap<u8, (u32, PathBuf)> = HashMap::new();

    for path in glob::glob(&pattern_str)
        .map_err(|e| CascError::InvalidFormat(format!("glob error: {e}")))?
    {
        let path = path.map_err(|e| CascError::Io(e.into_error()))?;
        let fname = match path.file_name().and_then(|f| f.to_str()) {
            Some(f) => f.to_owned(),
            None => continue,
        };

        if let Some((bucket, version)) = parse_idx_filename(&fname) {
            let entry = best.entry(bucket).or_insert((0, PathBuf::new()));
            if version >= entry.0 {
                *entry = (version, path);
            }
        }
    }

    let mut result: Vec<PathBuf> = best.into_values().map(|(_, p)| p).collect();
    result.sort();
    Ok(result)
}

impl CascIndex {
    /// Load all idx files from `data_dir`, parse them, and build a lookup map.
    pub fn load(data_dir: &Path) -> Result<Self> {
        let idx_files = select_idx_files(data_dir)?;
        let mut entries = HashMap::new();

        for path in &idx_files {
            let file_data = std::fs::read(path)?;
            if file_data.len() < 0x28 {
                continue;
            }

            let (spec, entries_size) = parse_idx_header(&file_data)?;
            let header_len = 0x28usize;
            let entry_end = header_len + entries_size as usize;
            let entry_data = if entry_end <= file_data.len() {
                &file_data[header_len..entry_end]
            } else {
                &file_data[header_len..]
            };

            for entry in parse_idx_entries(entry_data, &spec)? {
                entries.insert(entry.key, entry);
            }
        }

        Ok(Self { entries })
    }

    /// Return the total number of index entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Return whether the index contains no entries.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Look up an index entry by the first 9 bytes of an EKey.
    pub fn find(&self, ekey: &[u8]) -> Option<&IndexEntry> {
        if ekey.len() < 9 {
            return None;
        }
        let mut key = [0u8; 9];
        key.copy_from_slice(&ekey[..9]);
        self.entries.get(&key)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bucket_index_all_zeros() {
        let ekey = [0u8; 16];
        let bucket = bucket_index(&ekey);
        assert!(bucket < 16);
        assert_eq!(bucket, 0);
    }

    #[test]
    fn bucket_index_always_less_than_16() {
        for i in 0..=255u8 {
            let mut ekey = [0u8; 16];
            ekey[0] = i;
            assert!(bucket_index(&ekey) < 16, "bucket >= 16 for ekey[0]={}", i);
        }
    }

    #[test]
    fn bucket_index_specific() {
        let ekey = [0xFF, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let i = 0xFF_u8;
        let expected = (i & 0xF) ^ (i >> 4);
        assert_eq!(bucket_index(&ekey), expected);
    }

    #[test]
    fn parse_idx_header_valid() {
        let mut header = [0u8; 0x28];
        header[0..4].copy_from_slice(&0x10u32.to_le_bytes());
        // Version = 7
        header[0x08..0x0A].copy_from_slice(&7u16.to_le_bytes());
        // BucketIndex = 0x05
        header[0x0A] = 0x05;
        // ExtraBytes = 0
        header[0x0B] = 0;
        // SizeLen = 4, OffsetLen = 5, KeyLen = 9, OffsetBits = 30
        header[0x0C] = 4;
        header[0x0D] = 5;
        header[0x0E] = 9;
        header[0x0F] = 30;
        // EntriesSize = 36 (2 entries of 18 bytes each)
        header[0x20..0x24].copy_from_slice(&36u32.to_le_bytes());

        let (spec, entries_size) = parse_idx_header(&header).unwrap();
        assert_eq!(spec.key_len, 9);
        assert_eq!(spec.offset_len, 5);
        assert_eq!(spec.size_len, 4);
        assert_eq!(spec.offset_bits, 30);
        assert_eq!(entries_size, 36);
    }

    #[test]
    fn parse_idx_entries_single_entry() {
        let spec = IndexSpec {
            size_len: 4,
            offset_len: 5,
            key_len: 9,
            offset_bits: 30,
        };

        let mut entry = [0u8; 18];
        entry[0..9].copy_from_slice(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09]);
        // archive=1, offset=0x1000 -> 0x40001000 as 5-byte BE
        entry[9..14].copy_from_slice(&[0x00, 0x40, 0x00, 0x10, 0x00]);
        entry[14..18].copy_from_slice(&256u32.to_le_bytes());

        let entries = parse_idx_entries(&entry, &spec).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(
            entries[0].key,
            [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09]
        );
        assert_eq!(entries[0].archive_number, 1);
        assert_eq!(entries[0].archive_offset, 0x1000);
        assert_eq!(entries[0].size, 256);
    }

    #[test]
    fn parse_idx_entries_two_entries() {
        let spec = IndexSpec {
            size_len: 4,
            offset_len: 5,
            key_len: 9,
            offset_bits: 30,
        };
        let mut data = [0u8; 36];

        // Entry 1: key=all 0xAA, archive=0, offset=0, size=100
        data[0..9].copy_from_slice(&[0xAA; 9]);
        data[9..14].copy_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00]);
        data[14..18].copy_from_slice(&100u32.to_le_bytes());

        // Entry 2: key=all 0xBB, archive=2, offset=0x100, size=200
        data[18..27].copy_from_slice(&[0xBB; 9]);
        // archive=2 -> bits 30-31 = 10 -> 0x80000000 | 0x100 = 0x80000100
        data[27..32].copy_from_slice(&[0x00, 0x80, 0x00, 0x01, 0x00]);
        data[32..36].copy_from_slice(&200u32.to_le_bytes());

        let entries = parse_idx_entries(&data, &spec).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].archive_number, 0);
        assert_eq!(entries[1].archive_number, 2);
        assert_eq!(entries[1].archive_offset, 0x100);
    }

    #[test]
    fn idx_filename_parsing() {
        assert_eq!(parse_idx_filename("0000000001.idx"), Some((0x00, 1)));
        assert_eq!(parse_idx_filename("0f00000219.idx"), Some((0x0F, 0x219)));
        assert_eq!(parse_idx_filename("0500000003.idx"), Some((0x05, 3)));
        assert_eq!(parse_idx_filename("invalid.idx"), None);
    }

    #[test]
    fn casc_index_find_hit() {
        let entry = IndexEntry {
            key: [1, 2, 3, 4, 5, 6, 7, 8, 9],
            archive_number: 0,
            archive_offset: 0,
            size: 100,
        };
        let mut entries = HashMap::new();
        entries.insert(entry.key, entry);
        let index = CascIndex { entries };

        let ekey = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        assert!(index.find(&ekey).is_some());
    }

    #[test]
    fn casc_index_find_miss() {
        let index = CascIndex {
            entries: HashMap::new(),
        };
        let ekey = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        assert!(index.find(&ekey).is_none());
    }
}
