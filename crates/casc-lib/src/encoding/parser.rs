//! Binary parser for the CASC encoding file.
//!
//! The encoding file begins with a 22-byte header (magic `"EN"`, version 1),
//! followed by an ESpec string block, a page index, and then the actual
//! CKey-to-EKey (CE) data pages. Each page contains variable-length entries
//! consisting of a key count, a 5-byte file size (big-endian u40), the CKey,
//! and one or more EKeys.
//!
//! Use [`EncodingFile::parse`](crate::encoding::parser::EncodingFile::parse) to build a lookup table, then
//! [`EncodingFile::find_ekey`](crate::encoding::parser::EncodingFile::find_ekey) to resolve a CKey to its EKey(s).

use std::collections::HashMap;

use crate::error::{CascError, Result};
use crate::util::io::{read_be_u16, read_be_u32, read_be_u40};

/// Header of the encoding file (0x16 bytes, big-endian).
#[derive(Debug, Clone)]
pub struct EncodingHeader {
    /// Format version (must be 1).
    pub version: u8,
    /// Byte length of content key hashes (typically 16).
    pub hash_size_ckey: u8,
    /// Byte length of encoding key hashes (typically 16).
    pub hash_size_ekey: u8,
    /// CE page size in KiB (each CE data page is this value * 1024 bytes).
    pub ce_page_size_kb: u16,
    /// ESpec page size in KiB.
    pub espec_page_size_kb: u16,
    /// Number of CKey-to-EKey data pages.
    pub ce_page_count: u32,
    /// Number of ESpec pages.
    pub espec_page_count: u32,
    /// Total byte size of the ESpec string block.
    pub espec_block_size: u32,
}

/// A single CKey -> EKey mapping entry.
#[derive(Debug, Clone)]
pub struct EncodingEntry {
    /// Content key identifying the logical file.
    pub ckey: [u8; 16],
    /// One or more encoding keys that store this file's data in the archives.
    pub ekeys: Vec<[u8; 16]>,
    /// Decompressed file size in bytes.
    pub file_size: u64,
}

/// Parsed encoding file with fast CKey -> EKey lookup.
///
/// Constructed via [`EncodingFile::parse`] from the decoded (post-BLTE) encoding
/// file data. Use [`find_ekey`](EncodingFile::find_ekey) to resolve a content
/// key to its encoding key(s).
pub struct EncodingFile {
    header: EncodingHeader,
    /// Flat map of CKey -> EncodingEntry for O(1) lookup.
    entries: HashMap<[u8; 16], EncodingEntry>,
}

const HEADER_SIZE: usize = 0x16;
const PAGE_INDEX_ENTRY_MD5: usize = 16;

impl EncodingFile {
    /// Parse from decoded (post-BLTE) encoding file data.
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < HEADER_SIZE {
            return Err(CascError::InvalidFormat(
                "encoding data too short for header".into(),
            ));
        }

        // Validate signature
        if &data[0..2] != b"EN" {
            return Err(CascError::InvalidMagic {
                expected: "EN".into(),
                found: format!("{:02X}{:02X}", data[0], data[1]),
            });
        }

        let version = data[0x02];
        if version != 1 {
            return Err(CascError::UnsupportedVersion(version as u32));
        }

        let hash_size_ckey = data[0x03];
        let hash_size_ekey = data[0x04];
        let ce_page_size_kb = read_be_u16(&data[0x05..]);
        let espec_page_size_kb = read_be_u16(&data[0x07..]);
        let ce_page_count = read_be_u32(&data[0x09..]);
        let espec_page_count = read_be_u32(&data[0x0D..]);
        let flags = data[0x11];
        let espec_block_size = read_be_u32(&data[0x12..]);

        if flags != 0 {
            return Err(CascError::InvalidFormat(format!(
                "encoding flags must be 0, got {}",
                flags
            )));
        }

        let header = EncodingHeader {
            version,
            hash_size_ckey,
            hash_size_ekey,
            ce_page_size_kb,
            espec_page_size_kb,
            ce_page_count,
            espec_page_count,
            espec_block_size,
        };

        let ckey_size = hash_size_ckey as usize;
        let ekey_size = hash_size_ekey as usize;
        let ce_page_size = ce_page_size_kb as usize * 1024;
        let page_index_entry_size = ckey_size + PAGE_INDEX_ENTRY_MD5;

        // Calculate offsets into the data
        let mut offset = HEADER_SIZE;

        // 1. Skip ESpec string block
        offset += espec_block_size as usize;

        // 2. Skip CEKey page index
        let page_index_size = ce_page_count as usize * page_index_entry_size;
        offset += page_index_size;

        // 3. Parse all CEKey pages
        let mut entries = HashMap::new();

        for _ in 0..ce_page_count {
            if offset + ce_page_size > data.len() {
                return Err(CascError::InvalidFormat(
                    "encoding data truncated in CEKey pages".into(),
                ));
            }

            let page_end = offset + ce_page_size;
            let mut pos = offset;

            while pos < page_end {
                // Check if we hit padding (key_count == 0)
                if pos >= data.len() || data[pos] == 0 {
                    break;
                }

                let key_count = data[pos] as usize;
                pos += 1;

                // file_size: u40 BE (5 bytes)
                if pos + 5 > page_end {
                    break;
                }
                let file_size = read_be_u40(&data[pos..]);
                pos += 5;

                // ckey
                if pos + ckey_size > page_end {
                    break;
                }
                let mut ckey = [0u8; 16];
                ckey.copy_from_slice(&data[pos..pos + ckey_size]);
                pos += ckey_size;

                // ekeys
                let ekeys_total = key_count * ekey_size;
                if pos + ekeys_total > page_end {
                    break;
                }
                let mut ekeys = Vec::with_capacity(key_count);
                for _ in 0..key_count {
                    let mut ekey = [0u8; 16];
                    ekey.copy_from_slice(&data[pos..pos + ekey_size]);
                    ekeys.push(ekey);
                    pos += ekey_size;
                }

                entries.insert(
                    ckey,
                    EncodingEntry {
                        ckey,
                        ekeys,
                        file_size,
                    },
                );
            }

            offset = page_end;
        }

        // Skip EKeySpec page index and pages (not needed for extraction)

        Ok(Self { header, entries })
    }

    /// Find the encoding entry for a given CKey.
    pub fn find_ekey(&self, ckey: &[u8; 16]) -> Option<&EncodingEntry> {
        self.entries.get(ckey)
    }

    /// Total number of entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the encoding file has no entries.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Access the parsed header.
    pub fn header(&self) -> &EncodingHeader {
        &self.header
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal encoding file with the given entries.
    /// Each entry is (ckey, ekey, file_size).
    fn build_encoding_file(entries: &[([u8; 16], [u8; 16], u64)]) -> Vec<u8> {
        let hash_size: u8 = 16;
        let page_size_kb: u16 = 4; // 4096 bytes per page
        let page_size: usize = page_size_kb as usize * 1024;

        // Each entry = 1 (key_count) + 5 (file_size) + 16 (ckey) + 16 (ekey) = 38 bytes
        let entry_size = 38;
        let entries_per_page = page_size / entry_size;
        let ce_page_count = entries.len().div_ceil(entries_per_page).max(1) as u32;
        let espec_page_count: u32 = 0;
        let espec_block_size: u32 = 0;

        let mut data = Vec::new();

        // Header (0x16 = 22 bytes)
        data.extend_from_slice(b"EN"); // signature
        data.push(1); // version
        data.push(hash_size); // hash_size_ckey
        data.push(hash_size); // hash_size_ekey
        data.extend_from_slice(&page_size_kb.to_be_bytes()); // ce_page_size_kb
        data.extend_from_slice(&page_size_kb.to_be_bytes()); // espec_page_size_kb
        data.extend_from_slice(&ce_page_count.to_be_bytes()); // ce_page_count
        data.extend_from_slice(&espec_page_count.to_be_bytes()); // espec_page_count
        data.push(0); // flags
        data.extend_from_slice(&espec_block_size.to_be_bytes()); // espec_block_size
        assert_eq!(data.len(), 0x16);

        // ESpec string block (empty since espec_block_size = 0)

        // CEKey page index: ce_page_count entries of (first_ckey[16] + page_md5[16])
        let mut sorted_entries: Vec<_> = entries.to_vec();
        sorted_entries.sort_by_key(|a| a.0);

        for page_idx in 0..ce_page_count as usize {
            let first_entry_idx = page_idx * entries_per_page;
            if first_entry_idx < sorted_entries.len() {
                data.extend_from_slice(&sorted_entries[first_entry_idx].0); // first_ckey
            } else {
                data.extend_from_slice(&[0xFF; 16]); // padding
            }
            data.extend_from_slice(&[0u8; 16]); // page_md5 (zeroed for tests)
        }

        // CEKey pages: each page is page_size bytes, zero-padded
        for page_idx in 0..ce_page_count as usize {
            let start_idx = page_idx * entries_per_page;
            let end_idx = (start_idx + entries_per_page).min(sorted_entries.len());
            let mut page_data = Vec::new();

            for entry in sorted_entries.iter().take(end_idx).skip(start_idx) {
                let (ckey, ekey, file_size) = entry;
                page_data.push(1u8); // key_count = 1
                // file_size as u40 BE (5 bytes)
                let fs = *file_size;
                page_data.push((fs >> 32) as u8);
                page_data.push((fs >> 24) as u8);
                page_data.push((fs >> 16) as u8);
                page_data.push((fs >> 8) as u8);
                page_data.push(fs as u8);
                page_data.extend_from_slice(ckey);
                page_data.extend_from_slice(ekey);
            }

            // Zero-pad to page_size
            page_data.resize(page_size, 0);
            data.extend_from_slice(&page_data);
        }

        // No EKeySpec pages (espec_page_count = 0)
        data
    }

    #[test]
    fn parse_encoding_header_valid() {
        let data = build_encoding_file(&[]);
        let encoding = EncodingFile::parse(&data).unwrap();
        assert_eq!(encoding.header.version, 1);
        assert_eq!(encoding.header.hash_size_ckey, 16);
        assert_eq!(encoding.header.hash_size_ekey, 16);
        assert_eq!(encoding.header.ce_page_size_kb, 4);
    }

    #[test]
    fn parse_encoding_header_invalid_magic() {
        let mut data = build_encoding_file(&[]);
        data[0] = b'X';
        data[1] = b'X';
        assert!(EncodingFile::parse(&data).is_err());
    }

    #[test]
    fn parse_encoding_single_entry() {
        let ckey = [0x01; 16];
        let ekey = [0x02; 16];
        let data = build_encoding_file(&[(ckey, ekey, 12345)]);
        let encoding = EncodingFile::parse(&data).unwrap();

        assert_eq!(encoding.len(), 1);
        let entry = encoding.find_ekey(&ckey).unwrap();
        assert_eq!(entry.ekeys[0], ekey);
        assert_eq!(entry.file_size, 12345);
    }

    #[test]
    fn parse_encoding_multiple_entries() {
        let entries = vec![
            ([0x01; 16], [0xA1; 16], 100),
            ([0x02; 16], [0xA2; 16], 200),
            ([0x03; 16], [0xA3; 16], 300),
        ];
        let data = build_encoding_file(&entries);
        let encoding = EncodingFile::parse(&data).unwrap();

        assert_eq!(encoding.len(), 3);

        for (ckey, ekey, size) in &entries {
            let entry = encoding.find_ekey(ckey).unwrap();
            assert_eq!(entry.ekeys[0], *ekey);
            assert_eq!(entry.file_size, *size);
        }
    }

    #[test]
    fn parse_encoding_lookup_miss() {
        let data = build_encoding_file(&[([0x01; 16], [0xA1; 16], 100)]);
        let encoding = EncodingFile::parse(&data).unwrap();

        let missing = [0xFF; 16];
        assert!(encoding.find_ekey(&missing).is_none());
    }

    #[test]
    fn parse_encoding_empty() {
        let data = build_encoding_file(&[]);
        let encoding = EncodingFile::parse(&data).unwrap();
        assert_eq!(encoding.len(), 0);
        assert!(encoding.is_empty());
    }

    #[test]
    fn parse_encoding_large_file_size() {
        let ckey = [0x42; 16];
        let ekey = [0x43; 16];
        let large_size: u64 = 0xFF_FFFF_FFFF; // max u40
        let data = build_encoding_file(&[(ckey, ekey, large_size)]);
        let encoding = EncodingFile::parse(&data).unwrap();

        let entry = encoding.find_ekey(&ckey).unwrap();
        assert_eq!(entry.file_size, large_size);
    }

    #[test]
    fn parse_encoding_preserves_ckey() {
        let ckey = [
            10, 20, 30, 40, 50, 60, 70, 80, 90, 100, 110, 120, 130, 140, 150, 160,
        ];
        let ekey = [0xFF; 16];
        let data = build_encoding_file(&[(ckey, ekey, 42)]);
        let encoding = EncodingFile::parse(&data).unwrap();

        let entry = encoding.find_ekey(&ckey).unwrap();
        assert_eq!(entry.ckey, ckey);
    }
}
