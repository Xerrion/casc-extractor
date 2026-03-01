//! Reader for CASC `data.NNN` archive files.
//!
//! Each archive file contains a sequence of entries, where every entry starts with
//! a 30-byte header (EKey hash in reversed byte order, size, and flags) followed
//! by the BLTE-encoded payload. Files are memory-mapped for efficient random access
//! via [`DataStore`](crate::storage::data::DataStore).

use std::collections::HashMap;
use std::fs::File;
use std::path::Path;

use memmap2::Mmap;

use crate::error::{CascError, Result};
use crate::util::io::read_le_u32;

/// Size of the per-entry header in a data.NNN file.
pub const DATA_HEADER_SIZE: usize = 30;

/// Parsed data header from a data.NNN file.
#[derive(Debug, Clone)]
pub struct DataHeader {
    /// EKey hash (reversed from on-disk format, restored to normal order).
    pub ekey_hash: [u8; 16],
    /// Total size: header (30) + BLTE data.
    pub size: u32,
    /// Flags.
    pub flags: [u8; 2],
}

/// Manages memory-mapped data.NNN files.
pub struct DataStore {
    /// Memory-mapped data files, keyed by archive number.
    mmaps: HashMap<u32, Mmap>,
}

// ---------------------------------------------------------------------------
// Public helpers
// ---------------------------------------------------------------------------

/// Parse the 30-byte data header. The on-disk EKey is stored in reversed byte
/// order; this function restores it to the normal order.
pub fn parse_data_header(data: &[u8]) -> Result<DataHeader> {
    if data.len() < DATA_HEADER_SIZE {
        return Err(CascError::InvalidFormat(format!(
            "data header too short: {} bytes (need {})",
            data.len(),
            DATA_HEADER_SIZE
        )));
    }

    // EKey hash - stored reversed on disk, restore to normal order
    let mut ekey_hash = [0u8; 16];
    for i in 0..16 {
        ekey_hash[i] = data[15 - i];
    }

    let size = read_le_u32(&data[0x10..0x14]);
    let flags = [data[0x14], data[0x15]];

    Ok(DataHeader {
        ekey_hash,
        size,
        flags,
    })
}

/// Parse a data.NNN filename and return the archive number.
/// e.g. `"data.042"` -> `Some(42)`
fn parse_data_filename(name: &str) -> Option<u32> {
    let suffix = name.strip_prefix("data.")?;
    suffix.parse::<u32>().ok()
}

impl DataStore {
    /// Open and memory-map all `data.NNN` files found in `data_dir`.
    pub fn open(data_dir: &Path) -> Result<Self> {
        let pattern = data_dir.join("data.*");
        let pattern_str = pattern.to_string_lossy().to_string();

        let mut mmaps = HashMap::new();

        for path in glob::glob(&pattern_str)
            .map_err(|e| CascError::InvalidFormat(format!("glob error: {e}")))?
        {
            let path = path.map_err(|e| CascError::Io(e.into_error()))?;
            let fname = match path.file_name().and_then(|f| f.to_str()) {
                Some(f) => f.to_owned(),
                None => continue,
            };

            if let Some(archive_num) = parse_data_filename(&fname) {
                let file = File::open(&path)?;
                let mmap = unsafe { Mmap::map(&file)? };
                mmaps.insert(archive_num, mmap);
            }
        }

        Ok(Self { mmaps })
    }

    /// Read the BLTE payload for an entry (skips the 30-byte data header).
    pub fn read_entry(&self, archive_number: u32, offset: u64, size: u32) -> Result<&[u8]> {
        let raw = self.read_raw(archive_number, offset, size)?;
        if raw.len() < DATA_HEADER_SIZE {
            return Err(CascError::InvalidFormat(
                "data entry too small to contain header".into(),
            ));
        }
        Ok(&raw[DATA_HEADER_SIZE..])
    }

    /// Read the raw bytes for an entry (including the 30-byte header).
    pub fn read_raw(&self, archive_number: u32, offset: u64, size: u32) -> Result<&[u8]> {
        let mmap = self.mmaps.get(&archive_number).ok_or_else(|| {
            CascError::InvalidFormat(format!("data.{:03} not found", archive_number))
        })?;

        let start = offset as usize;
        let end = start + size as usize;

        if end > mmap.len() {
            return Err(CascError::InvalidFormat(format!(
                "data.{:03} read out of bounds: offset={}, size={}, file_len={}",
                archive_number,
                offset,
                size,
                mmap.len()
            )));
        }

        Ok(&mmap[start..end])
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_data_header_valid() {
        let mut header = [0u8; 30];
        // EKey hash (reversed on disk): put 0x01..0x10 reversed
        for (i, slot) in header.iter_mut().enumerate().take(16) {
            *slot = (16 - i) as u8;
        }
        // Size = 1000 (LE)
        header[0x10..0x14].copy_from_slice(&1000u32.to_le_bytes());
        // Flags = [0, 0]
        header[0x14] = 0;
        header[0x15] = 0;

        let dh = parse_data_header(&header).unwrap();
        // After reversing, should be 0x01..0x10
        assert_eq!(dh.ekey_hash[0], 1);
        assert_eq!(dh.ekey_hash[15], 16);
        assert_eq!(dh.size, 1000);
        assert_eq!(dh.flags, [0, 0]);
    }

    #[test]
    fn data_header_size_includes_header() {
        let mut header = [0u8; 30];
        header[0x10..0x14].copy_from_slice(&30u32.to_le_bytes());
        let dh = parse_data_header(&header).unwrap();
        assert_eq!(dh.size, 30);
    }

    #[test]
    fn data_header_too_short() {
        let header = [0u8; 10];
        assert!(parse_data_header(&header).is_err());
    }
}
