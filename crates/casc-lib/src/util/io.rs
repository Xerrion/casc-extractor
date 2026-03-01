//! Endian-aware byte-slice integer readers.
//!
//! CASC binary formats use a mix of big-endian and little-endian integers.
//! These helpers read fixed-width integers from raw byte slices without
//! requiring a cursor or buffered reader, which is convenient for
//! position-based parsing of memory-mapped or fully-loaded file data.

/// Read a big-endian u16 from a byte slice.
pub fn read_be_u16(data: &[u8]) -> u16 {
    u16::from_be_bytes([data[0], data[1]])
}

/// Read a big-endian u24 from a byte slice, returned as u32.
pub fn read_be_u24(data: &[u8]) -> u32 {
    ((data[0] as u32) << 16) | ((data[1] as u32) << 8) | (data[2] as u32)
}

/// Read a big-endian u32 from a byte slice.
pub fn read_be_u32(data: &[u8]) -> u32 {
    u32::from_be_bytes([data[0], data[1], data[2], data[3]])
}

/// Read a big-endian 40-bit (5-byte) unsigned integer, returned as u64.
pub fn read_be_u40(data: &[u8]) -> u64 {
    ((data[0] as u64) << 32)
        | ((data[1] as u64) << 24)
        | ((data[2] as u64) << 16)
        | ((data[3] as u64) << 8)
        | (data[4] as u64)
}

/// Read a little-endian u32 from a byte slice.
pub fn read_le_u32(data: &[u8]) -> u32 {
    u32::from_le_bytes([data[0], data[1], data[2], data[3]])
}

/// Read a little-endian i32 from a byte slice.
pub fn read_le_i32(data: &[u8]) -> i32 {
    i32::from_le_bytes([data[0], data[1], data[2], data[3]])
}

/// Read a little-endian u64 from a byte slice.
pub fn read_le_u64(data: &[u8]) -> u64 {
    u64::from_le_bytes([
        data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_be_u16_correct() {
        assert_eq!(read_be_u16(&[0x01, 0x02]), 0x0102);
    }

    #[test]
    fn read_be_u24_correct() {
        assert_eq!(read_be_u24(&[0x01, 0x02, 0x03]), 0x010203);
    }

    #[test]
    fn read_be_u32_correct() {
        assert_eq!(read_be_u32(&[0x01, 0x02, 0x03, 0x04]), 0x01020304);
    }

    #[test]
    fn read_be_u40_correct() {
        assert_eq!(read_be_u40(&[0x01, 0x02, 0x03, 0x04, 0x05]), 0x0102030405);
    }

    #[test]
    fn read_le_u32_correct() {
        assert_eq!(read_le_u32(&[0x04, 0x03, 0x02, 0x01]), 0x01020304);
    }

    #[test]
    fn read_le_i32_positive() {
        assert_eq!(read_le_i32(&[0x01, 0x00, 0x00, 0x00]), 1);
    }

    #[test]
    fn read_le_i32_negative() {
        assert_eq!(read_le_i32(&[0xFF, 0xFF, 0xFF, 0xFF]), -1);
    }

    #[test]
    fn read_be_u16_boundary() {
        assert_eq!(read_be_u16(&[0xFF, 0xFF]), 0xFFFF);
        assert_eq!(read_be_u16(&[0x00, 0x00]), 0x0000);
    }

    #[test]
    fn read_be_u40_max() {
        assert_eq!(read_be_u40(&[0xFF, 0xFF, 0xFF, 0xFF, 0xFF]), 0xFFFFFFFFFF);
    }
}
