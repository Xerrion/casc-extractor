//! Top-level BLTE stream decoder.
//!
//! Validates the `"BLTE"` magic, parses the chunk table (if present), and
//! iterates over each block - delegating to the [`compression`](crate::blte::compression)
//! module for per-block decompression and decryption. Supports both single-block
//! (header size = 0) and multi-block layouts.

use super::compression::decode_block_with_keys;
use crate::blte::encryption::TactKeyStore;
use crate::error::{CascError, Result};
use crate::util::io::{read_be_u24, read_be_u32};

/// A parsed BLTE chunk descriptor.
#[derive(Debug)]
struct ChunkInfo {
    compressed_size: u32,
    #[allow(dead_code)]
    decompressed_size: u32,
    #[allow(dead_code)]
    hash: [u8; 16],
}

/// Decode a BLTE-encoded payload into raw file content.
pub fn decode_blte(data: &[u8]) -> Result<Vec<u8>> {
    decode_blte_with_keys(data, None)
}

/// Decode a BLTE-encoded payload with optional encryption support.
///
/// When `keystore` is `Some`, encrypted (mode E) blocks are decrypted
/// using the keys in the store. Pass `None` for backwards-compatible
/// behaviour where encrypted blocks return an error.
pub fn decode_blte_with_keys(data: &[u8], keystore: Option<&TactKeyStore>) -> Result<Vec<u8>> {
    if data.len() < 8 {
        return Err(CascError::InvalidFormat("BLTE data too short".into()));
    }
    if &data[0..4] != b"BLTE" {
        return Err(CascError::InvalidMagic {
            expected: "BLTE".into(),
            found: String::from_utf8_lossy(&data[0..4]).into(),
        });
    }

    let header_size = read_be_u32(&data[4..8]);

    if header_size == 0 {
        // Single-block mode: everything after the 8-byte header is one block
        if data.len() <= 8 {
            return Ok(Vec::new());
        }
        return decode_block_with_keys(&data[8..], keystore);
    }

    // Multi-block mode: parse chunk table
    if data.len() < 12 {
        return Err(CascError::InvalidFormat(
            "BLTE chunk table too short".into(),
        ));
    }

    let table_format = data[8];
    if table_format != 0x0F {
        return Err(CascError::InvalidFormat(format!(
            "unsupported BLTE table format: 0x{:02X}",
            table_format
        )));
    }

    let num_blocks = read_be_u24(&data[9..12]) as usize;

    // Parse block descriptors (24 bytes each, starting at offset 12)
    let descriptors_start = 12;
    let descriptors_end = descriptors_start + num_blocks * 24;
    if data.len() < descriptors_end {
        return Err(CascError::InvalidFormat(
            "BLTE block descriptors truncated".into(),
        ));
    }

    let mut chunks = Vec::with_capacity(num_blocks);
    for i in 0..num_blocks {
        let base = descriptors_start + i * 24;
        let compressed_size = read_be_u32(&data[base..]);
        let decompressed_size = read_be_u32(&data[base + 4..]);
        let mut hash = [0u8; 16];
        hash.copy_from_slice(&data[base + 8..base + 24]);
        chunks.push(ChunkInfo {
            compressed_size,
            decompressed_size,
            hash,
        });
    }

    // Decode blocks sequentially
    let mut data_pos = header_size as usize;
    let mut output = Vec::new();
    for chunk in &chunks {
        let block_end = data_pos + chunk.compressed_size as usize;
        if data.len() < block_end {
            return Err(CascError::InvalidFormat("BLTE block data truncated".into()));
        }
        let block = &data[data_pos..block_end];
        let decoded = decode_block_with_keys(block, keystore)?;
        output.extend_from_slice(&decoded);
        data_pos = block_end;
    }

    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::Compression;
    use flate2::write::ZlibEncoder;
    use std::io::Write;

    fn zlib_compress(data: &[u8]) -> Vec<u8> {
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(data).unwrap();
        encoder.finish().unwrap()
    }

    fn make_block_descriptor(compressed_size: u32, decompressed_size: u32) -> Vec<u8> {
        let mut desc = Vec::new();
        desc.extend_from_slice(&compressed_size.to_be_bytes());
        desc.extend_from_slice(&decompressed_size.to_be_bytes());
        desc.extend_from_slice(&[0u8; 16]); // hash (zeroed for tests)
        desc
    }

    #[test]
    fn blte_validates_magic() {
        let data = b"XBLT\x00\x00\x00\x00";
        let err = decode_blte(data).unwrap_err();
        assert!(matches!(err, CascError::InvalidMagic { .. }));
    }

    #[test]
    fn blte_too_short() {
        assert!(decode_blte(&[0x42, 0x4C, 0x54]).is_err());
    }

    #[test]
    fn blte_single_block_raw() {
        let mut data = Vec::new();
        data.extend_from_slice(b"BLTE");
        data.extend_from_slice(&0u32.to_be_bytes());
        data.push(b'N');
        data.extend_from_slice(b"hello");
        assert_eq!(decode_blte(&data).unwrap(), b"hello");
    }

    #[test]
    fn blte_single_block_zlib() {
        let original = b"hello world compressed!";
        let compressed = zlib_compress(original);

        let mut data = Vec::new();
        data.extend_from_slice(b"BLTE");
        data.extend_from_slice(&0u32.to_be_bytes());
        data.push(b'Z');
        data.extend_from_slice(&compressed);

        assert_eq!(decode_blte(&data).unwrap(), original);
    }

    #[test]
    fn blte_single_block_empty() {
        let mut data = Vec::new();
        data.extend_from_slice(b"BLTE");
        data.extend_from_slice(&0u32.to_be_bytes());
        assert_eq!(decode_blte(&data).unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn blte_multi_block_two_raw() {
        let block1_data = b"Nhello"; // N + "hello"
        let block2_data = b"N world"; // N + " world"

        let desc1 = make_block_descriptor(block1_data.len() as u32, 5);
        let desc2 = make_block_descriptor(block2_data.len() as u32, 6);

        // headerSize = 4 (magic) + 4 (headerSize) + 1 (tableFormat) + 3 (numBlocks) + 2*24
        let header_size: u32 = 8 + 1 + 3 + 2 * 24; // = 60

        let mut data = Vec::new();
        data.extend_from_slice(b"BLTE");
        data.extend_from_slice(&header_size.to_be_bytes());
        data.push(0x0F); // tableFormat
        data.push(0x00);
        data.push(0x00);
        data.push(0x02); // numBlocks = 2 as u24 BE
        data.extend_from_slice(&desc1);
        data.extend_from_slice(&desc2);
        assert_eq!(data.len(), header_size as usize);
        data.extend_from_slice(block1_data);
        data.extend_from_slice(block2_data);

        let result = decode_blte(&data).unwrap();
        assert_eq!(result, b"hello world");
    }

    #[test]
    fn blte_multi_block_mixed_nz() {
        let raw_content = b"raw part";
        let zlib_content = b"compressed part";
        let compressed = zlib_compress(zlib_content);

        let block1 = {
            let mut b = vec![b'N'];
            b.extend_from_slice(raw_content);
            b
        };
        let block2 = {
            let mut b = vec![b'Z'];
            b.extend_from_slice(&compressed);
            b
        };

        let desc1 = make_block_descriptor(block1.len() as u32, raw_content.len() as u32);
        let desc2 = make_block_descriptor(block2.len() as u32, zlib_content.len() as u32);

        let header_size: u32 = 8 + 1 + 3 + 2 * 24;

        let mut data = Vec::new();
        data.extend_from_slice(b"BLTE");
        data.extend_from_slice(&header_size.to_be_bytes());
        data.push(0x0F);
        data.push(0x00);
        data.push(0x00);
        data.push(0x02);
        data.extend_from_slice(&desc1);
        data.extend_from_slice(&desc2);
        data.extend_from_slice(&block1);
        data.extend_from_slice(&block2);

        let result = decode_blte(&data).unwrap();
        let expected: Vec<u8> = [raw_content.as_ref(), zlib_content.as_ref()].concat();
        assert_eq!(result, expected);
    }

    #[test]
    fn blte_multi_block_truncated_data() {
        let header_size: u32 = 8 + 1 + 3 + 24;
        let mut data = Vec::new();
        data.extend_from_slice(b"BLTE");
        data.extend_from_slice(&header_size.to_be_bytes());
        data.push(0x0F);
        data.push(0x00);
        data.push(0x00);
        data.push(0x01);
        data.extend_from_slice(&make_block_descriptor(100, 100)); // claims 100 bytes
        // But we only provide 5 bytes of block data
        data.extend_from_slice(&[b'N', 1, 2, 3, 4]);

        assert!(decode_blte(&data).is_err());
    }

    #[test]
    fn blte_unsupported_table_format() {
        let mut data = Vec::new();
        data.extend_from_slice(b"BLTE");
        data.extend_from_slice(&100u32.to_be_bytes());
        data.push(0x10); // unsupported format
        data.extend_from_slice(&[0; 100]);

        assert!(decode_blte(&data).is_err());
    }

    #[test]
    fn blte_with_keys_none_works_for_non_encrypted() {
        let mut data = Vec::new();
        data.extend_from_slice(b"BLTE");
        data.extend_from_slice(&0u32.to_be_bytes());
        data.push(b'N');
        data.extend_from_slice(b"test");
        assert_eq!(decode_blte_with_keys(&data, None).unwrap(), b"test");
    }

    #[test]
    fn blte_encrypted_block_without_keystore_errors() {
        // Build a single-block BLTE with mode E - should fail without keystore
        let mut data = Vec::new();
        data.extend_from_slice(b"BLTE");
        data.extend_from_slice(&0u32.to_be_bytes()); // single block
        data.push(b'E'); // encrypted
        data.push(1u8); // key_count
        data.push(8u8); // key_name_size
        data.extend_from_slice(&0xDEADu64.to_le_bytes()); // unknown key
        data.extend_from_slice(&4u32.to_le_bytes()); // iv_size
        data.extend_from_slice(&[0; 4]); // iv
        data.push(b'S'); // salsa20
        data.extend_from_slice(b"fake_encrypted_data");

        // Without keystore -> error
        assert!(decode_blte(&data).is_err());

        // With empty keystore -> EncryptionKeyMissing
        let ks = TactKeyStore::new();
        let result = decode_blte_with_keys(&data, Some(&ks));
        assert!(result.is_err());
    }

    #[test]
    fn blte_encrypted_single_block_round_trip() {
        let key_name: u64 = 0xFA505078126ACB3E;
        let ks = TactKeyStore::with_known_keys();
        let key = ks.get(key_name).unwrap();

        // Inner content: mode N + "decrypted!"
        let plaintext = b"Ndecrypted!";
        let iv_bytes = [0x10, 0x20, 0x30, 0x40];

        // Encrypt plaintext with Salsa20
        let mut encrypted_payload = plaintext.to_vec();
        {
            use salsa20::Salsa20;
            use salsa20::cipher::{KeyIvInit, StreamCipher};
            let mut full_key = [0u8; 32];
            full_key[..16].copy_from_slice(key);
            full_key[16..].copy_from_slice(key);
            let mut nonce = [0u8; 8];
            nonce[..4].copy_from_slice(&iv_bytes);
            let mut cipher = Salsa20::new(&full_key.into(), &nonce.into());
            cipher.apply_keystream(&mut encrypted_payload);
        }

        // Build E-mode encryption header
        let mut e_block = Vec::new();
        e_block.push(1u8); // key_count
        e_block.push(8u8); // key_name_size
        e_block.extend_from_slice(&key_name.to_le_bytes());
        e_block.extend_from_slice(&4u32.to_le_bytes()); // iv_size
        e_block.extend_from_slice(&iv_bytes);
        e_block.push(b'S'); // salsa20
        e_block.extend_from_slice(&encrypted_payload);

        // Wrap in BLTE single-block format
        let mut data = Vec::new();
        data.extend_from_slice(b"BLTE");
        data.extend_from_slice(&0u32.to_be_bytes()); // single block
        data.push(b'E');
        data.extend_from_slice(&e_block);

        let result = decode_blte_with_keys(&data, Some(&ks)).unwrap();
        assert_eq!(result, b"decrypted!");
    }
}
