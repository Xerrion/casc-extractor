//! Block-level compression and mode dispatch for BLTE.
//!
//! Each BLTE block starts with a one-byte mode prefix:
//!
//! - `N` (0x4E) - raw / uncompressed data, returned as-is.
//! - `Z` (0x5A) - zlib-compressed data (RFC 1950).
//! - `4` (0x34) - LZ4 block compression with sub-block framing.
//! - `E` (0x45) - encrypted block; after decryption the inner payload is
//!   recursively decoded (its first byte is the inner compression mode).
//! - `F` (0x46) - recursive BLTE (not currently supported).

use super::encryption::{TactKeyStore, decrypt_block as decrypt_encrypted_block};
use crate::error::{CascError, Result};

/// Decode a BLTE block with optional encryption support.
///
/// `block` includes the mode byte as the first byte. When a mode-E
/// (encrypted) block is encountered the `keystore` is used to look up
/// the decryption key. Pass `None` if encryption support is not needed
/// - encrypted blocks will return an error in that case.
pub fn decode_block_with_keys(block: &[u8], keystore: Option<&TactKeyStore>) -> Result<Vec<u8>> {
    if block.is_empty() {
        return Ok(Vec::new());
    }
    match block[0] {
        b'N' => decode_raw(&block[1..]),
        b'Z' => decode_zlib(&block[1..]),
        b'4' => decode_lz4(&block[1..]),
        b'E' => decode_encrypted(&block[1..], keystore),
        b'F' => Err(CascError::InvalidFormat(
            "recursive BLTE (mode F) not supported".into(),
        )),
        mode => Err(CascError::InvalidFormat(format!(
            "unknown BLTE mode: 0x{:02X}",
            mode
        ))),
    }
}

/// Decode a BLTE block based on its mode byte (no encryption support).
///
/// `block` includes the mode byte as the first byte.
/// Encrypted blocks (mode E) will always return an error.
pub fn decode_block(block: &[u8]) -> Result<Vec<u8>> {
    decode_block_with_keys(block, None)
}

fn decode_encrypted(data: &[u8], keystore: Option<&TactKeyStore>) -> Result<Vec<u8>> {
    let keystore = keystore.ok_or_else(|| {
        CascError::EncryptionKeyMissing("no keystore provided for encrypted block".into())
    })?;
    // decrypt_encrypted_block returns decrypted data where the first byte is the inner mode
    let decrypted = decrypt_encrypted_block(data, keystore)?;
    // Recursively decode the inner block (which starts with a mode byte: N, Z, 4, etc.)
    decode_block_with_keys(&decrypted, Some(keystore))
}

fn decode_raw(data: &[u8]) -> Result<Vec<u8>> {
    Ok(data.to_vec())
}

fn decode_zlib(data: &[u8]) -> Result<Vec<u8>> {
    use flate2::read::ZlibDecoder;
    use std::io::Read;

    let mut decoder = ZlibDecoder::new(data);
    let mut output = Vec::new();
    decoder
        .read_to_end(&mut output)
        .map_err(|e| CascError::DecompressionFailed(format!("zlib: {}", e)))?;
    Ok(output)
}

fn decode_lz4(data: &[u8]) -> Result<Vec<u8>> {
    let mut output = Vec::new();
    let mut offset = 0;

    while offset < data.len() {
        // Each sub-block: u32 LE decompressed_size + u32 LE compressed_size + payload
        if offset + 8 > data.len() {
            return Err(CascError::InvalidFormat(
                "LZ4: truncated sub-block header".into(),
            ));
        }

        let decompressed_size =
            u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap()) as usize;
        offset += 4;

        let compressed_size =
            u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap()) as usize;
        offset += 4;

        if compressed_size >= decompressed_size {
            // Stored uncompressed - read decompressed_size raw bytes
            if offset + decompressed_size > data.len() {
                return Err(CascError::InvalidFormat(
                    "LZ4: truncated uncompressed sub-block payload".into(),
                ));
            }
            output.extend_from_slice(&data[offset..offset + decompressed_size]);
            offset += decompressed_size;
        } else {
            // LZ4 block compressed
            if offset + compressed_size > data.len() {
                return Err(CascError::InvalidFormat(
                    "LZ4: truncated compressed sub-block payload".into(),
                ));
            }
            let decompressed =
                lz4_flex::decompress(&data[offset..offset + compressed_size], decompressed_size)
                    .map_err(|e| CascError::DecompressionFailed(format!("LZ4: {}", e)))?;
            output.extend_from_slice(&decompressed);
            offset += compressed_size;
        }
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

    #[test]
    fn mode_n_passthrough() {
        let mut block = vec![b'N'];
        block.extend_from_slice(b"hello world");
        let result = decode_block(&block).unwrap();
        assert_eq!(result, b"hello world");
    }

    #[test]
    fn mode_n_empty_payload() {
        let block = vec![b'N'];
        let result = decode_block(&block).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn mode_z_decompresses() {
        let original = b"hello world compressed with zlib!";
        let compressed = zlib_compress(original);
        let mut block = vec![b'Z'];
        block.extend_from_slice(&compressed);
        let result = decode_block(&block).unwrap();
        assert_eq!(result, original);
    }

    #[test]
    fn mode_z_large_data() {
        let original: Vec<u8> = (0..10000).map(|i| (i % 256) as u8).collect();
        let compressed = zlib_compress(&original);
        let mut block = vec![b'Z'];
        block.extend_from_slice(&compressed);
        let result = decode_block(&block).unwrap();
        assert_eq!(result, original);
    }

    #[test]
    fn mode_z_invalid_data() {
        let block = vec![b'Z', 0xFF, 0xFE, 0xFD];
        assert!(decode_block(&block).is_err());
    }

    #[test]
    fn mode_e_without_keystore_errors() {
        let block = vec![b'E', 0x00];
        assert!(decode_block(&block).is_err());
        assert!(decode_block_with_keys(&block, None).is_err());
    }

    #[test]
    fn mode_e_with_empty_keystore_errors() {
        use crate::blte::encryption::TactKeyStore;
        // Build a minimal encrypted block with a key that won't be in the store
        let mut block = vec![b'E'];
        block.push(1u8); // key_count
        block.push(8u8); // key_name_size
        block.extend_from_slice(&0xDEADu64.to_le_bytes());
        block.extend_from_slice(&4u32.to_le_bytes()); // iv_size
        block.extend_from_slice(&[0; 4]); // iv
        block.push(b'S'); // salsa20
        block.extend_from_slice(b"fake_encrypted_data");

        let ks = TactKeyStore::new();
        let result = decode_block_with_keys(&block, Some(&ks));
        assert!(result.is_err());
    }

    #[test]
    fn mode_e_decrypt_and_decompress_raw() {
        use crate::blte::encryption::TactKeyStore;

        let key_name: u64 = 0xFA505078126ACB3E;
        let ks = TactKeyStore::with_known_keys();
        let key = ks.get(key_name).unwrap();

        // Inner content: mode N + "hello"
        let plaintext = b"Nhello";
        let iv_bytes = [0x10, 0x20, 0x30, 0x40];

        // Encrypt the plaintext with Salsa20
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

        // Build the full E-mode block: E + encryption header + encrypted payload
        let mut block = vec![b'E'];
        block.push(1u8);
        block.push(8u8);
        block.extend_from_slice(&key_name.to_le_bytes());
        block.extend_from_slice(&4u32.to_le_bytes());
        block.extend_from_slice(&iv_bytes);
        block.push(b'S');
        block.extend_from_slice(&encrypted_payload);

        let result = decode_block_with_keys(&block, Some(&ks)).unwrap();
        assert_eq!(result, b"hello");
    }

    #[test]
    fn mode_unknown_returns_error() {
        let block = vec![b'X', 0x00];
        let err = decode_block(&block).unwrap_err();
        assert!(err.to_string().contains("unknown BLTE mode"));
    }

    #[test]
    fn empty_block() {
        let result = decode_block(&[]).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn mode_4_single_subblock_compressed() {
        // Use highly repetitive data so LZ4 actually compresses it smaller
        let original: Vec<u8> = b"AAAA".repeat(256);
        let compressed = lz4_flex::compress(&original);
        assert!(
            compressed.len() < original.len(),
            "test data must actually compress smaller"
        );

        let decompressed_size = original.len() as u32;
        let compressed_size = compressed.len() as u32;

        let mut block = vec![b'4'];
        block.extend_from_slice(&decompressed_size.to_le_bytes());
        block.extend_from_slice(&compressed_size.to_le_bytes());
        block.extend_from_slice(&compressed);

        let result = decode_block(&block).unwrap();
        assert_eq!(result, original);
    }

    #[test]
    fn mode_4_single_subblock_uncompressed() {
        // When compressed_size >= decompressed_size, data is stored raw
        let original = b"raw data";
        let decompressed_size = original.len() as u32;
        let compressed_size = decompressed_size; // equal means uncompressed

        let mut block = vec![b'4'];
        block.extend_from_slice(&decompressed_size.to_le_bytes());
        block.extend_from_slice(&compressed_size.to_le_bytes());
        block.extend_from_slice(original);

        let result = decode_block(&block).unwrap();
        assert_eq!(result, original);
    }

    #[test]
    fn mode_4_multiple_subblocks() {
        // Use repetitive data so LZ4 compresses smaller than original
        let part1: Vec<u8> = b"BBBB".repeat(200);
        let part2: Vec<u8> = b"CCCC".repeat(300);
        let compressed1 = lz4_flex::compress(&part1);
        let compressed2 = lz4_flex::compress(&part2);
        assert!(compressed1.len() < part1.len());
        assert!(compressed2.len() < part2.len());

        let mut block = vec![b'4'];
        // Sub-block 1
        block.extend_from_slice(&(part1.len() as u32).to_le_bytes());
        block.extend_from_slice(&(compressed1.len() as u32).to_le_bytes());
        block.extend_from_slice(&compressed1);
        // Sub-block 2
        block.extend_from_slice(&(part2.len() as u32).to_le_bytes());
        block.extend_from_slice(&(compressed2.len() as u32).to_le_bytes());
        block.extend_from_slice(&compressed2);

        let result = decode_block(&block).unwrap();
        let expected: Vec<u8> = [part1.as_slice(), part2.as_slice()].concat();
        assert_eq!(result, expected);
    }

    #[test]
    fn mode_4_empty_returns_empty() {
        let block = vec![b'4'];
        let result = decode_block(&block).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn mode_4_truncated_header_errors() {
        // Only 4 bytes after mode (need 8 for decompressed_size + compressed_size)
        let block = vec![b'4', 0x10, 0x00, 0x00, 0x00];
        assert!(decode_block(&block).is_err());
    }
}
