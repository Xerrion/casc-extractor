//! TACT encryption support for BLTE mode-E blocks.
//!
//! Blizzard uses TACT (Trusted Application Content Transfer) to encrypt
//! sensitive game data inside BLTE containers. Each encrypted block carries
//! an encryption header that names the key (a `u64` key name), provides an
//! IV, and identifies the cipher:
//!
//! - **Salsa20** (`S`) - the 16-byte TACT key is doubled to 32 bytes and
//!   used with an 8-byte nonce derived from the IV.
//! - **ARC4** (`A`) - RC4 with the standard WoW 1024-byte keystream skip.
//!
//! Keys are stored in a [`TactKeyStore`](crate::blte::encryption::TactKeyStore) which can be populated from the
//! bundled community-known key list or loaded from a text key file.

use std::collections::HashMap;
use std::path::Path;

use salsa20::Salsa20;
use salsa20::cipher::{KeyIvInit, StreamCipher};

use crate::error::{CascError, Result};

// ---------------------------------------------------------------------------
// TactKeyStore
// ---------------------------------------------------------------------------

/// Stores TACT encryption keys (key_name u64 -> 16-byte key value).
pub struct TactKeyStore {
    keys: HashMap<u64, [u8; 16]>,
}

impl Default for TactKeyStore {
    fn default() -> Self {
        Self::new()
    }
}

impl TactKeyStore {
    /// Create an empty key store.
    pub fn new() -> Self {
        Self {
            keys: HashMap::new(),
        }
    }

    /// Create a key store pre-populated with community-known WoW TACT keys.
    pub fn with_known_keys() -> Self {
        let mut keys = HashMap::new();
        for (name, value) in known_keys() {
            keys.insert(name, value);
        }
        Self { keys }
    }

    /// Load a key store from a text file.
    ///
    /// Format: one key per line as `hex_key_name hex_key_value`.
    /// Lines starting with `#` and blank lines are ignored.
    pub fn load_keyfile(path: &Path) -> Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let mut keys = HashMap::new();

        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }

            let parts: Vec<&str> = trimmed.split_whitespace().collect();
            if parts.len() < 2 {
                return Err(CascError::InvalidFormat(format!(
                    "invalid keyfile line: {}",
                    trimmed
                )));
            }

            let key_name = u64::from_str_radix(parts[0], 16).map_err(|e| {
                CascError::InvalidFormat(format!("invalid key name '{}': {}", parts[0], e))
            })?;

            let key_value = hex_to_key_result(parts[1])?;
            keys.insert(key_name, key_value);
        }

        Ok(Self { keys })
    }

    /// Merge keys from another store into this one.
    /// Existing keys are overwritten if the other store has the same key name.
    pub fn merge(&mut self, other: &TactKeyStore) {
        for (&name, &value) in &other.keys {
            self.keys.insert(name, value);
        }
    }

    /// Look up a key by name.
    pub fn get(&self, key_name: u64) -> Option<&[u8; 16]> {
        self.keys.get(&key_name)
    }

    /// Return the number of keys in the store.
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    /// Return true if the store contains no keys.
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }
}

// ---------------------------------------------------------------------------
// Encryption header types
// ---------------------------------------------------------------------------

/// Encryption algorithm used by a BLTE encrypted block.
#[derive(Debug, PartialEq)]
pub enum EncryptionAlgorithm {
    /// Salsa20 stream cipher (mode byte `S`). The 16-byte key is doubled to 32 bytes.
    Salsa20,
    /// ARC4 (RC4) stream cipher with 1024-byte keystream skip (mode byte `A`).
    ARC4,
}

/// Parsed encryption header from a BLTE mode-E block.
#[derive(Debug)]
pub struct EncryptionHeader {
    /// 64-bit key name used to look up the decryption key in the [`TactKeyStore`].
    pub key_name: u64,
    /// Initialization vector for the cipher.
    pub iv: Vec<u8>,
    /// The encryption algorithm used (Salsa20 or ARC4).
    pub algorithm: EncryptionAlgorithm,
}

// ---------------------------------------------------------------------------
// Header parsing
// ---------------------------------------------------------------------------

/// Parse an encryption header from the data following the `E` mode byte.
///
/// Returns the parsed header and a slice of the remaining encrypted payload.
pub fn parse_encryption_header(data: &[u8]) -> Result<(EncryptionHeader, &[u8])> {
    if data.is_empty() {
        return Err(CascError::InvalidFormat(
            "encryption header: empty data".into(),
        ));
    }

    let mut pos = 0;

    // key_count (u8)
    let key_count = data[pos] as usize;
    pos += 1;

    if key_count == 0 {
        return Err(CascError::InvalidFormat(
            "encryption header: key_count is 0".into(),
        ));
    }

    // We only use the first key but must skip through all of them.
    let mut key_name: u64 = 0;
    for i in 0..key_count {
        if pos >= data.len() {
            return Err(CascError::InvalidFormat(
                "encryption header: truncated key_name_size".into(),
            ));
        }
        let key_name_size = data[pos] as usize;
        pos += 1;

        if pos + key_name_size > data.len() {
            return Err(CascError::InvalidFormat(
                "encryption header: truncated key_name".into(),
            ));
        }

        if i == 0 {
            if key_name_size != 8 {
                return Err(CascError::InvalidFormat(format!(
                    "encryption header: expected key_name_size 8, got {}",
                    key_name_size
                )));
            }
            key_name = u64::from_le_bytes(data[pos..pos + 8].try_into().map_err(|_| {
                CascError::InvalidFormat("encryption header: failed to read key_name".into())
            })?);
        }
        pos += key_name_size;
    }

    // IV size (u32 LE)
    if pos + 4 > data.len() {
        return Err(CascError::InvalidFormat(
            "encryption header: truncated IV size".into(),
        ));
    }
    let iv_size = u32::from_le_bytes(data[pos..pos + 4].try_into().map_err(|_| {
        CascError::InvalidFormat("encryption header: failed to read IV size".into())
    })?) as usize;
    pos += 4;

    // IV bytes
    if pos + iv_size > data.len() {
        return Err(CascError::InvalidFormat(
            "encryption header: truncated IV".into(),
        ));
    }
    let iv = data[pos..pos + iv_size].to_vec();
    pos += iv_size;

    // encryption_type (u8)
    if pos >= data.len() {
        return Err(CascError::InvalidFormat(
            "encryption header: missing encryption type".into(),
        ));
    }
    let algorithm = match data[pos] {
        b'S' => EncryptionAlgorithm::Salsa20,
        b'A' => EncryptionAlgorithm::ARC4,
        other => {
            return Err(CascError::InvalidFormat(format!(
                "encryption header: unknown algorithm 0x{:02X}",
                other
            )));
        }
    };
    pos += 1;

    Ok((
        EncryptionHeader {
            key_name,
            iv,
            algorithm,
        },
        &data[pos..],
    ))
}

// ---------------------------------------------------------------------------
// ARC4 (RC4 with 1024-byte skip)
// ---------------------------------------------------------------------------

struct Arc4 {
    s: [u8; 256],
    i: u8,
    j: u8,
}

impl Arc4 {
    fn new(key: &[u8]) -> Self {
        let mut s = [0u8; 256];
        for (i, slot) in s.iter_mut().enumerate() {
            *slot = i as u8;
        }
        // KSA requires in-place swaps driven by computed j, so indexing is necessary
        let mut j: u8 = 0;
        #[allow(clippy::needless_range_loop)]
        for i in 0..256 {
            j = j.wrapping_add(s[i]).wrapping_add(key[i % key.len()]);
            s.swap(i, j as usize);
        }
        // WoW-specific: skip first 1024 bytes of keystream
        let mut arc4 = Arc4 { s, i: 0, j: 0 };
        let mut discard = [0u8; 1024];
        arc4.process(&mut discard);
        arc4
    }

    fn process(&mut self, data: &mut [u8]) {
        for byte in data.iter_mut() {
            self.i = self.i.wrapping_add(1);
            self.j = self.j.wrapping_add(self.s[self.i as usize]);
            self.s.swap(self.i as usize, self.j as usize);
            let k =
                self.s[(self.s[self.i as usize].wrapping_add(self.s[self.j as usize])) as usize];
            *byte ^= k;
        }
    }
}

// ---------------------------------------------------------------------------
// Salsa20 decryption helper
// ---------------------------------------------------------------------------

fn decrypt_salsa20(key: &[u8; 16], iv: &[u8], data: &mut [u8]) {
    // Salsa20 requires a 32-byte key; double the 16-byte TACT key.
    let mut full_key = [0u8; 32];
    full_key[..16].copy_from_slice(key);
    full_key[16..].copy_from_slice(key);

    // Pad IV to 8-byte nonce.
    let mut nonce = [0u8; 8];
    let copy_len = iv.len().min(8);
    nonce[..copy_len].copy_from_slice(&iv[..copy_len]);

    let mut cipher = Salsa20::new(&full_key.into(), &nonce.into());
    cipher.apply_keystream(data);
}

// ---------------------------------------------------------------------------
// Public decrypt entry point
// ---------------------------------------------------------------------------

/// Decrypt a BLTE mode-E block.
///
/// `data` is everything after the `E` mode byte. Returns the decrypted
/// payload whose first byte is the inner compression mode (N, Z, 4, etc.).
pub fn decrypt_block(data: &[u8], keystore: &TactKeyStore) -> Result<Vec<u8>> {
    let (header, encrypted) = parse_encryption_header(data)?;

    let key = keystore
        .get(header.key_name)
        .ok_or_else(|| CascError::EncryptionKeyMissing(format!("0x{:016X}", header.key_name)))?;

    let mut output = encrypted.to_vec();
    match header.algorithm {
        EncryptionAlgorithm::Salsa20 => {
            decrypt_salsa20(key, &header.iv, &mut output);
        }
        EncryptionAlgorithm::ARC4 => {
            let mut cipher = Arc4::new(key);
            cipher.process(&mut output);
        }
    }

    Ok(output)
}

// ---------------------------------------------------------------------------
// Known TACT keys
// ---------------------------------------------------------------------------

/// Convert a hex string to a 16-byte key. Panics on invalid input.
fn hex_to_key(hex_str: &str) -> [u8; 16] {
    let bytes = hex::decode(hex_str).expect("invalid hex in known key");
    let mut key = [0u8; 16];
    key.copy_from_slice(&bytes);
    key
}

/// Convert a hex string to a 16-byte key, returning an error on failure.
fn hex_to_key_result(hex_str: &str) -> Result<[u8; 16]> {
    let bytes = hex::decode(hex_str).map_err(|e| {
        CascError::InvalidFormat(format!("invalid hex key value '{}': {}", hex_str, e))
    })?;
    if bytes.len() != 16 {
        return Err(CascError::InvalidFormat(format!(
            "key value must be 16 bytes, got {}",
            bytes.len()
        )));
    }
    let mut key = [0u8; 16];
    key.copy_from_slice(&bytes);
    Ok(key)
}

fn known_keys() -> Vec<(u64, [u8; 16])> {
    vec![
        (
            0xFA505078126ACB3E,
            hex_to_key("BDC51862ABED79B2DE48C8E7E66C6200"),
        ),
        (
            0xFF813F7D062AC0BC,
            hex_to_key("AA0B5C77F088CCC2D39049BD267F066D"),
        ),
        (
            0xD1E9B5EDF9283668,
            hex_to_key("8E4A2579894E38B4AB9058BA5C7328EE"),
        ),
        (
            0xB76729641141CB34,
            hex_to_key("9849D1AA7B1FD09819C5C66283A326EC"),
        ),
        (
            0xFFB9469FF16E6BF8,
            hex_to_key("D514BD1909A9E5DC8703F4B8BB1DFD9A"),
        ),
        (
            0x23C5B5DF837A226C,
            hex_to_key("1406E2D873B6FC99217A180881DA8D62"),
        ),
        (
            0x3AE403EF40AC3037,
            hex_to_key("EB31B554C67D603E2F10AA8C4584F1CE"),
        ),
        (
            0xE2854509C471C381,
            hex_to_key("A970FEF382CE86A53A1674C8F36C8F1B"),
        ),
        (
            0x8EE2CB82178C995A,
            hex_to_key("5FA43C8E204D2F1BFAF1FB26FFE5A34B"),
        ),
        (
            0x5813810F4EC9B005,
            hex_to_key("7F3DDA67B4A94DE6D3F3B8D4E45FC076"),
        ),
        (
            0x7F3DDA67B4A94DE6,
            hex_to_key("13AC5E1474618778916727B21F37B31E"),
        ),
        (
            0x402CD9D8D6BFED98,
            hex_to_key("AEB0EADFE24A0742C24B8FFC2DC28C69"),
        ),
        (
            0xFB680CB6A8BF81F3,
            hex_to_key("62D90EFA7F36D71C398AE2F1FE37C5F5"),
        ),
        (
            0xDBD3371554F60306,
            hex_to_key("34E397ACE6DD30EEFDC98A2AB093CD3C"),
        ),
        (
            0x11A9203C9A2D0DC8,
            hex_to_key("2E609EA137A31F85DE06A14A9FF04AA1"),
        ),
        (
            0x279C3FFB7E3229BC,
            hex_to_key("53D25B2053C58F053AA4A6EA4E2D1625"),
        ),
        (
            0xC7459A25DC3B7A4C,
            hex_to_key("C54CF38B19EA7ABCB17B1D5086423A90"),
        ),
    ]
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // TactKeyStore tests
    // -----------------------------------------------------------------------

    #[test]
    fn keystore_new_is_empty() {
        let ks = TactKeyStore::new();
        assert!(ks.is_empty());
        assert_eq!(ks.len(), 0);
    }

    #[test]
    fn keystore_with_known_keys_not_empty() {
        let ks = TactKeyStore::with_known_keys();
        assert!(!ks.is_empty());
        assert!(ks.len() >= 10);
    }

    #[test]
    fn keystore_get_known_key() {
        let ks = TactKeyStore::with_known_keys();
        let key = ks.get(0xFA505078126ACB3E);
        assert!(key.is_some());
        assert_eq!(key.unwrap().len(), 16);
    }

    #[test]
    fn keystore_get_unknown_returns_none() {
        let ks = TactKeyStore::with_known_keys();
        assert!(ks.get(0xDEADBEEFCAFEBABE).is_none());
    }

    #[test]
    fn keystore_merge() {
        let mut ks1 = TactKeyStore::new();
        let mut ks2 = TactKeyStore::new();
        ks2.keys.insert(0x1234, [0xAA; 16]);
        ks1.merge(&ks2);
        assert!(ks1.get(0x1234).is_some());
        assert_eq!(ks1.get(0x1234).unwrap(), &[0xAA; 16]);
    }

    #[test]
    fn keystore_load_keyfile() {
        use std::io::Write;

        let dir = std::env::temp_dir().join("casc_test_keyfile");
        std::fs::create_dir_all(&dir).ok();
        let path = dir.join("test.keys");
        let mut f = std::fs::File::create(&path).unwrap();
        writeln!(f, "# Comment line").unwrap();
        writeln!(f, "FA505078126ACB3E BDC51862ABED79B2DE48C8E7E66C6200").unwrap();
        writeln!(f).unwrap(); // blank line
        writeln!(f, "FF813F7D062AC0BC AA0B5C77F088CCC2D39049BD267F066D").unwrap();
        drop(f);

        let ks = TactKeyStore::load_keyfile(&path).unwrap();
        assert_eq!(ks.len(), 2);
        assert!(ks.get(0xFA505078126ACB3E).is_some());
        assert!(ks.get(0xFF813F7D062AC0BC).is_some());

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn keystore_load_keyfile_missing_file_errors() {
        let path = Path::new("nonexistent_keyfile.txt");
        assert!(TactKeyStore::load_keyfile(path).is_err());
    }

    #[test]
    fn keystore_load_keyfile_invalid_hex_errors() {
        use std::io::Write;

        let dir = std::env::temp_dir().join("casc_test_keyfile_bad");
        std::fs::create_dir_all(&dir).ok();
        let path = dir.join("bad.keys");
        let mut f = std::fs::File::create(&path).unwrap();
        writeln!(f, "ZZZZ INVALID_HEX_VALUE_HERE_TOO").unwrap();
        drop(f);

        assert!(TactKeyStore::load_keyfile(&path).is_err());
        std::fs::remove_dir_all(&dir).ok();
    }

    // -----------------------------------------------------------------------
    // Encryption header parsing tests
    // -----------------------------------------------------------------------

    #[test]
    fn parse_encryption_header_salsa20() {
        let mut data = Vec::new();
        data.push(1u8); // key_count = 1
        data.push(8u8); // key_name_size = 8
        data.extend_from_slice(&0xFA505078126ACB3Eu64.to_le_bytes());
        data.extend_from_slice(&4u32.to_le_bytes()); // iv_size = 4
        data.extend_from_slice(&[0x01, 0x02, 0x03, 0x04]); // IV
        data.push(b'S'); // Salsa20
        data.extend_from_slice(b"encrypted_payload");

        let (header, remaining) = parse_encryption_header(&data).unwrap();
        assert_eq!(header.key_name, 0xFA505078126ACB3E);
        assert_eq!(header.iv, vec![0x01, 0x02, 0x03, 0x04]);
        assert_eq!(header.algorithm, EncryptionAlgorithm::Salsa20);
        assert_eq!(remaining, b"encrypted_payload");
    }

    #[test]
    fn parse_encryption_header_arc4() {
        let mut data = Vec::new();
        data.push(1u8);
        data.push(8u8);
        data.extend_from_slice(&0xDEADBEEFu64.to_le_bytes());
        data.extend_from_slice(&4u32.to_le_bytes());
        data.extend_from_slice(&[0x0A, 0x0B, 0x0C, 0x0D]);
        data.push(b'A'); // ARC4
        data.extend_from_slice(b"payload");

        let (header, remaining) = parse_encryption_header(&data).unwrap();
        assert_eq!(header.algorithm, EncryptionAlgorithm::ARC4);
        assert_eq!(header.key_name, 0xDEADBEEF);
        assert_eq!(remaining, b"payload");
    }

    #[test]
    fn parse_encryption_header_empty_errors() {
        assert!(parse_encryption_header(&[]).is_err());
    }

    #[test]
    fn parse_encryption_header_unknown_algo_errors() {
        let mut data = Vec::new();
        data.push(1u8);
        data.push(8u8);
        data.extend_from_slice(&0u64.to_le_bytes());
        data.extend_from_slice(&4u32.to_le_bytes());
        data.extend_from_slice(&[0; 4]);
        data.push(b'X'); // unknown

        assert!(parse_encryption_header(&data).is_err());
    }

    // -----------------------------------------------------------------------
    // ARC4 tests
    // -----------------------------------------------------------------------

    #[test]
    fn arc4_round_trip() {
        let key = b"test_key_16bytes"; // 16 bytes
        let plaintext = b"Hello World! This is a test of ARC4 encryption.";

        let mut encrypted = plaintext.to_vec();
        let mut cipher1 = Arc4::new(key);
        cipher1.process(&mut encrypted);

        // encrypted should differ from plaintext
        assert_ne!(&encrypted[..], &plaintext[..]);

        // Decrypt with fresh cipher
        let mut decrypted = encrypted.clone();
        let mut cipher2 = Arc4::new(key);
        cipher2.process(&mut decrypted);

        assert_eq!(&decrypted[..], &plaintext[..]);
    }

    #[test]
    fn arc4_empty_data() {
        let key = b"some_key_16bytes";
        let mut data = Vec::new();
        let mut cipher = Arc4::new(key);
        cipher.process(&mut data);
        assert!(data.is_empty());
    }

    // -----------------------------------------------------------------------
    // Salsa20 tests
    // -----------------------------------------------------------------------

    #[test]
    fn salsa20_round_trip() {
        let key = [0x42u8; 16];
        let iv = [0x01, 0x02, 0x03, 0x04];
        let plaintext = b"test salsa20 encryption data";

        // Encrypt
        let mut data = plaintext.to_vec();
        decrypt_salsa20(&key, &iv, &mut data);
        assert_ne!(&data[..], &plaintext[..]);

        // Decrypt (XOR is self-inverse with same keystream)
        let mut roundtrip = data.clone();
        decrypt_salsa20(&key, &iv, &mut roundtrip);
        assert_eq!(&roundtrip[..], &plaintext[..]);
    }

    // -----------------------------------------------------------------------
    // Full decrypt_block tests
    // -----------------------------------------------------------------------

    #[test]
    fn decrypt_block_missing_key_errors() {
        let ks = TactKeyStore::new(); // empty - no keys
        let mut data = Vec::new();
        data.push(1u8); // key_count
        data.push(8u8); // key_name_size
        data.extend_from_slice(&0xDEADBEEFu64.to_le_bytes());
        data.extend_from_slice(&4u32.to_le_bytes());
        data.extend_from_slice(&[0; 4]);
        data.push(b'S');
        data.extend_from_slice(b"encrypted");

        let result = decrypt_block(&data, &ks);
        assert!(result.is_err());
        match result.unwrap_err() {
            CascError::EncryptionKeyMissing(_) => {}
            e => panic!("Expected EncryptionKeyMissing, got: {:?}", e),
        }
    }

    #[test]
    fn decrypt_block_salsa20_round_trip() {
        let key_name: u64 = 0xFA505078126ACB3E;
        let ks = TactKeyStore::with_known_keys();
        let key = ks.get(key_name).unwrap();

        // Prepare a "plaintext" that starts with an inner mode byte
        let plaintext = b"Nhello world inner content";
        let iv_bytes = [0x10, 0x20, 0x30, 0x40];

        // Encrypt the plaintext with Salsa20 to build a test encrypted payload
        let mut encrypted_payload = plaintext.to_vec();
        decrypt_salsa20(key, &iv_bytes, &mut encrypted_payload);

        // Build the full encrypted block (header + encrypted payload)
        let mut block_data = Vec::new();
        block_data.push(1u8);
        block_data.push(8u8);
        block_data.extend_from_slice(&key_name.to_le_bytes());
        block_data.extend_from_slice(&4u32.to_le_bytes());
        block_data.extend_from_slice(&iv_bytes);
        block_data.push(b'S');
        block_data.extend_from_slice(&encrypted_payload);

        // Decrypt and verify we get the original plaintext back
        let decrypted = decrypt_block(&block_data, &ks).unwrap();
        assert_eq!(&decrypted[..], &plaintext[..]);
    }

    #[test]
    fn decrypt_block_arc4_round_trip() {
        let key_name: u64 = 0xFA505078126ACB3E;
        let ks = TactKeyStore::with_known_keys();
        let key = ks.get(key_name).unwrap();

        let plaintext = b"Zcompressed inner data here";

        // Encrypt with ARC4
        let mut encrypted_payload = plaintext.to_vec();
        let mut cipher = Arc4::new(key);
        cipher.process(&mut encrypted_payload);

        // Build header
        let mut block_data = Vec::new();
        block_data.push(1u8);
        block_data.push(8u8);
        block_data.extend_from_slice(&key_name.to_le_bytes());
        block_data.extend_from_slice(&4u32.to_le_bytes());
        block_data.extend_from_slice(&[0x01, 0x02, 0x03, 0x04]);
        block_data.push(b'A');
        block_data.extend_from_slice(&encrypted_payload);

        let decrypted = decrypt_block(&block_data, &ks).unwrap();
        assert_eq!(&decrypted[..], &plaintext[..]);
    }

    #[test]
    fn hex_to_key_result_valid() {
        let key = hex_to_key_result("BDC51862ABED79B2DE48C8E7E66C6200").unwrap();
        assert_eq!(key.len(), 16);
        assert_eq!(key[0], 0xBD);
        assert_eq!(key[15], 0x00);
    }

    #[test]
    fn hex_to_key_result_invalid_hex_errors() {
        assert!(hex_to_key_result("ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ").is_err());
    }

    #[test]
    fn hex_to_key_result_wrong_length_errors() {
        assert!(hex_to_key_result("AABB").is_err());
    }

    #[test]
    fn known_keys_all_valid() {
        let keys = known_keys();
        assert!(keys.len() >= 15);
        for (name, value) in &keys {
            assert_ne!(*name, 0, "key name should not be zero");
            assert_ne!(*value, [0u8; 16], "key value should not be all zeros");
        }
    }
}
