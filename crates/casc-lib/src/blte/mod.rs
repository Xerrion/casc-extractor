//! BLTE (Binary Large Table Entry) container format decoder.
//!
//! BLTE is Blizzard's container format that wraps compressed and optionally
//! encrypted game data. A BLTE blob starts with a 4-byte `"BLTE"` magic, a
//! header-size field, and then either a single data block (when header size is 0)
//! or a chunk table describing multiple blocks. Each block carries a one-byte
//! mode prefix: `N` (raw), `Z` (zlib), `4` (LZ4), or `E` (encrypted).

/// Block-level compression and mode dispatch (N, Z, 4, E, F).
pub mod compression;
/// Top-level BLTE stream decoder (magic validation, chunk table, block iteration).
pub mod decoder;
/// TACT encryption key store and Salsa20/ARC4 decryption.
pub mod encryption;
