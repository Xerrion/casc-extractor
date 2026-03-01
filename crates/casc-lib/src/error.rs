//! Error types for CASC operations.
//!
//! All fallible functions in this crate return [`Result<T>`], which is an alias
//! for `std::result::Result<T, CascError>`.

use thiserror::Error;

/// Errors that can occur during CASC operations.
#[derive(Debug, Error)]
pub enum CascError {
    /// An underlying I/O failure (file not found, permission denied, etc.).
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// File magic bytes do not match the expected format identifier.
    #[error("Invalid magic: expected {expected}, found {found}")]
    InvalidMagic {
        /// The magic bytes the parser expected (e.g. `"BLTE"`, `"EN"`).
        expected: String,
        /// The magic bytes actually found in the data.
        found: String,
    },

    /// Structural parse failure - truncated data, bad field values, or unexpected layout.
    #[error("Invalid format: {0}")]
    InvalidFormat(String),

    /// A referenced key was not found in the index, encoding table, or root file.
    #[error("{key_type} key not found: {hash}")]
    KeyNotFound {
        /// The kind of key that was looked up (e.g. `"EKey"`, `"CKey"`).
        key_type: String,
        /// Hex representation of the key that was not found.
        hash: String,
    },

    /// The file format version is not supported by this library.
    #[error("Unsupported version: {0}")]
    UnsupportedVersion(u32),

    /// A TACT encryption key is required but was not present in the key store.
    #[error("Encryption key missing: {0}")]
    EncryptionKeyMissing(String),

    /// Zlib or LZ4 decompression failed.
    #[error("Decompression failed: {0}")]
    DecompressionFailed(String),

    /// Content hash does not match the expected value after extraction.
    #[error("Checksum mismatch: expected {expected}, actual {actual}")]
    ChecksumMismatch {
        /// The expected hash (from the encoding or root table).
        expected: String,
        /// The hash computed from the extracted data.
        actual: String,
    },

    /// A network request failed (e.g. listfile download).
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),
}

/// Crate-wide result type alias using [`CascError`].
pub type Result<T> = std::result::Result<T, CascError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_display_io() {
        let err = CascError::Io(std::io::Error::new(std::io::ErrorKind::NotFound, "test"));
        assert!(err.to_string().contains("I/O error"));
    }

    #[test]
    fn error_display_invalid_magic() {
        let err = CascError::InvalidMagic {
            expected: "BLTE".into(),
            found: "XXXX".into(),
        };
        assert!(err.to_string().contains("BLTE"));
        assert!(err.to_string().contains("XXXX"));
    }

    #[test]
    fn error_from_io() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "missing");
        let casc_err: CascError = io_err.into();
        assert!(matches!(casc_err, CascError::Io(_)));
    }
}
