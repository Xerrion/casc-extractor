//! Shared utility functions used across the CASC library.
//!
//! Provides low-level helpers for binary I/O (endian-aware integer reads) and
//! hashing (Jenkins hashlittle2 for CASC name hashes).

/// Jenkins hashlittle2 hash function and WoW file path hashing.
pub mod hash;
/// Endian-aware byte-slice integer readers.
pub mod io;
