//! Low-level CASC data archive and index file access.
//!
//! A CASC installation stores its data in numbered archive files (`data.NNN`) and
//! their companion index files (`.idx`). This module provides parsers and
//! memory-mapped readers for both.

/// Memory-mapped `data.NNN` archive reader.
pub mod data;
/// `.idx` index file parser and lookup table.
pub mod index;
