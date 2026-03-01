//! Root file handling for CASC storage.
//!
//! The root file maps FileDataIDs (FDIDs) to content keys (CKeys), enabling
//! lookup of game files by their numeric identifier. Different WoW versions
//! use different root file formats - Legacy (pre-8.2), MFST V1 (8.2+), and
//! MFST V2 (11.1.0+) - all of which are supported.

/// Locale and content flag bitmask types used in root file entries.
pub mod flags;
/// Root file format detection and binary parsing.
pub mod parser;
