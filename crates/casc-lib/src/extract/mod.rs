//! High-level CASC extraction pipeline.
//!
//! This module provides the main entry points for opening CASC storage,
//! listing available files, and extracting them to disk. It ties together
//! the lower-level storage, encoding, root, and listfile components into
//! a single `CascStorage` facade with parallel extraction support.

/// Extraction metadata recording (JSONL, CSV, and summary output).
pub mod metadata;
/// Core extraction pipeline - storage opening, file listing, and parallel extraction.
pub mod pipeline;

/// Re-exported types for convenient access.
pub use pipeline::{
    CascStorage, ExtractionConfig, OpenConfig, StorageInfo, extract_all, extract_single_file,
    list_files, output_path,
};
