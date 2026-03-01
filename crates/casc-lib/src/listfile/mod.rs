//! Community-maintained listfile for mapping FileDataIDs to file paths.
//!
//! CASC storage identifies files by numeric FileDataIDs, but the original
//! file paths are not stored in the archive. The community listfile
//! (`community-listfile.csv`) provides a semicolon-separated mapping of
//! `FileDataID;FilePath` that enables human-readable output directory
//! structures during extraction.

/// Downloading and caching the community listfile from remote sources.
pub mod downloader;
/// Parsing the listfile CSV format into a bidirectional lookup table.
pub mod parser;
