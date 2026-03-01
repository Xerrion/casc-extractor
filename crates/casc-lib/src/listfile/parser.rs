//! Listfile parser providing bidirectional FileDataID / path lookup.
//!
//! The community listfile format is one `FileDataID;FilePath` pair per line.
//! This module parses that format into a `Listfile` struct that supports
//! both forward (FDID -> path) and reverse (path -> FDID, case-insensitive)
//! lookups.

use std::collections::HashMap;
use std::path::Path;

use crate::error::Result;

/// Parsed listfile mapping FileDataID <-> file path.
///
/// The community listfile format is one `FileDataID;FilePath` pair per line
/// (semicolon-separated). This struct provides bidirectional lookup.
pub struct Listfile {
    /// FileDataID -> path (original case preserved)
    by_id: HashMap<u32, String>,
    /// Lowercase path -> FileDataID (case-insensitive lookup)
    by_path: HashMap<String, u32>,
}

impl Listfile {
    /// Parse listfile content (`FileDataID;Path` per line).
    ///
    /// Malformed lines (missing semicolon, non-numeric ID, empty ID) are
    /// silently skipped.
    pub fn parse(content: &str) -> Self {
        let mut by_id = HashMap::new();
        let mut by_path = HashMap::new();

        for line in content.lines() {
            let line = line.trim_end_matches('\r');
            if line.is_empty() {
                continue;
            }

            let Some((id_str, path)) = line.split_once(';') else {
                continue;
            };

            let Ok(fdid) = id_str.parse::<u32>() else {
                continue;
            };

            if path.is_empty() {
                continue;
            }

            by_path.insert(path.to_lowercase(), fdid);
            by_id.insert(fdid, path.to_string());
        }

        Self { by_id, by_path }
    }

    /// Load and parse a listfile from disk.
    pub fn load(path: &Path) -> Result<Self> {
        let content = std::fs::read_to_string(path)?;
        Ok(Self::parse(&content))
    }

    /// Look up a file path by FileDataID.
    pub fn path(&self, fdid: u32) -> Option<&str> {
        self.by_id.get(&fdid).map(|s| s.as_str())
    }

    /// Look up a FileDataID by path (case-insensitive).
    pub fn fdid(&self, path: &str) -> Option<u32> {
        self.by_path.get(&path.to_lowercase()).copied()
    }

    /// Number of entries in the listfile.
    pub fn len(&self) -> usize {
        self.by_id.len()
    }

    /// Whether the listfile is empty.
    pub fn is_empty(&self) -> bool {
        self.by_id.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_basic() {
        let content = "53;Cameras/FlyBy.m2\n69;Creature/Bear/bear.m2\n";
        let lf = Listfile::parse(content);
        assert_eq!(lf.len(), 2);
        assert_eq!(lf.path(53), Some("Cameras/FlyBy.m2"));
        assert_eq!(lf.path(69), Some("Creature/Bear/bear.m2"));
    }

    #[test]
    fn parse_reverse_lookup() {
        let content = "53;Cameras/FlyBy.m2\n";
        let lf = Listfile::parse(content);
        assert_eq!(lf.fdid("cameras/flyby.m2"), Some(53)); // case-insensitive
    }

    #[test]
    fn parse_skips_malformed() {
        let content = "53;Valid/Path.m2\nnot_a_number;Bad\n;empty_id\n42\n\n";
        let lf = Listfile::parse(content);
        assert_eq!(lf.len(), 1);
        assert_eq!(lf.path(53), Some("Valid/Path.m2"));
    }

    #[test]
    fn parse_empty() {
        let lf = Listfile::parse("");
        assert!(lf.is_empty());
    }

    #[test]
    fn lookup_miss() {
        let lf = Listfile::parse("53;Test.m2\n");
        assert!(lf.path(999).is_none());
        assert!(lf.fdid("nonexistent").is_none());
    }

    #[test]
    fn parse_handles_windows_line_endings() {
        let content = "53;Path/A.m2\r\n69;Path/B.m2\r\n";
        let lf = Listfile::parse(content);
        assert_eq!(lf.len(), 2);
        // Make sure no \r in paths
        assert_eq!(lf.path(53), Some("Path/A.m2"));
    }

    #[test]
    fn parse_preserves_original_case_in_path() {
        let content = "53;World/Maps/Azeroth.wdt\n";
        let lf = Listfile::parse(content);
        // by_id stores original case
        assert_eq!(lf.path(53), Some("World/Maps/Azeroth.wdt"));
        // by_path uses lowercase for lookup
        assert_eq!(lf.fdid("world/maps/azeroth.wdt"), Some(53));
    }
}
