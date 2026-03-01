//! Parser for CASC CDN configuration files.
//!
//! The CDN config is a `key = value` text file (with `#` comment lines) identified
//! by the `cdn_key` hash from `.build.info`.
//! It lists the archive hashes that make up the remote content store, an archive
//! group hash, and a file index reference.

use std::collections::HashMap;

use crate::error::Result;

/// Parsed CDN configuration from a CASC CDN config file.
#[derive(Debug, Clone, Default)]
pub struct CdnConfig {
    /// Hex hashes of the remote data archives.
    pub archives: Vec<String>,
    /// Combined group hash for the archive set.
    pub archive_group: String,
    /// File index hash used for loose-file CDN lookups.
    pub file_index: String,
    /// Raw key-value store for all fields.
    pub raw: HashMap<String, String>,
}

/// Parse a CASC CDN config (key = value format, `#` comments).
pub fn parse_cdn_config(content: &str) -> Result<CdnConfig> {
    let mut raw: HashMap<String, String> = HashMap::new();

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        if let Some((key, value)) = trimmed.split_once(" = ") {
            raw.insert(key.to_string(), value.to_string());
        }
    }

    let get = |key: &str| -> String { raw.get(key).cloned().unwrap_or_default() };

    let archives_raw = get("archives");
    let archives: Vec<String> = if archives_raw.is_empty() {
        Vec::new()
    } else {
        archives_raw.split(' ').map(String::from).collect()
    };

    Ok(CdnConfig {
        archives,
        archive_group: get("archive-group"),
        file_index: get("file-index"),
        raw,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_archives() {
        let data = "archives = abc123 def456 789abc\n";
        let config = parse_cdn_config(data).unwrap();
        assert_eq!(config.archives.len(), 3);
        assert_eq!(config.archives[0], "abc123");
    }

    #[test]
    fn parse_archive_group() {
        let data = "archive-group = deadbeef\n";
        let config = parse_cdn_config(data).unwrap();
        assert_eq!(config.archive_group, "deadbeef");
    }
}
