//! Parser for CASC build configuration files.
//!
//! The build config is a `key = value` text file (with `#` comment lines) identified
//! by the `build_key` hash from `.build.info`.
//! It contains the root CKey, encoding CKey/EKey pair, install and download keys,
//! and build metadata.

use std::collections::HashMap;

use crate::error::Result;

/// Parsed build configuration from a CASC build config file.
///
/// Fields like `encoding` and `install` contain two space-separated hashes
/// (content key, then encoding key). Sizes are space-separated integers.
#[derive(Debug, Clone)]
pub struct BuildConfig {
    /// Content key (CKey) of the root file.
    pub root_ckey: String,
    /// Content key (CKey) of the encoding file.
    pub encoding_ckey: String,
    /// Encoding key (EKey) of the encoding file.
    pub encoding_ekey: String,
    /// Encoding file sizes (content size and encoded size).
    pub encoding_size: Vec<u64>,
    /// Content key (CKey) of the install file.
    pub install_ckey: String,
    /// Encoding key (EKey) of the install file.
    pub install_ekey: String,
    /// Content key (CKey) of the download file.
    pub download_ckey: String,
    /// Encoding key (EKey) of the download file.
    pub download_ekey: String,
    /// Human-readable build name (e.g. `"WOW-66192patch12.0.1_Retail"`).
    pub build_name: String,
    /// Build UID used for product identification (e.g. `"wow"`).
    pub build_uid: String,
    /// Build product name (e.g. `"WoW"`).
    pub build_product: String,
    /// Raw key-value store for all fields (including vfs-*, patch-*, etc.)
    pub raw: HashMap<String, String>,
}

/// Parse a CASC build config (key = value format, `#` comments).
pub fn parse_build_config(content: &str) -> Result<BuildConfig> {
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

    let split_pair = |key: &str| -> (String, String) {
        let val = get(key);
        let mut parts = val.splitn(2, ' ');
        let first = parts.next().unwrap_or("").to_string();
        let second = parts.next().unwrap_or("").to_string();
        (first, second)
    };

    let parse_sizes = |key: &str| -> Vec<u64> {
        let val = get(key);
        if val.is_empty() {
            return Vec::new();
        }
        val.split(' ')
            .filter_map(|s| s.parse::<u64>().ok())
            .collect()
    };

    let (encoding_ckey, encoding_ekey) = split_pair("encoding");
    let (install_ckey, install_ekey) = split_pair("install");
    let (download_ckey, download_ekey) = split_pair("download");

    Ok(BuildConfig {
        root_ckey: get("root"),
        encoding_ckey,
        encoding_ekey,
        encoding_size: parse_sizes("encoding-size"),
        install_ckey,
        install_ekey,
        download_ckey,
        download_ekey,
        build_name: get("build-name"),
        build_uid: get("build-uid"),
        build_product: get("build-product"),
        raw,
    })
}

/// Convert a config hash to a CDN-style file path.
///
/// `"13e1eb56..."` becomes `"config/13/e1/13e1eb56..."`
pub fn config_path(hash: &str) -> String {
    format!("config/{}/{}/{}", &hash[..2], &hash[2..4], hash)
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE: &str = "# Build Configuration\nroot = 0ff1247849a5cd6049624d3a105811f8\ninstall = a33a459aa7585d626a3e4209858b4eed a9f3ece675323e1bbd2c17a765adc3c4\ninstall-size = 23286 22368\ndownload = 108fa2da5f5337d8eb4e35e0d3573925 697b5503715187be840f15ee5862adf4\ndownload-size = 72504201 61674341\nencoding = d2f601fe389b9a1133709e716899a633 d3e25753d9f33b6ab55c56532e2131cc\nencoding-size = 194221474 182793061\nbuild-name = WOW-66192patch12.0.1_Retail\nbuild-uid = wow\nbuild-product = WoW\n";

    #[test]
    fn parse_root_ckey() {
        let config = parse_build_config(FIXTURE).unwrap();
        assert_eq!(config.root_ckey, "0ff1247849a5cd6049624d3a105811f8");
    }

    #[test]
    fn parse_encoding_pair() {
        let config = parse_build_config(FIXTURE).unwrap();
        assert_eq!(config.encoding_ckey, "d2f601fe389b9a1133709e716899a633");
        assert_eq!(config.encoding_ekey, "d3e25753d9f33b6ab55c56532e2131cc");
    }

    #[test]
    fn parse_encoding_sizes() {
        let config = parse_build_config(FIXTURE).unwrap();
        assert_eq!(config.encoding_size, vec![194221474, 182793061]);
    }

    #[test]
    fn parse_build_name() {
        let config = parse_build_config(FIXTURE).unwrap();
        assert_eq!(config.build_name, "WOW-66192patch12.0.1_Retail");
    }

    #[test]
    fn parse_build_uid() {
        let config = parse_build_config(FIXTURE).unwrap();
        assert_eq!(config.build_uid, "wow");
    }

    #[test]
    fn parse_skips_comments() {
        let data = "# comment\nroot = abc123\n";
        let config = parse_build_config(data).unwrap();
        assert_eq!(config.root_ckey, "abc123");
    }

    #[test]
    fn parse_skips_empty_lines() {
        let data = "\n\nroot = abc123\n\n";
        let config = parse_build_config(data).unwrap();
        assert_eq!(config.root_ckey, "abc123");
    }

    #[test]
    fn config_path_from_hash() {
        let path = config_path("13e1eb56839dfaf734d7fab21b0c8ea4");
        assert_eq!(path, "config/13/e1/13e1eb56839dfaf734d7fab21b0c8ea4");
    }
}
