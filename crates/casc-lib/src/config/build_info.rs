//! Parser for the `.build.info` file found at the root of a WoW installation.
//!
//! `.build.info` uses a BPSV (Bar-Pipe Separated Values) format where the first
//! line declares column names with type annotations (e.g. `Name!TYPE:SIZE`) and
//! subsequent lines contain pipe-delimited data rows - one per installed product.

use std::collections::HashMap;

use crate::error::{CascError, Result};

/// A single entry from the `.build.info` BPSV file.
///
/// Each row represents one installed product (e.g. `wow`, `wow_classic`).
/// The [`build_key`](BuildInfo::build_key) and [`cdn_key`](BuildInfo::cdn_key)
/// are hex hashes used to locate the build config and CDN config files.
#[derive(Debug, Clone)]
pub struct BuildInfo {
    /// Branch name (e.g. `"eu"`, `"us"`).
    pub branch: String,
    /// Whether this entry is the currently active build.
    pub active: bool,
    /// Hex hash of the build configuration file.
    pub build_key: String,
    /// Hex hash of the CDN configuration file.
    pub cdn_key: String,
    /// CDN path prefix (e.g. `"tpr/wow"`).
    pub cdn_path: String,
    /// CDN host names for downloading remote data.
    pub cdn_hosts: Vec<String>,
    /// Build version string (e.g. `"12.0.1.66192"`).
    pub version: String,
    /// Product code (e.g. `"wow"`, `"wow_classic"`).
    pub product: String,
    /// Tags string containing locale, region, and speech options.
    pub tags: String,
    /// Hex hash of the keyring used for encrypted content.
    pub keyring: String,
}

/// Returns all available products and their versions from parsed build info entries.
pub fn list_products(entries: &[BuildInfo]) -> Vec<(&str, &str)> {
    entries
        .iter()
        .map(|e| (e.product.as_str(), e.version.as_str()))
        .collect()
}

/// Parse a `.build.info` BPSV (Bar-Pipe Separated Values) file.
///
/// The first line contains column definitions like `Name!TYPE:SIZE|...`.
/// Subsequent lines are pipe-delimited data rows.
pub fn parse_build_info(content: &str) -> Result<Vec<BuildInfo>> {
    let mut lines = content.lines();

    let header = lines
        .next()
        .ok_or_else(|| CascError::InvalidFormat("empty .build.info".into()))?;

    // Parse column names from header (strip the `!TYPE:SIZE` suffix from each)
    let columns: Vec<&str> = header
        .split('|')
        .map(|col| col.split('!').next().unwrap_or(col))
        .collect();

    // Build a name -> index lookup
    let index: HashMap<&str, usize> = columns
        .iter()
        .enumerate()
        .map(|(i, &name)| (name, i))
        .collect();

    let get = |row: &[&str], key: &str| -> String {
        index
            .get(key)
            .and_then(|&i| row.get(i))
            .map(|s| s.to_string())
            .unwrap_or_default()
    };

    let mut entries = Vec::new();

    for line in lines {
        if line.trim().is_empty() {
            continue;
        }

        let fields: Vec<&str> = line.split('|').collect();

        let active_str = get(&fields, "Active");
        let active = active_str == "1";

        let cdn_hosts_raw = get(&fields, "CDN Hosts");
        let cdn_hosts: Vec<String> = if cdn_hosts_raw.is_empty() {
            Vec::new()
        } else {
            cdn_hosts_raw.split(' ').map(String::from).collect()
        };

        entries.push(BuildInfo {
            branch: get(&fields, "Branch"),
            active,
            build_key: get(&fields, "Build Key"),
            cdn_key: get(&fields, "CDN Key"),
            cdn_path: get(&fields, "CDN Path"),
            cdn_hosts,
            version: get(&fields, "Version"),
            product: get(&fields, "Product"),
            tags: get(&fields, "Tags"),
            keyring: get(&fields, "KeyRing"),
        });
    }

    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE: &str = "Branch!STRING:0|Active!DEC:1|Build Key!HEX:16|CDN Key!HEX:16|Install Key!HEX:16|IM Size!DEC:4|CDN Path!STRING:0|CDN Hosts!STRING:0|CDN Servers!STRING:0|Tags!STRING:0|Armadillo!STRING:0|Last Activated!STRING:0|Version!STRING:0|KeyRing!HEX:16|Product!STRING:0\neu|1|13e1eb56839dfaf734d7fab21b0c8ea4|36b8057b5cb2175a551325240251f1c0|||tpr/wow|level3.blizzard.com blzddist1-a.akamaihd.net eu.cdn.blizzard.com|blizzard cdn|Windows?enUS?EU?speechoptions=enUS,enGB,deDE,esES,esMX,frFR,itIT,ptBR,ruRU,koKR,zhTW,zhCN|316c4a8ec31d3948a0e3ad5bd6be86f8||12.0.1.66192|3ca57fe7319a297346440e4d2a03a0cd|wow\neu|1|df2221c87fa81a64523f02a0b31d9586|36b8057b5cb2175a551325240251f1c0|||tpr/wow|level3.blizzard.com blzddist1-a.akamaihd.net eu.cdn.blizzard.com|blizzard cdn|Windows?enUS?EU?speechoptions=enUS,enGB,deDE,esES,esMX,frFR,itIT,koKR,ptBR,ruRU,zhCN,zhTW|||||wow_anniversary";

    #[test]
    fn parse_two_products() {
        let infos = parse_build_info(FIXTURE).unwrap();
        assert_eq!(infos.len(), 2);
    }

    #[test]
    fn parse_retail_product() {
        let infos = parse_build_info(FIXTURE).unwrap();
        let retail = infos.iter().find(|i| i.product == "wow").unwrap();
        assert_eq!(retail.build_key, "13e1eb56839dfaf734d7fab21b0c8ea4");
        assert_eq!(retail.cdn_key, "36b8057b5cb2175a551325240251f1c0");
        assert_eq!(retail.version, "12.0.1.66192");
        assert!(retail.active);
    }

    #[test]
    fn parse_anniversary_product() {
        let infos = parse_build_info(FIXTURE).unwrap();
        let anni = infos
            .iter()
            .find(|i| i.product == "wow_anniversary")
            .unwrap();
        assert_eq!(anni.build_key, "df2221c87fa81a64523f02a0b31d9586");
        assert_eq!(anni.version, ""); // anniversary has no version in this data
        assert!(anni.active);
    }

    #[test]
    fn parse_inactive_filtered() {
        let data =
            "Branch!STRING:0|Active!DEC:1|Build Key!HEX:16|Product!STRING:0\neu|0|abc|test_product";
        let infos = parse_build_info(data).unwrap();
        assert!(!infos.iter().all(|i| i.active)); // inactive should still be parsed but marked
        let inactive = infos.iter().find(|i| i.product == "test_product").unwrap();
        assert!(!inactive.active);
    }

    #[test]
    fn parse_empty_returns_empty() {
        let data = "Branch!STRING:0|Active!DEC:1|Build Key!HEX:16|Product!STRING:0\n";
        let infos = parse_build_info(data).unwrap();
        assert!(infos.is_empty());
    }

    #[test]
    fn list_products_returns_all() {
        let infos = parse_build_info(FIXTURE).unwrap();
        let products = list_products(&infos);
        assert_eq!(products.len(), 2);
        assert_eq!(products[0].0, "wow");
        assert_eq!(products[0].1, "12.0.1.66192");
        assert_eq!(products[1].0, "wow_anniversary");
        assert_eq!(products[1].1, "");
    }

    #[test]
    fn list_products_empty_entries() {
        let products = list_products(&[]);
        assert!(products.is_empty());
    }
}
