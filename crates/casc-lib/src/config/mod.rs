//! CASC configuration file parsers.
//!
//! These modules parse the three config layers that describe a CASC installation:
//! `.build.info` (product discovery), build config (key hashes and sizes), and
//! CDN config (archive lists and index URLs).

/// Build config parser - encoding/root/install key pairs and sizes.
pub mod build_config;
/// `.build.info` BPSV file parser - product discovery and CDN host selection.
pub mod build_info;
/// CDN config parser - archive hash lists and file index references.
pub mod cdn_config;
