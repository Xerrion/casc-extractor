//! Listfile download and caching.
//!
//! Downloads the community listfile from the `wowdev/wow-listfile` GitHub
//! release (primary) or the Wago Tools API (fallback), and caches it on disk
//! inside a `.casc-meta/` directory. A cached copy is considered fresh for 24
//! hours before re-downloading.

use std::path::{Path, PathBuf};

use crate::error::Result;

const LISTFILE_URL_PRIMARY: &str =
    "https://github.com/wowdev/wow-listfile/releases/latest/download/community-listfile.csv";
const LISTFILE_URL_FALLBACK: &str = "https://wago.tools/api/casc/listfile";

/// Get the cache path for the listfile inside the output directory.
pub fn cache_path(output_dir: &Path) -> PathBuf {
    output_dir.join(".casc-meta").join("listfile.csv")
}

/// Check if a cached listfile is still fresh (modified less than `max_age` ago).
///
/// Returns `false` when the file does not exist or its metadata cannot be read.
pub fn is_cache_fresh(path: &Path, max_age: std::time::Duration) -> bool {
    let Ok(meta) = std::fs::metadata(path) else {
        return false;
    };
    let Ok(modified) = meta.modified() else {
        return false;
    };
    let Ok(elapsed) = modified.elapsed() else {
        return false;
    };
    elapsed < max_age
}

/// Download the community listfile, trying the primary URL first then the
/// fallback. The file is stored at [`cache_path`] inside `output_dir`.
pub fn download_listfile(output_dir: &Path) -> Result<PathBuf> {
    let dest = cache_path(output_dir);
    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let body = match reqwest::blocking::get(LISTFILE_URL_PRIMARY) {
        Ok(resp) if resp.status().is_success() => resp.text()?,
        _ => {
            tracing::warn!(
                "Primary listfile URL failed, trying fallback: {}",
                LISTFILE_URL_FALLBACK,
            );
            reqwest::blocking::get(LISTFILE_URL_FALLBACK)?.text()?
        }
    };

    std::fs::write(&dest, &body)?;
    tracing::info!("Downloaded listfile to {}", dest.display());
    Ok(dest)
}

/// Load a cached listfile if fresh, otherwise download a new copy.
///
/// The cache is considered fresh for 24 hours.
pub fn load_or_download(output_dir: &Path) -> Result<super::parser::Listfile> {
    let path = cache_path(output_dir);
    let max_age = std::time::Duration::from_secs(24 * 60 * 60);

    if is_cache_fresh(&path, max_age) {
        tracing::info!("Using cached listfile at {}", path.display());
    } else {
        download_listfile(output_dir)?;
    }

    super::parser::Listfile::load(&path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cache_path_construction() {
        let path = cache_path(Path::new("F:\\output"));
        assert_eq!(path, PathBuf::from("F:\\output\\.casc-meta\\listfile.csv"));
    }

    #[test]
    fn cache_not_fresh_when_missing() {
        let path = Path::new("F:\\nonexistent\\file.csv");
        assert!(!is_cache_fresh(path, std::time::Duration::from_secs(86400)));
    }
}
