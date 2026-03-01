//! Extraction metadata recording and statistics.
//!
//! During a bulk extraction, the `MetadataWriter` records per-file results to
//! both JSONL and CSV index files under a `.casc-meta/` directory. When
//! extraction finishes, a `summary.json` with aggregate `ExtractionStats`
//! is written alongside the index files.

use std::fs::{self, File};
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Instant;

use serde::Serialize;

use crate::error::{CascError, Result};

/// A single file extraction result.
#[derive(Debug, Clone, Serialize)]
pub struct MetadataEntry {
    /// FileDataID of the extracted file.
    pub fdid: u32,
    /// Resolved file path from the listfile, or `"unknown/<fdid>.dat"`.
    pub path: String,
    /// Size of the extracted file in bytes (0 on error/skip).
    pub size: u64,
    /// Hex-encoded content key (CKey) for this file.
    pub ckey: String,
    /// Raw locale flags bitmask from the root entry.
    pub locale_flags: u32,
    /// Raw content flags bitmask from the root entry.
    pub content_flags: u32,
    /// Extraction status: `"ok"`, `"error:<reason>"`, or `"skipped:<reason>"`.
    pub status: String,
}

/// Accumulated extraction statistics.
#[derive(Debug, Clone, Serialize)]
pub struct ExtractionStats {
    /// Total number of files processed (success + errors + skipped).
    pub total: u64,
    /// Number of files successfully extracted.
    pub success: u64,
    /// Number of files that failed extraction.
    pub errors: u64,
    /// Number of files skipped (e.g. encrypted files when `skip_encrypted` is set).
    pub skipped: u64,
    /// Total bytes written to disk across all successful extractions.
    pub bytes_written: u64,
}

impl ExtractionStats {
    /// Create a zeroed stats instance.
    pub fn new() -> Self {
        Self {
            total: 0,
            success: 0,
            errors: 0,
            skipped: 0,
            bytes_written: 0,
        }
    }
}

impl Default for ExtractionStats {
    fn default() -> Self {
        Self::new()
    }
}

/// Summary written at the end of extraction.
#[derive(Debug, Serialize)]
pub struct ExtractionSummary {
    /// Build name from the build config.
    pub build: String,
    /// Product identifier (e.g. `"wow"`).
    pub product: String,
    /// ISO 8601 UTC timestamp of when extraction completed.
    pub extracted_at: String,
    /// Wall-clock duration of the extraction in seconds.
    pub duration_secs: f64,
    /// Aggregate extraction statistics.
    pub stats: ExtractionStats,
}

/// Thread-safe metadata writer that records extraction results to JSONL and CSV
/// files, and tracks statistics.
pub struct MetadataWriter {
    jsonl_writer: Mutex<BufWriter<File>>,
    csv_writer: Mutex<csv::Writer<File>>,
    stats: Mutex<ExtractionStats>,
    meta_dir: PathBuf,
    build_name: String,
    product: String,
    start_time: Instant,
}

impl MetadataWriter {
    /// Create a new writer, creating the `.casc-meta/` directory and opening
    /// index files. Writes the CSV header row.
    pub fn new(output_dir: &Path, build_name: &str, product: &str) -> Result<Self> {
        let meta_dir = output_dir.join(".casc-meta");
        fs::create_dir_all(&meta_dir)?;

        let jsonl_file = File::create(meta_dir.join("index.jsonl"))?;
        let csv_file = File::create(meta_dir.join("index.csv"))?;

        let jsonl_writer = BufWriter::new(jsonl_file);
        let mut csv_writer = csv::Writer::from_writer(csv_file);

        // Write CSV header
        csv_writer
            .write_record([
                "fdid",
                "path",
                "size",
                "ckey",
                "locale_flags",
                "content_flags",
                "status",
            ])
            .map_err(|e| CascError::Io(std::io::Error::other(e)))?;

        Ok(Self {
            jsonl_writer: Mutex::new(jsonl_writer),
            csv_writer: Mutex::new(csv_writer),
            stats: Mutex::new(ExtractionStats::new()),
            meta_dir,
            build_name: build_name.to_owned(),
            product: product.to_owned(),
            start_time: Instant::now(),
        })
    }

    /// Record a single extraction result. Thread-safe.
    pub fn record(&self, entry: &MetadataEntry) -> Result<()> {
        // Write JSONL line
        {
            let json_line = serde_json::to_string(entry)
                .map_err(|e| CascError::Io(std::io::Error::other(e)))?;
            let mut writer = self.jsonl_writer.lock().unwrap();
            writeln!(writer, "{json_line}")?;
        }

        // Write CSV row
        {
            let mut writer = self.csv_writer.lock().unwrap();
            writer
                .write_record(&[
                    entry.fdid.to_string(),
                    entry.path.clone(),
                    entry.size.to_string(),
                    entry.ckey.clone(),
                    entry.locale_flags.to_string(),
                    entry.content_flags.to_string(),
                    entry.status.clone(),
                ])
                .map_err(|e| CascError::Io(std::io::Error::other(e)))?;
        }

        // Update stats
        {
            let mut stats = self.stats.lock().unwrap();
            stats.total += 1;
            if entry.status == "ok" {
                stats.success += 1;
                stats.bytes_written += entry.size;
            } else if entry.status.starts_with("error") {
                stats.errors += 1;
            } else if entry.status.starts_with("skipped") {
                stats.skipped += 1;
            }
        }

        Ok(())
    }

    /// Get a snapshot of the current stats.
    pub fn stats(&self) -> ExtractionStats {
        self.stats.lock().unwrap().clone()
    }

    /// Finalize: flush files and write `summary.json`.
    pub fn finish(self) -> Result<ExtractionStats> {
        let duration = self.start_time.elapsed();

        // Flush JSONL writer
        {
            let mut writer = self.jsonl_writer.lock().unwrap();
            writer.flush()?;
        }

        // Flush CSV writer
        {
            let mut writer = self.csv_writer.lock().unwrap();
            writer
                .flush()
                .map_err(|e| CascError::Io(std::io::Error::other(e)))?;
        }

        let stats = self.stats.lock().unwrap().clone();

        // Write summary.json
        let summary = ExtractionSummary {
            build: self.build_name.clone(),
            product: self.product.clone(),
            extracted_at: now_iso8601(),
            duration_secs: duration.as_secs_f64(),
            stats: stats.clone(),
        };

        let summary_path = self.meta_dir.join("summary.json");
        let summary_file = File::create(summary_path)?;
        serde_json::to_writer_pretty(BufWriter::new(summary_file), &summary)
            .map_err(|e| CascError::Io(std::io::Error::other(e)))?;

        Ok(stats)
    }
}

/// Produce an ISO 8601 timestamp without pulling in the `chrono` crate.
fn now_iso8601() -> String {
    // Use SystemTime to produce a basic UTC timestamp.
    use std::time::SystemTime;
    let dur = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = dur.as_secs();

    // Break epoch seconds into date/time components (UTC).
    let days = secs / 86400;
    let time_of_day = secs % 86400;
    let hours = time_of_day / 3600;
    let minutes = (time_of_day % 3600) / 60;
    let seconds = time_of_day % 60;

    // Convert days since epoch to y/m/d using a civil calendar algorithm.
    let (year, month, day) = days_to_ymd(days as i64);

    format!("{year:04}-{month:02}-{day:02}T{hours:02}:{minutes:02}:{seconds:02}Z")
}

/// Convert days since Unix epoch to (year, month, day) using Howard Hinnant's
/// civil_from_days algorithm.
fn days_to_ymd(days: i64) -> (i64, u32, u32) {
    let z = days + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u32;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join("casc_metadata_test").join(name);
        if dir.exists() {
            fs::remove_dir_all(&dir).ok();
        }
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn sample_entry(fdid: u32, status: &str) -> MetadataEntry {
        MetadataEntry {
            fdid,
            path: format!("test/file_{fdid}.dat"),
            size: 1024,
            ckey: "abcdef1234567890abcdef1234567890".into(),
            locale_flags: 0x2,
            content_flags: 0x0,
            status: status.into(),
        }
    }

    #[test]
    fn creates_meta_directory() {
        let dir = temp_dir("creates_meta_dir");
        let writer = MetadataWriter::new(&dir, "test-build", "wow").unwrap();
        assert!(dir.join(".casc-meta").exists());
        assert!(dir.join(".casc-meta/index.jsonl").exists());
        assert!(dir.join(".casc-meta/index.csv").exists());
        drop(writer);
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn record_writes_jsonl_line() {
        let dir = temp_dir("jsonl_line");
        let writer = MetadataWriter::new(&dir, "test-build", "wow").unwrap();
        writer.record(&sample_entry(100, "ok")).unwrap();
        writer.finish().unwrap();

        let content = fs::read_to_string(dir.join(".casc-meta/index.jsonl")).unwrap();
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines.len(), 1);
        let parsed: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(parsed["fdid"], 100);
        assert_eq!(parsed["status"], "ok");
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn record_writes_csv_row() {
        let dir = temp_dir("csv_row");
        let writer = MetadataWriter::new(&dir, "test-build", "wow").unwrap();
        writer.record(&sample_entry(200, "ok")).unwrap();
        writer.finish().unwrap();

        let content = fs::read_to_string(dir.join(".casc-meta/index.csv")).unwrap();
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines.len(), 2); // header + 1 data row
        assert!(lines[0].starts_with("fdid,"));
        assert!(lines[1].starts_with("200,"));
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn stats_tracks_success_and_errors() {
        let dir = temp_dir("stats_tracking");
        let writer = MetadataWriter::new(&dir, "test-build", "wow").unwrap();
        writer.record(&sample_entry(1, "ok")).unwrap();
        writer.record(&sample_entry(2, "ok")).unwrap();
        writer
            .record(&sample_entry(3, "error:corrupt BLTE"))
            .unwrap();
        writer
            .record(&sample_entry(4, "skipped:encrypted"))
            .unwrap();

        let stats = writer.stats();
        assert_eq!(stats.total, 4);
        assert_eq!(stats.success, 2);
        assert_eq!(stats.errors, 1);
        assert_eq!(stats.skipped, 1);
        assert_eq!(stats.bytes_written, 2048); // 2 successful * 1024

        writer.finish().unwrap();
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn finish_writes_summary_json() {
        let dir = temp_dir("summary_json");
        let writer = MetadataWriter::new(&dir, "my-build-123", "wow").unwrap();
        writer.record(&sample_entry(1, "ok")).unwrap();
        let stats = writer.finish().unwrap();

        assert_eq!(stats.success, 1);

        let summary_path = dir.join(".casc-meta/summary.json");
        assert!(summary_path.exists());
        let content = fs::read_to_string(&summary_path).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&content).unwrap();
        assert_eq!(parsed["build"], "my-build-123");
        assert_eq!(parsed["product"], "wow");
        assert!(!parsed["extracted_at"].as_str().unwrap().is_empty());
        assert!(parsed["duration_secs"].as_f64().unwrap() >= 0.0);
        assert_eq!(parsed["stats"]["success"], 1);
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn multiple_records_accumulate() {
        let dir = temp_dir("accumulate");
        let writer = MetadataWriter::new(&dir, "build", "wow").unwrap();
        for i in 0..50 {
            writer.record(&sample_entry(i, "ok")).unwrap();
        }
        let stats = writer.finish().unwrap();
        assert_eq!(stats.total, 50);
        assert_eq!(stats.success, 50);

        let content = fs::read_to_string(dir.join(".casc-meta/index.jsonl")).unwrap();
        assert_eq!(content.lines().count(), 50);
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn entry_serialization_round_trip() {
        let entry = sample_entry(42, "ok");
        let json = serde_json::to_string(&entry).unwrap();
        let back: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(back["fdid"], 42);
        assert_eq!(back["path"], "test/file_42.dat");
    }
}
