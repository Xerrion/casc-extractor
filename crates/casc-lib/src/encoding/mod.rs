//! Encoding file parser.
//!
//! The encoding file is the central lookup table that maps content keys (CKeys)
//! to encoding keys (EKeys). Given a CKey (from the root file), the encoding
//! table provides the EKey(s) needed to locate the data in the archive index.

/// Encoding file binary parser and CKey-to-EKey lookup.
pub mod parser;
