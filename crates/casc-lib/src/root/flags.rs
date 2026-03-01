//! Locale and content flag bitmask types.
//!
//! Root file entries carry a pair of bitmasks - `LocaleFlags` and
//! `ContentFlags` - that describe which client locale and platform
//! configuration an entry applies to. During extraction the locale filter is
//! compared against each entry's flags to select the correct variant.

use std::fmt;

/// Locale flag constants (bitmask).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LocaleFlags(pub u32);

impl LocaleFlags {
    /// No locale selected (acts as "no filter" in [`matches`](Self::matches)).
    pub const NONE: Self = Self(0);
    /// English (United States).
    pub const EN_US: Self = Self(0x2);
    /// Korean (South Korea).
    pub const KO_KR: Self = Self(0x4);
    /// French (France).
    pub const FR_FR: Self = Self(0x10);
    /// German (Germany).
    pub const DE_DE: Self = Self(0x20);
    /// Chinese (Simplified, China).
    pub const ZH_CN: Self = Self(0x40);
    /// Spanish (Spain).
    pub const ES_ES: Self = Self(0x80);
    /// Chinese (Traditional, Taiwan).
    pub const ZH_TW: Self = Self(0x100);
    /// English (Great Britain).
    pub const EN_GB: Self = Self(0x200);
    /// English (China region).
    pub const EN_CN: Self = Self(0x400);
    /// English (Taiwan region).
    pub const EN_TW: Self = Self(0x800);
    /// Spanish (Mexico / Latin America).
    pub const ES_MX: Self = Self(0x1000);
    /// Russian (Russia).
    pub const RU_RU: Self = Self(0x2000);
    /// Portuguese (Brazil).
    pub const PT_BR: Self = Self(0x4000);
    /// Italian (Italy).
    pub const IT_IT: Self = Self(0x8000);
    /// Portuguese (Portugal).
    pub const PT_PT: Self = Self(0x10000);
    /// All locale bits set - matches every locale.
    pub const ALL: Self = Self(0xFFFFFFFF);

    /// Returns true if any of the bits in `other` are set in `self`.
    pub fn contains(self, other: Self) -> bool {
        (self.0 & other.0) != 0
    }

    /// Returns true if this locale matches the given filter.
    /// A zero/NONE filter means "no filter" and matches everything.
    /// ALL (0xFFFFFFFF) also matches everything.
    pub fn matches(self, filter: Self) -> bool {
        filter.0 == 0 || (self.0 & filter.0) != 0
    }
}

impl fmt::Display for LocaleFlags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.0 == 0 {
            return write!(f, "None");
        }
        if self.0 == 0xFFFFFFFF {
            return write!(f, "All");
        }

        const NAMES: &[(u32, &str)] = &[
            (0x2, "enUS"),
            (0x4, "koKR"),
            (0x10, "frFR"),
            (0x20, "deDE"),
            (0x40, "zhCN"),
            (0x80, "esES"),
            (0x100, "zhTW"),
            (0x200, "enGB"),
            (0x400, "enCN"),
            (0x800, "enTW"),
            (0x1000, "esMX"),
            (0x2000, "ruRU"),
            (0x4000, "ptBR"),
            (0x8000, "itIT"),
            (0x10000, "ptPT"),
        ];

        let mut first = true;
        for &(bit, name) in NAMES {
            if (self.0 & bit) != 0 {
                if !first {
                    write!(f, "|")?;
                }
                write!(f, "{}", name)?;
                first = false;
            }
        }
        if first {
            write!(f, "0x{:X}", self.0)?;
        }
        Ok(())
    }
}

/// Content flag constants (bitmask).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ContentFlags(pub u32);

impl ContentFlags {
    /// No content flags set.
    pub const NONE: Self = Self(0);
    /// High-resolution texture variant.
    pub const HIGH_RES_TEXTURE: Self = Self(0x1);
    /// File is part of the install manifest.
    pub const INSTALL: Self = Self(0x4);
    /// Load this file on Windows clients.
    pub const LOAD_ON_WINDOWS: Self = Self(0x8);
    /// Load this file on macOS clients.
    pub const LOAD_ON_MACOS: Self = Self(0x10);
    /// 32-bit x86 binary.
    pub const X86_32: Self = Self(0x20);
    /// 64-bit x86 binary.
    pub const X86_64: Self = Self(0x40);
    /// Low-violence regional variant.
    pub const LOW_VIOLENCE: Self = Self(0x80);
    /// Do not load this file during normal operation.
    pub const DO_NOT_LOAD: Self = Self(0x100);
    /// File belongs to the update plugin.
    pub const UPDATE_PLUGIN: Self = Self(0x800);
    /// ARM64 binary.
    pub const ARM64: Self = Self(0x8000);
    /// File data is encrypted with a TACT key.
    pub const ENCRYPTED: Self = Self(0x8000000);
    /// Block does not contain name hashes (FDID-only entries).
    pub const NO_NAME_HASH: Self = Self(0x10000000);
    /// Uncommon resolution texture variant.
    pub const UNCOMMON_RES: Self = Self(0x20000000);
    /// File is part of a bundle.
    pub const BUNDLE: Self = Self(0x40000000);
    /// File data is stored without compression.
    pub const NO_COMPRESSION: Self = Self(0x80000000);

    /// Returns true if the given flag bit(s) are set.
    pub fn has(self, flag: Self) -> bool {
        (self.0 & flag.0) != 0
    }

    /// Convenience: checks if the NoNameHash flag is set.
    pub fn has_no_name_hash(self) -> bool {
        self.has(Self::NO_NAME_HASH)
    }
}

impl fmt::Display for ContentFlags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.0 == 0 {
            return write!(f, "None");
        }

        const NAMES: &[(u32, &str)] = &[
            (0x1, "HighResTexture"),
            (0x4, "Install"),
            (0x8, "LoadOnWindows"),
            (0x10, "LoadOnMacOS"),
            (0x20, "x86_32"),
            (0x40, "x86_64"),
            (0x80, "LowViolence"),
            (0x100, "DoNotLoad"),
            (0x800, "UpdatePlugin"),
            (0x8000, "ARM64"),
            (0x8000000, "Encrypted"),
            (0x10000000, "NoNameHash"),
            (0x20000000, "UncommonRes"),
            (0x40000000, "Bundle"),
            (0x80000000, "NoCompression"),
        ];

        let mut first = true;
        for &(bit, name) in NAMES {
            if (self.0 & bit) != 0 {
                if !first {
                    write!(f, "|")?;
                }
                write!(f, "{}", name)?;
                first = false;
            }
        }
        if first {
            write!(f, "0x{:X}", self.0)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn locale_enus() {
        assert_eq!(LocaleFlags::EN_US.0, 0x2);
    }

    #[test]
    fn locale_dede() {
        assert_eq!(LocaleFlags::DE_DE.0, 0x20);
    }

    #[test]
    fn locale_contains() {
        let flags = LocaleFlags(0x2 | 0x200); // enUS + enGB
        assert!(flags.contains(LocaleFlags::EN_US));
        assert!(flags.contains(LocaleFlags::EN_GB));
        assert!(!flags.contains(LocaleFlags::DE_DE));
    }

    #[test]
    fn locale_matches_filter() {
        let flags = LocaleFlags(0x2); // enUS
        assert!(flags.matches(LocaleFlags::EN_US));
        assert!(!flags.matches(LocaleFlags::DE_DE));
        assert!(flags.matches(LocaleFlags::ALL)); // ALL matches everything
    }

    #[test]
    fn locale_matches_none_filter() {
        // A NONE filter (0) means "no filter applied" - matches everything
        let flags = LocaleFlags(0x2);
        assert!(flags.matches(LocaleFlags::NONE));
    }

    #[test]
    fn content_no_name_hash() {
        let flags = ContentFlags(0x10000000);
        assert!(flags.has_no_name_hash());
    }

    #[test]
    fn content_flags_combined() {
        let flags = ContentFlags(0x8 | 0x40); // Windows + x86_64
        assert!(flags.has(ContentFlags::LOAD_ON_WINDOWS));
        assert!(flags.has(ContentFlags::X86_64));
        assert!(!flags.has(ContentFlags::LOAD_ON_MACOS));
    }

    #[test]
    fn content_flags_none_has_nothing() {
        let flags = ContentFlags::NONE;
        assert!(!flags.has(ContentFlags::LOAD_ON_WINDOWS));
        assert!(!flags.has_no_name_hash());
    }

    #[test]
    fn locale_display_single() {
        assert_eq!(format!("{}", LocaleFlags::EN_US), "enUS");
    }

    #[test]
    fn locale_display_combined() {
        let flags = LocaleFlags(0x2 | 0x20); // enUS + deDE
        assert_eq!(format!("{}", flags), "enUS|deDE");
    }

    #[test]
    fn locale_display_none() {
        assert_eq!(format!("{}", LocaleFlags::NONE), "None");
    }

    #[test]
    fn locale_display_all() {
        assert_eq!(format!("{}", LocaleFlags::ALL), "All");
    }

    #[test]
    fn content_display_single() {
        assert_eq!(
            format!("{}", ContentFlags::LOAD_ON_WINDOWS),
            "LoadOnWindows"
        );
    }

    #[test]
    fn content_display_combined() {
        let flags = ContentFlags(0x8 | 0x10000000); // Windows + NoNameHash
        assert_eq!(format!("{}", flags), "LoadOnWindows|NoNameHash");
    }

    #[test]
    fn content_display_none() {
        assert_eq!(format!("{}", ContentFlags::NONE), "None");
    }
}
