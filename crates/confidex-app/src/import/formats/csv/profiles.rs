//! Suggest profiles only for verified, exact source headers.
use super::Header;
use crate::import::{CsvColumn, CsvMapping, Error, ErrorKind};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Profile {
    Chromium,
    Firefox,
    ApplePasswords,
}
const CHROMIUM: &[&str] = &["name", "url", "username", "password", "note"];
const CHROMIUM_OLD: &[&str] = &["name", "url", "username", "password"];
const FIREFOX: &[&str] = &[
    "url",
    "username",
    "password",
    "httpRealm",
    "formActionOrigin",
    "guid",
    "timeCreated",
    "timeLastUsed",
    "timePasswordChanged",
];
const APPLE: &[&str] = &["Title", "URL", "Username", "Password", "Notes", "OTPAuth"];
const APPLE_OLD: &[&str] = &["Title", "Url", "Username", "Password"];
impl Profile {
    /// Current verified header order. Import also accepts the documented older shapes.
    pub fn headings(self) -> &'static [&'static str] {
        match self {
            Self::Chromium => CHROMIUM,
            Self::Firefox => FIREFOX,
            Self::ApplePasswords => APPLE,
        }
    }
    pub(super) fn target(self, index: usize) -> &'static str {
        match (self, index) {
            (Self::Chromium | Self::ApplePasswords, 0) => "title",
            (Self::Chromium | Self::ApplePasswords, 1) | (Self::Firefox, 0) => "url/v1",
            (Self::Chromium | Self::ApplePasswords, 2) | (Self::Firefox, 1) => "username/v1",
            (Self::Chromium | Self::ApplePasswords, 3) | (Self::Firefox, 2) => "password/v1",
            (Self::Chromium | Self::ApplePasswords, 4) => "secure-note/v1",
            (Self::ApplePasswords, 5) => "totp/v1",
            _ => "secret/v1",
        }
    }
    pub fn id(self) -> &'static str {
        match self {
            Self::Chromium => "chromium",
            Self::Firefox => "firefox",
            Self::ApplePasswords => "apple-passwords",
        }
    }
    fn matches(self, header: &Header) -> bool {
        let same = |names: &[&str]| {
            header.names.len() == names.len()
                && header
                    .names
                    .iter()
                    .zip(names)
                    .all(|(a, b)| a.as_str() == *b)
        };
        match self {
            Self::Chromium => same(CHROMIUM) || same(CHROMIUM_OLD),
            Self::Firefox => same(FIREFOX),
            Self::ApplePasswords => same(APPLE) || same(APPLE_OLD),
        }
    }
    pub fn mapping(self, header: &Header) -> Result<CsvMapping, Error> {
        if !self.matches(header) || header.delimiter != b',' {
            return Err(ErrorKind::InvalidOptions.into());
        }
        let columns = header
            .names
            .iter()
            .enumerate()
            .map(|(index, name)| {
                let target = self.target(index);
                CsvColumn {
                    index,
                    target: target.into(),
                    name: name.as_str().into(),
                }
            })
            .collect();
        Ok(CsvMapping {
            delimiter: b',',
            header: true,
            columns,
        })
    }
}
impl Header {
    pub fn profiles(&self) -> Vec<Profile> {
        if self.delimiter != b',' {
            return Vec::new();
        }
        [Profile::Chromium, Profile::Firefox, Profile::ApplePasswords]
            .into_iter()
            .filter(|profile| profile.matches(self))
            .collect()
    }
    /// Keep unknown columns private until the user assigns their meanings.
    pub fn private_mapping(&self) -> CsvMapping {
        CsvMapping {
            delimiter: self.delimiter,
            header: true,
            columns: self
                .names
                .iter()
                .enumerate()
                .map(|(index, name)| CsvColumn {
                    index,
                    target: "secret/v1".into(),
                    name: name.as_str().into(),
                })
                .collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::import::Limits;
    fn header(value: &str) -> Header {
        super::super::header(value.as_bytes(), b',', Limits::default(), &mut |_| true).unwrap()
    }
    #[test]
    fn exact_profiles_keep_positions_and_default_notes_to_private() {
        for (names, profile) in [
            (CHROMIUM, Profile::Chromium),
            (CHROMIUM_OLD, Profile::Chromium),
            (FIREFOX, Profile::Firefox),
            (APPLE, Profile::ApplePasswords),
            (APPLE_OLD, Profile::ApplePasswords),
        ] {
            let input = header(&names.join(","));
            assert_eq!(input.profiles(), [profile]);
            let mapping = profile.mapping(&input).unwrap();
            assert_eq!(mapping.columns.len(), names.len());
            for (index, column) in mapping.columns.iter().enumerate() {
                assert_eq!(column.index, index);
                assert_eq!(column.name, names[index]);
                if matches!(column.name.as_str(), "note" | "Notes") {
                    assert_eq!(column.target, "secure-note/v1");
                }
            }
        }
    }
    #[test]
    fn reordered_repeated_unknown_headers_require_manual_mapping() {
        for names in [
            "url,name,username,password,note",
            "name,url,username,password,note,unknown",
            "name,url,username,password,password",
            "Name,Url,Username,Password,Note",
            "extra,extra,,password",
        ] {
            let input = header(names);
            assert!(input.profiles().is_empty());
            assert!(Profile::Chromium.mapping(&input).is_err());
            let mapping = input.private_mapping();
            assert!(mapping.columns.iter().all(|c| c.target == "secret/v1"));
            assert_eq!(
                mapping
                    .columns
                    .iter()
                    .map(|c| c.name.as_str())
                    .collect::<Vec<_>>(),
                names.split(',').collect::<Vec<_>>()
            );
        }
        let input = super::super::header(
            b"name;url;username;password;note",
            b';',
            Limits::default(),
            &mut |_| true,
        )
        .unwrap();
        assert!(input.profiles().is_empty());
        assert_eq!(input.private_mapping().delimiter, b';');
    }
}
