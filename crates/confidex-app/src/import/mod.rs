//! Vendor import builds a bounded plan. Only the application can apply it.
use confidex_vault::record::Mapping;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;
pub mod archive;
pub mod control;
pub mod formats;
mod inspect;
pub mod json;
mod limits;
mod plan;
pub mod totp;
pub use control::{Control, Phase, Progress};
pub use inspect::{Inspection, inspect};
pub use limits::{Limits, Memory, Reservation};
pub use plan::{Attributes, Context, Item, Plan, PlannedItem, Statistics, attribute_record};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Format {
    BitwardenJson,
    #[serde(rename = "onepassword-1pux")]
    Onepassword1pux,
    KeepassXml,
    BitwardenZip,
    Csv,
    Kdbx,
    BitwardenEncryptedJson,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ErrorKind {
    Limit,
    Allocation,
    Malformed,
    DuplicateKey,
    UnsupportedFormat,
    UnsupportedVersion,
    UnsupportedEncoding,
    AmbiguousFormat,
    OwnBackup,
    InvalidPath,
    DuplicatePath,
    ArchiveOverlap,
    EncryptedArchive,
    UnsupportedCompression,
    SizeMismatch,
    Checksum,
    InvalidRecord,
    InvalidOptions,
    Canceled,
    KdfLimit,
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Location {
    pub item: Option<usize>,
    pub field: Option<usize>,
    pub offset: Option<usize>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Error {
    pub kind: ErrorKind,
    pub location: Location,
}
impl From<ErrorKind> for Error {
    fn from(kind: ErrorKind) -> Self {
        Self {
            kind,
            location: Location::default(),
        }
    }
}
impl Error {
    pub fn at(mut self, location: Location) -> Self {
        self.location = Location {
            item: location.item.or(self.location.item),
            field: location.field.or(self.location.field),
            offset: location.offset.or(self.location.offset),
        };
        self
    }
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self.kind)
    }
}
impl std::error::Error for Error {}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Status {
    Ready,
    Review,
    Blocked,
    Excluded,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Code {
    SourceDataPreserved,
    NotesProtectedByDefault,
    ProtectedUrlNotIndexed,
    ArchivedExcludedByDefault,
    RecycleBinExcludedByDefault,
    UnknownItemPreserved,
    UnresolvedFieldReference,
    MissingSourceScope,
    MissingAttachment,
    UnsupportedEncoding,
    UnsupportedVersion,
    UnsupportedFeature,
    SourceGroupsRequireReview,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Diagnostic {
    pub code: Code,
    pub location: Location,
}

#[derive(Default, Serialize, Deserialize)]
pub struct Source {
    pub instance: Option<String>,
    pub account: Option<String>,
    pub vault: Option<String>,
    pub item: Option<String>,
    pub locator: usize,
}
impl Source {
    pub fn has_scoped_id(&self) -> bool {
        self.instance.as_ref().is_some_and(|s| !s.trim().is_empty())
            && self.item.as_ref().is_some_and(|s| !s.is_empty())
    }
}
impl Drop for Source {
    fn drop(&mut self) {
        self.instance.zeroize();
        self.account.zeroize();
        self.vault.zeroize();
        self.item.zeroize();
    }
}
#[derive(Default, Serialize, Deserialize)]
pub struct Options {
    pub source_instance: Option<String>,
    pub password: String,
    pub keyfile: Vec<u8>,
    #[serde(default)]
    pub password_present: bool,
    #[serde(default)]
    pub keyfile_present: bool,
    pub include_archived: bool,
    pub include_deleted: bool,
    pub csv: Option<CsvMapping>,
}
impl Drop for Options {
    fn drop(&mut self) {
        self.source_instance.zeroize();
        self.password.zeroize();
        self.keyfile.zeroize();
    }
}
#[derive(Clone, Serialize, Deserialize)]
pub struct CsvMapping {
    pub delimiter: u8,
    pub header: bool,
    pub columns: Vec<CsvColumn>,
}
#[derive(Clone, Serialize, Deserialize)]
pub struct CsvColumn {
    pub index: usize,
    pub target: String,
    pub name: String,
}
impl Drop for CsvColumn {
    fn drop(&mut self) {
        self.target.zeroize();
        self.name.zeroize();
    }
}

pub type Parser = fn(&[u8], &mut Context<'_>) -> Result<(), Error>;
pub fn prepare(
    format: Format,
    input: &[u8],
    options: &Options,
    limits: Limits,
    callback: &mut dyn FnMut(Progress) -> bool,
    parser: Parser,
) -> Result<Plan, Error> {
    let mut context = Context::new(format, input.len(), options, limits, callback)?;
    parser(input, &mut context)?;
    context.finish()
}

pub fn protected_original(name: &str, text: &str) -> confidex_vault::record::Entry {
    confidex_vault::record::Entry {
        name: name.into(),
        type_name: "secure-note/v1".into(),
        value: Mapping::from([("text".into(), text.into())]),
        extra: Mapping::new(),
    }
}
