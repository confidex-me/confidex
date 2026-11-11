//! Individual ZIP exports share JSON semantics and keep archived file bytes.
use super::{
    super::{
        Code, Context, Diagnostic, Error, ErrorKind, Location, Phase, Reservation, Status,
        archive::Archive, json,
    },
    bitwarden_json,
};
use confidex_vault::record::{Entry, Mapping, Record, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use zeroize::{Zeroize, Zeroizing};
mod writer;
pub use writer::Writer;

struct Name {
    folder: [u8; 32],
    count: usize,
    owner: usize,
}
struct Folder {
    owner: Option<usize>,
    repeats: usize,
}
struct Names(BTreeMap<[u8; 32], Folder>);
impl Drop for Names {
    fn drop(&mut self) {
        for (mut key, _) in std::mem::take(&mut self.0) {
            key.zeroize();
        }
    }
}
#[derive(Default)]
struct Files {
    members: Vec<(usize, Zeroizing<String>)>,
}

fn digest(name: &str) -> [u8; 32] {
    Sha256::digest(name.as_bytes()).into()
}
fn sanitized(name: &str) -> Zeroizing<String> {
    let mut output = Zeroizing::new(String::with_capacity(name.len()));
    for c in name.chars() {
        let c = if "/\\><:\"|?*".contains(c) { '_' } else { c };
        if c != '_' || !output.ends_with('_') {
            output.push(c);
        }
    }
    output
}
#[derive(Default)]
struct NameIndex(BTreeMap<[u8; 32], Name>);
impl Drop for NameIndex {
    fn drop(&mut self) {
        for (mut key, mut name) in std::mem::take(&mut self.0) {
            key.zeroize();
            name.folder.zeroize();
        }
    }
}
impl NameIndex {
    fn add(&mut self, owner: usize, name: &str) {
        let entry = self.0.entry(digest(name)).or_insert_with(|| Name {
            folder: digest(&sanitized(name)),
            count: 0,
            owner,
        });
        entry.count += 1;
    }
    fn finish(mut self) -> Names {
        let mut names = Names(BTreeMap::new());
        for (mut key, mut name) in std::mem::take(&mut self.0) {
            let owner = (name.count == 1).then_some(name.owner);
            names
                .0
                .entry(name.folder)
                .and_modify(|folder| {
                    folder.owner = None;
                    folder.repeats = folder.repeats.max(name.count);
                })
                .or_insert(Folder {
                    owner,
                    repeats: name.count,
                });
            key.zeroize();
            name.folder.zeroize();
        }
        names
    }
}

impl Names {
    fn read(input: &[u8], context: &mut Context<'_>) -> Result<Self, Error> {
        let document = json::Document::parse(input, context)?;
        let root = json::object(document.raw(), context)?;
        if root.get("collections").is_some() {
            return Err(ErrorKind::UnsupportedFormat.into());
        }
        if root.get("encrypted").map(|v| v.get()) != Some("false") {
            return Err(ErrorKind::UnsupportedFormat.into());
        }
        let mut original = NameIndex::default();
        for (owner, raw) in json::array(root.get("items").ok_or(ErrorKind::Malformed)?)?.enumerate()
        {
            if owner >= context.limits.records {
                return Err(ErrorKind::Limit.into());
            }
            context.checkpoint(Phase::Inspect, owner, context.limits.records)?;
            let item = json::object(raw?, context)?;
            let name = json::owned(item.get("name").ok_or(ErrorKind::Malformed)?, context)?;
            let name = name.as_str().ok_or(ErrorKind::Malformed)?;
            if name.len() > context.limits.name_bytes {
                return Err(ErrorKind::Limit.into());
            }
            original.add(owner, name);
        }
        Ok(original.finish())
    }
    fn owner(&self, name: &str) -> Result<Option<usize>, ErrorKind> {
        // Only ciphers with files affect the producer's duplicate-name counter.
        if let Some((base, number)) = name.rsplit_once('_')
            && !number.starts_with('0')
            && number.bytes().all(|b| b.is_ascii_digit())
            && let Ok(number) = number.parse::<usize>()
            && self
                .0
                .get(&digest(base))
                .is_some_and(|f| f.repeats > number)
        {
            return Err(ErrorKind::AmbiguousFormat);
        }
        match self.0.get(&digest(name)) {
            Some(Folder {
                owner: Some(owner), ..
            }) => Ok(Some(*owner)),
            Some(_) => Err(ErrorKind::AmbiguousFormat),
            None => Ok(None),
        }
    }
}

pub fn parse(input: &[u8], context: &mut Context<'_>) -> Result<(), Error> {
    let mut archive = Archive::open(input, context)?;
    let index = archive
        .index("data.json")
        .ok_or(ErrorKind::UnsupportedFormat)?;
    let document = archive.read(index, context)?;
    let metadata = archive
        .names()
        .try_fold(context.limits.records * 512, |total, name| {
            if name.len() > context.limits.name_bytes {
                return Err(ErrorKind::Limit);
            }
            total
                .checked_add(name.len() * 4 + 1024)
                .ok_or(ErrorKind::Limit)
        })?;
    let _metadata = context.memory().reserve(metadata)?;
    let names = Names::read(&document, context)?;
    let mut files: BTreeMap<usize, Files> = BTreeMap::new();
    let mut extra = Record::default();
    let mut unresolved = Record::default();
    unresolved
        .extra
        .insert("bitwarden.zip.unresolved".into(), Value::Array(Vec::new()));
    for (index, path) in archive.names().enumerate() {
        context.checkpoint(Phase::Inspect, index, archive.len())?;
        if matches!(path, "data.json" | "attachments/") {
            continue;
        }
        let directory = path.ends_with('/');
        let relative = path.strip_prefix("attachments/").unwrap_or("");
        let parts = if directory {
            Some((relative.trim_end_matches('/'), ""))
        } else {
            relative.split_once('/')
        };
        let folder = match parts {
            Some((folder, filename))
                if !folder.is_empty() && !folder.contains('/') && !filename.contains('/') =>
            {
                folder
            }
            _ => {
                if let Value::Array(paths) = unresolved
                    .extra
                    .get_mut("bitwarden.zip.unresolved")
                    .unwrap()
                {
                    paths.push(Value::from(path));
                }
                issue(context, Code::UnsupportedFeature, Status::Blocked)?;
                continue;
            }
        };
        match names.owner(folder) {
            Ok(Some(owner)) => {
                let group = files.entry(owner).or_default();
                if !directory {
                    group.members.push((index, Zeroizing::new(path.into())));
                }
            }
            result => {
                if let Value::Array(paths) = unresolved
                    .extra
                    .get_mut("bitwarden.zip.unresolved")
                    .unwrap()
                {
                    paths.push(Value::from(path));
                }
                issue(
                    context,
                    if result.is_err() {
                        Code::UnresolvedFieldReference
                    } else {
                        Code::MissingAttachment
                    },
                    Status::Blocked,
                )?;
            }
        }
    }
    extra.extra.insert(
        "bitwarden.zip.profile".into(),
        "individual-name-folders/v1".into(),
    );
    extra.extra.insert(
        "bitwarden.zip.attachment-inventory-verified".into(),
        false.into(),
    );
    if let Some(Value::Array(paths)) = unresolved.extra.get("bitwarden.zip.unresolved")
        && !paths.is_empty()
    {
        extra.extra.append(&mut unresolved.extra);
    }
    // Partial download failures have no reference in data.json or the archive.
    issue(context, Code::UnsupportedFeature, Status::Review)?;
    bitwarden_json::parse_with(
        &document,
        context,
        std::mem::take(&mut extra.extra),
        &mut |_, item, context| {
            let Some(group) = files.get(&item.source.locator) else {
                return Ok(Vec::new());
            };
            if group.members.is_empty() {
                if item.status != Status::Excluded {
                    item.status = Status::Blocked;
                }
                item.diagnostics.push(Diagnostic {
                    code: Code::MissingAttachment,
                    location: Location {
                        item: Some(item.source.locator),
                        ..Location::default()
                    },
                });
                return Ok(Vec::new());
            }
            if item.record.entries.len() + group.members.len() > context.limits.fields {
                return Err(ErrorKind::Limit.into());
            }
            let mut guards: Vec<Reservation> = Vec::with_capacity(group.members.len());
            for (index, path) in &group.members {
                let (mut bytes, guard) = archive.read(*index, context)?.into_parts();
                let filename = path.rsplit('/').next().ok_or(ErrorKind::InvalidPath)?;
                item.record.entries.push(Entry {
                    name: filename.into(),
                    type_name: "file/v1".into(),
                    value: Mapping::from([
                        ("filename".into(), filename.into()),
                        ("mime".into(), "application/octet-stream".into()),
                        ("data".into(), Value::Binary(std::mem::take(&mut *bytes))),
                    ]),
                    extra: Mapping::from([("bitwarden.zip.path".into(), path.as_str().into())]),
                });
                guards.push(guard);
            }
            Ok(guards)
        },
    )
}
fn issue(context: &mut Context<'_>, code: Code, status: Status) -> Result<(), Error> {
    context.container_diagnostic(
        status,
        Diagnostic {
            code,
            location: Location::default(),
        },
    )
}
