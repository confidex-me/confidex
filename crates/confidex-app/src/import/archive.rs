//! Read vendor ZIP members in memory. No member is extracted to a path.
use super::{Context, Error, ErrorKind, Phase, Reservation};
use std::{
    collections::BTreeSet,
    io::{Cursor, Read},
    ops::Deref,
};
use zeroize::Zeroizing;
use zip::ZipArchive;

pub struct Buffer {
    bytes: Zeroizing<Vec<u8>>,
    _memory: Reservation,
}
impl Buffer {
    /// Transfer bytes and their reservation together, without a plaintext copy.
    pub fn into_parts(self) -> (Zeroizing<Vec<u8>>, Reservation) {
        (self.bytes, self._memory)
    }
}
impl Deref for Buffer {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.bytes
    }
}
struct Member<'a> {
    name: &'a str,
    size: usize,
    compressed: usize,
    offset: usize,
    directory: bool,
}
pub struct Archive<'a> {
    zip: ZipArchive<Cursor<&'a [u8]>>,
    members: Vec<Member<'a>>,
    _memory: Reservation,
}
impl<'a> Archive<'a> {
    pub fn open(input: &'a [u8], context: &mut Context<'_>) -> Result<Self, Error> {
        if input.len() > context.limits.input_bytes {
            return Err(ErrorKind::Limit.into());
        }
        let directory = directory(input)?;
        if directory.count > context.limits.zip_entries
            || directory.metadata > context.limits.zip_metadata_bytes
        {
            return Err(ErrorKind::Limit.into());
        }
        let metadata = directory
            .metadata
            .checked_mul(3)
            .and_then(|n| {
                directory
                    .count
                    .checked_mul(1024)
                    .and_then(|m| n.checked_add(m))
            })
            .ok_or(ErrorKind::Limit)?;
        let memory = context.memory().reserve(metadata)?;
        let members = members(input, directory, context)?;
        let mut zip = ZipArchive::new(Cursor::new(input)).map_err(|_| ErrorKind::Malformed)?;
        if zip.offset() != 0 || zip.len() != members.len() {
            return Err(ErrorKind::Malformed.into());
        }
        if zip
            .has_overlapping_entries()
            .map_err(|_| ErrorKind::Malformed)?
        {
            return Err(ErrorKind::ArchiveOverlap.into());
        }
        for (index, member) in members.iter().enumerate() {
            context.checkpoint(Phase::Inspect, index, members.len())?;
            let file = zip.by_index(index).map_err(|_| ErrorKind::Malformed)?;
            if file
                .name()
                .map_err(|_| ErrorKind::UnsupportedEncoding)?
                .as_ref()
                != member.name
                || file.size() != member.size as u64
                || file.compressed_size() != member.compressed as u64
                || file.header_start() != member.offset as u64
            {
                return Err(ErrorKind::Malformed.into());
            }
        }
        Ok(Self {
            zip,
            members,
            _memory: memory,
        })
    }
    pub fn len(&self) -> usize {
        self.members.len()
    }
    pub fn is_empty(&self) -> bool {
        self.members.is_empty()
    }
    pub fn names(&self) -> impl Iterator<Item = &str> {
        self.members.iter().map(|m| m.name)
    }
    pub fn index(&self, name: &str) -> Option<usize> {
        self.members.iter().position(|m| m.name == name)
    }
    pub fn size(&self, index: usize) -> Option<usize> {
        self.members.get(index).map(|m| m.size)
    }
    pub fn read(&mut self, index: usize, context: &mut Context<'_>) -> Result<Buffer, Error> {
        let member = self.members.get(index).ok_or(ErrorKind::Malformed)?;
        if member.directory {
            return Err(ErrorKind::InvalidPath.into());
        }
        let memory = context.memory().reserve(member.size)?;
        let _scratch = context.memory().reserve(1 << 20)?;
        let mut bytes = Zeroizing::new(Vec::new());
        bytes
            .try_reserve_exact(member.size)
            .map_err(|_| ErrorKind::Allocation)?;
        bytes.resize(member.size, 0);
        let mut file = self.zip.by_index(index).map_err(|_| ErrorKind::Malformed)?;
        for (part, chunk) in bytes.chunks_mut(65_536).enumerate() {
            context.checkpoint(Phase::Read, part * 65_536, member.size)?;
            file.read_exact(chunk).map_err(read_error)?;
        }
        let mut extra = Zeroizing::new([0; 1]);
        if file.read(&mut extra[..]).map_err(read_error)? != 0 {
            return Err(ErrorKind::SizeMismatch.into());
        }
        Ok(Buffer {
            bytes,
            _memory: memory,
        })
    }
}
fn read_error(error: std::io::Error) -> Error {
    match error.kind() {
        std::io::ErrorKind::UnexpectedEof => ErrorKind::SizeMismatch,
        std::io::ErrorKind::InvalidData => ErrorKind::Checksum,
        _ => ErrorKind::Malformed,
    }
    .into()
}
#[derive(Clone, Copy)]
struct Directory {
    offset: usize,
    bytes: usize,
    count: usize,
    metadata: usize,
}
fn u16_at(input: &[u8], at: usize) -> Result<u16, Error> {
    Ok(u16::from_le_bytes(
        input
            .get(at..at.checked_add(2).ok_or(ErrorKind::Malformed)?)
            .ok_or(ErrorKind::Malformed)?
            .try_into()
            .unwrap(),
    ))
}
fn u32_at(input: &[u8], at: usize) -> Result<u32, Error> {
    Ok(u32::from_le_bytes(
        input
            .get(at..at.checked_add(4).ok_or(ErrorKind::Malformed)?)
            .ok_or(ErrorKind::Malformed)?
            .try_into()
            .unwrap(),
    ))
}
fn u64_at(input: &[u8], at: usize) -> Result<usize, Error> {
    usize::try_from(u64::from_le_bytes(
        input
            .get(at..at.checked_add(8).ok_or(ErrorKind::Malformed)?)
            .ok_or(ErrorKind::Malformed)?
            .try_into()
            .unwrap(),
    ))
    .map_err(|_| ErrorKind::Limit.into())
}
fn directory(input: &[u8]) -> Result<Directory, Error> {
    if input.len() < 22 {
        return Err(ErrorKind::Malformed.into());
    }
    let end = (input.len().saturating_sub(65_557)..=input.len() - 22)
        .rev()
        .find(|&i| {
            input.get(i..i + 4) == Some(b"PK\x05\x06")
                && u16_at(input, i + 20).is_ok_and(|n| i + 22 + n as usize == input.len())
        })
        .ok_or(ErrorKind::Malformed)?;
    if u16_at(input, end + 4)? != 0
        || u16_at(input, end + 6)? != 0
        || u16_at(input, end + 8)? != u16_at(input, end + 10)?
    {
        return Err(ErrorKind::Malformed.into());
    }
    let (count, bytes, offset) = (
        u16_at(input, end + 10)? as usize,
        u32_at(input, end + 12)? as usize,
        u32_at(input, end + 16)? as usize,
    );
    let (mut result, central_end) =
        if count == 0xffff || bytes == 0xffff_ffff || offset == 0xffff_ffff {
            let locator = end.checked_sub(20).ok_or(ErrorKind::Malformed)?;
            if u32_at(input, locator)? != 0x07064b50
                || u32_at(input, locator + 4)? != 0
                || u32_at(input, locator + 16)? != 1
            {
                return Err(ErrorKind::Malformed.into());
            }
            let start = u64_at(input, locator + 8)?;
            if input
                .get(start..start.saturating_add(56))
                .is_none_or(|s| s.len() != 56)
            {
                return Err(ErrorKind::Malformed.into());
            }
            let length = u64_at(input, start + 4)?;
            if u32_at(input, start)? != 0x06064b50
                || length < 44
                || start.checked_add(12).and_then(|n| n.checked_add(length)) != Some(locator)
                || u32_at(input, start + 16)? != 0
                || u32_at(input, start + 20)? != 0
                || u64_at(input, start + 24)? != u64_at(input, start + 32)?
            {
                return Err(ErrorKind::Malformed.into());
            }
            (
                Directory {
                    count: u64_at(input, start + 32)?,
                    bytes: u64_at(input, start + 40)?,
                    offset: u64_at(input, start + 48)?,
                    metadata: 0,
                },
                start,
            )
        } else {
            (
                Directory {
                    count,
                    bytes,
                    offset,
                    metadata: 0,
                },
                end,
            )
        };
    if result.offset.checked_add(result.bytes) != Some(central_end) {
        return Err(ErrorKind::Malformed.into());
    }
    result.metadata = input
        .len()
        .checked_sub(result.offset)
        .ok_or(ErrorKind::Malformed)?;
    Ok(result)
}
fn path(name: &str) -> Result<bool, Error> {
    let directory = name.ends_with('/');
    let trimmed = name.strip_suffix('/').unwrap_or(name);
    if trimmed.is_empty()
        || name.starts_with('/')
        || name.contains('\\')
        || name.chars().any(char::is_control)
        || name.as_bytes().get(1) == Some(&b':')
        || trimmed
            .split('/')
            .any(|s| s.is_empty() || s == "." || s == "..")
    {
        return Err(ErrorKind::InvalidPath.into());
    }
    Ok(directory)
}
fn members<'a>(
    input: &'a [u8],
    directory: Directory,
    context: &mut Context<'_>,
) -> Result<Vec<Member<'a>>, Error> {
    let mut at = directory.offset;
    let mut total = 0usize;
    let mut names = BTreeSet::new();
    let mut members = Vec::new();
    members
        .try_reserve_exact(directory.count)
        .map_err(|_| ErrorKind::Allocation)?;
    for index in 0..directory.count {
        context.checkpoint(Phase::Inspect, index, directory.count)?;
        if u32_at(input, at)? != 0x02014b50 {
            return Err(ErrorKind::Malformed.into());
        }
        let flags = u16_at(input, at + 8)?;
        if flags & (1 | 1 << 6 | 1 << 13) != 0 {
            return Err(ErrorKind::EncryptedArchive.into());
        }
        if !matches!(u16_at(input, at + 10)?, 0 | 8) {
            return Err(ErrorKind::UnsupportedCompression.into());
        }
        let (mut compressed, mut size, mut offset, mut disk) = (
            u32_at(input, at + 20)? as usize,
            u32_at(input, at + 24)? as usize,
            u32_at(input, at + 42)? as usize,
            u16_at(input, at + 34)? as usize,
        );
        let (name_len, extra_len, comment_len) = (
            u16_at(input, at + 28)? as usize,
            u16_at(input, at + 30)? as usize,
            u16_at(input, at + 32)? as usize,
        );
        if name_len > context.limits.name_bytes {
            return Err(ErrorKind::Limit.into());
        }
        let name_start = at.checked_add(46).ok_or(ErrorKind::Malformed)?;
        let name_end = name_start
            .checked_add(name_len)
            .ok_or(ErrorKind::Malformed)?;
        let extra_end = name_end
            .checked_add(extra_len)
            .ok_or(ErrorKind::Malformed)?;
        let end = extra_end
            .checked_add(comment_len)
            .filter(|n| *n <= directory.offset + directory.bytes)
            .ok_or(ErrorKind::Malformed)?;
        let raw_name = input
            .get(name_start..name_end)
            .ok_or(ErrorKind::Malformed)?;
        let name = std::str::from_utf8(raw_name).map_err(|_| ErrorKind::UnsupportedEncoding)?;
        let directory_entry = path(name)?;
        let canonical = name.strip_suffix('/').unwrap_or(name);
        if !names.insert(canonical) {
            return Err(ErrorKind::DuplicatePath.into());
        }
        let mut extra = name_end;
        let mut zip64 = false;
        while extra < extra_end {
            let id = u16_at(input, extra)?;
            let len = u16_at(input, extra + 2)? as usize;
            let start = extra.checked_add(4).ok_or(ErrorKind::Malformed)?;
            let stop = start
                .checked_add(len)
                .filter(|n| *n <= extra_end)
                .ok_or(ErrorKind::Malformed)?;
            if id == 1 {
                if zip64 {
                    return Err(ErrorKind::Malformed.into());
                }
                zip64 = true;
                let mut cursor = start;
                for number in [&mut size, &mut compressed, &mut offset] {
                    if *number == 0xffff_ffff {
                        if cursor + 8 > stop {
                            return Err(ErrorKind::Malformed.into());
                        }
                        *number = u64_at(input, cursor)?;
                        cursor += 8;
                    }
                }
                if disk == 0xffff {
                    if cursor + 4 > stop {
                        return Err(ErrorKind::Malformed.into());
                    }
                    disk = u32_at(input, cursor)? as usize;
                }
            }
            extra = stop;
        }
        if disk != 0 || size == 0xffff_ffff || compressed == 0xffff_ffff || offset == 0xffff_ffff {
            return Err(ErrorKind::Malformed.into());
        }
        if u16_at(input, at + 4)? >> 8 == 3 {
            let mode = u32_at(input, at + 38)? >> 16 & 0o170000;
            if !matches!(mode, 0 | 0o100000 | 0o040000)
                || (mode == 0o040000) != directory_entry && mode != 0
            {
                return Err(ErrorKind::InvalidPath.into());
            }
        }
        if directory_entry && size != 0 {
            return Err(ErrorKind::SizeMismatch.into());
        }
        total = total
            .checked_add(size)
            .filter(|n| *n <= context.limits.unpacked_bytes)
            .ok_or(ErrorKind::Limit)?;
        if size
            > compressed
                .saturating_mul(context.limits.zip_ratio)
                .saturating_add(1 << 20)
        {
            return Err(ErrorKind::Limit.into());
        }
        // Check local names too. Central and local aliases must not disagree.
        if u32_at(input, offset)? != 0x04034b50
            || u16_at(input, offset + 6)? != flags
            || u16_at(input, offset + 8)? != u16_at(input, at + 10)?
        {
            return Err(ErrorKind::Malformed.into());
        }
        let local_name = offset.checked_add(30).ok_or(ErrorKind::Malformed)?;
        let local_end = local_name
            .checked_add(u16_at(input, offset + 26)? as usize)
            .ok_or(ErrorKind::Malformed)?;
        if input.get(local_name..local_end) != Some(raw_name) {
            return Err(ErrorKind::Malformed.into());
        }
        let data_end = local_end
            .checked_add(u16_at(input, offset + 28)? as usize)
            .and_then(|n| n.checked_add(compressed))
            .filter(|n| *n <= directory.offset)
            .ok_or(ErrorKind::ArchiveOverlap)?;
        if data_end < local_end {
            return Err(ErrorKind::Malformed.into());
        }
        members.push(Member {
            name,
            size,
            compressed,
            offset,
            directory: directory_entry,
        });
        at = end;
    }
    if at != directory.offset + directory.bytes {
        return Err(ErrorKind::Malformed.into());
    }
    Ok(members)
}
