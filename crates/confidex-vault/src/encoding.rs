#[derive(Clone, Copy)]
pub struct Limits {
    pub bytes: usize,
    pub depth: usize,
    pub nodes: usize,
    pub string: usize,
    pub binary: usize,
    pub key: usize,
}

pub const CONTENT_LIMITS: Limits = Limits {
    bytes: 64 * 1024 * 1024,
    depth: 64,
    nodes: 65_536,
    string: 1024 * 1024,
    binary: 64 * 1024 * 1024,
    key: 1024,
};

pub const HEADER_LIMITS: Limits = Limits {
    bytes: 65_536,
    depth: 4,
    nodes: 8192,
    string: 256,
    binary: 32,
    key: 32,
};

#[derive(Debug, PartialEq, Eq)]
pub enum EncodingError {
    Invalid,
    Limit,
    Allocation,
}

pub fn validate_messagepack(bytes: &[u8], limits: Limits) -> Result<(), EncodingError> {
    scan_messagepack(bytes, limits).map(|_| ())
}

pub struct ScanStats {
    pub nodes: usize,
}

pub fn scan_messagepack(bytes: &[u8], limits: Limits) -> Result<ScanStats, EncodingError> {
    if bytes.len() > limits.bytes
        || limits.bytes > CONTENT_LIMITS.bytes
        || limits.depth > CONTENT_LIMITS.depth
        || limits.nodes > CONTENT_LIMITS.nodes
        || limits.string > CONTENT_LIMITS.string
        || limits.binary > CONTENT_LIMITS.binary
        || limits.key > CONTENT_LIMITS.key
    {
        return Err(EncodingError::Limit);
    }
    let mut scan = Scan {
        remaining: bytes,
        limits,
        nodes_left: limits.nodes,
        key_slots_left: limits.nodes / 2,
    };
    scan.value(0)?;
    if scan.remaining.is_empty() {
        Ok(ScanStats {
            nodes: limits.nodes - scan.nodes_left,
        })
    } else {
        Err(EncodingError::Invalid)
    }
}

struct Scan<'a> {
    remaining: &'a [u8],
    limits: Limits,
    nodes_left: usize,
    key_slots_left: usize,
}

impl<'a> Scan<'a> {
    fn take(&mut self, len: usize) -> Result<&'a [u8], EncodingError> {
        let (bytes, rest) = self
            .remaining
            .split_at_checked(len)
            .ok_or(EncodingError::Invalid)?;
        self.remaining = rest;
        Ok(bytes)
    }

    fn length(&mut self, width: usize) -> Result<usize, EncodingError> {
        Ok(self
            .take(width)?
            .iter()
            .fold(0usize, |len, byte| (len << 8) | usize::from(*byte)))
    }

    fn value(&mut self, depth: usize) -> Result<Option<&'a str>, EncodingError> {
        if depth > self.limits.depth {
            return Err(EncodingError::Limit);
        }
        self.nodes_left = self.nodes_left.checked_sub(1).ok_or(EncodingError::Limit)?;
        let marker = self.take(1)?[0];
        match marker {
            0x00..=0x7f | 0xe0..=0xff | 0xc0 | 0xc2 | 0xc3 => (),
            0xcc | 0xd0 => {
                self.take(1)?;
            }
            0xcd | 0xd1 => {
                self.take(2)?;
            }
            0xca | 0xce | 0xd2 => {
                self.take(4)?;
            }
            0xcb | 0xcf | 0xd3 => {
                self.take(8)?;
            }
            0xa0..=0xbf | 0xd9..=0xdb => {
                let len = match marker {
                    0xa0..=0xbf => usize::from(marker & 31),
                    0xd9 => self.length(1)?,
                    0xda => self.length(2)?,
                    _ => self.length(4)?,
                };
                if len > self.limits.string {
                    return Err(EncodingError::Limit);
                }
                return std::str::from_utf8(self.take(len)?)
                    .map(Some)
                    .map_err(|_| EncodingError::Invalid);
            }
            0xc4..=0xc9 => {
                let width = 1 << ((marker - 0xc4) % 3);
                let len = self.length(width)?;
                if len > self.limits.binary {
                    return Err(EncodingError::Limit);
                }
                if marker >= 0xc7 {
                    self.take(1)?;
                }
                self.take(len)?;
            }
            0xd4..=0xd8 => {
                let len = 1 << (marker - 0xd4);
                if len > self.limits.binary {
                    return Err(EncodingError::Limit);
                }
                self.take(1 + len)?;
            }
            0x90..=0x9f | 0xdc | 0xdd => {
                let count = match marker {
                    0xdc => self.length(2)?,
                    0xdd => self.length(4)?,
                    _ => usize::from(marker & 15),
                };
                if count > self.nodes_left {
                    return Err(EncodingError::Limit);
                }
                for _ in 0..count {
                    self.value(depth + 1)?;
                }
            }
            0x80..=0x8f | 0xde | 0xdf => {
                let count = match marker {
                    0xde => self.length(2)?,
                    0xdf => self.length(4)?,
                    _ => usize::from(marker & 15),
                };
                if count > self.nodes_left / 2 {
                    return Err(EncodingError::Limit);
                }
                self.key_slots_left = self
                    .key_slots_left
                    .checked_sub(count)
                    .ok_or(EncodingError::Limit)?;
                let mut keys = Vec::new();
                keys.try_reserve_exact(count)
                    .map_err(|_| EncodingError::Allocation)?;
                for _ in 0..count {
                    let key = self.value(depth + 1)?.ok_or(EncodingError::Invalid)?;
                    if key.len() > self.limits.key {
                        return Err(EncodingError::Limit);
                    }
                    keys.push(key);
                    self.value(depth + 1)?;
                }
                keys.sort_unstable();
                if keys.windows(2).any(|pair| pair[0] == pair[1]) {
                    return Err(EncodingError::Invalid);
                }
                self.key_slots_left += count;
            }
            _ => return Err(EncodingError::Invalid),
        }
        Ok(None)
    }
}
