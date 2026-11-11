use crate::{envelope, trust::TrustAnchor};
use std::io::{self, Read, Write};

const MAGIC: &[u8] = b"confidex/records";
pub const MAX_BYTES: usize = 512 * 1024 * 1024;
pub const MAX_ITEMS: usize = 10_000;
pub const MAX_EDGES: usize = 100_000;

#[derive(Clone, Copy)]
pub struct Limits {
    pub bytes: usize,
    pub items: usize,
    pub edges: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            bytes: MAX_BYTES,
            items: MAX_ITEMS,
            edges: MAX_EDGES,
        }
    }
}
impl Limits {
    fn validate(self) -> Result<(), Error> {
        if self.bytes > MAX_BYTES || self.items > MAX_ITEMS || self.edges > MAX_EDGES {
            return Err(Error::Limit);
        }
        Ok(())
    }
}
#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    Invalid,
    Version,
    WrongVault,
    Limit,
    Allocation,
    State,
    Io(io::ErrorKind),
    Envelope(envelope::Error),
}

struct Stream<T> {
    inner: T,
    used: usize,
    limit: usize,
    exceeded: bool,
    error: Option<io::ErrorKind>,
}
impl<T> Stream<T> {
    fn new(inner: T, limit: usize) -> Self {
        Self {
            inner,
            used: 0,
            limit,
            exceeded: false,
            error: None,
        }
    }
    fn failure(&self) -> Error {
        if self.exceeded {
            Error::Limit
        } else if let Some(kind) = self.error {
            Error::Io(kind)
        } else {
            Error::Invalid
        }
    }
    fn account(&mut self, result: io::Result<usize>) -> io::Result<usize> {
        match result {
            Ok(n) => {
                self.error = None;
                self.used += n;
                if self.used > self.limit {
                    self.exceeded = true;
                    Err(io::ErrorKind::FileTooLarge.into())
                } else {
                    Ok(n)
                }
            }
            Err(e) => {
                self.error = Some(e.kind());
                Err(e)
            }
        }
    }
}
impl<T: Read> Read for Stream<T> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        // One extra byte distinguishes EOF at the inclusive limit from excess data.
        let len = buffer.len().min(self.limit.saturating_sub(self.used) + 1);
        let result = self.inner.read(&mut buffer[..len]);
        self.account(result)
    }
}
impl<T: Write> Write for Stream<T> {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        if buffer.len() > self.limit.saturating_sub(self.used) {
            self.exceeded = true;
            return Err(io::ErrorKind::FileTooLarge.into());
        }
        let result = self.inner.write(buffer);
        self.account(result)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.inner
            .flush()
            .inspect_err(|e| self.error = Some(e.kind()))
    }
}

pub struct Object<'a> {
    pub wire: &'a [u8],
    pub revision: envelope::VerifiedRevision<'a>,
}
#[derive(Debug, PartialEq, Eq)]
pub struct Summary {
    pub bytes: usize,
    pub items: usize,
    pub edges: usize,
}

pub struct Reader<'a, R> {
    stream: Stream<R>,
    anchor: &'a TrustAnchor,
    limits: Limits,
    remaining: usize,
    items: usize,
    edges: usize,
    buffer: Vec<u8>,
    failed: bool,
    finished: bool,
}
impl<'a, R: Read> Reader<'a, R> {
    pub fn declared_items(&self) -> usize {
        self.items + self.remaining
    }
    pub fn new(reader: R, anchor: &'a TrustAnchor, limits: Limits) -> Result<Self, Error> {
        limits.validate()?;
        let mut stream = Stream::new(reader, limits.bytes);
        let count = rmp::decode::read_array_len(&mut stream).map_err(|_| stream.failure())?;
        if count != 4 {
            return Err(Error::Invalid);
        }
        let len = rmp::decode::read_str_len(&mut stream).map_err(|_| stream.failure())? as usize;
        if len != MAGIC.len() {
            return Err(Error::Invalid);
        }
        let mut magic = [0; MAGIC.len()];
        stream
            .read_exact(&mut magic)
            .map_err(|_| stream.failure())?;
        if magic != MAGIC {
            return Err(Error::Invalid);
        }
        let version: u64 = rmp::decode::read_int(&mut stream).map_err(|_| stream.failure())?;
        if version != 2 {
            return Err(Error::Version);
        }
        if rmp::decode::read_bin_len(&mut stream).map_err(|_| stream.failure())? != 16 {
            return Err(Error::Invalid);
        }
        let mut vault = [0; 16];
        stream
            .read_exact(&mut vault)
            .map_err(|_| stream.failure())?;
        if vault != anchor.vault_id() {
            return Err(Error::WrongVault);
        }
        let remaining =
            rmp::decode::read_array_len(&mut stream).map_err(|_| stream.failure())? as usize;
        if remaining > limits.items {
            return Err(Error::Limit);
        }
        Ok(Self {
            stream,
            anchor,
            limits,
            remaining,
            items: 0,
            edges: 0,
            buffer: Vec::new(),
            failed: false,
            finished: false,
        })
    }
    fn eof(&mut self) -> Result<(), Error> {
        let mut byte = [0];
        loop {
            match self.stream.read(&mut byte) {
                Ok(0) => return Ok(()),
                Ok(_) => return Err(Error::Invalid),
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(_) => return Err(self.stream.failure()),
            }
        }
    }
    pub fn read_next(&mut self, memory_budget: usize) -> Result<Option<Object<'_>>, Error> {
        if self.failed {
            return Err(Error::State);
        }
        if self.finished {
            return Ok(None);
        }
        self.failed = true;
        envelope::admit(memory_budget).map_err(Error::Envelope)?;
        if self.remaining == 0 {
            self.eof()?;
            self.finished = true;
            self.failed = false;
            return Ok(None);
        }
        let len = rmp::decode::read_bin_len(&mut self.stream).map_err(|_| self.stream.failure())?
            as usize;
        if len > envelope::MAX_ENVELOPE {
            return Err(Error::Limit);
        }
        if len > self.limits.bytes.saturating_sub(self.stream.used) {
            return Err(Error::Limit);
        }
        self.buffer.clear();
        self.buffer
            .try_reserve_exact(len)
            .map_err(|_| Error::Allocation)?;
        self.buffer.resize(len, 0);
        self.stream
            .read_exact(&mut self.buffer)
            .map_err(|_| self.stream.failure())?;
        let revision = envelope::verify(&self.buffer, self.anchor, None, memory_budget)
            .map_err(Error::Envelope)?;
        let edges = self
            .edges
            .checked_add(revision.header().parents.len())
            .ok_or(Error::Limit)?;
        if edges > self.limits.edges {
            return Err(Error::Limit);
        }
        self.edges = edges;
        self.items += 1;
        self.remaining -= 1;
        self.failed = false;
        Ok(Some(Object {
            wire: &self.buffer,
            revision,
        }))
    }
    pub fn finish(mut self) -> Result<Summary, Error> {
        if self.failed || self.remaining != 0 {
            return Err(Error::State);
        }
        if !self.finished {
            self.eof()?;
        }
        Ok(Summary {
            bytes: self.stream.used,
            items: self.items,
            edges: self.edges,
        })
    }
}

pub struct Writer<'a, W> {
    stream: Stream<W>,
    anchor: &'a TrustAnchor,
    limits: Limits,
    remaining: usize,
    edges: usize,
    failed: bool,
}
impl<'a, W: Write> Writer<'a, W> {
    pub fn new(
        writer: W,
        anchor: &'a TrustAnchor,
        count: usize,
        limits: Limits,
    ) -> Result<Self, Error> {
        limits.validate()?;
        if count > limits.items {
            return Err(Error::Limit);
        }
        let mut stream = Stream::new(writer, limits.bytes);
        macro_rules! write {
            ($e:expr) => {
                $e.map_err(|_| stream.failure())?
            };
        }
        write!(rmp::encode::write_array_len(&mut stream, 4));
        write!(rmp::encode::write_str(
            &mut stream,
            std::str::from_utf8(MAGIC).unwrap()
        ));
        write!(rmp::encode::write_uint(&mut stream, 2));
        write!(rmp::encode::write_bin(&mut stream, &anchor.vault_id()));
        write!(rmp::encode::write_array_len(&mut stream, count as u32));
        Ok(Self {
            stream,
            anchor,
            limits,
            remaining: count,
            edges: 0,
            failed: false,
        })
    }
    pub fn push(&mut self, wire: &[u8], memory_budget: usize) -> Result<(), Error> {
        if self.failed {
            return Err(Error::State);
        }
        self.failed = true;
        if self.remaining == 0 {
            return Err(Error::State);
        }
        let revision =
            envelope::verify(wire, self.anchor, None, memory_budget).map_err(Error::Envelope)?;
        let edges = self
            .edges
            .checked_add(revision.header().parents.len())
            .ok_or(Error::Limit)?;
        if edges > self.limits.edges {
            return Err(Error::Limit);
        }
        let prefix = if wire.len() < 256 {
            2
        } else if wire.len() < 65536 {
            3
        } else {
            5
        };
        if prefix + wire.len() > self.limits.bytes.saturating_sub(self.stream.used) {
            return Err(Error::Limit);
        }
        rmp::encode::write_bin_len(&mut self.stream, wire.len() as u32)
            .map_err(|_| self.stream.failure())?;
        self.stream
            .write_all(wire)
            .map_err(|_| self.stream.failure())?;
        self.remaining -= 1;
        self.edges = edges;
        self.failed = false;
        Ok(())
    }
    pub fn finish(mut self) -> Result<W, Error> {
        if self.failed || self.remaining != 0 {
            return Err(Error::State);
        }
        self.stream.flush().map_err(|_| self.stream.failure())?;
        Ok(self.stream.inner)
    }
}
