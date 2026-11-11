use super::{Control, Error, File, Memory, Phase, Progress, Records, Reservation};
use std::{
    cell::RefCell,
    io::{self, Seek, SeekFrom, Write},
};
use zeroize::Zeroizing;

pub(crate) struct Sink<'cell, 'output, 'callback>(
    pub(crate) &'cell RefCell<&'output mut Output<'callback>>,
);
impl Write for Sink<'_, '_, '_> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.borrow_mut().write(bytes)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.0.borrow_mut().flush()
    }
}
impl Seek for Sink<'_, '_, '_> {
    fn seek(&mut self, from: SeekFrom) -> std::io::Result<u64> {
        self.0.borrow_mut().seek(from)
    }
}

pub struct Artifact {
    pub file: File,
    bytes: Zeroizing<Vec<u8>>,
    _memory: Reservation,
    memory: Memory,
}
impl Artifact {
    pub(crate) fn memory(&self) -> &Memory {
        &self.memory
    }
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}
/// A bounded seekable file for JSON, XML, CSV and ZIP writers.
pub struct Output<'a> {
    bytes: Zeroizing<Vec<u8>>,
    position: usize,
    limit: usize,
    error: Option<Error>,
    control: Control<'a>,
    memory: Memory,
    reservation: Reservation,
    progress: Progress,
}
impl<'a> Output<'a> {
    pub(super) fn new(
        records: &Records,
        callback: &'a mut dyn FnMut(Progress) -> bool,
    ) -> Result<Self, Error> {
        let limit = records.limits.output_bytes;
        let reservation = records.memory.reserve(0).map_err(|_| Error::Limit)?;
        Ok(Self {
            bytes: Zeroizing::new(Vec::new()),
            position: 0,
            limit,
            error: None,
            control: Control {
                callback,
                canceled: false,
            },
            memory: records.memory.clone(),
            reservation,
            progress: Progress {
                phase: Phase::Write,
                current: 0,
                total: records.len(),
            },
        })
    }
    pub fn checkpoint(&mut self, current: usize, total: usize) -> Result<(), Error> {
        self.status()?;
        self.progress = Progress {
            phase: Phase::Write,
            current,
            total,
        };
        if let Err(error) = self.control.checkpoint(self.progress) {
            self.error = Some(error);
            return Err(error);
        }
        Ok(())
    }
    /// Charge writer scratch space before allocating it.
    pub fn reserve(&self, bytes: usize) -> Result<Reservation, Error> {
        self.memory.reserve(bytes).map_err(|_| Error::Limit)
    }
    pub fn available_memory(&self) -> usize {
        self.memory.available()
    }
    pub(crate) fn limit(&self) -> usize {
        self.limit
    }
    /// Poll a library callback without changing the current progress fraction.
    pub(crate) fn poll(&mut self) -> Result<(), Error> {
        self.checkpoint(self.progress.current, self.progress.total)
    }
    pub(super) fn status(&self) -> Result<(), Error> {
        self.error.map_or(Ok(()), Err)
    }
    pub(super) fn finish(self, file: File) -> Artifact {
        Artifact {
            file,
            bytes: self.bytes,
            _memory: self.reservation,
            memory: self.memory,
        }
    }
    fn check_io(&mut self) -> io::Result<()> {
        self.checkpoint(self.progress.current, self.progress.total)
            .map_err(io_error)
    }
    fn fail(&mut self, error: Error) -> io::Error {
        self.error = Some(error);
        io_error(error)
    }
    fn grow(&mut self, end: usize) -> Result<(), Error> {
        if end <= self.bytes.capacity() {
            return Ok(());
        }
        let capacity = end.next_power_of_two().max(64 << 10).min(self.limit);
        // Charge both allocations until the old plaintext buffer is cleared.
        let reservation = self.memory.reserve(capacity).map_err(|_| Error::Limit)?;
        let mut bytes = Zeroizing::new(Vec::new());
        bytes
            .try_reserve_exact(capacity)
            .map_err(|_| Error::Allocation)?;
        bytes.extend_from_slice(&self.bytes);
        let old = std::mem::replace(&mut self.bytes, bytes);
        let old_reservation = std::mem::replace(&mut self.reservation, reservation);
        drop(old);
        drop(old_reservation);
        Ok(())
    }
}
fn io_error(error: Error) -> io::Error {
    match error {
        Error::Limit => io::ErrorKind::FileTooLarge,
        // Write::write_all retries Interrupted and would never observe cancellation.
        Error::Canceled => io::ErrorKind::ConnectionAborted,
        _ => io::ErrorKind::Other,
    }
    .into()
}
impl Write for Output<'_> {
    fn write(&mut self, input: &[u8]) -> io::Result<usize> {
        self.check_io()?;
        let Some(end) = self
            .position
            .checked_add(input.len())
            .filter(|&end| end <= self.limit)
        else {
            return Err(self.fail(Error::Limit));
        };
        if let Err(error) = self.grow(end) {
            return Err(self.fail(error));
        }
        if end > self.bytes.len() {
            self.bytes.resize(end, 0);
        }
        self.bytes[self.position..end].copy_from_slice(input);
        self.position = end;
        Ok(input.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        self.check_io()
    }
}
impl Seek for Output<'_> {
    fn seek(&mut self, from: SeekFrom) -> io::Result<u64> {
        self.check_io()?;
        let position = match from {
            SeekFrom::Start(position) => usize::try_from(position).ok(),
            SeekFrom::Current(offset) => self
                .position
                .checked_add_signed(isize::try_from(offset).map_err(|_| self.fail(Error::Limit))?),
            SeekFrom::End(offset) => self
                .bytes
                .len()
                .checked_add_signed(isize::try_from(offset).map_err(|_| self.fail(Error::Limit))?),
        }
        .filter(|&position| position <= self.limit);
        let Some(position) = position else {
            return Err(self.fail(Error::Limit));
        };
        self.position = position;
        Ok(position as u64)
    }
}
