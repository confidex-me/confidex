//! Import budgets apply before allocation and after decompression.
use super::{Error, ErrorKind};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

#[derive(Clone, Copy, Debug)]
pub struct Limits {
    pub input_bytes: usize,
    pub unpacked_bytes: usize,
    pub plan_bytes: usize,
    pub memory_bytes: usize,
    pub records: usize,
    pub fields: usize,
    pub depth: usize,
    pub nodes: usize,
    pub string_bytes: usize,
    pub name_bytes: usize,
    pub zip_entries: usize,
    pub zip_metadata_bytes: usize,
    pub zip_ratio: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            input_bytes: 64 << 20,
            unpacked_bytes: 64 << 20,
            plan_bytes: 64 << 20,
            memory_bytes: confidex_vault::resources::MAX_OPEN_MEMORY,
            records: 10_000,
            fields: crate::fields::MAX_FIELDS,
            depth: 32,
            nodes: 1_000_000,
            string_bytes: 16 << 20,
            name_bytes: 4096,
            zip_entries: 20_003,
            zip_metadata_bytes: 8 << 20,
            zip_ratio: 1000,
        }
    }
}
impl Limits {
    pub fn validate(self) -> Result<Self, Error> {
        let max = Self::default();
        let pairs = [
            (self.input_bytes, max.input_bytes),
            (self.unpacked_bytes, max.unpacked_bytes),
            (self.plan_bytes, max.plan_bytes),
            (self.memory_bytes, max.memory_bytes),
            (self.records, max.records),
            (self.fields, max.fields),
            (self.depth, max.depth),
            (self.nodes, max.nodes),
            (self.string_bytes, max.string_bytes),
            (self.name_bytes, max.name_bytes),
            (self.zip_entries, max.zip_entries),
            (self.zip_metadata_bytes, max.zip_metadata_bytes),
            (self.zip_ratio, max.zip_ratio),
        ];
        if pairs.iter().any(|&(n, ceiling)| n == 0 || n > ceiling) {
            return Err(ErrorKind::Limit.into());
        }
        Ok(self)
    }
}
#[derive(Clone)]
pub struct Memory {
    live: Arc<AtomicUsize>,
    limit: usize,
}
pub struct Reservation {
    live: Arc<AtomicUsize>,
    bytes: usize,
    limit: usize,
}
impl Memory {
    pub fn new(limit: usize) -> Self {
        Self {
            live: Arc::new(AtomicUsize::new(0)),
            limit,
        }
    }
    pub fn available(&self) -> usize {
        self.limit.saturating_sub(self.live.load(Ordering::Relaxed))
    }
    pub fn reserve(&self, bytes: usize) -> Result<Reservation, Error> {
        self.live
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |live| {
                live.checked_add(bytes).filter(|total| *total <= self.limit)
            })
            .map_err(|_| Error::from(ErrorKind::Limit))?;
        Ok(Reservation {
            live: self.live.clone(),
            bytes,
            limit: self.limit,
        })
    }
}
impl Reservation {
    /// Adjust a live library-work charge without a gap in the shared budget.
    pub(crate) fn resize(&mut self, bytes: usize) -> Result<(), Error> {
        if bytes <= self.bytes {
            return self.shrink_to(bytes);
        }
        let added = bytes - self.bytes;
        self.live
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |live| {
                live.checked_add(added).filter(|total| *total <= self.limit)
            })
            .map_err(|_| ErrorKind::Limit)?;
        self.bytes = bytes;
        Ok(())
    }
    /// Keep a resident allocation charged after its temporary work has been cleared.
    pub fn shrink_to(&mut self, bytes: usize) -> Result<(), Error> {
        let released = self.bytes.checked_sub(bytes).ok_or(ErrorKind::Limit)?;
        self.live.fetch_sub(released, Ordering::Relaxed);
        self.bytes = bytes;
        Ok(())
    }
}
impl Drop for Reservation {
    fn drop(&mut self) {
        self.live.fetch_sub(self.bytes, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resizing_respects_other_owners_and_keeps_the_charge_on_failure() {
        let memory = Memory::new(100);
        let mut work = memory.reserve(60).unwrap();
        let other = memory.reserve(30).unwrap();
        assert!(work.resize(80).is_err());
        assert_eq!(memory.available(), 10);
        work.resize(40).unwrap();
        assert_eq!(memory.available(), 30);
        drop(other);
        work.resize(100).unwrap();
        assert_eq!(memory.available(), 0);
        assert!(work.resize(usize::MAX).is_err());
        drop(work);
        assert_eq!(memory.available(), 100);
    }

    #[test]
    fn resident_reservation_stays_charged_when_work_is_released() {
        let memory = Memory::new(100);
        let other = memory.clone();
        let mut work = memory.reserve(90).unwrap();
        work.shrink_to(30).unwrap();
        assert_eq!(other.available(), 70);
        assert_eq!(work.shrink_to(31).unwrap_err().kind, ErrorKind::Limit);
        assert_eq!(other.available(), 70);
        let next = other.reserve(70).unwrap();
        assert!(memory.reserve(1).is_err());
        drop(work);
        assert_eq!(memory.available(), 30);
        drop(next);
        assert_eq!(memory.available(), 100);
    }
}
