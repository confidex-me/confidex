//! Cancellable ownership of a bounded export between the worker and file host.
use super::{CHUNK_BYTES, File, Ready};
use std::{
    io,
    sync::{
        Arc, Mutex, TryLockError,
        atomic::{AtomicU8, Ordering},
    },
};
use zeroize::Zeroizing;

#[derive(Clone)]
pub struct Transfer {
    file: File,
    total: usize,
    inner: Arc<Inner>,
}
const OPEN: u8 = 0;
const PUBLISHING: u8 = 1;
const CLOSED: u8 = 2;
struct Inner {
    phase: AtomicU8,
    state: Mutex<State>,
}
enum State {
    Loading(Zeroizing<Vec<u8>>),
    Ready(Zeroizing<Vec<u8>>),
    Closed,
}
fn canceled() -> io::Error {
    io::Error::from(io::ErrorKind::ConnectionAborted)
}
impl Transfer {
    pub fn new(ready: &Ready) -> io::Result<Self> {
        if ready.bytes > crate::export::Limits::default().output_bytes
            || ready.file.name.is_empty()
            || ready.file.name.len() > 128
            || ready.file.name.starts_with('.')
            || !ready
                .file
                .name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
            || ready.file.media_type.is_empty()
            || ready.file.media_type.len() > 128
            || !ready.file.media_type.bytes().all(|b| b.is_ascii_graphic())
        {
            return Err(io::ErrorKind::InvalidData.into());
        }
        let mut bytes = Zeroizing::new(Vec::new());
        bytes
            .try_reserve_exact(ready.bytes)
            .map_err(|_| io::ErrorKind::OutOfMemory)?;
        Ok(Self {
            file: ready.file.clone(),
            total: ready.bytes,
            inner: Arc::new(Inner {
                phase: AtomicU8::new(OPEN),
                state: Mutex::new(State::Loading(bytes)),
            }),
        })
    }
    pub fn file(&self) -> &File {
        &self.file
    }
    pub fn len(&self) -> usize {
        self.total
    }
    pub fn is_empty(&self) -> bool {
        self.total == 0
    }
    /// Reject gaps, overlaps, truncation, extension and inconsistent continuation.
    pub fn append(&self, offset: usize, chunk: &[u8], next: Option<usize>) -> io::Result<()> {
        let mut state = self.state()?;
        let State::Loading(bytes) = &mut *state else {
            return Err(canceled());
        };
        let end = offset.checked_add(chunk.len());
        if offset != bytes.len()
            || chunk.len() > CHUNK_BYTES
            || end.is_none_or(|end| end > self.total)
            || (chunk.is_empty() && self.total != 0)
            || next != end.filter(|&end| end < self.total)
        {
            *state = State::Closed;
            return Err(io::ErrorKind::InvalidData.into());
        }
        bytes.extend_from_slice(chunk);
        if next.is_none() {
            *state = State::Ready(std::mem::take(bytes));
        }
        if self.inner.phase.load(Ordering::Acquire) != OPEN {
            *state = State::Closed;
            return Err(canceled());
        }
        Ok(())
    }
    fn state(&self) -> io::Result<std::sync::MutexGuard<'_, State>> {
        if self.inner.phase.load(Ordering::Acquire) != OPEN {
            return Err(canceled());
        }
        let state = self.inner.state.lock().map_err(|_| canceled())?;
        if self.inner.phase.load(Ordering::Acquire) != OPEN {
            return Err(canceled());
        }
        Ok(state)
    }
    pub fn cancel(&self) {
        let _ =
            self.inner
                .phase
                .compare_exchange(OPEN, CLOSED, Ordering::AcqRel, Ordering::Acquire);
        // Do not wait for a bounded copy or an OS publication on the UI thread.
        match self.inner.state.try_lock() {
            Ok(mut state) => {
                *state = State::Closed;
                self.inner.phase.store(CLOSED, Ordering::Release);
            }
            Err(TryLockError::Poisoned(error)) => {
                *error.into_inner() = State::Closed;
                self.inner.phase.store(CLOSED, Ordering::Release);
            }
            Err(TryLockError::WouldBlock) => (),
        }
    }
    pub fn available(&self) -> bool {
        self.inner.phase.load(Ordering::Acquire) == OPEN
            && self
                .inner
                .state
                .try_lock()
                .is_ok_and(|state| matches!(*state, State::Ready(_)))
    }
    /// Copy one bounded chunk. The file host never holds this lock during I/O.
    pub fn read(&self, offset: usize) -> io::Result<Zeroizing<Vec<u8>>> {
        let mut state = self.state()?;
        let State::Ready(bytes) = &*state else {
            return Err(canceled());
        };
        if offset > bytes.len() {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let end = bytes.len().min(offset.saturating_add(CHUNK_BYTES));
        let mut chunk = Zeroizing::new(Vec::new());
        chunk
            .try_reserve_exact(end - offset)
            .map_err(|_| io::ErrorKind::OutOfMemory)?;
        chunk.extend_from_slice(&bytes[offset..end]);
        if self.inner.phase.load(Ordering::Acquire) != OPEN {
            *state = State::Closed;
            return Err(canceled());
        }
        Ok(chunk)
    }
    /// Serialize cancellation with the final rename or browser download action.
    /// Once the host claims this action, cancellation cannot retract publication.
    pub fn publish<T>(&self, action: impl FnOnce(&[u8]) -> io::Result<T>) -> io::Result<T> {
        let mut state = self.state()?;
        let State::Ready(bytes) = &*state else {
            return Err(canceled());
        };
        self.inner
            .phase
            .compare_exchange(OPEN, PUBLISHING, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| canceled())?;
        let result = action(bytes);
        self.inner.phase.store(CLOSED, Ordering::Release);
        *state = State::Closed;
        result
    }
}
