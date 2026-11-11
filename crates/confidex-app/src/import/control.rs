//! Hosts can cancel work at each bounded checkpoint.
use super::{Error, ErrorKind};
use serde::{Deserialize, Serialize};
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Phase {
    Inspect,
    Read,
    Map,
    Validate,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Progress {
    pub phase: Phase,
    pub current: usize,
    pub total: usize,
}
pub struct Control<'a> {
    callback: &'a mut dyn FnMut(Progress) -> bool,
    canceled: bool,
}
impl<'a> Control<'a> {
    pub fn new(callback: &'a mut dyn FnMut(Progress) -> bool) -> Self {
        Self {
            callback,
            canceled: false,
        }
    }
    pub fn checkpoint(&mut self, phase: Phase, current: usize, total: usize) -> Result<(), Error> {
        if self.canceled
            || !(self.callback)(Progress {
                phase,
                current,
                total,
            })
        {
            self.canceled = true;
            return Err(ErrorKind::Canceled.into());
        }
        Ok(())
    }
}
