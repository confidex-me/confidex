use crate::protocol::SyncStatus;
use confidex_app::Error;

const INTERVAL: u64 = 60_000;
const RETRY_DELAYS: [u64; 3] = [5_000, 15_000, INTERVAL];

pub struct SyncSchedule {
    status: SyncStatus,
    due: u64,
    failures: usize,
}

impl Default for SyncSchedule {
    fn default() -> Self {
        Self {
            status: SyncStatus::Disabled,
            due: 0,
            failures: 0,
        }
    }
}

impl SyncSchedule {
    pub fn status(&self) -> SyncStatus {
        self.status
    }

    pub fn start(&mut self, now: u64) {
        self.status = SyncStatus::Pending;
        self.due = now;
    }

    pub fn local_change(&mut self, now: u64) {
        if self.status != SyncStatus::Disabled && self.failures == 0 {
            self.start(now);
        }
    }

    pub fn delay(&self, now: u64) -> i32 {
        if self.status == SyncStatus::Disabled {
            return -1;
        }
        self.due.saturating_sub(now).min(INTERVAL) as i32
    }

    pub fn finish(&mut self, now: u64, result: Result<bool, Error>) {
        let delay = match result {
            Ok(more) => {
                self.failures = 0;
                if more {
                    self.status = SyncStatus::Pending;
                    0
                } else {
                    self.status = SyncStatus::Current;
                    INTERVAL
                }
            }
            Err(error) => {
                self.status = match error {
                    Error::Network => SyncStatus::Offline,
                    _ => SyncStatus::Failed(error),
                };
                let delay = RETRY_DELAYS[self.failures];
                self.failures = (self.failures + 1).min(RETRY_DELAYS.len() - 1);
                delay
            }
        };
        self.due = now.saturating_add(delay);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn network_backoff_saturates_and_local_writes_do_not_bypass_it() {
        let mut sync = SyncSchedule::default();
        assert_eq!(sync.delay(0), -1);
        sync.start(0);
        assert_eq!(sync.delay(0), 0);
        let mut now = 100;
        for delay in [5_000, 15_000, 60_000, 60_000] {
            sync.finish(now, Err(Error::Network));
            assert_eq!(sync.status(), SyncStatus::Offline);
            sync.local_change(now + 1);
            assert_eq!(sync.delay(now + 1), delay - 1);
            now += delay as u64;
            assert_eq!(sync.delay(now), 0);
        }
        sync.finish(now, Ok(true));
        assert_eq!(sync.delay(now), 0);
        sync.finish(now, Ok(false));
        assert_eq!(sync.status(), SyncStatus::Current);
        assert_eq!(sync.delay(now), INTERVAL as i32);
        sync.local_change(now + 10);
        assert_eq!(sync.status(), SyncStatus::Pending);
        assert_eq!(sync.delay(now + 10), 0);
        sync.finish(now + 10, Err(Error::Network));
        assert_eq!(sync.delay(now + 10), 5_000);
    }
}
