use std::{cell::Cell, rc::Rc};

const IDLE_MS: u64 = 15 * 60 * 1000;

#[derive(Clone, Default)]
pub struct Lease(Rc<Cell<State>>);

#[derive(Clone, Copy, Default, PartialEq, Eq)]
enum State {
    #[default]
    Locked,
    Opened(u64),
    Retired,
    Expired,
}

impl Lease {
    pub fn open(&self, now: u64) {
        if self.0.get() == State::Locked {
            self.0.set(State::Opened(now));
        }
    }

    pub fn retire(&self) {
        self.0.set(State::Retired);
    }

    pub fn was_locked(&self) -> bool {
        self.0.get() == State::Retired
    }

    // A retired worker must be destroyed. An initially locked worker can unlock once.
    pub fn remaining(&self, now: u64) -> i32 {
        match self.0.get() {
            State::Locked => -1,
            State::Retired | State::Expired => 0,
            State::Opened(last) => match now.checked_sub(last).filter(|elapsed| *elapsed < IDLE_MS)
            {
                Some(elapsed) => (IDLE_MS - elapsed) as i32,
                None => {
                    self.0.set(State::Expired);
                    0
                }
            },
        }
    }

    pub fn activity(&self, now: u64) {
        if self.remaining(now) > 0 {
            self.0.set(State::Opened(now));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn activity_can_renew_only_a_live_lease() {
        let lease = Lease::default();
        lease.activity(1);
        assert_eq!(lease.remaining(1), -1);
        lease.open(1);
        let almost_expired = IDLE_MS;
        assert_eq!(lease.remaining(almost_expired), 1);
        lease.activity(almost_expired);
        assert_eq!(lease.remaining(almost_expired), IDLE_MS as i32);
        let expired = almost_expired + IDLE_MS;
        lease.activity(expired);
        lease.open(expired);
        assert_eq!(lease.remaining(expired), 0);
        assert!(!lease.was_locked());

        let lease = Lease::default();
        lease.open(1);
        lease.retire();
        assert!(lease.was_locked());
        assert_eq!(lease.remaining(2), 0);
    }

    #[test]
    fn checks_do_not_extend_the_lease_and_a_clock_rollback_retires_it() {
        let lease = Lease::default();
        lease.open(100);
        assert!(lease.remaining(IDLE_MS) > 0);
        assert_eq!(lease.remaining(IDLE_MS + 100), 0);

        let lease = Lease::default();
        lease.open(100);
        assert_eq!(lease.remaining(99), 0);
        assert_eq!(lease.remaining(110), 0);
    }
}
