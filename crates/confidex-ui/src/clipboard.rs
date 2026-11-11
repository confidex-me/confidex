//! Clipboard feedback acknowledged by native/browser hosts.
use crate::ui_kit::value::CopyState;
use eframe::egui::{Context, Id};
use std::{collections::HashMap, sync::mpsc, time::Duration};

pub type Completion = Box<dyn FnOnce(bool)>;
type Handler = Box<dyn FnMut(String, Completion)>;
struct Entry {
    attempt: u64,
    state: CopyState,
    expires: f64,
}

pub(crate) struct Clipboard {
    handler: Option<Handler>,
    sender: mpsc::Sender<(Id, u64, bool)>,
    receiver: mpsc::Receiver<(Id, u64, bool)>,
    entries: HashMap<Id, Entry>,
    attempt: u64,
    pub completed: u32,
    pub failed: u32,
}
impl Default for Clipboard {
    fn default() -> Self {
        let (sender, receiver) = mpsc::channel();
        Self {
            handler: None,
            sender,
            receiver,
            entries: HashMap::new(),
            attempt: 0,
            completed: 0,
            failed: 0,
        }
    }
}
impl Clipboard {
    pub fn set_handler(&mut self, handler: impl FnMut(String, Completion) + 'static) {
        self.handler = Some(Box::new(handler));
    }
    pub fn poll(&mut self, ctx: &Context) {
        let now = ctx.input(|i| i.time);
        while let Ok((id, attempt, success)) = self.receiver.try_recv() {
            if let Some(entry) = self.entries.get_mut(&id)
                && entry.attempt == attempt
            {
                entry.state = if success {
                    self.completed += 1;
                    CopyState::Copied
                } else {
                    self.failed += 1;
                    CopyState::Failed
                };
                entry.expires = now + 2.;
            }
        }
        self.entries
            .retain(|_, entry| entry.state != CopyState::Copied || entry.expires > now);
        if self.entries.values().any(|e| e.state == CopyState::Copied) {
            ctx.request_repaint_after(Duration::from_millis(100));
        }
    }
    pub fn state(&self, id: Id) -> CopyState {
        self.entries.get(&id).map_or(CopyState::Idle, |e| e.state)
    }
    pub fn invalidate(&mut self, id: Id) {
        self.entries.remove(&id);
    }
    pub fn clear(&mut self) {
        self.entries.clear();
    }
    pub fn request(&mut self, ctx: &Context, id: Id, value: String) {
        if value.is_empty() || self.state(id) == CopyState::Pending {
            return;
        }
        self.attempt += 1;
        let attempt = self.attempt;
        self.entries.insert(
            id,
            Entry {
                attempt,
                state: CopyState::Pending,
                expires: 0.,
            },
        );
        let sender = self.sender.clone();
        let ctx = ctx.clone();
        let done = Box::new(move |success| {
            let _ = sender.send((id, attempt, success));
            ctx.request_repaint();
        });
        if let Some(handler) = &mut self.handler {
            handler(value, done);
        } else {
            done(false);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{cell::RefCell, rc::Rc};
    #[test]
    fn acknowledgment_errors_retry_and_late_results() {
        let ctx = Context::default();
        let pending = Rc::new(RefCell::new(Vec::new()));
        let captured = pending.clone();
        let mut clipboard = Clipboard::default();
        clipboard.set_handler(move |text, done| captured.borrow_mut().push((text, done)));
        let id = Id::unique("value");
        let value = "public-Жe\u{301}🔐\n\n".repeat(1024);
        clipboard.request(&ctx, id, value.clone());
        clipboard.request(&ctx, id, "duplicate".into());
        assert!(clipboard.state(id) == CopyState::Pending);
        assert_eq!(pending.borrow().len(), 1);
        let (text, done) = pending.borrow_mut().pop().unwrap();
        assert_eq!(text, value);
        done(false);
        clipboard.poll(&ctx);
        assert!(clipboard.state(id) == CopyState::Failed);
        assert_eq!((clipboard.completed, clipboard.failed), (0, 1));
        clipboard.request(&ctx, id, value.clone());
        let (_, done) = pending.borrow_mut().pop().unwrap();
        done(true);
        clipboard.poll(&ctx);
        assert!(clipboard.state(id) == CopyState::Copied);
        clipboard.request(&ctx, id, value);
        let (_, done) = pending.borrow_mut().pop().unwrap();
        clipboard.invalidate(id);
        done(true);
        clipboard.poll(&ctx);
        assert!(clipboard.state(id) == CopyState::Idle);
        assert_eq!((clipboard.completed, clipboard.failed), (1, 1));
    }
}
