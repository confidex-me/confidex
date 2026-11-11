//! Bounded password analysis runs outside the UI thread.
use eframe::egui::{self, Id};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, sync::mpsc};
use zeroize::Zeroizing;

#[derive(Clone, Copy, Deserialize, Serialize)]
pub struct Report {
    pub bits: f64,
    pub score: usize,
    pub advice: Option<usize>,
}
impl Report {
    pub fn valid(self) -> bool {
        self.bits.is_finite()
            && self.bits >= 0.
            && self.score <= 4
            && self.advice.is_none_or(|i| i < 8)
    }
}
fn bounded_prefix(password: &str) -> Zeroizing<String> {
    let mut prefix = Zeroizing::new(String::with_capacity(400));
    prefix.extend(password.chars().take(100));
    prefix
}
pub fn assess(password: &str) -> Report {
    use zxcvbn::feedback::Warning::*;
    let prefix = bounded_prefix(password);
    let result = zxcvbn::zxcvbn(&prefix, &[]);
    let advice = result.feedback().map(|feedback| match feedback.warning() {
        Some(
            ThisIsATop10Password
            | ThisIsATop100Password
            | ThisIsACommonPassword
            | ThisIsSimilarToACommonlyUsedPassword,
        ) => 0,
        Some(StraightRowsOfKeysAreEasyToGuess | ShortKeyboardPatternsAreEasyToGuess) => 1,
        Some(RepeatsLikeAaaAreEasyToGuess | RepeatsLikeAbcAbcAreOnlySlightlyHarderToGuess) => 2,
        Some(SequencesLikeAbcAreEasyToGuess) => 3,
        Some(RecentYearsAreEasyToGuess | DatesAreOftenEasyToGuess) => 4,
        Some(AWordByItselfIsEasyToGuess) => 5,
        Some(NamesAndSurnamesByThemselvesAreEasyToGuess | CommonNamesAndSurnamesAreEasyToGuess) => {
            6
        }
        None => 7,
    });
    Report {
        bits: result.guesses_log10().max(0.) * std::f64::consts::LOG2_10,
        score: result.score() as usize,
        advice,
    }
}
pub type Completion = Box<dyn FnOnce(Result<Report, ()>) + Send>;
type Worker = Box<dyn FnMut(Zeroizing<String>, Completion)>;
type Reply = (Id, u64, Result<Report, ()>);
struct Entry {
    prefix: Zeroizing<String>,
    ticket: u64,
    report: Option<Result<Report, ()>>,
    seen: bool,
}
pub struct Evaluator {
    entries: HashMap<Id, Entry>,
    worker: Option<Worker>,
    sender: mpsc::Sender<Reply>,
    receiver: mpsc::Receiver<Reply>,
    ticket: u64,
    running: bool,
}
impl Default for Evaluator {
    fn default() -> Self {
        let (sender, receiver) = mpsc::channel();
        Self {
            entries: HashMap::new(),
            worker: None,
            sender,
            receiver,
            ticket: 0,
            running: false,
        }
    }
}
impl Evaluator {
    pub fn set_worker(&mut self, worker: impl FnMut(Zeroizing<String>, Completion) + 'static) {
        self.worker = Some(Box::new(worker));
    }
    pub fn clear(&mut self) {
        self.entries.clear();
    }
    pub fn begin_frame(&mut self, ctx: &egui::Context) {
        while let Ok((id, ticket, report)) = self.receiver.try_recv() {
            self.running = false;
            if let Some(entry) = self.entries.get_mut(&id)
                && entry.ticket == ticket
            {
                entry.report =
                    Some(report.and_then(|report| report.valid().then_some(report).ok_or(())));
            }
        }
        for entry in self.entries.values_mut() {
            entry.seen = false;
        }
        if self.running {
            return;
        }
        let Some((&id, entry)) = self
            .entries
            .iter()
            .find(|(_, entry)| entry.report.is_none())
        else {
            return;
        };
        let ticket = entry.ticket;
        let password = entry.prefix.clone();
        let sender = self.sender.clone();
        let ctx = ctx.clone();
        let done: Completion = Box::new(move |report| {
            let _ = sender.send((id, ticket, report));
            ctx.request_repaint();
        });
        self.running = true;
        if let Some(worker) = &mut self.worker {
            worker(password, done);
        } else {
            #[cfg(not(target_arch = "wasm32"))]
            std::thread::spawn(move || done(Ok(assess(&password))));
            #[cfg(target_arch = "wasm32")]
            {
                let _ = password;
                done(Err(()));
            }
        }
    }
    pub fn end_frame(&mut self) {
        self.entries.retain(|_, entry| entry.seen);
    }
    pub fn report(&self, id: Id) -> Option<&Report> {
        self.entries.get(&id)?.report.as_ref()?.as_ref().ok()
    }
    pub(super) fn update(
        &mut self,
        ctx: &egui::Context,
        id: Id,
        password: Option<&str>,
    ) -> Option<Result<Report, ()>> {
        let Some(password) = password.filter(|password| !password.is_empty()) else {
            self.entries.remove(&id);
            return None;
        };
        let prefix = bounded_prefix(password);
        if self
            .entries
            .get(&id)
            .is_none_or(|entry| entry.prefix != prefix)
        {
            self.ticket = self
                .ticket
                .checked_add(1)
                .expect("password assessment ticket exhausted");
            self.entries.insert(
                id,
                Entry {
                    prefix,
                    ticket: self.ticket,
                    report: None,
                    seen: true,
                },
            );
            ctx.request_repaint();
        }
        let entry = self.entries.get_mut(&id).unwrap();
        entry.seen = true;
        entry.report
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{cell::RefCell, rc::Rc};
    #[test]
    fn analysis_coalesces_input_and_discards_stale_and_hidden_results() {
        let ctx = egui::Context::default();
        let id = Id::unique("public assessment fixture");
        let jobs = Rc::new(RefCell::new(Vec::new()));
        let pending = jobs.clone();
        let mut evaluator = Evaluator::default();
        evaluator.set_worker(move |password, done| pending.borrow_mut().push((password, done)));
        evaluator.update(&ctx, id, Some("old public fixture"));
        evaluator.begin_frame(&ctx);
        for i in 0..20 {
            evaluator.update(&ctx, id, Some(&format!("new public fixture {i}")));
        }
        evaluator.end_frame();
        evaluator.begin_frame(&ctx);
        assert_eq!(jobs.borrow().len(), 1);
        assert!(evaluator.report(id).is_none());
        let (_, done) = jobs.borrow_mut().remove(0);
        done(Ok(Report {
            bits: 80.,
            score: 4,
            advice: None,
        }));
        evaluator.begin_frame(&ctx);
        assert!(evaluator.report(id).is_none());
        let (password, done) = jobs.borrow_mut().remove(0);
        assert_eq!(password.as_str(), "new public fixture 19");
        done(Ok(Report {
            bits: 2.,
            score: 0,
            advice: Some(0),
        }));
        evaluator.begin_frame(&ctx);
        assert_eq!(evaluator.report(id).unwrap().score, 0);
        evaluator.end_frame();
        assert!(evaluator.entries.is_empty());
        evaluator.update(&ctx, id, Some(&"密码🗝️".repeat(1000)));
        assert_eq!(evaluator.entries[&id].prefix.chars().count(), 100);
        evaluator.clear();
        assert!(evaluator.entries.is_empty());
    }
    #[test]
    fn malformed_worker_reports_are_rejected() {
        assert!(
            !Report {
                bits: f64::NAN,
                score: 0,
                advice: None
            }
            .valid()
        );
        assert!(
            !Report {
                bits: 5.,
                score: 5,
                advice: None
            }
            .valid()
        );
        assert!(
            !Report {
                bits: 5.,
                score: 1,
                advice: Some(8)
            }
            .valid()
        );
        assert!(
            !Report {
                bits: -1.,
                score: 1,
                advice: None
            }
            .valid()
        );
    }
    #[test]
    fn background_analysis_finishes_without_a_ui_thread_calculation() {
        let ctx = egui::Context::default();
        let id = Id::unique("native public assessment fixture");
        let mut evaluator = Evaluator::default();
        evaluator.update(&ctx, id, Some("P@ssword1!"));
        evaluator.begin_frame(&ctx);
        assert!(evaluator.running && evaluator.report(id).is_none());
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while evaluator.report(id).is_none() {
            assert!(std::time::Instant::now() < deadline);
            std::thread::yield_now();
            evaluator.begin_frame(&ctx);
        }
        assert!(evaluator.report(id).unwrap().score <= 1);
    }
}
