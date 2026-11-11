use super::proof::LoadEvent;
use confidex_app::{import, import_apply};

#[cfg(not(target_arch = "wasm32"))]
pub fn now() -> f64 {
    static START: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();
    START
        .get_or_init(std::time::Instant::now)
        .elapsed()
        .as_secs_f64()
        * 1000.0
}
#[cfg(target_arch = "wasm32")]
#[wasm_bindgen::prelude::wasm_bindgen(
    inline_js = "export function profile_now() { return performance.now(); }"
)]
extern "C" {
    fn profile_now() -> f64;
}
#[cfg(target_arch = "wasm32")]
pub fn now() -> f64 {
    profile_now()
}

#[derive(Clone, Copy)]
enum Stage {
    Inspect,
    Read,
    Map,
    Validate,
    Review,
    Seal,
    Commit,
    Index,
    Other,
}
#[derive(serde::Serialize)]
pub struct Summary {
    pub records: usize,
    pub input_bytes: usize,
    pub encoded_bytes: usize,
    pub retained_budget_bytes: usize,
    pub inspect_ms: f64,
    pub read_ms: f64,
    pub map_ms: f64,
    pub validate_ms: f64,
    pub review_ms: f64,
    pub seal_ms: f64,
    pub commit_ms: f64,
    pub commit_release_ms: f64,
    pub index_ms: f64,
    pub other_ms: f64,
    pub total_ms: f64,
    pub parse_checkpoints: [usize; 4],
}
pub struct Timing {
    started: f64,
    last: f64,
    stage: Stage,
    times: [f64; 9],
    counts: [usize; 4],
    sizes: [usize; 3],
    ended: bool,
}
impl Timing {
    pub fn new() -> Self {
        Self::at(now())
    }
    fn at(time: f64) -> Self {
        Self {
            started: time,
            last: time,
            stage: Stage::Other,
            times: [0.0; 9],
            counts: [0; 4],
            sizes: [0; 3],
            ended: false,
        }
    }
    fn enter(&mut self, stage: Stage, time: f64) {
        assert!(time >= self.last && !self.ended);
        self.times[self.stage as usize] += time - self.last;
        self.last = time;
        self.stage = stage;
    }
    pub fn observe(&mut self, event: LoadEvent) {
        self.observe_at(event, now());
    }
    fn observe_at(&mut self, event: LoadEvent, time: f64) {
        let stage = match event {
            LoadEvent::Boundary("create") => {
                *self = Self::at(time);
                return;
            }
            LoadEvent::Boundary("parse-map-validate" | "review") => Stage::Review,
            LoadEvent::Boundary("seal-commit") => Stage::Index,
            LoadEvent::Boundary("index-search") => {
                self.enter(Stage::Other, time);
                self.ended = true;
                return;
            }
            LoadEvent::Boundary(_) => panic!("unknown load boundary"),
            LoadEvent::Parsed {
                input,
                encoded,
                retained,
            } => {
                self.sizes = [input, encoded, retained];
                return;
            }
            LoadEvent::Applied => Stage::Other,
            LoadEvent::Parse(progress) => {
                let stage = match progress.phase {
                    import::Phase::Inspect => Stage::Inspect,
                    import::Phase::Read => Stage::Read,
                    import::Phase::Map => Stage::Map,
                    import::Phase::Validate => Stage::Validate,
                };
                self.counts[stage as usize] += 1;
                stage
            }
            LoadEvent::Apply(progress) => match progress.phase {
                import_apply::Phase::Catalog | import_apply::Phase::Review => Stage::Review,
                import_apply::Phase::Seal => Stage::Seal,
                import_apply::Phase::Commit => Stage::Commit,
            },
        };
        self.enter(stage, time);
    }
    pub fn finish(self, commit_ms: f64) -> Summary {
        let total_ms = self.last - self.started;
        assert!(self.ended && commit_ms.is_finite() && commit_ms >= 0.0);
        assert!(
            self.times
                .iter()
                .all(|time| time.is_finite() && *time >= 0.0)
        );
        assert!((self.times.iter().sum::<f64>() - total_ms).abs() < 0.001);
        let commit_release_ms = self.times[Stage::Commit as usize] - commit_ms;
        assert!(commit_release_ms >= -0.001);
        Summary {
            records: crate::load::ROWS,
            input_bytes: self.sizes[0],
            encoded_bytes: self.sizes[1],
            retained_budget_bytes: self.sizes[2],
            inspect_ms: self.times[Stage::Inspect as usize],
            read_ms: self.times[Stage::Read as usize],
            map_ms: self.times[Stage::Map as usize],
            validate_ms: self.times[Stage::Validate as usize],
            review_ms: self.times[Stage::Review as usize],
            seal_ms: self.times[Stage::Seal as usize],
            commit_ms,
            commit_release_ms: commit_release_ms.max(0.0),
            index_ms: self.times[Stage::Index as usize],
            other_ms: self.times[Stage::Other as usize],
            total_ms,
            parse_checkpoints: self.counts,
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn a_timeline_splits_commit_io_and_accounts_for_all_wall_time() {
        let mut timing = Timing::at(0.0);
        timing.observe_at(LoadEvent::Boundary("create"), 100.0);
        for (phase, time) in [
            (import::Phase::Inspect, 101.0),
            (import::Phase::Read, 102.0),
            (import::Phase::Map, 104.0),
            (import::Phase::Validate, 107.0),
        ] {
            timing.observe_at(
                LoadEvent::Parse(import::Progress {
                    phase,
                    current: 0,
                    total: 1,
                }),
                time,
            );
        }
        timing.observe_at(LoadEvent::Boundary("parse-map-validate"), 109.0);
        for (phase, time) in [
            (import_apply::Phase::Seal, 112.0),
            (import_apply::Phase::Commit, 117.0),
        ] {
            timing.observe_at(
                LoadEvent::Apply(import_apply::Progress {
                    phase,
                    current: 0,
                    total: 1,
                }),
                time,
            );
        }
        timing.observe_at(LoadEvent::Applied, 120.0);
        timing.observe_at(LoadEvent::Boundary("seal-commit"), 122.0);
        timing.observe_at(LoadEvent::Boundary("index-search"), 129.0);
        let summary = timing.finish(2.0);
        assert_eq!(
            [
                summary.inspect_ms,
                summary.read_ms,
                summary.map_ms,
                summary.validate_ms,
                summary.review_ms,
                summary.seal_ms,
                summary.commit_ms,
                summary.commit_release_ms,
                summary.index_ms,
                summary.other_ms,
                summary.total_ms
            ],
            [1.0, 2.0, 3.0, 2.0, 3.0, 5.0, 2.0, 1.0, 7.0, 3.0, 29.0]
        );
        assert_eq!(summary.parse_checkpoints, [1; 4]);
    }
}
