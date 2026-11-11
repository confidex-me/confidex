use super::{Mode, fixture, prepare, snapshot, writer};
use confidex_app::{Error, export, export_flow as flow};
use std::sync::atomic::Ordering;

#[derive(Clone, Copy)]
pub enum Stage {
    Prepare,
    BeforeWrite,
    AfterWrite,
}
pub(super) struct Failure<'a> {
    inject: &'a mut dyn FnMut(Stage, bool),
    stage: Stage,
    pub(super) wrote: bool,
    pub(super) injected: bool,
    minimum_read: usize,
}
impl<'a> Failure<'a> {
    pub(super) fn new(
        inject: &'a mut dyn FnMut(Stage, bool),
        stage: Stage,
        minimum_read: usize,
    ) -> Self {
        Self {
            inject,
            stage,
            wrote: false,
            injected: false,
            minimum_read,
        }
    }
}
impl flow::Control for Failure<'_> {
    fn computing(&mut self, progress: export::Progress) -> bool {
        self.wrote |= progress.phase == export::Phase::Write;
        true
    }
    async fn checkpoint(&mut self, progress: export::Progress) -> bool {
        let inject = match self.stage {
            Stage::Prepare => {
                progress.phase == export::Phase::Read
                    && progress.total > 0
                    && progress.current >= self.minimum_read
            }
            Stage::BeforeWrite => progress.phase == export::Phase::Check,
            Stage::AfterWrite => self.wrote && progress.phase == export::Phase::Check,
        };
        if inject && !self.injected {
            (self.inject)(self.stage, true);
            self.injected = true;
        }
        true
    }
}

pub async fn run(store: &mut impl confidex_storage::Store, mut inject: impl FnMut(Stage, bool)) {
    let mut fixture = fixture(store).await;
    let before = snapshot(store, fixture.created.info.id).await;
    for selected in [false, true] {
        for stage in [Stage::Prepare, Stage::BeforeWrite, Stage::AfterWrite] {
            let selection = if selected {
                flow::Selection::Records(vec![fixture.head.clone()])
            } else {
                flow::Selection::All
            };
            let (output_writer, calls) = writer(Mode::Full);
            let review = fixture
                .engine
                .prepare_export(
                    store,
                    &selection,
                    output_writer,
                    export::Limits::default(),
                    &mut |_| true,
                )
                .await
                .unwrap();
            let mut failure = Failure::new(&mut inject, stage, 0);
            let error = if matches!(stage, Stage::Prepare) {
                fixture
                    .engine
                    .prepare_export(
                        store,
                        &selection,
                        writer(Mode::Full).0,
                        export::Limits::default(),
                        &mut failure,
                    )
                    .await
                    .err()
            } else {
                fixture
                    .engine
                    .generate_export(store, review.token, export::Consent::Lossless, &mut failure)
                    .await
                    .err()
            };
            assert!(failure.injected);
            assert_eq!(
                error,
                Some(flow::Error::App(Error::Storage(
                    confidex_storage::Error::Storage
                )))
            );
            assert_eq!(
                calls.load(Ordering::SeqCst),
                usize::from(matches!(stage, Stage::AfterWrite))
            );
            assert_eq!(
                fixture.engine.export_rows(review.token, 0).err(),
                Some(flow::Error::InvalidSession)
            );
            assert_eq!(
                fixture.engine.export_chunk(review.token, 0).err(),
                Some(flow::Error::InvalidSession)
            );
            inject(stage, false);
            assert_eq!(*snapshot(store, fixture.created.info.id).await, *before);
            let fresh = prepare(store, &mut fixture, Mode::Full).await;
            let ready = fixture
                .engine
                .generate_export(store, fresh.token, export::Consent::Lossless, &mut |_| true)
                .await
                .unwrap();
            assert!(
                !fixture
                    .engine
                    .export_chunk(ready.token, 0)
                    .unwrap()
                    .bytes
                    .is_empty()
            );
            fixture.engine.finish_export(ready.token).unwrap();
            assert_eq!(*snapshot(store, fixture.created.info.id).await, *before);
        }
    }
}
