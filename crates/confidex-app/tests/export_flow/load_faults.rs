//! Large real-Store failure checks. Every value is public synthetic data.
use super::{
    load,
    storage_failure::{Failure, Stage},
    *,
};
use confidex_vault::crypto::revision_id as hash;

#[derive(Clone, Copy)]
enum CancelAt {
    Read,
    Write,
    Late,
}
struct Cancel {
    at: CancelAt,
    wrote: bool,
    canceled: bool,
}
impl flow::Control for Cancel {
    fn computing(&mut self, progress: export::Progress) -> bool {
        self.wrote |= progress.phase == export::Phase::Write && progress.current > 0;
        let cancel = matches!(self.at, CancelAt::Write) && self.wrote;
        self.canceled |= cancel;
        !cancel
    }
    async fn checkpoint(&mut self, progress: export::Progress) -> bool {
        let cancel = match self.at {
            CancelAt::Read => {
                progress.phase == export::Phase::Read && progress.current >= load::COUNT / 2
            }
            CancelAt::Late => progress.phase == export::Phase::Write,
            CancelAt::Write => false,
        };
        self.canceled |= cancel;
        !cancel
    }
}
struct TokenFailure<'a> {
    inject: &'a mut dyn FnMut(bool),
    phase: export::Phase,
    injected: bool,
}
impl flow::Control for TokenFailure<'_> {
    fn computing(&mut self, _: export::Progress) -> bool {
        true
    }
    async fn checkpoint(&mut self, progress: export::Progress) -> bool {
        if progress.phase == self.phase && !self.injected {
            (self.inject)(true);
            self.injected = true;
        }
        true
    }
}
#[derive(serde::Serialize)]
pub struct Run {
    format: export::Format,
    cases: Vec<&'static str>,
    recovered_bytes: usize,
}
#[derive(serde::Serialize)]
pub struct Report {
    records: usize,
    objects_checked: usize,
    entropy_injected: bool,
    runs: Vec<Run>,
}
async fn digest(
    store: &mut impl Store,
    id: VaultId,
    heads: &[Head],
    history: &[[u8; 32]],
) -> [u8; 32] {
    // Reuse the core's framed SHA256 without another client dependency.
    let mut digest = hash(
        b"public-export-load-witness",
        &serde_json::to_vec(&store.vault(id).await.unwrap()).unwrap(),
    );
    digest = hash(
        &digest,
        &serde_json::to_vec(&store.sync_state(id).await.unwrap()).unwrap(),
    );
    for head in heads {
        digest = hash(&digest, &head.record);
        digest = hash(&digest, &head.revision);
    }
    for revision in heads.iter().map(|head| &head.revision).chain(history) {
        let wire = store.object(id, *revision).await.unwrap();
        digest = hash(&digest, revision);
        digest = hash(&digest, &wire);
    }
    digest
}
fn revoked(engine: &Engine, token: [u8; 16]) {
    assert_eq!(
        engine.export_rows(token, 0).err(),
        Some(flow::Error::InvalidSession)
    );
    assert_eq!(
        engine.export_chunk(token, 0).err(),
        Some(flow::Error::InvalidSession)
    );
}
fn factory(format: export::Format) -> Box<dyn export::Writer> {
    export::writer(format, load::options(format), 1_735_689_600).unwrap()
}
async fn review(
    store: &mut impl Store,
    engine: &mut Engine,
    format: export::Format,
) -> flow::Review {
    let review = engine
        .prepare_export(
            store,
            &flow::Selection::All,
            factory(format),
            export::Limits::default(),
            &mut |_| true,
        )
        .await
        .unwrap();
    assert_eq!((review.records, review.blocked), (load::COUNT, 0));
    review
}
async fn ready(store: &mut impl Store, engine: &mut Engine, format: export::Format) -> flow::Ready {
    let review = review(store, engine, format).await;
    engine
        .generate_export(
            store,
            review.token,
            export::Consent::AllowLosses,
            &mut |_| true,
        )
        .await
        .unwrap()
}

pub async fn run(
    store: &mut impl Store,
    mut storage: impl FnMut(Stage, bool),
    mut entropy: Option<&mut dyn FnMut(bool)>,
) -> Report {
    let (mut fixture, ..) = load::seed(store, || 0.0).await;
    let id = fixture.created.info.id;
    let before_heads = load::heads(store, id).await;
    assert_eq!(before_heads.len(), load::COUNT);
    let old = store.object(id, fixture.head.revision).await.unwrap();
    let verified = envelope::verify(
        &old,
        fixture.vault.anchor(),
        Some(&fixture.head.revision),
        MAX_OPEN_MEMORY,
    )
    .unwrap();
    assert_eq!(verified.header().parents.len(), 1);
    let history = [verified.header().parents[0], fixture.head.revision];
    let before = digest(store, id, &before_heads, &history).await;
    let mut report = Report {
        records: load::COUNT,
        objects_checked: load::COUNT + history.len(),
        entropy_injected: entropy.is_some(),
        runs: Vec::new(),
    };
    for format in [
        export::Format::BitwardenJson,
        export::Format::Kdbx,
        export::Format::BitwardenEncryptedJson,
        export::Format::BitwardenZip,
        export::Format::KeepassXml,
        export::Format::Onepassword1pux,
        export::Format::Csv,
    ] {
        let mut cases = Vec::new();
        let previous = ready(store, &mut fixture.engine, format).await;
        let mut cancel = Cancel {
            at: CancelAt::Read,
            wrote: false,
            canceled: false,
        };
        assert_eq!(
            fixture
                .engine
                .prepare_export(
                    store,
                    &flow::Selection::All,
                    factory(format),
                    export::Limits::default(),
                    &mut cancel
                )
                .await
                .err(),
            Some(flow::Error::Export(export::Error::Canceled))
        );
        assert!(cancel.canceled);
        revoked(&fixture.engine, previous.token);
        cases.push("cancel-mid-read");
        for (at, name) in [
            (CancelAt::Write, "cancel-during-write"),
            (CancelAt::Late, "cancel-after-write"),
        ] {
            let review = review(store, &mut fixture.engine, format).await;
            let mut cancel = Cancel {
                at,
                wrote: false,
                canceled: false,
            };
            assert_eq!(
                fixture
                    .engine
                    .generate_export(
                        store,
                        review.token,
                        export::Consent::AllowLosses,
                        &mut cancel
                    )
                    .await
                    .err(),
                Some(flow::Error::Export(export::Error::Canceled))
            );
            assert!(cancel.canceled && cancel.wrote);
            revoked(&fixture.engine, review.token);
            cases.push(name);
        }
        for (stage, name) in [
            (Stage::Prepare, "storage-mid-read"),
            (Stage::BeforeWrite, "storage-before-write"),
            (Stage::AfterWrite, "storage-after-write"),
        ] {
            let old_token = if matches!(stage, Stage::Prepare) {
                previous.token
            } else {
                review(store, &mut fixture.engine, format).await.token
            };
            let mut failure = Failure::new(&mut storage, stage, load::COUNT / 2);
            let error = if matches!(stage, Stage::Prepare) {
                fixture
                    .engine
                    .prepare_export(
                        store,
                        &flow::Selection::All,
                        factory(format),
                        export::Limits::default(),
                        &mut failure,
                    )
                    .await
                    .err()
            } else {
                fixture
                    .engine
                    .generate_export(store, old_token, export::Consent::AllowLosses, &mut failure)
                    .await
                    .err()
            };
            assert!(failure.injected);
            assert_eq!(failure.wrote, matches!(stage, Stage::AfterWrite));
            assert_eq!(
                error,
                Some(flow::Error::App(app::Error::Storage(
                    confidex_storage::Error::Storage
                )))
            );
            storage(stage, false);
            revoked(&fixture.engine, old_token);
            assert_eq!(load::heads(store, id).await, before_heads);
            cases.push(name);
        }
        if let Some(inject) = entropy.as_deref_mut() {
            for (phase, name) in [
                (export::Phase::Review, "entropy-review-token"),
                (export::Phase::Write, "entropy-ready-token"),
            ] {
                let old_token = if phase == export::Phase::Write {
                    review(store, &mut fixture.engine, format).await.token
                } else {
                    previous.token
                };
                let mut failure = TokenFailure {
                    inject,
                    phase,
                    injected: false,
                };
                let error = if phase == export::Phase::Review {
                    fixture
                        .engine
                        .prepare_export(
                            store,
                            &flow::Selection::All,
                            factory(format),
                            export::Limits::default(),
                            &mut failure,
                        )
                        .await
                        .err()
                } else {
                    fixture
                        .engine
                        .generate_export(
                            store,
                            old_token,
                            export::Consent::AllowLosses,
                            &mut failure,
                        )
                        .await
                        .err()
                };
                assert!(failure.injected);
                assert_eq!(error, Some(flow::Error::Entropy));
                inject(false);
                revoked(&fixture.engine, old_token);
                cases.push(name);
            }
            if matches!(
                format,
                export::Format::Kdbx | export::Format::BitwardenEncryptedJson
            ) {
                let review = review(store, &mut fixture.engine, format).await;
                inject(true);
                let error = fixture
                    .engine
                    .generate_export(
                        store,
                        review.token,
                        export::Consent::AllowLosses,
                        &mut |_| true,
                    )
                    .await
                    .err();
                inject(false);
                assert_eq!(error, Some(flow::Error::Export(export::Error::Writer)));
                revoked(&fixture.engine, review.token);
                cases.push("entropy-crypto-writer");
            }
        }
        let canceled = ready(store, &mut fixture.engine, format).await;
        assert!(
            fixture
                .engine
                .export_chunk(canceled.token, 0)
                .unwrap()
                .next
                .is_some()
        );
        fixture.engine.cancel_export(Some(canceled.token)).unwrap();
        revoked(&fixture.engine, canceled.token);
        cases.push("cancel-ready");
        let recovered = ready(store, &mut fixture.engine, format).await;
        assert!(
            fixture
                .engine
                .export_chunk(recovered.token, 0)
                .unwrap()
                .next
                .is_some()
        );
        command(store, &mut fixture.engine, Command::Lock).await;
        revoked(&fixture.engine, recovered.token);
        let opened = command(
            store,
            &mut fixture.engine,
            Command::Unlock {
                vault: id,
                password: PASSWORD.into(),
                key: fixture.created.key.clone(),
                remember: false,
            },
        )
        .await;
        assert!(matches!(opened, Output::Opened { .. }));
        revoked(&fixture.engine, recovered.token);
        assert_eq!(load::heads(store, id).await, before_heads);
        cases.push("lock-ready");
        report.runs.push(Run {
            format,
            cases,
            recovered_bytes: recovered.bytes,
        });
    }
    assert_eq!(load::heads(store, id).await, before_heads);
    assert_eq!(digest(store, id, &before_heads, &history).await, before);
    report
}
