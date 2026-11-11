use super::{Agent, failure};
use crate::protocol::{Code, Failure, Reply};
use confidex_app::local_sync;
#[cfg(feature = "sync")]
use confidex_app::{Command, Error, Output, Request, sync};
use confidex_storage::{Head, RecordId, SqliteStore, VaultId};
use std::time::{Duration, Instant};

const STEP_TIMEOUT: Duration = Duration::from_secs(45);

impl Agent {
    pub(super) async fn synchronize(
        &mut self,
        vault: VaultId,
        folder: bool,
    ) -> Result<Reply, Failure> {
        let session = self
            .sessions
            .get_mut(&vault)
            .ok_or_else(|| failure(confidex_app::Error::Locked))?;
        let store = &mut self.store;
        let reply = if folder {
            let mut control = || true;
            let local_sync::Reply::State { path, .. } = session
                .engine
                .execute_folder(
                    store,
                    &mut self.keys,
                    &mut local_sync::Command::Status,
                    &mut control,
                )
                .await
                .map_err(folder_failure)?
            else {
                unreachable!()
            };
            let (report, conflict) = if path.is_some() {
                let started = Instant::now();
                let local_sync::Reply::Synced { report, .. } = session
                    .engine
                    .execute_folder(
                        store,
                        &mut self.keys,
                        &mut local_sync::Command::Sync,
                        &mut || started.elapsed() < STEP_TIMEOUT,
                    )
                    .await
                    .map_err(folder_failure)?
                else {
                    unreachable!()
                };
                (Some(report), conflicted_record(store, vault).await?)
            } else {
                (None, None)
            };
            Reply::FolderSynced { report, conflict }
        } else {
            #[cfg(feature = "sync")]
            let (report, conflict) = if let Some(server) = sync::configured_server(store, vault)
                .await
                .map_err(failure)?
            {
                if self.net.is_none() {
                    self.net = Some(
                        confidex_native::sync_transport::Net::new()
                            .map_err(crate::runtime::io_failure)?,
                    );
                }
                let transport = self.net.as_mut().unwrap();
                let response = tokio::time::timeout(
                    STEP_TIMEOUT,
                    session.engine.execute_with_transport(
                        store,
                        &mut self.keys,
                        transport,
                        &mut Request {
                            generation: 0,
                            command: Command::Sync { server },
                        },
                    ),
                )
                .await
                .map_err(|_| timed_out())?;
                let report = match response.result {
                    Ok(Output::Synced(report)) => report,
                    Err(Error::Storage(confidex_storage::Error::Conflict)) => sync::Report {
                        more: true,
                        ..Default::default()
                    },
                    Err(error) => return Err(failure(error)),
                    Ok(_) => unreachable!(),
                };
                let conflict = if report.more && report.conflicts.is_empty() {
                    None
                } else if let Some(conflict) = report.conflicts.first() {
                    Some(conflict.record)
                } else {
                    conflicted_record(store, vault).await?
                };
                (Some(report), conflict)
            } else {
                (None, None)
            };
            #[cfg(not(feature = "sync"))]
            let (report, conflict) = (None, None);
            Reply::Synced { report, conflict }
        };
        session.used = Instant::now();
        Ok(reply)
    }
}

async fn conflicted_record(
    store: &mut SqliteStore,
    vault: VaultId,
) -> Result<Option<RecordId>, Failure> {
    let mut after: Option<Head> = None;
    loop {
        let heads = store
            .branch_heads(vault, after.as_ref(), None)
            .await
            .map_err(|error| failure(error.into()))?;
        if heads.is_empty() {
            return Ok(None);
        }
        for head in heads {
            if after
                .as_ref()
                .is_some_and(|previous| previous.record == head.record)
            {
                return Ok(Some(head.record));
            }
            after = Some(head);
        }
    }
}

fn folder_failure(error: local_sync::Error) -> Failure {
    match error {
        local_sync::Error::App(error) => failure(error),
        local_sync::Error::Canceled => timed_out(),
        local_sync::Error::Unavailable => Failure {
            code: Code::Network,
            message: "The configured sync folder is unavailable.".into(),
        },
    }
}

fn timed_out() -> Failure {
    Failure {
        code: Code::Network,
        message: "The synchronization step timed out. Run cfdex sync to resume.".into(),
    }
}
