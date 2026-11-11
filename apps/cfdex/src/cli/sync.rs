use super::{call, json};
use crate::{
    protocol::{Code, Failure, Operation, Reply},
    runtime::{self, Location},
};
use confidex_app::local_sync;
use confidex_storage::{RecordId, VaultId};
use serde::Serialize;
use std::io::{self, Write};

#[derive(Default, Serialize)]
struct Http {
    downloaded: usize,
    uploaded: usize,
    duplicates: usize,
}

pub(super) fn run(location: &Location, vault: VaultId, structured: bool) -> Result<(), Failure> {
    progress(structured, "Synchronizing vault.");
    let (mut folder, mut conflict) = sync_folder(location, vault)?;
    let mut http = None;
    let mut stalled = 0;
    loop {
        let (reply, _) = call(location, Some(vault), Operation::Sync { folder: false })?;
        let Reply::Synced {
            report,
            conflict: http_conflict,
        } = reply
        else {
            return Err(unexpected());
        };
        let Some(report) = report else {
            break;
        };
        let counts = http.get_or_insert_with(Http::default);
        counts.downloaded += report.downloaded;
        counts.uploaded += report.uploaded;
        counts.duplicates += report.duplicates;
        if let Some(record) = http_conflict {
            return Err(branch_conflict(record));
        }
        if !report.more {
            break;
        }
        if report.downloaded + report.uploaded == 0 {
            stalled += 1;
            if stalled == 16 {
                return Err(Failure {
                    code: Code::Network,
                    message: "Synchronization made no progress. Run cfdex sync to resume.".into(),
                });
            }
        } else {
            stalled = 0;
            progress(
                structured,
                &format!(
                    "HTTP synchronization has downloaded {} and uploaded {} revisions.",
                    counts.downloaded, counts.uploaded
                ),
            );
        }
    }
    if folder.is_none() && http.is_none() {
        return Err(Failure {
            code: Code::Network,
            message: "No available synchronization transport is configured for this vault.".into(),
        });
    }
    if let Some(before) = &mut folder
        && http.is_some()
    {
        let (after, latest_conflict) = sync_folder(location, vault)?;
        if let Some(after) = after {
            before.downloaded += after.downloaded;
            before.uploaded += after.uploaded;
            before.pending = after.pending;
        }
        conflict = latest_conflict;
    }
    if let Some(record) = conflict {
        return Err(branch_conflict(record));
    }
    if structured {
        #[derive(Serialize)]
        struct Totals {
            http: Option<Http>,
            folder: Option<local_sync::Report>,
        }
        return json(&Totals { http, folder });
    }
    let mut stdout = io::stdout().lock();
    if let Some(counts) = http {
        writeln!(
            stdout,
            "HTTP downloaded {}, uploaded {}, duplicates {}.",
            counts.downloaded, counts.uploaded, counts.duplicates
        )
        .map_err(runtime::io_failure)?;
    }
    if let Some(counts) = folder {
        writeln!(
            stdout,
            "Folder downloaded {}, uploaded {}, pending {}.",
            counts.downloaded, counts.uploaded, counts.pending
        )
        .map_err(runtime::io_failure)?;
    }
    Ok(())
}

fn sync_folder(
    location: &Location,
    vault: VaultId,
) -> Result<(Option<local_sync::Report>, Option<RecordId>), Failure> {
    let (reply, _) = call(location, Some(vault), Operation::Sync { folder: true })?;
    let Reply::FolderSynced { report, conflict } = reply else {
        return Err(unexpected());
    };
    Ok((report, conflict))
}

fn progress(structured: bool, message: &str) {
    if !structured {
        let _ = writeln!(io::stderr().lock(), "{message}");
    }
}

fn branch_conflict(record: RecordId) -> Failure {
    Failure {
        code: Code::Ambiguous,
        message: format!(
            "Record {} has conflicting revisions. Use the Confidex app to resolve the conflict.",
            runtime::hex(&record)
        ),
    }
}

fn unexpected() -> Failure {
    Failure {
        code: Code::Protocol,
        message: "Unexpected synchronization response.".into(),
    }
}
