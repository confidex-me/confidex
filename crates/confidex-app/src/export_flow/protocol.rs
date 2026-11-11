use super::*;

#[derive(Serialize, Deserialize)]
pub enum Command {
    Begin,
    List {
        operation: u32,
        after: Option<Head>,
    },
    Fields {
        operation: u32,
        head: confidex_storage::Head,
        start: usize,
    },
    Prepare {
        operation: u32,
        /// Unix seconds for new external items, not source revision times.
        created_at: u64,
        format: export::Format,
        options: export::Options,
        selection: Selection,
    },
    Rows {
        token: [u8; 16],
        start: usize,
    },
    Issues {
        token: [u8; 16],
        start: usize,
    },
    Generate {
        operation: u32,
        token: [u8; 16],
        consent: Consent,
    },
    Chunk {
        token: [u8; 16],
        offset: usize,
    },
    Finish {
        token: [u8; 16],
    },
    Cancel {
        token: Option<[u8; 16]>,
    },
}
impl Command {
    pub fn operation(&self) -> Option<u32> {
        match self {
            Self::List { operation, .. }
            | Self::Fields { operation, .. }
            | Self::Prepare { operation, .. }
            | Self::Generate { operation, .. } => Some(*operation),
            _ => None,
        }
    }
}
#[derive(Serialize, Deserialize)]
pub enum Reply {
    Listed {
        operation: u32,
        vault: VaultId,
        after: Option<Head>,
        page: SelectionPage,
    },
    Begun {
        vault: VaultId,
        formats: Vec<export::FormatInfo>,
    },
    Fields {
        operation: u32,
        vault: VaultId,
        head: confidex_storage::Head,
        start: usize,
        fields: FieldSources,
    },
    Reviewed {
        operation: u32,
        review: Review,
    },
    Rows {
        token: [u8; 16],
        start: usize,
        rows: Rows,
    },
    Issues {
        token: [u8; 16],
        start: usize,
        issues: Issues,
    },
    Progress {
        operation: u32,
        progress: Progress,
    },
    Ready {
        operation: u32,
        ready: Ready,
    },
    Chunk {
        token: [u8; 16],
        chunk: Chunk,
    },
    Finished,
    Canceled,
}
impl Engine {
    pub async fn execute_export(
        &mut self,
        store: &mut impl Store,
        command: &mut Command,
        control: &mut impl Control,
    ) -> Result<Reply, Error> {
        let formats = export::catalog();
        match command {
            Command::Fields {
                operation,
                head,
                start,
            } => {
                self.begin_export()?;
                if *operation == 0 {
                    return Err(export::Error::InvalidOptions.into());
                }
                let fields = self.export_fields(store, head, *start, control).await?;
                Ok(Reply::Fields {
                    operation: *operation,
                    vault: self.vault.as_ref().ok_or(AppError::Locked)?.vault_id(),
                    head: head.clone(),
                    start: *start,
                    fields,
                })
            }
            Command::List { operation, after } => {
                let vault = self.begin_export()?;
                if *operation == 0 {
                    return Err(export::Error::InvalidOptions.into());
                }
                let page = self.export_selection(store, after.clone(), control).await?;
                Ok(Reply::Listed {
                    operation: *operation,
                    vault,
                    after: after.clone(),
                    page,
                })
            }
            Command::Begin => Ok(Reply::Begun {
                vault: self.begin_export()?,
                formats,
            }),
            Command::Prepare {
                operation,
                created_at,
                format,
                options,
                selection,
            } => {
                self.begin_export()?;
                if *operation == 0 {
                    return Err(export::Error::InvalidOptions.into());
                }
                if !formats.iter().any(|info| info.format == *format) {
                    return Err(export::Error::UnsupportedFormat.into());
                }
                options.validate(*format)?;
                let writer = export::writer(*format, std::mem::take(options), *created_at)?;
                if writer.format() != *format {
                    return Err(export::Error::InvalidWriter.into());
                }
                let review = self
                    .prepare_export(store, selection, writer, export::Limits::default(), control)
                    .await?;
                Ok(Reply::Reviewed {
                    operation: *operation,
                    review,
                })
            }
            Command::Rows { token, start } => Ok(Reply::Rows {
                token: *token,
                start: *start,
                rows: self.export_rows(*token, *start)?,
            }),
            Command::Issues { token, start } => Ok(Reply::Issues {
                token: *token,
                start: *start,
                issues: self.export_issues(*token, *start)?,
            }),
            Command::Generate {
                operation,
                token,
                consent,
            } => {
                if *operation == 0 {
                    return Err(export::Error::InvalidOptions.into());
                }
                let ready = self
                    .generate_export(store, *token, *consent, control)
                    .await?;
                Ok(Reply::Ready {
                    operation: *operation,
                    ready,
                })
            }
            Command::Chunk { token, offset } => Ok(Reply::Chunk {
                token: *token,
                chunk: self.export_chunk(*token, *offset)?,
            }),
            Command::Finish { token } => {
                self.finish_export(*token)?;
                Ok(Reply::Finished)
            }
            Command::Cancel { token } => {
                self.cancel_export(*token)?;
                Ok(Reply::Canceled)
            }
        }
    }
}
