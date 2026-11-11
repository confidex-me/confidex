use super::*;
use import::formats::csv as adapter;

#[derive(Clone, Serialize, Deserialize)]
pub struct Profile {
    pub id: String,
    pub mapping: import::CsvMapping,
}
#[derive(Clone, Serialize, Deserialize)]
pub struct Setup {
    pub token: [u8; 16],
    pub file: File,
    pub mapping: import::CsvMapping,
    pub profiles: Vec<Profile>,
}

impl Engine {
    pub(super) async fn begin_csv(
        &mut self,
        vault: VaultId,
        operation: u32,
        file: File,
        bytes: Zeroizing<Vec<u8>>,
        mut options: import::Options,
        control: &mut impl Control,
    ) -> Result<Reply, Error> {
        if options.csv.is_some() {
            return Err(Error::InvalidOptions);
        }
        let mut clean = import::Options::default();
        clean.source_instance = options.source_instance.take();
        clean.include_archived = options.include_archived;
        clean.include_deleted = options.include_deleted;
        options = clean;
        let mut token = [0; 16];
        confidex_vault::entropy::fill_random(&mut token).map_err(|_| import_apply::Error::Limit)?;
        let source = Input {
            token,
            vault,
            file,
            bytes,
            options,
            format: import::Format::Csv,
            memory: None,
        };
        let reply = setup(&source, operation, b',', false, control)?;
        if !control
            .checkpoint(import_apply::Progress {
                phase: import_apply::Phase::Review,
                current: 0,
                total: 0,
            })
            .await
        {
            return Err(import_apply::Error::Canceled.into());
        }
        self.import_input = Some(source);
        Ok(reply)
    }
    fn check_csv(&self, token: [u8; 16]) -> Result<(), Error> {
        let vault = self.vault.as_ref().ok_or(AppError::Locked)?.vault_id();
        self.import_input
            .as_ref()
            .filter(|source| {
                source.token == token
                    && source.vault == vault
                    && source.format == import::Format::Csv
            })
            .ok_or(import_apply::Error::InvalidSession)?;
        Ok(())
    }
    pub(super) fn configure_csv(
        &mut self,
        operation: u32,
        token: [u8; 16],
        delimiter: u8,
        header: bool,
        control: &mut impl Control,
    ) -> Result<Reply, Error> {
        self.check_csv(token)?;
        self.import_session = None;
        let source = self.import_input.as_mut().unwrap();
        source.memory = None;
        setup(source, operation, delimiter, header, control)
    }
    pub(super) async fn preview_csv(
        &mut self,
        store: &mut impl Store,
        operation: u32,
        token: [u8; 16],
        mapping: &import::CsvMapping,
        control: &mut impl Control,
    ) -> Result<Reply, Error> {
        self.check_csv(token)?;
        self.import_session = None;
        let mut source = self.import_input.take().unwrap();
        source.memory = None;
        if !control
            .checkpoint(import_apply::Progress {
                phase: import_apply::Phase::Review,
                current: 0,
                total: 0,
            })
            .await
        {
            return Err(import_apply::Error::Canceled.into());
        }
        if mapping.columns.len() > import::Limits::default().fields
            || mapping
                .columns
                .iter()
                .any(|column| column.name.len() > 4096 || column.target.len() > 64)
        {
            self.import_input = Some(source);
            return Err(Error::InvalidOptions);
        }
        source.options.csv = Some(mapping.clone());
        let parsed = import::prepare(
            import::Format::Csv,
            &source.bytes,
            &source.options,
            import::Limits::default(),
            &mut |progress| control.parsing(progress),
            adapter::parse,
        );
        source.options.csv = None;
        let parsed = match parsed {
            Ok(parsed) => parsed,
            Err(error) if error.kind == import::ErrorKind::Canceled => return Err(error.into()),
            Err(error) => {
                self.import_input = Some(source);
                return Err(error.into());
            }
        };
        // Re-preview keeps the raw CSV against the same budget as the plan.
        source.memory = match parsed
            .memory()
            .reserve(source.bytes.capacity().saturating_add(16384))
        {
            Ok(memory) => Some(memory),
            Err(error) => {
                self.import_input = Some(source);
                return Err(error.into());
            }
        };
        let reply = self
            .review_source(
                store,
                source.vault,
                operation,
                source.file.clone(),
                parsed,
                control,
            )
            .await;
        if !matches!(&reply, Err(Error::Apply(import_apply::Error::Canceled))) {
            self.import_input = Some(source);
        }
        reply
    }
}

fn setup(
    source: &Input,
    operation: u32,
    delimiter: u8,
    header: bool,
    control: &mut impl Control,
) -> Result<Reply, Error> {
    let limits = import::Limits::default();
    let budget = import::Memory::new(limits.memory_bytes);
    let _output = budget.reserve(source.bytes.capacity().saturating_add(32 << 20))?;
    let (mapping, profiles) = if header {
        let header = adapter::header(&source.bytes, delimiter, limits, &mut |progress| {
            control.parsing(progress)
        })?;
        let profiles = header
            .profiles()
            .into_iter()
            .map(|profile| {
                Ok(Profile {
                    id: profile.id().into(),
                    mapping: profile.mapping(&header)?,
                })
            })
            .collect::<Result<Vec<_>, Error>>()?;
        (header.private_mapping(), profiles)
    } else {
        let count = adapter::column_count(&source.bytes, delimiter, limits, &mut |progress| {
            control.parsing(progress)
        })?;
        (
            import::CsvMapping {
                delimiter,
                header: false,
                columns: (0..count)
                    .map(|index| import::CsvColumn {
                        index,
                        target: "secret/v1".into(),
                        name: String::new(),
                    })
                    .collect(),
            },
            Vec::new(),
        )
    };
    Ok(Reply::CsvRequired {
        operation,
        setup: Setup {
            token: source.token,
            file: source.file.clone(),
            mapping,
            profiles,
        },
    })
}
