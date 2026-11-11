use super::*;

impl Engine {
    pub(super) async fn begin_unlock(
        &mut self,
        operation: u32,
        format: import::Format,
        file: File,
        bytes: Zeroizing<Vec<u8>>,
        mut options: import::Options,
        control: &mut impl Control,
    ) -> Result<Reply, Error> {
        let vault = self.vault.as_ref().ok_or(AppError::Locked)?.vault_id();
        options.password.zeroize();
        options.keyfile.zeroize();
        options.password_present = false;
        options.keyfile_present = false;
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
        let mut token = [0; 16];
        confidex_vault::entropy::fill_random(&mut token).map_err(|_| import_apply::Error::Limit)?;
        self.import_input = Some(Input {
            token,
            vault,
            format,
            file: file.clone(),
            bytes,
            options,
            memory: None,
        });
        Ok(if format == import::Format::Kdbx {
            Reply::KdbxRequired {
                operation,
                token,
                file,
            }
        } else {
            Reply::PasswordRequired {
                operation,
                token,
                file,
            }
        })
    }
    pub(super) async fn unlock_source(
        &mut self,
        store: &mut impl Store,
        command: &mut Command,
        control: &mut impl Control,
    ) -> Result<Reply, Error> {
        let (operation, token, format, password, keyfile) = match command {
            Command::Unlock {
                operation,
                token,
                password,
            } => (
                *operation,
                *token,
                import::Format::BitwardenEncryptedJson,
                Some(std::mem::take(password)),
                None,
            ),
            Command::UnlockKdbx {
                operation,
                token,
                password,
                keyfile,
            } => (
                *operation,
                *token,
                import::Format::Kdbx,
                password.take(),
                keyfile.take(),
            ),
            _ => return Err(Error::InvalidOptions),
        };
        let mut password = Zeroizing::new(password);
        let mut keyfile = Zeroizing::new(keyfile);
        let vault = self.vault.as_ref().ok_or(AppError::Locked)?.vault_id();
        self.import_input
            .as_ref()
            .filter(|source| {
                source.token == token && source.vault == vault && source.format == format
            })
            .ok_or(import_apply::Error::InvalidSession)?;
        if password.as_ref().is_some_and(|p| p.len() > 65536)
            || keyfile
                .as_ref()
                .is_some_and(|k| k.len() > MAX_KEYFILE_BYTES)
            || (password.is_none() && keyfile.is_none())
            || (format == import::Format::BitwardenEncryptedJson
                && (keyfile.is_some() || password.as_ref().is_none_or(String::is_empty)))
        {
            return Err(Error::InvalidOptions);
        }
        let mut source = self.import_input.take().unwrap();
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
        let password_present = password.is_some();
        let keyfile_present = keyfile.is_some();
        source.options.password = password.take().unwrap_or_default();
        source.options.keyfile = keyfile.take().unwrap_or_default();
        source.options.password_present = password_present;
        source.options.keyfile_present = keyfile_present;
        let parser: import::Parser = if format == import::Format::Kdbx {
            import::formats::kdbx::parse
        } else {
            import::formats::bitwarden_encrypted_json::parse
        };
        let parsed = import::prepare(
            format,
            &source.bytes,
            &source.options,
            import::Limits::default(),
            &mut |progress| control.parsing(progress),
            parser,
        );
        source.options.password.zeroize();
        source.options.keyfile.zeroize();
        source.options.password_present = false;
        source.options.keyfile_present = false;
        let parsed = match parsed {
            Ok(parsed) => parsed,
            Err(error) if error.kind == import::ErrorKind::Checksum => {
                self.import_input = Some(source);
                return Err(Error::Authentication);
            }
            Err(error) => return Err(error.into()),
        };
        let file = source.file.clone();
        drop(source);
        self.review_source(store, vault, operation, file, parsed, control)
            .await
    }
}
