use crate::{
    protocol::{self, Code, Credentials, Failure, Secret},
    runtime,
};
use std::io::{self, IsTerminal, Read, Write};
use zeroize::{Zeroize, Zeroizing};

pub fn unlock(
    vault: confidex_storage::VaultId,
    credentials_stdin: bool,
) -> Result<Credentials, Failure> {
    if credentials_stdin {
        let mut credentials = from_stdin()?;
        if credentials.secret_key.is_none() {
            credentials.secret_key = Some(
                saved(vault).ok_or(Failure {
                    code: Code::Locked,
                    message:
                        "The saved key is unavailable. Include secret_key in the JSON credentials."
                            .into(),
                })?,
            );
        }
        return Ok(credentials);
    }
    if !io::stdin().is_terminal() {
        return Err(Failure {
            code: Code::Locked,
            message: "Use --credentials-stdin with JSON credentials.".into(),
        });
    }
    let secret_key = match saved(vault) {
        Some(key) => key,
        None => prompt("Secret key")?,
    };
    Ok(Credentials {
        password: prompt("Master password")?,
        secret_key: Some(secret_key),
    })
}

fn saved(vault: confidex_storage::VaultId) -> Option<Secret> {
    let key = Secret(confidex_native::load_key(vault, false).ok().flatten()?);
    checked(key).ok()
}

#[derive(serde::Deserialize)]
#[serde(transparent)]
struct TextSecret(String);
impl Drop for TextSecret {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

pub fn from_stdin() -> Result<Credentials, Failure> {
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Input {
        password: TextSecret,
        secret_key: Option<TextSecret>,
    }
    let mut bytes = Zeroizing::new(Vec::new());
    bytes
        .try_reserve_exact(protocol::MAX_REQUEST + 1)
        .map_err(|_| Failure {
            code: Code::Io,
            message: "Credential allocation failed.".into(),
        })?;
    io::stdin()
        .take((protocol::MAX_REQUEST + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(runtime::io_failure)?;
    if bytes.len() > protocol::MAX_REQUEST {
        return Err(Failure {
            code: Code::Input,
            message: "Credential input exceeds the limit.".into(),
        });
    }
    let mut input: Input = serde_json::from_slice(&bytes).map_err(|_| Failure {
        code: Code::Input,
        message: "Invalid credential JSON.".into(),
    })?;
    Ok(Credentials {
        password: checked(Secret(std::mem::take(&mut input.password.0)))?,
        secret_key: input
            .secret_key
            .take()
            .map(|mut key| checked(Secret(std::mem::take(&mut key.0))))
            .transpose()?,
    })
}

fn checked(secret: Secret) -> Result<Secret, Failure> {
    if secret.0.is_empty() || secret.0.len() > protocol::MAX_SECRET {
        Err(Failure {
            code: Code::Input,
            message: "Credentials must contain 1 to 4096 UTF-8 bytes.".into(),
        })
    } else {
        Ok(secret)
    }
}

pub fn prompt(label: &str) -> Result<Secret, Failure> {
    if !io::stdin().is_terminal() {
        return Err(Failure {
            code: Code::Locked,
            message: "Use --credentials-stdin with JSON credentials.".into(),
        });
    }
    let mut terminal = Terminal::open().map_err(runtime::io_failure)?;
    let mut stderr = io::stderr().lock();
    write!(stderr, "{label}: ")
        .and_then(|_| stderr.flush())
        .map_err(runtime::io_failure)?;
    let result = read_secret(&mut terminal);
    drop(terminal);
    let _ = writeln!(stderr);
    match result {
        Ok(secret) => checked(secret),
        Err(error) if error.kind() == io::ErrorKind::Interrupted => Err(Failure {
            code: Code::Cancelled,
            message: "Credential input was cancelled.".into(),
        }),
        Err(error) if error.kind() == io::ErrorKind::InvalidData => Err(Failure {
            code: Code::Input,
            message: "Invalid credential input.".into(),
        }),
        Err(error) => Err(runtime::io_failure(error)),
    }
}

fn read_secret(reader: &mut impl Read) -> io::Result<Secret> {
    let mut bytes = Zeroizing::new(Vec::<u8>::with_capacity(protocol::MAX_SECRET));
    let mut byte = Zeroizing::new([0u8; 1]);
    let mut escape = false;
    let mut sequence = false;
    loop {
        if reader.read(&mut *byte)? == 0 {
            return Err(io::ErrorKind::Interrupted.into());
        }
        match byte[0] {
            3 | 4 => return Err(io::ErrorKind::Interrupted.into()),
            b'\n' | b'\r' => break,
            27 => {
                escape = true;
                sequence = false;
            }
            b'[' | b'O' if escape => {
                escape = false;
                sequence = true;
            }
            _ if escape => escape = false,
            0x40..=0x7e if sequence => sequence = false,
            _ if sequence => (),
            8 | 127 => {
                while let Some(last) = bytes.last_mut() {
                    let continuation = *last & 0xc0 == 0x80;
                    last.zeroize();
                    bytes.pop();
                    if !continuation {
                        break;
                    }
                }
            }
            21 => bytes.zeroize(),
            value if value >= 32 => {
                if bytes.len() == protocol::MAX_SECRET {
                    return Err(io::ErrorKind::InvalidData.into());
                }
                bytes.push(value);
            }
            _ => (),
        }
    }
    match String::from_utf8(std::mem::take(&mut *bytes)) {
        Ok(text) => Ok(Secret(text)),
        Err(error) => {
            error.into_bytes().zeroize();
            Err(io::ErrorKind::InvalidData.into())
        }
    }
}

#[cfg(unix)]
struct Terminal {
    file: std::fs::File,
    original: libc::termios,
}
#[cfg(unix)]
impl Terminal {
    fn open() -> io::Result<Self> {
        use std::os::fd::AsRawFd;
        let file = std::fs::File::open("/dev/tty")?;
        let mut original = std::mem::MaybeUninit::uninit();
        if unsafe { libc::tcgetattr(file.as_raw_fd(), original.as_mut_ptr()) } != 0 {
            return Err(io::Error::last_os_error());
        }
        let original = unsafe { original.assume_init() };
        let mut mode = original;
        mode.c_lflag &= !(libc::ECHO | libc::ECHONL | libc::ICANON | libc::ISIG);
        mode.c_cc[libc::VMIN] = 1;
        mode.c_cc[libc::VTIME] = 0;
        if unsafe { libc::tcsetattr(file.as_raw_fd(), libc::TCSAFLUSH, &mode) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self { file, original })
    }
}
#[cfg(unix)]
impl Drop for Terminal {
    fn drop(&mut self) {
        use std::os::fd::AsRawFd;
        unsafe {
            libc::tcsetattr(self.file.as_raw_fd(), libc::TCSAFLUSH, &self.original);
        }
    }
}

#[cfg(windows)]
struct Terminal {
    handle: windows_sys::Win32::Foundation::HANDLE,
    original: u32,
}
#[cfg(windows)]
impl Terminal {
    fn open() -> io::Result<Self> {
        use windows_sys::Win32::System::Console::*;
        let handle = unsafe { GetStdHandle(STD_INPUT_HANDLE) };
        let mut original = 0;
        if unsafe { GetConsoleMode(handle, &mut original) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let mode = original & !(ENABLE_ECHO_INPUT | ENABLE_LINE_INPUT | ENABLE_PROCESSED_INPUT);
        if unsafe { SetConsoleMode(handle, mode) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self { handle, original })
    }
}
#[cfg(windows)]
impl Drop for Terminal {
    fn drop(&mut self) {
        unsafe {
            windows_sys::Win32::System::Console::SetConsoleMode(self.handle, self.original);
        }
    }
}

impl Read for Terminal {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        #[cfg(unix)]
        let count = self.file.read(bytes)?;
        #[cfg(windows)]
        let count = io::stdin().read(bytes)?;
        Ok(count)
    }
}
