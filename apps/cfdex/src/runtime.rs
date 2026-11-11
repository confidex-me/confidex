use crate::{
    protocol,
    socket::{Connection, Listener},
};
use sha2::{Digest, Sha256};
#[cfg(unix)]
use std::fs::{OpenOptions, TryLockError};
use std::{
    fs::{self, File},
    io,
    path::PathBuf,
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

pub struct Location {
    pub database: PathBuf,
    pub endpoint: PathBuf,
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

pub fn id<const N: usize>(text: &str) -> Option<[u8; N]> {
    let text = if N == 16 && text.len() == 36 {
        if ![8, 13, 18, 23]
            .iter()
            .all(|index| text.as_bytes()[*index] == b'-')
        {
            return None;
        }
        text.chars().filter(|ch| *ch != '-').collect::<String>()
    } else {
        text.to_owned()
    };
    if text.len() != N * 2 || !text.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    let mut bytes = [0; N];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&text[index * 2..index * 2 + 2], 16).ok()?;
    }
    Some(bytes)
}

impl Location {
    pub fn new(database: PathBuf) -> io::Result<Self> {
        let database = if database.exists() {
            fs::canonicalize(database)?
        } else {
            let absolute = std::path::absolute(database)?;
            let parent = absolute.parent().ok_or(io::ErrorKind::InvalidInput)?;
            fs::create_dir_all(parent)?;
            fs::canonicalize(parent)?.join(absolute.file_name().ok_or(io::ErrorKind::InvalidInput)?)
        };
        let mut hash = Sha256::new();
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStrExt;
            hash.update(database.as_os_str().as_bytes());
        }
        #[cfg(windows)]
        {
            use std::os::windows::ffi::OsStrExt;
            for word in database.as_os_str().encode_wide() {
                hash.update(word.to_le_bytes());
            }
            hash.update(crate::socket::identity()?.as_bytes());
        }
        let hash = hex(&hash.finalize());
        #[cfg(unix)]
        let endpoint = {
            use std::os::unix::fs::{DirBuilderExt, MetadataExt};
            let directory =
                PathBuf::from(format!("/tmp/cfdex-{}-{hash}", unsafe { libc::geteuid() }));
            match fs::DirBuilder::new().mode(0o700).create(&directory) {
                Ok(()) => (),
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => (),
                Err(error) => return Err(error),
            }
            let metadata = fs::symlink_metadata(&directory)?;
            if !metadata.is_dir()
                || metadata.uid() != unsafe { libc::geteuid() }
                || metadata.mode() & 0o077 != 0
            {
                return Err(io::ErrorKind::PermissionDenied.into());
            }
            directory.join("agent.sock")
        };
        #[cfg(windows)]
        let endpoint = PathBuf::from(format!("cfdex-{hash}"));
        Ok(Self { database, endpoint })
    }

    pub fn lock(&self) -> io::Result<Option<File>> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(false)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(self.endpoint.with_file_name("agent.lock"))?;
            let metadata = file.metadata()?;
            if !metadata.is_file()
                || metadata.uid() != unsafe { libc::geteuid() }
                || metadata.mode() & 0o077 != 0
            {
                return Err(io::ErrorKind::PermissionDenied.into());
            }
            file.try_lock().map_err(|error| match error {
                TryLockError::WouldBlock => io::ErrorKind::WouldBlock.into(),
                TryLockError::Error(error) => error,
            })?;
            Ok(Some(file))
        }
        #[cfg(windows)]
        {
            Ok(None)
        }
    }

    pub fn listener(&self) -> io::Result<Listener> {
        #[cfg(unix)]
        if let Ok(metadata) = fs::symlink_metadata(&self.endpoint) {
            use std::os::unix::fs::{FileTypeExt, MetadataExt};
            if !metadata.file_type().is_socket()
                || metadata.uid() != unsafe { libc::geteuid() }
                || metadata.mode() & 0o077 != 0
            {
                return Err(io::ErrorKind::PermissionDenied.into());
            }
            match Connection::connect(&self.endpoint) {
                Ok(_) => return Err(io::ErrorKind::AddrInUse.into()),
                Err(error) if error.kind() == io::ErrorKind::ConnectionRefused => {
                    fs::remove_file(&self.endpoint)?
                }
                Err(error) => return Err(error),
            }
        }
        Listener::bind(&self.endpoint)
    }

    pub fn connect(&self, start: bool) -> io::Result<Connection> {
        match Connection::connect(&self.endpoint) {
            Ok(connection) => return Ok(connection),
            Err(error)
                if start
                    && matches!(
                        error.kind(),
                        io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused
                    ) =>
            {
                ()
            }
            Err(error) => return Err(error),
        }
        let mut command = Command::new(std::env::current_exe()?);
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            // Keep the agent alive when the client's controlling terminal closes.
            unsafe {
                command.pre_exec(|| {
                    if libc::setsid() < 0 {
                        return Err(io::Error::last_os_error());
                    }
                    Ok(())
                });
            }
        }
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            use windows_sys::Win32::{
                Foundation::{HANDLE_FLAG_INHERIT, INVALID_HANDLE_VALUE, SetHandleInformation},
                System::{
                    Console::{
                        GetStdHandle, STD_ERROR_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE,
                    },
                    Threading::CREATE_NO_WINDOW,
                },
            };
            // The agent must not keep the client's redirected streams open.
            for stream in [STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, STD_ERROR_HANDLE] {
                let handle = unsafe { GetStdHandle(stream) };
                if !handle.is_null()
                    && handle != INVALID_HANDLE_VALUE
                    && unsafe { SetHandleInformation(handle, HANDLE_FLAG_INHERIT, 0) } == 0
                {
                    return Err(io::Error::last_os_error());
                }
            }
            command.creation_flags(CREATE_NO_WINDOW);
        }
        let mut child: Child = command
            .arg("--database")
            .arg(&self.database)
            .arg("agent")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            match Connection::connect(&self.endpoint) {
                Ok(connection) => return Ok(connection),
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused
                    ) =>
                {
                    ()
                }
                Err(error) => return Err(error),
            }
            let _ = child.try_wait()?;
            if Instant::now() >= deadline {
                return Err(io::ErrorKind::TimedOut.into());
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    pub fn call(
        &self,
        request: &protocol::Request,
        start: bool,
    ) -> io::Result<(protocol::Response, zeroize::Zeroizing<Vec<u8>>)> {
        let mut connection = self.connect(start)?;
        protocol::write_request(&mut connection, request)?;
        protocol::read_response(&mut connection, request)
    }
}

pub fn harden() -> io::Result<()> {
    #[cfg(unix)]
    {
        if unsafe {
            libc::setrlimit(
                libc::RLIMIT_CORE,
                &libc::rlimit {
                    rlim_cur: 0,
                    rlim_max: 0,
                },
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }
    }
    #[cfg(target_os = "linux")]
    if unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

pub(crate) fn private_file(path: &std::path::Path) -> io::Result<File> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
    }
    #[cfg(windows)]
    {
        use interprocess::os::windows::security_descriptor::AsSecurityDescriptor;
        use std::os::windows::{ffi::OsStrExt, io::FromRawHandle};
        use windows_sys::Win32::{
            Foundation::{GENERIC_WRITE, INVALID_HANDLE_VALUE},
            Security::SECURITY_ATTRIBUTES,
            Storage::FileSystem::{CREATE_NEW, CreateFileW, FILE_ATTRIBUTE_NORMAL},
        };
        let mut name: Vec<u16> = path.as_os_str().encode_wide().collect();
        if name.contains(&0) {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        name.push(0);
        let descriptor = crate::socket::descriptor()?;
        let security = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: descriptor.as_sd().cast_mut(),
            bInheritHandle: 0,
        };
        let handle = unsafe {
            CreateFileW(
                name.as_ptr(),
                GENERIC_WRITE,
                0,
                &security,
                CREATE_NEW,
                FILE_ATTRIBUTE_NORMAL,
                std::ptr::null_mut(),
            )
        };
        if handle == INVALID_HANDLE_VALUE {
            return Err(io::Error::last_os_error());
        }
        Ok(unsafe { File::from_raw_handle(handle) })
    }
}

pub fn io_failure(error: io::Error) -> protocol::Failure {
    protocol::Failure {
        code: if error.kind() == io::ErrorKind::PermissionDenied {
            protocol::Code::Auth
        } else {
            protocol::Code::Io
        },
        message: "The I/O operation failed.".into(),
    }
}

pub fn protocol_failure(error: io::Error) -> protocol::Failure {
    use protocol::{Code, Failure};
    let (code, message) = match error.kind() {
        io::ErrorKind::PermissionDenied => (Code::Auth, "Access denied."),
        io::ErrorKind::InvalidInput => (Code::Input, "Invalid input."),
        io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused => {
            (Code::Protocol, "The agent is not running.")
        }
        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock => (
            Code::Protocol,
            "The agent did not respond before the deadline.",
        ),
        io::ErrorKind::InvalidData | io::ErrorKind::UnexpectedEof | io::ErrorKind::BrokenPipe => {
            (Code::Protocol, "The agent exchange failed.")
        }
        _ => (Code::Io, "The operation failed."),
    };
    Failure {
        code,
        message: message.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn stable_ids_are_strict_and_roundtrip() {
        assert_eq!(
            id::<16>("00112233-4455-6677-8899-aabbccddeeff"),
            Some([
                0, 17, 34, 51, 68, 85, 102, 119, 136, 153, 170, 187, 204, 221, 238, 255
            ])
        );
        assert!(id::<16>("00112233445566778899aabbccddee-f-f").is_none());
        assert!(id::<16>("+0112233445566778899aabbccddeeff").is_none());
        assert_eq!(id::<32>(&hex(&[42; 32])), Some([42; 32]));
        assert!(id::<16>("this is a title").is_none());
    }
    #[cfg(unix)]
    #[test]
    fn startup_lock_is_exclusive_and_never_removes_foreign_files() {
        let directory = tempfile::tempdir().unwrap();
        let location = Location::new(directory.path().join("vault.sqlite")).unwrap();
        let guard = location.lock().unwrap();
        assert_eq!(
            location.lock().unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        fs::write(&location.endpoint, b"keep").unwrap();
        assert!(location.listener().is_err());
        assert_eq!(fs::read(&location.endpoint).unwrap(), b"keep");
        fs::remove_file(&location.endpoint).unwrap();
        drop(guard);
        assert!(location.lock().is_ok());
        fs::remove_file(location.endpoint.with_file_name("agent.lock")).unwrap();
        fs::remove_dir(location.endpoint.parent().unwrap()).unwrap();
    }
}
