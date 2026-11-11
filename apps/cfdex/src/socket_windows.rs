use interprocess::{
    ConnectWaitMode,
    local_socket::{Stream, prelude::*},
    os::windows::{
        named_pipe::{
            DuplexPipeStream, PipeListener, PipeListenerOptions,
            local_socket::Stream as PipeStream, pipe_mode::Bytes,
        },
        security_descriptor::SecurityDescriptor,
    },
};
use std::{
    io::{self, Read, Write},
    os::windows::io::{AsHandle, AsRawHandle, FromRawHandle, OwnedHandle},
    path::Path,
    time::{Duration, Instant},
};
use windows_sys::Win32::{
    Foundation::{ERROR_NO_DATA, ERROR_PIPE_NOT_CONNECTED, HANDLE, LocalFree},
    Security::{
        Authorization::ConvertSidToStringSidW, EqualSid, GetTokenInformation, TOKEN_QUERY,
        TOKEN_USER, TokenUser,
    },
    System::{
        Pipes::PeekNamedPipe,
        Threading::{
            GetCurrentProcess, OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION,
        },
    },
};

pub struct Listener {
    inner: PipeListener<Bytes, Bytes>,
}
pub struct Connection {
    stream: Stream,
    deadline: Instant,
}

fn denied() -> io::Error {
    io::ErrorKind::PermissionDenied.into()
}

fn name(path: &Path) -> io::Result<&str> {
    path.to_str()
        .filter(|name| {
            !name.is_empty()
                && name.len() <= 160
                && name
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'.')
        })
        .ok_or_else(|| io::ErrorKind::InvalidInput.into())
}

fn user(process: HANDLE) -> io::Result<Vec<usize>> {
    let mut token = std::ptr::null_mut();
    if unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut token) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let token = unsafe { OwnedHandle::from_raw_handle(token) };
    let mut storage = vec![0usize; 128];
    let mut length = 0;
    if unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            TokenUser,
            storage.as_mut_ptr().cast(),
            (storage.len() * std::mem::size_of::<usize>()) as u32,
            &mut length,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    if length < std::mem::size_of::<TOKEN_USER>() as u32
        || length as usize > storage.len() * std::mem::size_of::<usize>()
    {
        return Err(denied());
    }
    Ok(storage)
}

fn sid(storage: &[usize]) -> *mut std::ffi::c_void {
    unsafe { (*storage.as_ptr().cast::<TOKEN_USER>()).User.Sid }
}

fn same_user(pid: u32) -> io::Result<()> {
    let peer = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if peer.is_null() {
        return Err(io::Error::last_os_error());
    }
    let peer = unsafe { OwnedHandle::from_raw_handle(peer) };
    let peer = user(peer.as_raw_handle())?;
    let own = user(unsafe { GetCurrentProcess() })?;
    if unsafe { EqualSid(sid(&peer), sid(&own)) } == 0 {
        return Err(denied());
    }
    Ok(())
}

pub(crate) fn identity() -> io::Result<String> {
    let own = user(unsafe { GetCurrentProcess() })?;
    let mut text = std::ptr::null_mut();
    if unsafe { ConvertSidToStringSidW(sid(&own), &mut text) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let result = unsafe { widestring::U16CStr::from_ptr_str(text) }.to_string();
    unsafe {
        LocalFree(text.cast());
    }
    result.map_err(|_| denied())
}

pub(crate) fn descriptor() -> io::Result<SecurityDescriptor> {
    let text = identity()?;
    let sddl = widestring::U16CString::from_str(format!("O:{text}D:P(A;;GA;;;{text})"))
        .map_err(|_| denied())?;
    SecurityDescriptor::deserialize(&sddl)
}

impl Listener {
    pub fn bind(path: &Path) -> io::Result<Self> {
        let inner = PipeListenerOptions::new()
            .path(format!(r"\\.\pipe\{}", name(path)?))
            .security_descriptor(Some(descriptor()?))
            .input_buffer_size_hint(64 * 1024)
            .output_buffer_size_hint(64 * 1024)
            .create_duplex()?;
        Ok(Self { inner })
    }
    pub fn set_nonblocking(&self, enabled: bool) -> io::Result<()> {
        self.inner.set_nonblocking(enabled)
    }
    pub fn accept(&self) -> io::Result<Connection> {
        Connection::verified(Stream::NamedPipe(PipeStream::from(self.inner.accept()?)))
    }
}

impl Connection {
    fn verified(stream: Stream) -> io::Result<Self> {
        same_user(stream.peer_creds()?.pid().ok_or_else(denied)?)?;
        stream.set_nonblocking(true)?;
        Ok(Self {
            stream,
            deadline: Instant::now() + Duration::from_secs(60),
        })
    }
    pub fn connect(path: &Path) -> io::Result<Self> {
        // Use the pipe API: the generic stream ignores wait_mode in interprocess 2.4.7.
        let pipe = DuplexPipeStream::<Bytes>::connect_by_path_with_wait_mode(
            format!(r"\\.\pipe\{}", name(path)?),
            ConnectWaitMode::Timeout(Duration::from_secs(5)),
        )?;
        Self::verified(Stream::NamedPipe(PipeStream::from(pipe)))
    }
    pub fn set_io_timeout(&mut self, timeout: Duration) -> io::Result<()> {
        if timeout.is_zero() || timeout > Duration::from_secs(60) {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        self.deadline = Instant::now() + timeout;
        Ok(())
    }
    fn remaining(&self) -> io::Result<Duration> {
        self.deadline
            .checked_duration_since(Instant::now())
            .filter(|time| !time.is_zero())
            .ok_or_else(|| io::ErrorKind::TimedOut.into())
    }
    fn wait(&self) -> io::Result<()> {
        std::thread::sleep(self.remaining()?.min(Duration::from_millis(1)));
        Ok(())
    }
}

fn retry(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
    ) || error.raw_os_error() == Some(ERROR_NO_DATA as i32)
}
impl Read for Connection {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        if bytes.is_empty() {
            return Ok(0);
        }
        loop {
            self.remaining()?;
            match self.stream.read(bytes) {
                Ok(0) => {
                    // Interprocess can report an empty pipe as end of file.
                    let Stream::NamedPipe(pipe) = &self.stream;
                    let connected = unsafe {
                        PeekNamedPipe(
                            pipe.inner().as_handle().as_raw_handle(),
                            std::ptr::null_mut(),
                            0,
                            std::ptr::null_mut(),
                            std::ptr::null_mut(),
                            std::ptr::null_mut(),
                        )
                    };
                    if connected == 0 {
                        let error = io::Error::last_os_error();
                        if !retry(&error) {
                            return if error.kind() == io::ErrorKind::BrokenPipe
                                || error.raw_os_error() == Some(ERROR_PIPE_NOT_CONNECTED as i32)
                            {
                                Ok(0)
                            } else {
                                Err(error)
                            };
                        }
                    }
                    self.wait()?;
                }
                Err(error) if retry(&error) => self.wait()?,
                result => return result,
            }
        }
    }
}
impl Write for Connection {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.is_empty() {
            return Ok(0);
        }
        // Keep each write smaller than the pipe buffer.
        let bytes = &bytes[..bytes.len().min(16 * 1024)];
        loop {
            self.remaining()?;
            match self.stream.write(bytes) {
                Ok(0) => self.wait()?,
                Err(error) if retry(&error) => self.wait()?,
                result => return result,
            }
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        self.stream.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pipe_names_cannot_select_a_remote_host_or_another_path() {
        for invalid in ["", r"\\host\pipe\test", "a/b", "a\\b", "a\0b", "../a"] {
            assert!(name(Path::new(invalid)).is_err());
        }
        assert!(name(Path::new("cfdex-123.public-test")).is_ok());
    }

    #[test]
    fn owner_checked_pipe_roundtrip_and_deadline() {
        let name = format!(
            "cfdex-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let path = std::path::PathBuf::from(name);
        let listener = Listener::bind(&path).unwrap();
        assert!(Listener::bind(&path).is_err());
        use windows_sys::Win32::{
            Security::{ImpersonateAnonymousToken, RevertToSelf},
            System::Threading::GetCurrentThread,
        };
        assert_ne!(unsafe { ImpersonateAnonymousToken(GetCurrentThread()) }, 0);
        let denied = Connection::connect(&path);
        assert_ne!(unsafe { RevertToSelf() }, 0);
        assert!(matches!(denied, Err(error) if error.kind() == io::ErrorKind::PermissionDenied));
        let mut client = Connection::connect(&path).unwrap();
        let mut server = listener.accept().unwrap();
        client.write_all(b"public").unwrap();
        let mut bytes = [0; 6];
        server.read_exact(&mut bytes).unwrap();
        assert_eq!(&bytes, b"public");
        server.set_io_timeout(Duration::from_millis(30)).unwrap();
        assert_eq!(
            server.read(&mut bytes).unwrap_err().kind(),
            io::ErrorKind::TimedOut
        );
        drop(client);
        server.set_io_timeout(Duration::from_secs(1)).unwrap();
        assert_eq!(server.read(&mut bytes).unwrap(), 0);
        assert!(same_user(0).is_err());
    }
}
