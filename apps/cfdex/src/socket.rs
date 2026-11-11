use interprocess::ConnectWaitMode;
use interprocess::local_socket::{
    ConnectOptions, GenericFilePath, Listener as LocalListener, ListenerNonblockingMode,
    ListenerOptions, Stream, prelude::*,
};
use std::{
    fs,
    io::{self, Read, Write},
    os::fd::{AsFd, AsRawFd},
    os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

pub struct Listener {
    inner: LocalListener,
    path: PathBuf,
    identity: (u64, u64),
}

pub struct Connection {
    stream: Stream,
    deadline: Instant,
}

fn denied() -> io::Error {
    io::ErrorKind::PermissionDenied.into()
}

fn check_uid(uid: Option<u32>) -> io::Result<()> {
    if uid != Some(unsafe { libc::geteuid() }) {
        return Err(denied());
    }
    Ok(())
}

fn private_parent(path: &Path) -> io::Result<()> {
    let parent = path.parent().ok_or(io::ErrorKind::InvalidInput)?;
    let metadata = fs::symlink_metadata(parent)?;
    if !metadata.is_dir() || metadata.mode() & 0o077 != 0 {
        return Err(denied());
    }
    check_uid(Some(metadata.uid()))
}

fn private_socket(path: &Path) -> io::Result<fs::Metadata> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_socket() || metadata.mode() & 0o077 != 0 {
        return Err(denied());
    }
    check_uid(Some(metadata.uid()))?;
    Ok(metadata)
}

impl Listener {
    pub fn bind(path: &Path) -> io::Result<Self> {
        private_parent(path)?;
        let inner = ListenerOptions::new()
            .name(path.to_fs_name::<GenericFilePath>()?)
            .reclaim_name(false)
            .create_sync()?;
        let metadata = fs::symlink_metadata(path)?;
        let listener = Self {
            inner,
            path: path.to_owned(),
            identity: (metadata.dev(), metadata.ino()),
        };
        // The private parent protects the bind-to-chmod interval on macOS.
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
        Ok(listener)
    }

    pub fn set_nonblocking(&self, enabled: bool) -> io::Result<()> {
        self.inner.set_nonblocking(if enabled {
            ListenerNonblockingMode::Accept
        } else {
            ListenerNonblockingMode::Neither
        })
    }

    pub fn accept(&self) -> io::Result<Connection> {
        Connection::verified(self.inner.accept()?)
    }
}

impl Drop for Listener {
    fn drop(&mut self) {
        if fs::symlink_metadata(&self.path).is_ok_and(|metadata| {
            metadata.file_type().is_socket() && (metadata.dev(), metadata.ino()) == self.identity
        }) {
            let _ = fs::remove_file(&self.path);
        }
    }
}

impl Connection {
    fn verified(stream: Stream) -> io::Result<Self> {
        check_uid(stream.peer_creds()?.euid())?;
        stream.set_nonblocking(true)?;
        Ok(Self {
            stream,
            deadline: Instant::now() + Duration::from_secs(60),
        })
    }

    pub fn connect(path: &Path) -> io::Result<Self> {
        private_parent(path)?;
        private_socket(path)?;
        Self::verified(
            ConnectOptions::new()
                .name(path.to_fs_name::<GenericFilePath>()?)
                .wait_mode(ConnectWaitMode::Timeout(Duration::from_secs(5)))
                .connect_sync()?,
        )
    }

    pub fn set_io_timeout(&mut self, timeout: Duration) -> io::Result<()> {
        if timeout.is_zero() || timeout > Duration::from_secs(60) {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        self.deadline = Instant::now() + timeout;
        Ok(())
    }

    fn wait(&self, events: i16) -> io::Result<()> {
        loop {
            let remaining = self
                .deadline
                .checked_duration_since(Instant::now())
                .filter(|time| !time.is_zero())
                .ok_or(io::ErrorKind::TimedOut)?;
            let Stream::UdSocket(stream) = &self.stream;
            let mut poll = libc::pollfd {
                fd: stream.as_fd().as_raw_fd(),
                events,
                revents: 0,
            };
            let milliseconds = remaining
                .as_millis()
                .saturating_add(1)
                .min(i32::MAX as u128) as i32;
            let result = unsafe { libc::poll(&mut poll, 1, milliseconds) };
            if result > 0 {
                return Ok(());
            }
            if result == 0 {
                return Err(io::ErrorKind::TimedOut.into());
            }
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::Interrupted {
                return Err(error);
            }
        }
    }
}

impl Read for Connection {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        if bytes.is_empty() {
            return Ok(0);
        }
        loop {
            self.wait(libc::POLLIN)?;
            match self.stream.read(bytes) {
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                    ) =>
                {
                    ()
                }
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
        loop {
            self.wait(libc::POLLOUT)?;
            match self.stream.write(bytes) {
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                    ) =>
                {
                    ()
                }
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
    use crate::protocol::{self, Operation, Reply, Request, Response, VERSION};

    fn directory() -> tempfile::TempDir {
        {
            let directory = tempfile::Builder::new()
                .prefix("cfdex-")
                .tempdir_in("/tmp")
                .unwrap();
            fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
            directory
        }
    }

    #[test]
    fn private_socket_roundtrip_checks_both_peers() {
        let directory = directory();
        let path = directory.path().join("agent.sock");
        let listener = Listener::bind(&path).unwrap();
        assert_eq!(fs::metadata(&path).unwrap().mode() & 0o777, 0o600);
        assert!(Listener::bind(&path).is_err());
        let server = std::thread::spawn(move || {
            let mut connection = listener.accept().unwrap();
            let request = protocol::read_request(&mut connection).unwrap();
            protocol::write_response(
                &mut connection,
                &Response {
                    version: VERSION,
                    id: request.id,
                    vault: Some([1; 16]),
                    result: Ok(Reply::Status { unlocked: false }),
                },
                b"",
            )
            .unwrap();
        });
        let mut client = Connection::connect(&path).unwrap();
        let request = Request {
            version: VERSION,
            id: 91,
            vault: Some([1; 16]),
            command: Operation::Status {},
        };
        protocol::write_request(&mut client, &request).unwrap();
        server.join().unwrap();
        let (response, payload) = protocol::read_response(&mut client, &request).unwrap();
        assert!(matches!(
            response.result,
            Ok(Reply::Status { unlocked: false })
        ));
        assert!(payload.is_empty());
        assert!(!path.exists());
    }

    #[test]
    fn denies_public_parents_symlinks_and_wrong_peers() {
        let directory = directory();
        let path = directory.path().join("agent.sock");
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(
            Listener::bind(&path).err().unwrap().kind(),
            io::ErrorKind::PermissionDenied
        );
        assert!(Connection::connect(&path).is_err());
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let link = directory.path().join("link");
        std::os::unix::fs::symlink(directory.path(), &link).unwrap();
        assert!(Listener::bind(&link.join("agent.sock")).is_err());
        assert!(check_uid(None).is_err());
        assert!(check_uid(Some(unsafe { libc::geteuid() }.wrapping_add(1))).is_err());
        fs::write(&path, b"keep").unwrap();
        assert!(Connection::connect(&path).is_err());
        assert!(Listener::bind(&path).is_err());
        assert_eq!(fs::read(path).unwrap(), b"keep");
    }

    #[test]
    fn timeout_is_finite_and_drop_keeps_a_replacement_path() {
        let directory = directory();
        let path = directory.path().join("agent.sock");
        let listener = Listener::bind(&path).unwrap();
        let _client = Connection::connect(&path).unwrap();
        let mut connection = listener.accept().unwrap();
        assert!(connection.set_io_timeout(Duration::ZERO).is_err());
        assert!(connection.set_io_timeout(Duration::from_secs(61)).is_err());
        connection
            .set_io_timeout(Duration::from_millis(30))
            .unwrap();
        let error = connection.read(&mut [0; 1]).unwrap_err();
        assert!(matches!(
            error.kind(),
            io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
        ));
        fs::remove_file(&path).unwrap();
        fs::write(&path, b"keep").unwrap();
        drop(listener);
        assert_eq!(fs::read(path).unwrap(), b"keep");
    }

    #[test]
    fn a_slow_writer_cannot_restart_the_request_deadline() {
        let directory = directory();
        let path = directory.path().join("agent.sock");
        let listener = Listener::bind(&path).unwrap();
        let mut client = Connection::connect(&path).unwrap();
        let mut server = listener.accept().unwrap();
        server.set_io_timeout(Duration::from_millis(30)).unwrap();
        let writer = std::thread::spawn(move || {
            for _ in 0..10 {
                std::thread::sleep(Duration::from_millis(10));
                if client.write_all(b"x").is_err() {
                    break;
                }
            }
        });
        assert_eq!(
            server.read_exact(&mut [0; 10]).unwrap_err().kind(),
            io::ErrorKind::TimedOut
        );
        drop(server);
        writer.join().unwrap();
    }
}
