use confidex_vault::ssh::Key;
#[cfg(unix)]
use interprocess::local_socket::GenericFilePath;
#[cfg(windows)]
use interprocess::local_socket::GenericNamespaced;
use interprocess::local_socket::{Listener as LocalListener, ListenerOptions, Stream, prelude::*};
use std::{
    io::{self, Read, Write},
    time::Duration,
};
use zeroize::Zeroizing;

mod protocol;

pub const MAX_IDENTITIES: usize = 256;
pub const MAX_REQUEST: usize = 40 * 1024;
pub const MAX_RESPONSE: usize = 128 * 1024;

pub struct Identity {
    pub public_key: Vec<u8>,
    pub comment: String,
}
pub trait KeySource {
    fn identities(&mut self) -> io::Result<Vec<Identity>>;
    fn load(&mut self, public_key: &[u8]) -> io::Result<Key>;
}
#[derive(Clone, Copy, Debug)]
pub struct Peer {
    pub pid: Option<u32>,
    #[cfg(unix)]
    pub uid: u32,
}
pub struct SignRequest<'a> {
    pub peer: Peer,
    pub public_key: &'a [u8],
    pub data: &'a [u8],
}
pub struct Listener {
    inner: LocalListener,
}
pub struct Connection {
    stream: Stream,
    peer: Peer,
    usable: bool,
}

fn denied() -> io::Error {
    io::ErrorKind::PermissionDenied.into()
}
fn invalid() -> io::Error {
    io::ErrorKind::InvalidData.into()
}

impl Listener {
    #[cfg(unix)]
    pub fn bind(path: &std::path::Path) -> io::Result<Self> {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let parent = std::fs::symlink_metadata(path.parent().ok_or_else(invalid)?)?;
        // The private directory protects the bind-to-chmod interval on macOS.
        let uid = unsafe { libc::geteuid() };
        if !parent.is_dir() || parent.uid() != uid || parent.mode() & 0o077 != 0 {
            return Err(denied());
        }
        let inner = ListenerOptions::new()
            .name(path.to_fs_name::<GenericFilePath>()?)
            .create_sync()?;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        Ok(Self { inner })
    }
    #[cfg(windows)]
    pub fn bind(name: &str) -> io::Result<Self> {
        use interprocess::os::windows::{
            local_socket::ListenerOptionsExt, security_descriptor::SecurityDescriptor,
        };
        use widestring::u16cstr;
        let sd = SecurityDescriptor::deserialize(u16cstr!("D:P(A;;GA;;;OW)"))?;
        let inner = ListenerOptions::new()
            .name(name.to_ns_name::<GenericNamespaced>()?)
            .security_descriptor(sd)
            .create_sync()?;
        Ok(Self { inner })
    }
    pub fn accept(&self) -> io::Result<Connection> {
        let stream = self.inner.accept()?;
        let credentials = stream.peer_creds()?;
        #[cfg(unix)]
        if credentials.euid() != Some(unsafe { libc::geteuid() }) {
            return Err(denied());
        }
        #[cfg(unix)]
        let pid = credentials.pid().and_then(|n| u32::try_from(n).ok());
        #[cfg(windows)]
        let pid = credentials.pid();
        let peer = Peer {
            pid,
            #[cfg(unix)]
            uid: credentials.euid().ok_or_else(denied)?,
        };
        Ok(Connection {
            stream,
            peer,
            usable: true,
        })
    }
}
impl Connection {
    pub fn set_io_timeout(&self, timeout: Duration) -> io::Result<()> {
        if timeout.is_zero() || timeout > Duration::from_secs(60) {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        self.stream.set_recv_timeout(Some(timeout))?;
        self.stream.set_send_timeout(Some(timeout))
    }
    pub fn peer(&self) -> Peer {
        self.peer
    }
    pub fn handle_one(
        &mut self,
        source: &mut impl KeySource,
        approve: &mut impl FnMut(&SignRequest<'_>) -> bool,
    ) -> io::Result<bool> {
        if !std::mem::replace(&mut self.usable, false) {
            return Err(io::ErrorKind::BrokenPipe.into());
        }
        let result = self.process_one(source, approve);
        self.usable = matches!(result, Ok(true));
        result
    }
    fn process_one(
        &mut self,
        source: &mut impl KeySource,
        approve: &mut impl FnMut(&SignRequest<'_>) -> bool,
    ) -> io::Result<bool> {
        let mut prefix = [0; 4];
        loop {
            match self.stream.read(&mut prefix[..1]) {
                Ok(0) => return Ok(false),
                Ok(_) => break,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            }
        }
        self.stream.read_exact(&mut prefix[1..])?;
        let length = u32::from_be_bytes(prefix) as usize;
        if length == 0 || length > MAX_REQUEST {
            return Err(invalid());
        }
        let mut bytes = Zeroizing::new(Vec::new());
        bytes
            .try_reserve_exact(length)
            .map_err(|_| io::ErrorKind::OutOfMemory)?;
        bytes.resize(length, 0);
        self.stream.read_exact(&mut bytes)?;
        let response = protocol::dispatch(&bytes, self.peer, source, approve)
            .unwrap_or_else(|_| Zeroizing::new(vec![5]));
        self.stream
            .write_all(&(response.len() as u32).to_be_bytes())?;
        self.stream.write_all(&response)?;
        self.stream.flush()?;
        Ok(true)
    }
}
