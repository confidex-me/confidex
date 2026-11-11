#![cfg(unix)]
use confidex_ssh_agent::{Identity, KeySource, Listener};
use confidex_vault::{
    record::Mapping,
    ssh::{Key, REQUIRED_MEMORY},
};
use std::{
    io,
    os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt},
    process::Command,
    time::Duration,
};

struct Source {
    value: Mapping,
    public: Vec<u8>,
}
impl KeySource for Source {
    fn identities(&mut self) -> io::Result<Vec<Identity>> {
        Ok(vec![Identity {
            public_key: self.public.clone(),
            comment: "synthetic fixture".into(),
        }])
    }
    fn load(&mut self, _: &[u8]) -> io::Result<Key> {
        Key::from_value(&self.value, REQUIRED_MEMORY).map_err(|_| io::ErrorKind::InvalidData.into())
    }
}
#[test]
fn openssh_lists_and_tests_a_key_over_an_owner_only_peer_checked_socket() {
    let private = ssh_key::PrivateKey::new(
        ssh_key::private::Ed25519Keypair::from_seed(&[42; 32]).into(),
        "fixture",
    )
    .unwrap();
    let pem = private.to_openssh(ssh_key::LineEnding::LF).unwrap();
    let key = Key::import(pem.as_bytes(), None, REQUIRED_MEMORY).unwrap();
    let mut source = Source {
        value: key.to_value().unwrap(),
        public: key.public_blob().unwrap(),
    };
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::path::PathBuf::from(format!(
        "/tmp/confidex-agent-{}-{unique}",
        std::process::id()
    ));
    std::fs::DirBuilder::new().mode(0o700).create(&dir).unwrap();
    let socket = dir.join("agent.sock");
    let public = dir.join("key.pub");
    std::fs::write(&public, private.public_key().to_openssh().unwrap()).unwrap();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
    assert_eq!(
        Listener::bind(&socket).err().unwrap().kind(),
        io::ErrorKind::PermissionDenied
    );
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    let listener = Listener::bind(&socket).unwrap();
    assert!(Listener::bind(&socket).is_err());
    assert_eq!(std::fs::metadata(&socket).unwrap().mode() & 0o777, 0o600);
    let server = std::thread::spawn(move || {
        let mut approvals = 0;
        for _ in 0..2 {
            let mut connection = listener.accept().unwrap();
            connection.set_io_timeout(Duration::from_secs(5)).unwrap();
            assert_eq!(connection.peer().uid, unsafe { libc::geteuid() });
            while connection
                .handle_one(&mut source, &mut |_| {
                    approvals += 1;
                    true
                })
                .unwrap()
            {}
        }
        for expected in [io::ErrorKind::InvalidData, io::ErrorKind::UnexpectedEof] {
            let mut connection = listener.accept().unwrap();
            assert_eq!(
                connection
                    .handle_one(&mut source, &mut |_| panic!("bad packet"))
                    .err()
                    .unwrap()
                    .kind(),
                expected
            );
            assert_eq!(
                connection
                    .handle_one(&mut source, &mut |_| panic!("poisoned connection"))
                    .err()
                    .unwrap()
                    .kind(),
                io::ErrorKind::BrokenPipe
            );
        }
        approvals
    });
    let list = Command::new("ssh-add")
        .arg("-L")
        .env("SSH_AUTH_SOCK", &socket)
        .output()
        .unwrap();
    assert!(
        list.status.success(),
        "{}",
        String::from_utf8_lossy(&list.stderr)
    );
    assert!(
        String::from_utf8(list.stdout)
            .unwrap()
            .starts_with("ssh-ed25519 ")
    );
    let test = Command::new("ssh-add")
        .arg("-T")
        .arg(&public)
        .env("SSH_AUTH_SOCK", &socket)
        .output()
        .unwrap();
    assert!(
        test.status.success(),
        "{}",
        String::from_utf8_lossy(&test.stderr)
    );
    use std::io::Write;
    {
        let mut client = std::os::unix::net::UnixStream::connect(&socket).unwrap();
        client
            .write_all(&((confidex_ssh_agent::MAX_REQUEST + 1) as u32).to_be_bytes())
            .unwrap();
    }
    {
        let mut client = std::os::unix::net::UnixStream::connect(&socket).unwrap();
        client.write_all(&10u32.to_be_bytes()).unwrap();
        client.write_all(&[13]).unwrap();
    }
    assert!(server.join().unwrap() > 0);
    std::fs::remove_file(public).unwrap();
    std::fs::remove_dir(dir).unwrap();
}
