use cfdex::{
    protocol::{self, Code, Credentials, Operation, Reply, Request, Secret},
    runtime::Location,
};
use confidex_app::{Command as CoreCommand, DeviceKeys, Engine, Output};
use confidex_storage::{Store, VaultId};
use std::{
    io::{Read, Write},
    process::{Child, Command, Output as ProcessOutput, Stdio},
    time::{Duration, Instant},
};

const PASSWORD: &str = "PUBLIC-CFDEX-LIFECYCLE";

#[cfg(unix)]
#[test]
fn terminal_unlock_hides_input_and_restores_echo_on_cancel() {
    use std::fs::File;
    use std::os::{
        fd::{AsRawFd, FromRawFd},
        unix::process::CommandExt,
    };

    fn wait_for(terminal: &mut File, prompt: &[u8]) -> Vec<u8> {
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut output = Vec::new();
        let mut bytes = [0; 256];
        while !output.windows(prompt.len()).any(|window| window == prompt) {
            assert!(Instant::now() < deadline, "credential prompt was not shown");
            let mut poll = libc::pollfd {
                fd: terminal.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            if unsafe { libc::poll(&mut poll, 1, 50) } > 0 {
                let count = terminal.read(&mut bytes).unwrap();
                assert!(count != 0, "terminal closed before the prompt");
                output.extend_from_slice(&bytes[..count]);
            }
        }
        output
    }

    let mut fixture = Fixture::new();
    for cancel in [false, true] {
        let (mut master, mut slave) = (-1, -1);
        assert_eq!(
            unsafe {
                libc::openpty(
                    &mut master,
                    &mut slave,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                )
            },
            0
        );
        let mut master = unsafe { File::from_raw_fd(master) };
        let slave = unsafe { File::from_raw_fd(slave) };
        for fd in [master.as_raw_fd(), slave.as_raw_fd()] {
            assert_eq!(
                unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) },
                0
            );
        }
        let mode = || {
            let mut value = std::mem::MaybeUninit::uninit();
            assert_eq!(
                unsafe { libc::tcgetattr(slave.as_raw_fd(), value.as_mut_ptr()) },
                0
            );
            unsafe { value.assume_init() }
        };
        let original = mode().c_lflag;
        let mut command = Command::new("/bin/sh");
        command
            .args([
                "-c",
                "\"$@\"; result=$?; printf 'child done\\n' >&2; read -r line; exit \"$result\"",
                "pty-test",
                env!("CARGO_BIN_EXE_cfdex"),
            ])
            .arg("--database")
            .arg(&fixture.location.database)
            .args(["--vault", "Public one", "unlock"])
            .stdin(slave.try_clone().unwrap())
            .stderr(slave.try_clone().unwrap())
            .stdout(Stdio::null());
        unsafe {
            command.pre_exec(|| {
                if libc::setsid() == -1 || libc::ioctl(0, libc::TIOCSCTTY as _, 0) == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        fixture.children.push(command.spawn().unwrap());
        wait_for(&mut master, b"Secret key: ");
        assert_eq!(mode().c_lflag & libc::ECHO, 0);
        if cancel {
            master.write_all(b"\x03").unwrap();
        } else {
            master.write_all(fixture.vaults[0].key.as_bytes()).unwrap();
            master.write_all(b"\n").unwrap();
            let output = wait_for(&mut master, b"Master password: ");
            assert!(
                !output
                    .windows(fixture.vaults[0].key.len())
                    .any(|window| window == fixture.vaults[0].key.as_bytes())
            );
            assert_eq!(mode().c_lflag & libc::ECHO, 0);
            writeln!(master, "{PASSWORD}").unwrap();
        }
        let final_output = wait_for(&mut master, b"child done");
        assert!(
            !final_output
                .windows(PASSWORD.len())
                .any(|window| window == PASSWORD.as_bytes())
        );
        assert_eq!(mode().c_lflag, original);
        master.write_all(b"\n").unwrap();
        let child = fixture.children.last_mut().unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        let status = loop {
            if let Some(status) = child.try_wait().unwrap() {
                break status;
            }
            assert!(
                Instant::now() < deadline,
                "terminal unlock did not exit (cancel={cancel})"
            );
            let mut poll = libc::pollfd {
                fd: master.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            if unsafe { libc::poll(&mut poll, 1, 10) } > 0 && poll.revents & libc::POLLIN != 0 {
                let mut bytes = [0; 256];
                let _ = master.read(&mut bytes);
            }
        };
        assert_eq!(status.code(), Some(if cancel { 130 } else { 0 }));
        assert_eq!(fixture.unlocked(0), !cancel);
        let _ = fixture.rpc(Some(fixture.vaults[0].info.id), Operation::Lock {});
    }
}

#[cfg(target_os = "macos")]
#[test]
#[ignore = "requires an available macOS Keychain and Secure Enclave"]
fn reads_the_gui_device_key_from_a_separate_cli_process() {
    struct SavedKey(VaultId);
    impl Drop for SavedKey {
        fn drop(&mut self) {
            let _ = tokio::runtime::Builder::new_current_thread()
                .build()
                .unwrap()
                .block_on(confidex_native::Credentials.remove(self.0));
        }
    }

    let fixture = Fixture::new();
    let vault = &fixture.vaults[0];
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    assert!(matches!(
        confidex_native::load_key(vault.info.id, false),
        Ok(None)
    ));
    let saved = SavedKey(vault.info.id);
    assert!(
        runtime.block_on(confidex_native::Credentials.save(vault.info.id, &vault.key)),
        "cannot save the synthetic protected credential"
    );
    let credentials = serde_json::to_vec(&serde_json::json!({"password": PASSWORD})).unwrap();
    let unlocked = fixture.cli(
        &[
            "--vault",
            "Public one",
            "unlock",
            "--credentials-stdin",
            "--json",
        ],
        Some(&credentials),
    );
    assert!(
        unlocked.status.success(),
        "saved-key unlock failed: {}",
        String::from_utf8_lossy(&unlocked.stderr)
    );
    assert!(fixture.unlocked(0));
    assert!(unlocked.stderr.is_empty());
    assert!(
        !unlocked
            .stdout
            .windows(vault.key.len())
            .any(|bytes| bytes == vault.key.as_bytes())
    );
    assert!(
        fixture
            .cli(&["--vault", "Public one", "lock"], None)
            .status
            .success()
    );
    drop(saved);
    let missing = fixture.cli(
        &[
            "--vault",
            "Public one",
            "unlock",
            "--credentials-stdin",
            "--json",
        ],
        Some(&credentials),
    );
    assert_eq!(missing.status.code(), Some(3));
    assert!(missing.stdout.is_empty());
    assert!(!fixture.unlocked(0));
}

struct NoKeys;
impl DeviceKeys for NoKeys {
    async fn remove(&mut self, _: VaultId) -> bool {
        true
    }
    async fn load(&mut self, _: VaultId) -> Option<String> {
        None
    }
    async fn save(&mut self, _: VaultId, _: &str) -> bool {
        false
    }
}

struct Fixture {
    _directory: tempfile::TempDir,
    location: Location,
    vaults: Vec<confidex_app::Created>,
    children: Vec<Child>,
}
impl Fixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let location = Location::new(directory.path().join("vault.sqlite")).unwrap();
        let vaults = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap()
            .block_on(async {
                let mut store = confidex_native::open_store(&location.database).unwrap();
                let mut result = Vec::new();
                for name in ["Public one", "Public two"] {
                    let response = Engine::default()
                        .execute(
                            &mut store,
                            &mut NoKeys,
                            &mut confidex_app::Request {
                                generation: 1,
                                command: CoreCommand::Create {
                                    name: name.into(),
                                    password: PASSWORD.into(),
                                    remember: false,
                                },
                            },
                        )
                        .await;
                    let Output::Created(created) = response.result.unwrap() else {
                        panic!("created vault");
                    };
                    result.push(created);
                }
                result
            });
        Self {
            _directory: directory,
            location,
            vaults,
            children: Vec::new(),
        }
    }
    fn spawn(&mut self, timeout: u64) {
        self.children.push(
            Command::new(env!("CARGO_BIN_EXE_cfdex"))
                .arg("--database")
                .arg(&self.location.database)
                .arg("agent")
                .arg("--idle-timeout")
                .arg(timeout.to_string())
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap(),
        );
    }
    fn wait(&self) {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if cfdex::socket::Connection::connect(&self.location.endpoint).is_ok() {
                return;
            }
            assert!(Instant::now() < deadline, "agent startup deadline");
            std::thread::sleep(Duration::from_millis(10));
        }
    }
    fn rpc(&self, vault: Option<VaultId>, command: Operation) -> Result<Reply, protocol::Failure> {
        let request = Request {
            version: protocol::VERSION,
            id: 72,
            vault,
            command,
        };
        let (response, payload) = self.location.call(&request, false).unwrap();
        assert!(payload.is_empty());
        response.result
    }
    fn unlocked(&self, index: usize) -> bool {
        match self.rpc(Some(self.vaults[index].info.id), Operation::Status {}) {
            Ok(Reply::Status { unlocked }) => unlocked,
            _ => panic!("expected status"),
        }
    }
    fn unlock(&self, index: usize, password: &str) -> Result<Reply, protocol::Failure> {
        self.rpc(
            Some(self.vaults[index].info.id),
            Operation::Unlock {
                credentials: Credentials {
                    password: Secret(password.into()),
                    secret_key: Some(Secret(self.vaults[index].key.clone())),
                },
            },
        )
    }
    fn save_drafts(
        &self,
        created: &confidex_app::Created,
        drafts: Vec<confidex_app::Draft>,
        server: Option<String>,
    ) -> Vec<confidex_storage::Head> {
        tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap()
            .block_on(async {
                let mut store = confidex_native::open_store(&self.location.database).unwrap();
                let mut engine = Engine::default();
                let mut keys = NoKeys;
                let mut request = confidex_app::Request {
                    generation: 0,
                    command: CoreCommand::Unlock {
                        vault: created.info.id,
                        password: PASSWORD.into(),
                        key: created.key.clone(),
                        remember: false,
                    },
                };
                assert!(matches!(
                    engine
                        .execute(&mut store, &mut keys, &mut request)
                        .await
                        .result,
                    Ok(Output::Opened { .. })
                ));
                if let Some(server) = server {
                    request.command = CoreCommand::SyncConfig {
                        server: Some(server),
                    };
                    assert!(matches!(
                        engine
                            .execute(&mut store, &mut keys, &mut request)
                            .await
                            .result,
                        Ok(Output::Synced(_))
                    ));
                }
                let mut heads = Vec::new();
                for draft in drafts {
                    request.command = CoreCommand::Save { draft, epoch: 1 };
                    let Output::Saved(head) = engine
                        .execute(&mut store, &mut keys, &mut request)
                        .await
                        .result
                        .unwrap()
                    else {
                        panic!("expected saved record")
                    };
                    heads.push(head);
                }
                heads
            })
    }
    fn cli(&self, arguments: &[&str], stdin: Option<&[u8]>) -> ProcessOutput {
        let mut child = Command::new(env!("CARGO_BIN_EXE_cfdex"))
            .arg("--database")
            .arg(&self.location.database)
            .args(arguments)
            .stdin(if stdin.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        if let Some(bytes) = stdin {
            child.stdin.take().unwrap().write_all(bytes).unwrap();
        }
        child.wait_with_output().unwrap()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let request = Request {
            version: protocol::VERSION,
            id: 99,
            vault: None,
            command: Operation::Stop {},
        };
        let _ = self.location.call(&request, false);
        for child in &mut self.children {
            let _ = child.kill();
            let _ = child.wait();
        }
        #[cfg(unix)]
        {
            let deadline = Instant::now() + Duration::from_secs(2);
            while self.location.endpoint.exists() && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(10));
            }
            if !self.location.endpoint.exists() {
                let _ = std::fs::remove_file(self.location.endpoint.with_file_name("agent.lock"));
                let _ = std::fs::remove_dir(self.location.endpoint.parent().unwrap());
            }
        }
    }
}

#[test]
fn separate_processes_reuse_sessions_and_lock_only_the_selected_vault() {
    let fixture = Fixture::new();
    let catalog = fixture.cli(&["vaults", "--json"], None);
    assert!(catalog.status.success());
    assert!(catalog.stderr.is_empty());
    let json: serde_json::Value = serde_json::from_slice(&catalog.stdout).unwrap();
    assert_eq!(json["version"], 1);
    assert_eq!(json["result"].as_array().unwrap().len(), 2);
    assert!(!String::from_utf8_lossy(&catalog.stdout).contains(PASSWORD));
    assert!(!fixture.unlocked(0));
    assert!(matches!(
        fixture.unlock(0, PASSWORD),
        Ok(Reply::Opened { .. })
    ));
    assert!(matches!(
        fixture.unlock(1, PASSWORD),
        Ok(Reply::Opened { .. })
    ));
    assert_eq!(
        fixture
            .unlock(0, "WRONG-PUBLIC-PASSWORD")
            .err()
            .unwrap()
            .code,
        Code::Auth
    );
    assert!(fixture.unlocked(0));
    assert!(fixture.unlocked(1));
    let lock = fixture.cli(&["--vault", "Public one", "lock", "--json"], None);
    assert!(lock.status.success());
    assert!(!fixture.unlocked(0));
    assert!(fixture.unlocked(1));
    assert!(
        fixture
            .cli(&["--vault", "Public one", "lock"], None)
            .status
            .success()
    );
    let status = fixture.cli(&["--vault", "Public two", "status", "--json"], None);
    assert!(status.status.success());
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&status.stdout).unwrap()["result"]["unlocked"],
        true
    );
}

#[test]
fn status_polling_does_not_extend_idle_timeout_and_crash_does_not_restore_keys() {
    let mut fixture = Fixture::new();
    fixture.spawn(1);
    fixture.wait();
    assert!(matches!(
        fixture.unlock(0, PASSWORD),
        Ok(Reply::Opened { .. })
    ));
    assert!(fixture.unlocked(0));
    let deadline = Instant::now() + Duration::from_secs(4);
    while fixture.unlocked(0) {
        assert!(
            Instant::now() < deadline,
            "idle timeout was extended by status"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(matches!(
        fixture.unlock(0, PASSWORD),
        Ok(Reply::Opened { .. })
    ));
    fixture.children[0].kill().unwrap();
    fixture.children[0].wait().unwrap();
    let status = fixture.cli(&["--vault", "Public one", "status", "--json"], None);
    assert!(status.status.success());
    assert!(!fixture.unlocked(0));
}

#[test]
fn concurrent_start_has_one_agent_and_stop_releases_its_endpoint() {
    let mut fixture = Fixture::new();
    fixture.spawn(900);
    fixture.spawn(900);
    fixture.wait();
    let deadline = Instant::now() + Duration::from_secs(4);
    loop {
        let active = fixture
            .children
            .iter_mut()
            .map(|child| usize::from(child.try_wait().unwrap().is_none()))
            .sum::<usize>();
        if active == 1 {
            break;
        }
        assert!(Instant::now() < deadline, "duplicate agents stayed alive");
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(matches!(
        fixture.rpc(None, Operation::Stop {}),
        Ok(Reply::Stopped { .. })
    ));
    for child in &mut fixture.children {
        assert!(child.wait().unwrap().success());
    }
    assert!(cfdex::socket::Connection::connect(&fixture.location.endpoint).is_err());
}

#[test]
fn malformed_and_incomplete_connections_cannot_keep_an_idle_vault_open() {
    let mut fixture = Fixture::new();
    fixture.spawn(1);
    fixture.wait();
    assert!(matches!(
        fixture.unlock(0, PASSWORD),
        Ok(Reply::Opened { .. })
    ));
    let mut invalid = cfdex::socket::Connection::connect(&fixture.location.endpoint).unwrap();
    invalid
        .write_all(&((protocol::MAX_REQUEST + 1) as u32).to_be_bytes())
        .unwrap();
    assert_eq!(invalid.read(&mut [0; 1]).unwrap(), 0);
    let mut incomplete = cfdex::socket::Connection::connect(&fixture.location.endpoint).unwrap();
    incomplete.write_all(&100u32.to_be_bytes()).unwrap();
    incomplete.write_all(b"{").unwrap();
    std::thread::sleep(Duration::from_millis(1200));
    assert!(!fixture.unlocked(0));
    assert_eq!(incomplete.read(&mut [0; 1]).unwrap(), 0);
}

#[test]
fn stdin_credentials_and_error_output_do_not_disclose_values() {
    let fixture = Fixture::new();
    let credentials = zeroize::Zeroizing::new(
        serde_json::to_vec(
            &serde_json::json!({"password":PASSWORD,"secret_key":fixture.vaults[0].key}),
        )
        .unwrap(),
    );
    let unlocked = fixture.cli(
        &[
            "--vault",
            "Public one",
            "unlock",
            "--credentials-stdin",
            "--json",
        ],
        Some(&credentials),
    );
    assert!(unlocked.status.success());
    assert!(unlocked.stderr.is_empty());
    assert!(!String::from_utf8_lossy(&unlocked.stdout).contains(PASSWORD));
    let arguments = fixture.cli(
        &["--json", "unlock", "--password", "PUBLIC-ARGV-SECRET"],
        None,
    );
    assert_eq!(arguments.status.code(), Some(2));
    assert!(arguments.stdout.is_empty());
    assert!(!String::from_utf8_lossy(&arguments.stderr).contains("PUBLIC-ARGV-SECRET"));
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&arguments.stderr).unwrap()["error"]["code"],
        "input"
    );
    let no_stdin = fixture.cli(&["--vault", "Public two", "unlock", "--json"], None);
    assert_eq!(no_stdin.status.code(), Some(3));
    let malformed = fixture.cli(
        &[
            "--vault",
            "Public two",
            "unlock",
            "--credentials-stdin",
            "--json",
        ],
        Some(b"{\"password\":\"PUBLIC-MALFORMED-SECRET\",\"extra\":true}"),
    );
    assert_eq!(malformed.status.code(), Some(2));
    assert!(!String::from_utf8_lossy(&malformed.stderr).contains("PUBLIC-MALFORMED-SECRET"));
    let help = fixture.cli(&["--help"], None);
    assert!(help.status.success());
    assert!(help.stderr.is_empty());
    assert!(!help.stdout.contains(&27));
    let version = fixture.cli(&["--version"], None);
    assert!(version.status.success());
    assert_eq!(version.stdout, b"cfdex 0.1.0\n");
    assert!(version.stderr.is_empty());
}

#[test]
fn ambiguous_vault_names_fail_and_an_explicit_id_selects_one_vault() {
    let fixture = Fixture::new();
    tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap()
        .block_on(async {
            let mut store = confidex_native::open_store(&fixture.location.database).unwrap();
            store
                .rename(fixture.vaults[1].info.id, "Public two", "Public one")
                .await
                .unwrap();
        });
    let ambiguous = fixture.cli(&["--vault", "Public one", "status", "--json"], None);
    assert_eq!(ambiguous.status.code(), Some(5));
    assert!(ambiguous.stdout.is_empty());
    let id = cfdex::runtime::hex(&fixture.vaults[1].info.id);
    let selected = fixture.cli(&["--vault", &id, "status", "--json"], None);
    assert!(selected.status.success());
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&selected.stdout).unwrap()["result"]["unlocked"],
        false
    );
}

#[test]
fn init_persists_a_local_id_and_failed_setup_preserves_it() {
    let fixture = Fixture::new();
    let unconfigured = fixture.cli(&["status"], None);
    assert_eq!(unconfigured.status.code(), Some(2));
    let selected = fixture.cli(&["init", "--select", "Public one", "--json"], None);
    assert!(selected.status.success());
    let result: serde_json::Value = serde_json::from_slice(&selected.stdout).unwrap();
    assert_eq!(
        result["result"]["id"],
        cfdex::runtime::hex(&fixture.vaults[0].info.id)
    );
    assert!(
        fixture
            .cli(&["init", "--select", "Public one"], None)
            .status
            .success()
    );
    assert!(matches!(
        fixture.unlock(0, PASSWORD),
        Ok(Reply::Opened { .. })
    ));
    let failed = fixture.cli(&["init", "--select", "does not exist"], None);
    assert_eq!(failed.status.code(), Some(4));
    let status = fixture.cli(&["status"], None);
    assert!(status.status.success());
    assert_eq!(status.stdout, b"unlocked\n");
    assert_eq!(fixture.cli(&["init"], None).status.code(), Some(2));
}

#[test]
fn creation_publishes_only_after_a_private_key_copy_is_saved() {
    let fixture = Fixture::new();
    fixture.cli(&["vaults"], None);
    let path = fixture._directory.path().join("recovery.txt");
    std::fs::write(&path, b"keep existing file").unwrap();
    let credentials = serde_json::to_vec(&serde_json::json!({"password":PASSWORD})).unwrap();
    let result = fixture.cli(
        &[
            "init",
            "--create",
            "Public new",
            "--key-output",
            path.to_str().unwrap(),
            "--credentials-stdin",
        ],
        Some(&credentials),
    );
    assert_eq!(result.status.code(), Some(1));
    assert_eq!(std::fs::read(&path).unwrap(), b"keep existing file");
    assert!(
        matches!(fixture.rpc(None, Operation::Vaults {}), Ok(Reply::Vaults { vaults }) if vaults.len() == 2)
    );
    std::fs::remove_file(&path).unwrap();
    let request = Request {
        version: protocol::VERSION,
        id: 94,
        vault: None,
        command: Operation::Create {
            name: "Public new".into(),
            key_output: path.clone(),
            credentials: Credentials {
                password: Secret(PASSWORD.into()),
                secret_key: None,
            },
        },
    };
    let (response, key) = fixture.location.call(&request, false).unwrap();
    let Ok(Reply::Created { vault, .. }) = response.result else {
        panic!("vault creation failed");
    };
    let copy = zeroize::Zeroizing::new(std::fs::read(&path).unwrap());
    assert!(
        copy.strip_suffix(b"\n")
            .is_some_and(|bytes| bytes == key.as_slice())
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    assert!(
        matches!(fixture.rpc(None, Operation::Vaults {}), Ok(Reply::Vaults { vaults }) if vaults.iter().any(|row| row.id == vault.id))
    );
}

#[test]
fn incompatible_agents_fail_without_writing_partial_results() {
    let fixture = Fixture::new();
    let listener = cfdex::socket::Listener::bind(&fixture.location.endpoint).unwrap();
    let server = std::thread::spawn(move || {
        let mut connection = listener.accept().unwrap();
        let request = protocol::read_request(&mut connection).unwrap();
        let response = protocol::Response {
            version: protocol::VERSION + 1,
            id: request.id,
            vault: request.vault,
            result: Ok(Reply::Vaults { vaults: vec![] }),
        };
        let bytes = serde_json::to_vec(&response).unwrap();
        connection
            .write_all(&(bytes.len() as u32).to_be_bytes())
            .unwrap();
        connection.write_all(&bytes).unwrap();
    });
    let result = fixture.cli(&["vaults", "--json"], None);
    server.join().unwrap();
    assert_eq!(result.status.code(), Some(8));
    assert!(result.stdout.is_empty());
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&result.stderr).unwrap()["error"]["code"],
        "protocol"
    );
}

#[test]
fn reads_only_selected_values_and_traverses_pages() {
    let fixture = Fixture::new();
    let created = &fixture.vaults[0];
    let title = "Личный vault reference";
    let chosen = "PUBLIC-SELECTED-Ä\n";
    let adjacent = "PUBLIC-ADJACENT-PASSWORD";
    let bytes: Vec<_> = (0..128 * 1024).map(|index| (index % 251) as u8).collect();
    let mut draft = confidex_app::new_record().unwrap();
    draft.record = [255; 16];
    let id = cfdex::runtime::hex(&draft.record);
    draft.title = title.into();
    draft.tags = vec!["Login".into()];
    for (name, value) in [("Пароль", chosen), ("Пароль", adjacent), ("", adjacent)] {
        let mut field = confidex_app::field("password/v1").unwrap();
        field.name = name.into();
        field.values.insert("password".into(), value.into());
        draft.fields.push(field);
    }
    let mut attachment = confidex_app::field("file/v1").unwrap();
    attachment.name = "License".into();
    attachment.data = Some(bytes.clone().into());
    draft.fields.push(attachment);

    let mut drafts: Vec<_> = (0..=confidex_storage::PAGE_SIZE)
        .map(|index| {
            let mut filler = confidex_app::new_record().unwrap();
            filler.title = format!("Reference {index}");
            filler.tags = vec!["Login".into()];
            filler
        })
        .collect();
    drafts.push(draft);
    fixture.save_drafts(created, drafts, None);

    assert!(
        fixture
            .cli(&["init", "--select", "Public one"], None)
            .status
            .success()
    );
    let locked = fixture.cli(&["get", &id, "--field-index", "0", "--json"], None);
    assert_eq!(locked.status.code(), Some(3));
    assert!(locked.stdout.is_empty());
    assert!(matches!(
        fixture.unlock(0, PASSWORD),
        Ok(Reply::Opened { .. })
    ));

    for arguments in [
        &["list", "--tag", "Login", "--json"][..],
        &["list", "reference", "--tag", "Login", "--json"][..],
    ] {
        let listed = fixture.cli(arguments, None);
        assert!(
            listed.status.success(),
            "{}",
            String::from_utf8_lossy(&listed.stderr)
        );
        let json: serde_json::Value = serde_json::from_slice(&listed.stdout).unwrap();
        let rows = json["result"].as_array().unwrap();
        assert_eq!(rows.len(), confidex_storage::PAGE_SIZE + 2);
        assert!(
            rows.iter()
                .any(|row| row["id"] == id && row["title"] == title)
        );
        assert!(!String::from_utf8_lossy(&listed.stdout).contains(adjacent));
    }
    let fields = fixture.cli(&["fields", title, "--json"], None);
    assert!(fields.status.success());
    let metadata: serde_json::Value = serde_json::from_slice(&fields.stdout).unwrap();
    assert_eq!(metadata["result"][0]["name"], "Пароль");
    assert_eq!(metadata["result"][2]["name"], "");
    assert_eq!(metadata["result"][3]["binary"], true);
    assert!(!String::from_utf8_lossy(&fields.stdout).contains(adjacent));
    let duplicate = fixture.cli(&["get", &id, "--field", "Пароль"], None);
    assert_eq!(duplicate.status.code(), Some(5));
    assert!(duplicate.stdout.is_empty());
    let raw = fixture.cli(&["get", &id, "--field-index", "0"], None);
    assert!(raw.status.success());
    assert_eq!(raw.stdout, chosen.as_bytes());
    assert!(raw.stderr.is_empty());
    let json = fixture.cli(&["get", &id, "--field-index", "0", "--json"], None);
    assert!(json.status.success());
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&json.stdout).unwrap()["result"],
        chosen
    );
    let missing = fixture.cli(&["get", &id, "--field", "Unknown"], None);
    assert_eq!(missing.status.code(), Some(4));
    assert!(missing.stdout.is_empty());

    let binary = ["get", &id, "--field", "License", "--value", "data"];
    let rejected = fixture.cli(&binary, None);
    assert_eq!(rejected.status.code(), Some(2));
    assert!(rejected.stdout.is_empty());
    let path = fixture._directory.path().join("license.bin");
    let mut command = binary.to_vec();
    command.extend(["--output", path.to_str().unwrap()]);
    let exported = fixture.cli(&command, None);
    assert!(
        exported.status.success(),
        "{}",
        String::from_utf8_lossy(&exported.stderr)
    );
    assert!(exported.stdout.is_empty());
    assert!(std::fs::read(&path).unwrap() == bytes);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    assert!(!fixture.cli(&command, None).status.success());
    assert!(std::fs::read(&path).unwrap() == bytes);
}

#[cfg(feature = "sync")]
#[test]
fn connects_and_syncs_two_processes_through_the_native_server() {
    use confidexsyncd::{
        Limits,
        native::{Blobs, Index, router},
    };
    use std::sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
        mpsc,
    };

    struct Server {
        stop: Option<tokio::sync::oneshot::Sender<()>>,
        thread: Option<std::thread::JoinHandle<()>>,
    }
    impl Drop for Server {
        fn drop(&mut self) {
            let _ = self.stop.take().unwrap().send(());
            self.thread.take().unwrap().join().unwrap();
        }
    }
    struct SavedKey(VaultId);
    impl Drop for SavedKey {
        fn drop(&mut self) {
            let _ = tokio::runtime::Builder::new_current_thread()
                .build()
                .unwrap()
                .block_on(confidex_native::Credentials.remove(self.0));
        }
    }
    fn account(value: &str) -> confidex_app::Draft {
        let mut draft = confidex_app::new_record().unwrap();
        draft.title = "Shared account".into();
        let mut field = confidex_app::field("password/v1").unwrap();
        field.name = "Password".into();
        field.values.insert("password".into(), value.into());
        draft.fields.push(field);
        draft
    }
    fn success(output: ProcessOutput) -> serde_json::Value {
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(output.stderr.is_empty());
        serde_json::from_slice::<serde_json::Value>(&output.stdout).unwrap()["result"].clone()
    }

    let source = Fixture::new();
    let target = Fixture::new();
    let created = &source.vaults[0];
    let chosen = "PUBLIC-SYNC-PASSWORD";
    let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
    listener.set_nonblocking(true).unwrap();
    let url = format!("http://{}/", listener.local_addr().unwrap());
    let objects = source._directory.path().join("objects");
    let calls = Arc::new(AtomicUsize::new(0));
    let leaked = Arc::new(AtomicBool::new(false));
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let requests = Arc::clone(&calls);
    let secret_leaked = Arc::clone(&leaked);
    type Gate = (mpsc::Sender<()>, tokio::sync::oneshot::Receiver<()>);
    let pause = Arc::new(Mutex::new(None::<Gate>));
    let gate = Arc::clone(&pause);
    let secrets = Arc::new([PASSWORD.to_owned(), created.key.clone(), chosen.to_owned()]);
    let thread = std::thread::spawn(move || {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                let app = router(
                    Index::open(":memory:").await.unwrap(),
                    vec![Blobs::posix(objects).unwrap()],
                    Limits::default(),
                )
                .layer(axum::middleware::from_fn(
                    move |request: axum::extract::Request, next: axum::middleware::Next| {
                        let (requests, leaked, secrets, gate) = (
                            requests.clone(),
                            secret_leaked.clone(),
                            secrets.clone(),
                            gate.clone(),
                        );
                        async move {
                            requests.fetch_add(1, Ordering::Relaxed);
                            let (parts, body) = request.into_parts();
                            if parts.method == axum::http::Method::GET
                                && parts.uri.path().ends_with("/records")
                            {
                                let pause = gate.lock().unwrap().take();
                                if let Some((reached, release)) = pause {
                                    reached.send(()).unwrap();
                                    tokio::time::timeout(Duration::from_secs(10), release)
                                        .await
                                        .unwrap()
                                        .unwrap();
                                }
                            }
                            let body = axum::body::to_bytes(body, confidex_app::sync::MAX_BODY)
                                .await
                                .unwrap();
                            if secrets.iter().any(|secret| {
                                body.windows(secret.len())
                                    .any(|window| window == secret.as_bytes())
                                    || parts.uri.to_string().contains(secret)
                                    || parts.headers.values().any(|value| {
                                        value
                                            .as_bytes()
                                            .windows(secret.len())
                                            .any(|window| window == secret.as_bytes())
                                    })
                            }) {
                                leaked.store(true, Ordering::Relaxed);
                            }
                            next.run(axum::extract::Request::from_parts(
                                parts,
                                axum::body::Body::from(body),
                            ))
                            .await
                        }
                    },
                ));
                let listener = tokio::net::TcpListener::from_std(listener).unwrap();
                tokio::select! {
                    result = axum::serve(listener, app) => result.unwrap(),
                    _ = stopped => (),
                }
            });
    });
    let server = Server {
        stop: Some(stop),
        thread: Some(thread),
    };

    let mut drafts = vec![account(chosen)];
    for index in 0..20 {
        let mut draft = confidex_app::new_record().unwrap();
        draft.title = format!("Shared record {index}");
        drafts.push(draft);
    }
    let heads = source.save_drafts(created, drafts, Some(url.clone()));
    let record = &heads[0];
    let id = cfdex::runtime::hex(&record.record);
    let credentials =
        serde_json::to_vec(&serde_json::json!({"password": PASSWORD, "secret_key": created.key}))
            .unwrap();
    assert!(
        source
            .cli(&["init", "--select", "Public one"], None)
            .status
            .success()
    );
    assert!(matches!(
        source.unlock(0, PASSWORD),
        Ok(Reply::Opened { .. })
    ));
    let sent = success(source.cli(&["sync", "--json"], None));
    assert_eq!(sent["http"]["uploaded"], 21);

    let _saved_key = SavedKey(created.info.id);
    let connected = success(target.cli(
        &[
            "init",
            "--connect",
            "Connected vault",
            "--server",
            &url,
            "--credentials-stdin",
            "--json",
        ],
        Some(&credentials),
    ));
    assert_eq!(connected["id"], cfdex::runtime::hex(&created.info.id));
    assert!(target.cli(&["lock"], None).status.success());
    assert!(
        target
            .cli(&["unlock", "--credentials-stdin"], Some(&credentials))
            .status
            .success()
    );
    let before = calls.load(Ordering::Relaxed);
    assert_eq!(
        success(target.cli(&["list", "--json"], None)),
        serde_json::json!([])
    );
    assert_eq!(calls.load(Ordering::Relaxed), before);

    let received = success(target.cli(&["sync", "--json"], None));
    assert_eq!(received["http"]["downloaded"], 21);
    let fetched = target.cli(&["get", "Shared account", "--field", "Password"], None);
    assert!(fetched.status.success());
    assert_eq!(fetched.stdout, chosen.as_bytes());
    let again = success(target.cli(&["sync", "--json"], None));
    assert_eq!(again["http"]["downloaded"], 0);
    assert_eq!(again["http"]["uploaded"], 0);

    let mut remote = account("PUBLIC-REMOTE-BRANCH");
    let mut local = account("PUBLIC-LOCAL-BRANCH");
    for draft in [&mut remote, &mut local] {
        draft.record = record.record;
        draft.revision = Some(record.revision);
        draft.fields[0].source = Some(0);
    }
    let (reached, waiting) = mpsc::channel();
    let (release, resume) = tokio::sync::oneshot::channel();
    *pause.lock().unwrap() = Some((reached, resume));
    let (conflict, remote, local) = std::thread::scope(|scope| {
        let syncing = scope.spawn(|| target.cli(&["sync", "--json"], None));
        waiting.recv_timeout(Duration::from_secs(5)).unwrap();
        let remote = source.save_drafts(created, vec![remote], None).remove(0);
        let local = target.save_drafts(created, vec![local], None).remove(0);
        success(source.cli(&["sync", "--json"], None));
        release.send(()).unwrap();
        (syncing.join().unwrap(), remote, local)
    });
    assert_eq!(
        conflict.status.code(),
        Some(5),
        "{}",
        String::from_utf8_lossy(&conflict.stderr)
    );
    assert!(conflict.stdout.is_empty());
    assert!(String::from_utf8_lossy(&conflict.stderr).contains(&id));
    let ambiguous = target.cli(&["get", &id, "--field", "Password"], None);
    assert_eq!(ambiguous.status.code(), Some(5));
    assert!(ambiguous.stdout.is_empty());
    for (head, expected) in [
        (remote, b"PUBLIC-REMOTE-BRANCH".as_slice()),
        (local, b"PUBLIC-LOCAL-BRANCH".as_slice()),
    ] {
        let revision = cfdex::runtime::hex(&head.revision);
        let value = target.cli(
            &["get", &id, "--revision", &revision, "--field", "Password"],
            None,
        );
        assert!(value.status.success());
        assert_eq!(value.stdout, expected);
    }

    let duplicate = target
        .save_drafts(created, vec![account("PUBLIC-OTHER-ACCOUNT")], None)
        .remove(0);
    let ambiguous = target.cli(&["get", "Shared account", "--field", "Password"], None);
    assert_eq!(ambiguous.status.code(), Some(5));
    assert!(ambiguous.stdout.is_empty());
    let error = String::from_utf8_lossy(&ambiguous.stderr);
    assert!(error.contains(&id));
    assert!(error.contains(&cfdex::runtime::hex(&duplicate.record)));
    assert!(!error.contains("PUBLIC-OTHER-ACCOUNT"));
    assert!(!leaked.load(Ordering::Relaxed));

    drop(server);
    let offline = target.cli(&["sync", "--json"], None);
    assert_eq!(offline.status.code(), Some(7));
    assert!(offline.stdout.is_empty());
    let offline = target.cli(
        &[
            "get",
            &cfdex::runtime::hex(&duplicate.record),
            "--field",
            "Password",
        ],
        None,
    );
    assert!(offline.status.success());
    assert_eq!(offline.stdout, b"PUBLIC-OTHER-ACCOUNT");
}

#[test]
fn synchronizes_a_configured_folder_without_http() {
    let source = Fixture::new();
    let target = Fixture::new();
    let shared = tempfile::tempdir().unwrap();
    let created = &source.vaults[0];
    let mut draft = confidex_app::new_record().unwrap();
    draft.title = "Folder-only note".into();
    let mut note = confidex_app::field("secure-note/v1").unwrap();
    note.name = "Note".into();
    note.values
        .insert("text".into(), "PUBLIC-FOLDER-NOTE".into());
    draft.fields.push(note);
    source.save_drafts(created, vec![draft], None);

    tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap()
        .block_on(async {
            let mut a = confidex_native::open_store(&source.location.database).unwrap();
            let mut b = confidex_native::open_store(&target.location.database).unwrap();
            b.create(&a.vault(created.info.id).await.unwrap())
                .await
                .unwrap();
            for store in [&mut a, &mut b] {
                let mut engine = Engine::default();
                let mut keys = NoKeys;
                let output = engine
                    .execute(
                        store,
                        &mut keys,
                        &mut confidex_app::Request {
                            generation: 0,
                            command: CoreCommand::Unlock {
                                vault: created.info.id,
                                password: PASSWORD.into(),
                                key: created.key.clone(),
                                remember: false,
                            },
                        },
                    )
                    .await;
                assert!(matches!(output.result, Ok(Output::Opened { .. })));
                engine
                    .execute_folder(
                        store,
                        &mut keys,
                        &mut confidex_app::local_sync::Command::Configure {
                            path: Some(shared.path().to_str().unwrap().into()),
                        },
                        &mut || true,
                    )
                    .await
                    .unwrap();
            }
        });
    let id = cfdex::runtime::hex(&created.info.id);
    let credentials =
        serde_json::to_vec(&serde_json::json!({"password": PASSWORD, "secret_key": created.key}))
            .unwrap();
    for fixture in [&source, &target] {
        assert!(
            fixture
                .cli(&["init", "--select", &id], None)
                .status
                .success()
        );
        assert!(
            fixture
                .cli(&["unlock", "--credentials-stdin"], Some(&credentials))
                .status
                .success()
        );
        let synced = fixture.cli(&["sync", "--json"], None);
        assert!(
            synced.status.success(),
            "{}",
            String::from_utf8_lossy(&synced.stderr)
        );
        let json: serde_json::Value = serde_json::from_slice(&synced.stdout).unwrap();
        assert!(json["result"]["http"].is_null());
        assert_eq!(json["result"]["folder"]["pending"], 0);
    }
    let value = target.cli(&["get", "Folder-only note", "--field", "Note"], None);
    assert!(value.status.success());
    assert_eq!(value.stdout, b"PUBLIC-FOLDER-NOTE");
}

#[test]
fn reports_an_opaque_field_without_reading_or_rewriting_it() {
    use confidex_vault::{
        envelope::{self, EventKind, Options},
        kdf, lock,
        record::{Entry, Record},
        resources::MAX_OPEN_MEMORY,
        transfer_code,
    };
    let fixture = Fixture::new();
    let created = &fixture.vaults[0];
    let vault = created.info.id;
    let record_id = confidex_app::new_record().unwrap().record;
    let mut record = Record::default();
    record.entries.push(Entry {
        name: "Extension".into(),
        type_name: "unknown.example/v1".into(),
        value: [("data".into(), "PUBLIC-OPAQUE".into())].into(),
        extra: Default::default(),
    });
    let revision = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap()
        .block_on(async {
            let mut store = confidex_native::open_store(&fixture.location.database).unwrap();
            let stored = store.vault(vault).await.unwrap();
            let code = transfer_code::decode(&created.key).unwrap();
            let opened = lock::open(
                &stored.lock,
                PASSWORD.as_bytes(),
                &code.secret,
                kdf::REQUIRED_MEMORY,
            )
            .unwrap();
            let wire = envelope::seal(
                &record,
                opened.keys(),
                Options {
                    vault_id: vault,
                    record_id,
                    parents: &[],
                    epoch: 1,
                    kind: EventKind::Content,
                },
                MAX_OPEN_MEMORY,
            )
            .unwrap();
            let revision = envelope::verify(&wire, opened.anchor(), None, MAX_OPEN_MEMORY)
                .unwrap()
                .id();
            store
                .append(
                    vault,
                    &confidex_storage::Head {
                        record: record_id,
                        revision,
                    },
                    None,
                    &wire,
                    &[],
                )
                .await
                .unwrap();
            revision
        });
    assert!(
        fixture
            .cli(&["init", "--select", "Public one"], None)
            .status
            .success()
    );
    assert!(matches!(
        fixture.unlock(0, PASSWORD),
        Ok(Reply::Opened { .. })
    ));
    let id = cfdex::runtime::hex(&record_id);
    let fields = fixture.cli(&["fields", &id, "--json"], None);
    assert!(fields.status.success());
    let json: serde_json::Value = serde_json::from_slice(&fields.stdout).unwrap();
    assert_eq!(json["result"][0]["type_name"], "unknown.example/v1");
    assert_eq!(json["result"][0]["opaque"], 1);
    assert!(!String::from_utf8_lossy(&fields.stdout).contains("PUBLIC-OPAQUE"));
    let value = fixture.cli(&["get", &id, "--field", "Extension"], None);
    assert_eq!(value.status.code(), Some(2));
    assert!(value.stdout.is_empty());
    assert!(!String::from_utf8_lossy(&value.stderr).contains("PUBLIC-OPAQUE"));
    let list = fixture.cli(&["list", "--json"], None);
    let json: serde_json::Value = serde_json::from_slice(&list.stdout).unwrap();
    assert_eq!(
        json["result"][0]["revision"],
        cfdex::runtime::hex(&revision)
    );
}
