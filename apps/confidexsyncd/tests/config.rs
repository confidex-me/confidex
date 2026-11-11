#![cfg(not(target_arch = "wasm32"))]
use std::{
    io::{BufRead, BufReader},
    process::{Command, Stdio},
    sync::mpsc,
    time::Duration,
};

#[test]
fn environment_paths_and_listen_fields_start_the_actual_binary() {
    let temp = tempfile::tempdir().unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_confidexsyncd"))
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap())
        .env("INDEX_URL", temp.path().join("index.sqlite"))
        .env("LISTEN_ADDRESS", "127.0.0.1")
        .env("LISTEN_PORT", "0")
        .env("BACKEND_POSIX_PATH_0", temp.path().join("first"))
        .env("BACKEND_POSIX_PATH_2", temp.path().join("second"))
        .env("BACKEND_GIT_PATH_0", temp.path().join("git"))
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let stderr = child.stderr.take().unwrap();
    let (sender, receiver) = mpsc::channel();
    let reader = std::thread::spawn(move || {
        let mut line = String::new();
        let result = BufReader::new(stderr).read_line(&mut line);
        let _ = sender.send((result, line));
    });
    let result = receiver.recv_timeout(Duration::from_secs(5));
    let _ = child.kill();
    child.wait().unwrap();
    reader.join().unwrap();
    let (read, line) = result.unwrap();
    assert!(read.unwrap() > 0);
    assert!(
        line.starts_with("confidexsyncd listening on 127.0.0.1:"),
        "{line}"
    );
    assert!(temp.path().join("first").is_dir());
    assert!(temp.path().join("second").is_dir());
    assert!(temp.path().join("git/objects").is_dir());
}
