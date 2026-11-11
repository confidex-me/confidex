#![cfg(all(feature = "sqlite", not(target_arch = "wasm32")))]
use confidex_storage::{Error, Head, SqliteStore, Store};
use std::{
    io::{BufRead, BufReader, Read, Write},
    process::{Child, ChildStdout, Command, Stdio},
};

struct Writer(Child, BufReader<ChildStdout>);
impl Drop for Writer {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
#[test]
fn independent_processes_reject_a_lost_update_and_preserve_committed_data() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("vault.sqlite");
    let binary = env!("CARGO_BIN_EXE_confidex-store-probe");
    let init = Command::new(binary)
        .arg(&path)
        .arg("init")
        .status()
        .unwrap();
    assert!(init.success());
    let spawn = |value: &str| {
        let mut child = Command::new(binary)
            .arg(&path)
            .args(["race", value])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let mut reader = BufReader::new(child.stdout.take().unwrap());
        let mut ready = String::new();
        reader.read_line(&mut ready).unwrap();
        assert_eq!(ready.trim(), format!("ready:{}", child.id()));
        Writer(child, reader)
    };
    let mut first = spawn("3");
    let mut second = spawn("4");
    assert_ne!(first.0.id(), second.0.id());
    first
        .0
        .stdin
        .take()
        .unwrap()
        .write_all(b"commit\n")
        .unwrap();
    second
        .0
        .stdin
        .take()
        .unwrap()
        .write_all(b"commit\n")
        .unwrap();
    let mut a = String::new();
    let mut b = String::new();
    first.1.read_to_string(&mut a).unwrap();
    second.1.read_to_string(&mut b).unwrap();
    assert!(first.0.wait().unwrap().success());
    assert!(second.0.wait().unwrap().success());
    assert!(matches!(
        (a.trim(), b.trim()),
        ("Ok(())", "Err(Conflict)") | ("Err(Conflict)", "Ok(())")
    ));
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    runtime.block_on(async {
        let mut store = SqliteStore::open(&path).unwrap();
        println!("SQLite {}", store.sqlite_version());
        let head = store.head([1; 16], [2; 16]).await.unwrap().unwrap();
        let winner = head.revision[0];
        let loser = if winner == 3 { 4 } else { 3 };
        assert_eq!(store.object([1; 16], [winner; 32]).await.unwrap(), [winner]);
        assert_eq!(
            store.object([1; 16], [loser; 32]).await,
            Err(Error::NotFound)
        );
        assert_eq!(
            store.append([1; 16], &head, None, &[winner], &[]).await,
            Ok(())
        );
        assert_eq!(
            store.append([1; 16], &head, None, b"different", &[]).await,
            Err(Error::Conflict)
        );
        store
            .append(
                [1; 16],
                &Head {
                    record: [2; 16],
                    revision: [5; 32],
                },
                Some(head.revision),
                b"new",
                &[],
            )
            .await
            .unwrap();
        assert_eq!(store.object([1; 16], [winner; 32]).await.unwrap(), [winner]);
    });
    let reopened = Command::new(binary)
        .arg(&path)
        .arg("list")
        .output()
        .unwrap();
    assert!(reopened.status.success());
    assert_eq!(reopened.stdout, b"1\n");
}
