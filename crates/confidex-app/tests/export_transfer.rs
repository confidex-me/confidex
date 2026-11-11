#[cfg(not(target_arch = "wasm32"))]
use confidex_app::export_flow::CHUNK_BYTES;
use confidex_app::export_flow::{File, Ready, Transfer};
use std::io;
fn transfer(size: usize) -> Transfer {
    Transfer::new(&Ready {
        token: [1; 16],
        bytes: size,
        file: File {
            name: "export.json".into(),
            media_type: "application/json".into(),
            encrypted: false,
        },
    })
    .unwrap()
}
#[test]
fn publication_requires_complete_ordered_bytes_and_happens_once() {
    let transfer = transfer(6);
    assert!(transfer.publish(|_| Ok(())).is_err());
    transfer.append(0, b"abc", Some(3)).unwrap();
    assert!(!transfer.available());
    transfer.append(3, b"def", None).unwrap();
    assert_eq!(transfer.read(0).unwrap().as_slice(), b"abcdef");
    transfer
        .publish(|bytes| {
            assert_eq!(bytes, b"abcdef");
            Ok(())
        })
        .unwrap();
    assert!(
        transfer
            .publish::<()>(|_| panic!("duplicate publication"))
            .is_err()
    );
}
#[test]
fn malformed_chunks_fail_closed() {
    for (offset, bytes, next) in [
        (1, &b"abc"[..], Some(4)),
        (0, b"abcd", None),
        (0, b"abc", None),
        (0, b"", Some(0)),
        (0, b"abcdefg", None),
    ] {
        let transfer = transfer(6);
        assert!(transfer.append(offset, bytes, next).is_err());
        assert!(transfer.append(0, b"abcdef", None).is_err());
    }
    let transfer = transfer(0);
    transfer.append(0, b"", None).unwrap();
    transfer
        .publish(|bytes| {
            assert!(bytes.is_empty());
            Ok(())
        })
        .unwrap();
}
#[test]
fn cancellation_clears_all_owners_and_failure_cannot_retry() {
    let transfer = transfer(3);
    transfer.append(0, b"key", None).unwrap();
    let host = transfer.clone();
    transfer.cancel();
    assert!(!host.available());
    assert!(host.read(0).is_err());
    assert!(
        host.publish::<()>(|_| panic!("canceled publication"))
            .is_err()
    );
    let transfer = self::transfer(3);
    transfer.append(0, b"key", None).unwrap();
    assert!(
        transfer
            .publish::<()>(|_| Err(io::ErrorKind::PermissionDenied.into()))
            .is_err()
    );
    assert!(!transfer.available());
}
#[test]
#[cfg(not(target_arch = "wasm32"))]
fn cancel_between_chunks_prevents_publication() {
    let transfer = transfer(CHUNK_BYTES + 1);
    transfer
        .append(0, &vec![0; CHUNK_BYTES], Some(CHUNK_BYTES))
        .unwrap();
    transfer.append(CHUNK_BYTES, b"x", None).unwrap();
    let host = transfer.clone();
    let (written, wait_written) = std::sync::mpsc::channel();
    let (resume, wait_resume) = std::sync::mpsc::channel();
    let thread = std::thread::spawn(move || {
        assert_eq!(host.read(0).unwrap().len(), CHUNK_BYTES);
        written.send(()).unwrap();
        wait_resume.recv().unwrap();
        assert!(host.read(CHUNK_BYTES).is_err());
        assert!(
            host.publish::<()>(|_| panic!("publish after cancel"))
                .is_err()
        );
    });
    wait_written.recv().unwrap();
    transfer.cancel();
    resume.send(()).unwrap();
    thread.join().unwrap();
}
#[test]
#[cfg(not(target_arch = "wasm32"))]
fn cancellation_never_waits_for_an_os_action_already_claimed_by_the_host() {
    let transfer = transfer(3);
    transfer.append(0, b"key", None).unwrap();
    let host = transfer.clone();
    let (claimed, wait_claimed) = std::sync::mpsc::channel();
    let (resume, wait_resume) = std::sync::mpsc::channel();
    let thread = std::thread::spawn(move || {
        host.publish(|bytes| {
            assert_eq!(bytes, b"key");
            claimed.send(()).unwrap();
            wait_resume.recv().unwrap();
            Ok(())
        })
        .unwrap()
    });
    wait_claimed.recv().unwrap();
    transfer.cancel();
    assert!(!transfer.available());
    resume.send(()).unwrap();
    thread.join().unwrap();
    assert!(transfer.read(0).is_err());
}
