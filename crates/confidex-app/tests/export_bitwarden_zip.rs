use confidex_app::export::{self, Consent};
use confidex_vault::{
    record::{Record, Value},
    resources::MAX_OPEN_MEMORY,
};
#[path = "export_bitwarden_zip/proof.rs"]
mod proof;
use proof::{field, file, fixture, imported, plan};
use std::io::Read;

#[test]
fn portable_worker_proof_keeps_json_and_every_file() {
    proof::run();
}
#[cfg(not(target_arch = "wasm32"))]
#[test]
#[ignore = "Requires pinned Bitwarden sources, Python, and Node"]
fn independent_zip_reader_and_pinned_json_consumer_read_actual_output() {
    use std::{
        io::Write,
        process::{Command, Stdio},
    };
    let source = std::env::var_os("CONFIDEX_BITWARDEN_SOURCE").unwrap();
    let (plan, _) = plan(fixture(), export::Limits::default());
    let artifact = plan.write(Consent::Lossless, &mut |_| true).unwrap();
    let mut child = Command::new("python3")
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/export_fixtures/bitwarden_zip/reader.py"
        ))
        .arg(source)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(artifact.bytes())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    print!("{}", String::from_utf8_lossy(&output.stdout));
}
fn document(bytes: &[u8]) -> serde_json::Value {
    let mut zip = zip::ZipArchive::new(std::io::Cursor::new(bytes)).unwrap();
    let mut data = Vec::new();
    zip.by_name("data.json")
        .unwrap()
        .read_to_end(&mut data)
        .unwrap();
    serde_json::from_slice(&data).unwrap()
}
#[test]
fn real_zip_has_standard_members_fresh_ids_and_unchanged_safe_filenames() {
    let mut all = std::collections::BTreeSet::new();
    for _ in 0..2 {
        let (plan, _) = plan(fixture(), export::Limits::default());
        let artifact = plan.write(Consent::Lossless, &mut |_| true).unwrap();
        let json = document(artifact.bytes());
        assert_eq!(json["encrypted"], false);
        assert!(json.get("collections").is_none());
        assert_eq!(json["items"][0]["login"]["password"], "PUBLIC-CURRENT");
        for item in json["items"].as_array().unwrap() {
            let id = item["id"].as_str().unwrap();
            assert_eq!(id.len(), 36);
            assert!(all.insert(id.to_owned()));
            assert!(item.get("attachments").is_none());
        }
        let zip = zip::ZipArchive::new(std::io::Cursor::new(artifact.bytes())).unwrap();
        let names: Vec<_> = zip.file_names().map(Result::unwrap).collect();
        assert_eq!(
            names,
            [
                "data.json",
                "attachments/",
                "attachments/Почта _ 東京/",
                "attachments/Почта _ 東京/same.bin",
                "attachments/Почта _ 東京/empty.bin",
                "attachments/Почта _ 東京/scan.part.txt",
                "attachments/Почта _ 東京/公開 café.bin",
                "attachments/Second/",
                "attachments/Second/same.bin"
            ]
        );
    }
}
#[test]
fn ambiguous_name_owners_are_rejected_before_any_archive_can_be_saved() {
    for names in [
        &["Same", "Same"][..],
        &["a/b", "a\\b"][..],
        &["Same", "Same", "Same_1"][..],
    ] {
        let mut records = Vec::new();
        for (index, &name) in names.iter().enumerate() {
            let mut record = Record::default();
            record.extra.insert("confidex.title".into(), name.into());
            if index == names.len() - 1 {
                record.entries.push(file("public.bin", &[1]));
            }
            records.push(record);
        }
        let (plan, memory) = plan(records, export::Limits::default());
        assert_eq!(
            plan.write(Consent::AllowLosses, &mut |_| true).err(),
            Some(export::Error::Blocked)
        );
        assert_eq!(memory.available(), MAX_OPEN_MEMORY);
    }
}
#[test]
fn same_titles_without_files_are_allowed_and_json_matches_the_plain_writer() {
    use confidex_app::import::formats::bitwarden_json;
    let records = || {
        let mut records = fixture();
        for record in &mut records {
            record.entries.retain(|entry| entry.type_name != "file/v1");
            record.extra.insert("confidex.title".into(), "Same".into());
        }
        records
    };
    let (zipped, _) = plan(records(), export::Limits::default());
    let artifact = zipped.write(Consent::Lossless, &mut |_| true).unwrap();
    let mut actual = document(artifact.bytes());
    for item in actual["items"].as_array_mut().unwrap() {
        item.as_object_mut().unwrap().remove("id");
    }
    let mut snapshot = export::Records::new(export::Limits::default()).unwrap();
    for record in records() {
        snapshot.push(record).unwrap();
    }
    let plain = export::prepare(
        snapshot,
        Box::new(bitwarden_json::Writer::new(
            bitwarden_json::Profile::Personal,
        )),
        &mut |_| true,
    )
    .unwrap()
    .write(Consent::Lossless, &mut |_| true)
    .unwrap();
    assert_eq!(
        actual,
        serde_json::from_slice::<serde_json::Value>(plain.bytes()).unwrap()
    );
    assert_eq!(imported(artifact.bytes()).items.len(), 2);
}
#[test]
fn malformed_file_and_overlong_paths_are_blocked_in_review() {
    for entry in [
        field("Broken", "file/v1", "filename", "missing.bin"),
        file(&"a".repeat(4096), &[1]),
    ] {
        let mut record = Record::default();
        record.entries.push(entry);
        let (plan, _) = plan(vec![record], export::Limits::default());
        assert!(
            plan.issues()
                .iter()
                .any(|i| i.severity == export::Severity::Blocked)
        );
        assert_eq!(
            plan.write(Consent::AllowLosses, &mut |_| true).err(),
            Some(export::Error::Blocked)
        );
    }
}
#[test]
fn archive_entry_budget_is_checked_before_serialization_and_releases_memory() {
    let mut records = Vec::new();
    for owner in 0..40 {
        let mut record = Record::default();
        record
            .extra
            .insert("confidex.title".into(), format!("Item {owner}").into());
        for index in 0..500 {
            record.entries.push(file(&format!("{index}.bin"), &[]));
        }
        records.push(record);
    }
    let (plan, memory) = plan(records, export::Limits::default());
    assert!(plan.issues().is_empty());
    assert_eq!(
        plan.write(Consent::Lossless, &mut |_| true).err(),
        Some(export::Error::Limit)
    );
    assert_eq!(memory.available(), MAX_OPEN_MEMORY);
}
#[test]
fn unsafe_or_duplicate_filenames_and_protection_cannot_be_overridden() {
    for name in [
        "../file",
        "bad\\file",
        "C:stream",
        "",
        ".",
        "..",
        "bad\0file",
        "same.bin",
    ] {
        let mut items = fixture();
        items[0].entries.push(file(name, &[3]));
        let (plan, _) = plan(items, export::Limits::default());
        assert!(
            plan.issues()
                .iter()
                .any(|i| i.severity == export::Severity::Blocked)
        );
        assert_eq!(
            plan.write(Consent::AllowLosses, &mut |_| true).err(),
            Some(export::Error::Blocked)
        );
    }
    let mut items = fixture();
    items[0].entries[6].extra.insert(
        "metadata".into(),
        Value::Map(vec![("protected".into(), true.into())]),
    );
    let (plan, _) = plan(items, export::Limits::default());
    assert!(
        plan.issues()
            .iter()
            .any(|i| i.code == export::Code::Protection && i.severity == export::Severity::Blocked)
    );
}
#[test]
fn file_labels_order_metadata_and_source_snapshots_have_exact_review() {
    let mut record = Record::default();
    record
        .extra
        .insert("confidex.title".into(), "Current".into());
    let mut attached = file("current.bin", &[4, 2]);
    attached.name = "Old label".into();
    attached.extra.insert(
        "bitwarden.zip.path".into(),
        "attachments/OLD/removed.bin".into(),
    );
    attached.value.insert("mime".into(), "image/webp".into());
    record
        .entries
        .extend([attached, field("Text", "text/v1", "text", "PUBLIC")]);
    record.extra.insert(
        "confidex.import.origin".into(),
        Value::Map(vec![("old-password".into(), "PUBLIC-OLD-REMOVED".into())]),
    );
    let (plan, _) = plan(vec![record], export::Limits::default());
    for code in [
        export::Code::FieldNames,
        export::Code::FieldOrder,
        export::Code::UnknownValue,
        export::Code::SourceContext,
    ] {
        assert!(plan.issues().iter().any(|i| i.code == code));
    }
    let artifact = plan.write(Consent::AllowLosses, &mut |_| true).unwrap();
    assert!(
        !document(artifact.bytes())
            .to_string()
            .contains("PUBLIC-OLD-REMOVED")
    );
    let imported = imported(artifact.bytes());
    let record = imported.items[0].record(MAX_OPEN_MEMORY).unwrap();
    assert_eq!(record.entries[0].name, "Text");
    assert_eq!(record.entries[1].name, "current.bin");
    assert_eq!(
        record.entries[1].value["data"].as_slice(),
        Some(&[4, 2][..])
    );
}
