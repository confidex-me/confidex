//! Artificial writers test the shared contract without advertising a vendor format.
use confidex_app::export::{
    self, Code, Consent, Error, File, Format, Limits, Output, Phase, Records, Review, Severity,
    Writer,
};
use confidex_vault::record::{Entry, Mapping, Record, Value};
use std::{
    io::{Cursor, Read, Seek, SeekFrom, Write},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

fn limits() -> Limits {
    Limits {
        records: 16,
        snapshot_bytes: 1 << 20,
        output_bytes: 4096,
        issues: 32,
        memory_bytes: 8 << 20,
    }
}
fn record(unknown: bool, metadata: bool) -> Record {
    let mut record = Record::default();
    record.entries.push(Entry {
        name: "".into(),
        type_name: "text/v1".into(),
        value: Mapping::from([("text".into(), "current synthetic value".into())]),
        extra: Mapping::new(),
    });
    if unknown {
        record.entries.push(Entry {
            name: "".into(),
            type_name: "future/v9".into(),
            value: Mapping::from([("opaque".into(), Value::Ext(42, vec![1, 2, 3]))]),
            extra: Mapping::new(),
        });
    }
    if metadata {
        record.tags.push("synthetic tag".into());
        record
            .extra
            .insert("source-context".into(), "deleted synthetic password".into());
    }
    record
}
fn records(unknown: bool, metadata: bool) -> Records {
    let mut records = Records::new(limits()).unwrap();
    records.push(record(unknown, metadata)).unwrap();
    records
}
#[derive(Clone, Copy)]
enum Mode {
    Normal,
    Block,
    Fail,
    IgnoreOutputErrors,
    Seek,
    Zip,
    ReviewOverflow,
    ReviewBadField,
    LargeScratch,
    Grow,
    GrowMemoryFailure,
}
struct Fixture {
    calls: Arc<AtomicUsize>,
    mode: Mode,
}
impl Writer for Fixture {
    fn format(&self) -> Format {
        Format::Csv
    }
    fn file(&self) -> File {
        File {
            name: "fixture.txt",
            media_type: "text/plain",
            encrypted: false,
        }
    }
    fn review(&self, record: &Record, review: &mut Review<'_>) -> Result<(), Error> {
        for (index, entry) in record.entries.iter().enumerate() {
            if entry.type_name == "text/v1" {
                review.preserved(index)?;
            } else {
                review.issue(
                    Some(index),
                    if matches!(self.mode, Mode::Block) {
                        Severity::Blocked
                    } else {
                        Severity::Loss
                    },
                    Code::UnsupportedField,
                )?;
            }
        }
        if !record.tags.is_empty() {
            review.issue(None, Severity::Loss, Code::Tags)?;
        }
        review.tags();
        if !record.extra.is_empty() {
            review.issue(None, Severity::Loss, Code::SourceContext)?;
        }
        review.metadata();
        if matches!(self.mode, Mode::ReviewOverflow) {
            for _ in 0..33 {
                let _ = review.issue(None, Severity::Loss, Code::History);
            }
        }
        if matches!(self.mode, Mode::ReviewBadField) {
            let _ = review.preserved(usize::MAX);
        }
        Ok(())
    }
    fn write(&self, records: &Records, output: &mut Output<'_>) -> Result<(), Error> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        match self.mode {
            Mode::LargeScratch => {
                let _scratch = output.reserve(128 << 20)?;
                output.write_all(b"small public output")?;
                return Ok(());
            }
            Mode::Grow => {
                for byte in 0..8 {
                    output.write_all(&[byte; 20_000])?;
                }
                return Ok(());
            }
            Mode::GrowMemoryFailure => {
                let _scratch = output.reserve(7 << 20)?;
                let bytes = zeroize::Zeroizing::new(vec![3; 512 << 10]);
                output.write_all(&bytes)?;
                let _ = output.write_all(b"x");
                return Ok(());
            }
            Mode::Fail => {
                output.write_all(b"partial secret")?;
                return Err(Error::Writer);
            }
            Mode::IgnoreOutputErrors => {
                let _ = output.write_all(&[1; 8192]);
                return Ok(());
            }
            Mode::Seek => {
                output.write_all(b"0000")?;
                output.seek(SeekFrom::Start(0))?;
                output.write_all(b"head")?;
                output.seek(SeekFrom::End(2))?;
                output.write_all(b"tail")?;
                return Ok(());
            }
            Mode::Zip => {
                let mut zip = zip::ZipWriter::new(output);
                zip.start_file(
                    "item.txt",
                    zip::write::SimpleFileOptions::default()
                        .compression_method(zip::CompressionMethod::Stored),
                )
                .map_err(|_| Error::Writer)?;
                zip.write_all(b"synthetic container value")?;
                zip.finish().map_err(|_| Error::Writer)?;
                return Ok(());
            }
            _ => {}
        }
        for (index, record) in records.iter().enumerate() {
            output.checkpoint(index, records.len())?;
            for entry in &record.entries {
                if entry.type_name == "text/v1" {
                    output.write_all(entry.value["text"].as_str().unwrap().as_bytes())?;
                    output.write_all(b"\n")?;
                }
            }
        }
        Ok(())
    }
}
fn writer(mode: Mode) -> (Box<dyn Writer>, Arc<AtomicUsize>) {
    let calls = Arc::new(AtomicUsize::new(0));
    (
        Box::new(Fixture {
            mode,
            calls: calls.clone(),
        }),
        calls,
    )
}

#[test]
fn preview_freezes_current_values_and_requires_explicit_loss_consent() {
    let (writer, calls) = writer(Mode::Normal);
    let plan = export::prepare(records(true, true), writer, &mut |_| true).unwrap();
    assert_eq!(calls.load(Ordering::Relaxed), 0);
    assert_eq!(plan.records(), 1);
    assert_eq!(plan.issues().len(), 3);
    assert_eq!(plan.issues()[0].field, Some(1));
    assert_eq!(
        plan.write(Consent::default(), &mut |_| true).err(),
        Some(Error::Losses)
    );
    assert_eq!(calls.load(Ordering::Relaxed), 0);

    let (writer, _) = self::writer(Mode::Normal);
    let plan = export::prepare(records(true, true), writer, &mut |_| true).unwrap();
    let file = plan.write(Consent::AllowLosses, &mut |_| true).unwrap();
    assert_eq!(file.bytes(), b"current synthetic value\n");
    assert!(!file.file.encrypted);
    assert!(!file.bytes().windows(7).any(|bytes| bytes == b"deleted"));
}

#[test]
fn blocked_data_cannot_be_accepted_as_a_loss() {
    let (writer, calls) = writer(Mode::Block);
    let plan = export::prepare(records(true, false), writer, &mut |_| true).unwrap();
    assert_eq!(
        plan.write(Consent::AllowLosses, &mut |_| true).err(),
        Some(Error::Blocked)
    );
    assert_eq!(calls.load(Ordering::Relaxed), 0);
}

#[test]
fn all_paths_release_snapshot_and_output_reservations() {
    for mode in [Mode::Normal, Mode::Fail, Mode::IgnoreOutputErrors] {
        let records = records(false, false);
        let memory = records.memory().clone();
        let (writer, _) = writer(mode);
        let plan = export::prepare(records, writer, &mut |_| true).unwrap();
        let result = plan.write(Consent::Lossless, &mut |_| true);
        match mode {
            Mode::Normal => {
                let artifact = result.unwrap();
                let charged = limits().memory_bytes - memory.available();
                assert!(charged >= artifact.bytes().len() && charged <= limits().output_bytes);
                drop(artifact);
            }
            Mode::Fail => assert_eq!(result.err(), Some(Error::Writer)),
            Mode::IgnoreOutputErrors => assert_eq!(result.err(), Some(Error::Limit)),
            _ => unreachable!(),
        }
        assert_eq!(memory.available(), limits().memory_bytes);
    }
}

#[test]
fn cancellation_is_terminal_even_when_writer_ignores_io_errors() {
    for mode in [Mode::Normal, Mode::IgnoreOutputErrors] {
        let records = records(false, false);
        let memory = records.memory().clone();
        let (writer, _) = writer(mode);
        let plan = export::prepare(records, writer, &mut |_| true).unwrap();
        let mut checkpoints = 0;
        let result = plan.write(Consent::Lossless, &mut |progress| {
            assert_eq!(progress.phase, Phase::Write);
            checkpoints += 1;
            checkpoints < 2
        });
        assert_eq!(result.err(), Some(Error::Canceled));
        assert_eq!(checkpoints, 2);
        assert_eq!(memory.available(), limits().memory_bytes);
    }
    let records = records(false, false);
    let memory = records.memory().clone();
    let (writer, calls) = writer(Mode::Normal);
    assert_eq!(
        export::prepare(records, writer, &mut |_| false).err(),
        Some(Error::Canceled)
    );
    assert_eq!(calls.load(Ordering::Relaxed), 0);
    assert_eq!(memory.available(), limits().memory_bytes);
}

#[test]
fn seek_supports_container_headers_and_zero_filled_gaps() {
    let (writer, _) = writer(Mode::Seek);
    let plan = export::prepare(records(false, false), writer, &mut |_| true).unwrap();
    let file = plan.write(Consent::Lossless, &mut |_| true).unwrap();
    assert_eq!(file.bytes(), b"head\0\0tail");
}

#[test]
fn real_zip_writer_can_finish_its_headers_in_the_bounded_output() {
    let (writer, _) = writer(Mode::Zip);
    let plan = export::prepare(records(false, false), writer, &mut |_| true).unwrap();
    let file = plan.write(Consent::Lossless, &mut |_| true).unwrap();
    let mut archive = zip::ZipArchive::new(Cursor::new(file.bytes())).unwrap();
    assert_eq!(archive.len(), 1);
    let mut value = String::new();
    archive
        .by_name("item.txt")
        .unwrap()
        .read_to_string(&mut value)
        .unwrap();
    assert_eq!(value, "synthetic container value");
}

#[test]
fn ignored_review_errors_still_reject_the_plan() {
    for (mode, expected) in [
        (Mode::ReviewOverflow, Error::Limit),
        (Mode::ReviewBadField, Error::InvalidWriter),
    ] {
        let records = records(false, false);
        let memory = records.memory().clone();
        let (writer, calls) = writer(mode);
        assert_eq!(
            export::prepare(records, writer, &mut |_| true).err(),
            Some(expected)
        );
        assert_eq!(calls.load(Ordering::Relaxed), 0);
        assert_eq!(memory.available(), limits().memory_bytes);
    }
}

struct Incomplete;
impl Writer for Incomplete {
    fn format(&self) -> Format {
        Format::Csv
    }
    fn file(&self) -> File {
        File {
            name: "fixture.txt",
            media_type: "text/plain",
            encrypted: false,
        }
    }
    fn review(&self, _: &Record, _: &mut Review<'_>) -> Result<(), Error> {
        Ok(())
    }
    fn write(&self, _: &Records, _: &mut Output<'_>) -> Result<(), Error> {
        panic!("incomplete review must not be written")
    }
}
#[test]
fn accidentally_unreviewed_fields_tags_or_metadata_block_the_plan() {
    for (fields, tags, metadata) in [
        (true, false, false),
        (false, true, false),
        (false, false, true),
    ] {
        let mut record = record(false, metadata);
        if !fields {
            record.entries.clear();
        }
        if tags {
            record.tags.push("not reviewed".into());
        }
        let mut records = Records::new(limits()).unwrap();
        records.push(record).unwrap();
        assert_eq!(
            export::prepare(records, Box::new(Incomplete), &mut |_| true).err(),
            Some(Error::InvalidWriter)
        );
    }
}

#[test]
fn resource_limits_reject_without_changing_the_existing_snapshot() {
    let mut limits = limits();
    limits.records = 1;
    let mut records = Records::new(limits).unwrap();
    records.push(record(false, false)).unwrap();
    assert_eq!(records.push(record(false, false)), Err(Error::Limit));
    assert_eq!(records.len(), 1);
    limits.snapshot_bytes = 1;
    let mut records = Records::new(limits).unwrap();
    assert_eq!(records.push(record(false, false)), Err(Error::Limit));
    assert!(records.is_empty());
    limits.output_bytes = 0;
    assert_eq!(Records::new(limits).err(), Some(Error::Limit));
}

#[test]
fn a_small_file_does_not_reserve_its_full_ceiling_before_expensive_work() {
    let mut records = Records::new(Limits::default()).unwrap();
    records.push(record(false, false)).unwrap();
    let memory = records.memory().clone();
    let (writer, _) = writer(Mode::LargeScratch);
    let plan = export::prepare(records, writer, &mut |_| true).unwrap();
    let file = plan.write(Consent::Lossless, &mut |_| true).unwrap();
    assert_eq!(file.bytes(), b"small public output");
    assert!(Limits::default().memory_bytes - memory.available() < 1 << 20);
    drop(file);
    assert_eq!(memory.available(), Limits::default().memory_bytes);
}

#[test]
fn bounded_growth_preserves_every_written_byte_and_releases_old_charges() {
    let mut records = Records::new(Limits::default()).unwrap();
    records.push(record(false, false)).unwrap();
    let memory = records.memory().clone();
    let (writer, _) = writer(Mode::Grow);
    let plan = export::prepare(records, writer, &mut |_| true).unwrap();
    let file = plan.write(Consent::Lossless, &mut |_| true).unwrap();
    assert_eq!(file.bytes().len(), 160_000);
    let (parts, remainder) = file.bytes().as_chunks::<20_000>();
    assert!(remainder.is_empty());
    for (index, part) in parts.iter().enumerate() {
        assert!(part.iter().all(|&byte| byte == index as u8));
    }
    assert!(Limits::default().memory_bytes - memory.available() < 1 << 20);
    drop(file);
    assert_eq!(memory.available(), Limits::default().memory_bytes);
}

#[test]
fn failed_growth_never_releases_a_partial_file_even_if_writer_ignores_it() {
    let mut limits = limits();
    limits.output_bytes = 1 << 20;
    let mut records = Records::new(limits).unwrap();
    records.push(record(false, false)).unwrap();
    let memory = records.memory().clone();
    let (writer, _) = writer(Mode::GrowMemoryFailure);
    let plan = export::prepare(records, writer, &mut |_| true).unwrap();
    assert_eq!(
        plan.write(Consent::Lossless, &mut |_| true).err(),
        Some(Error::Limit)
    );
    assert_eq!(memory.available(), limits.memory_bytes);
}

#[test]
fn format_options_preserve_optional_credentials_and_reject_ambiguous_csv() {
    use export::{Column, Csv, Options, Source};
    for (password, keyfile) in [
        (Some("public"), None),
        (None, Some(vec![1])),
        (Some("public"), Some(vec![1])),
        (Some(""), None),
        (Some(""), Some(vec![])),
    ] {
        let options = Options::Password {
            password: password.map(str::to_owned),
            keyfile,
        };
        options.validate(Format::Kdbx).unwrap();
        let bytes = zeroize::Zeroizing::new(serde_json::to_vec(&options).unwrap());
        let decoded: Options = serde_json::from_slice(&bytes).unwrap();
        let Options::Password {
            password: old,
            keyfile: old_file,
        } = &options
        else {
            unreachable!()
        };
        let Options::Password {
            password: new,
            keyfile: new_file,
        } = &decoded
        else {
            unreachable!()
        };
        assert_eq!(old, new);
        assert_eq!(old_file, new_file);
        assert_eq!(
            options.validate(Format::BitwardenJson),
            Err(Error::InvalidOptions)
        );
    }
    assert_eq!(
        Options::Password {
            password: None,
            keyfile: None
        }
        .validate(Format::Kdbx),
        Err(Error::InvalidOptions)
    );
    assert_eq!(
        Options::Password {
            password: Some("public".into()),
            keyfile: Some(vec![])
        }
        .validate(Format::BitwardenEncryptedJson),
        Err(Error::InvalidOptions)
    );
    let mut csv = Csv {
        profile: None,
        delimiter: b',',
        header: true,
        columns: vec![Column {
            heading: "".into(),
            source: Source::Field {
                index: 0,
                type_name: "password/v1".into(),
                key: "password".into(),
            },
        }],
    };
    let mut options = Options::Csv(csv);
    options.validate(Format::Csv).unwrap();
    let Options::Csv(ref mut value) = options else {
        unreachable!()
    };
    value.profile = Some("chromium".into());
    assert_eq!(options.validate(Format::Csv), Err(Error::InvalidOptions));
    let Options::Csv(ref mut value) = options else {
        unreachable!()
    };
    value.columns.clear();
    options.validate(Format::Csv).unwrap();
    csv = Csv {
        profile: None,
        delimiter: 0,
        header: true,
        columns: vec![],
    };
    assert_eq!(
        Options::Csv(csv).validate(Format::Csv),
        Err(Error::InvalidOptions)
    );
}

#[cfg(not(feature = "export-check"))]
#[test]
fn ordinary_builds_do_not_advertise_synthetic_writers() {
    let formats = export::catalog();
    assert_eq!(formats.len(), 6);
    assert_eq!(formats[0].format, Format::BitwardenJson);
    assert_eq!(formats[1].format, Format::Kdbx);
    assert_eq!(formats[2].format, Format::BitwardenEncryptedJson);
    assert_eq!(formats[3].format, Format::BitwardenZip);
    assert_eq!(formats[4].format, Format::KeepassXml);
    assert_eq!(formats[5].format, Format::Onepassword1pux);
    assert!(!formats.iter().any(|info| info.format == Format::Csv));
    assert_eq!(
        export::writer(
            Format::Csv,
            export::Options::Csv(export::Csv {
                profile: Some("chromium".into()),
                delimiter: b',',
                header: true,
                columns: vec![],
            }),
            0
        )
        .unwrap()
        .format(),
        Format::Csv
    );
}

#[cfg(not(feature = "export-check"))]
#[test]
fn csv_factory_preserves_options_and_refuses_invalid_profiles_or_bindings() {
    use export::{Column, Csv, Options, Source};
    for profile in ["unknown", "chromium", "firefox", "apple-passwords"] {
        for delimiter in *b",;" {
            let writer = export::writer(
                Format::Csv,
                Options::Csv(Csv {
                    profile: Some(profile.into()),
                    delimiter,
                    header: true,
                    columns: vec![],
                }),
                0,
            );
            assert_eq!(writer.is_ok(), profile != "unknown" && delimiter == b',');
        }
    }
    for duplicate in [false, true] {
        let options = Options::Csv(Csv {
            profile: None,
            delimiter: b';',
            header: false,
            columns: vec![
                Column {
                    heading: "Same".into(),
                    source: Source::Title,
                },
                Column {
                    heading: "Same".into(),
                    source: if duplicate {
                        Source::Title
                    } else {
                        Source::Field {
                            index: 0,
                            type_name: "text/v1".into(),
                            key: "text".into(),
                        }
                    },
                },
            ],
        });
        let encoded = zeroize::Zeroizing::new(serde_json::to_vec(&options).unwrap());
        let writer = export::writer(Format::Csv, serde_json::from_slice(&encoded).unwrap(), 0);
        if duplicate {
            assert_eq!(writer.err(), Some(Error::InvalidOptions));
        } else {
            let plan =
                export::prepare(records(false, false), writer.unwrap(), &mut |_| true).unwrap();
            let artifact = plan.write(Consent::AllowLosses, &mut |_| true).unwrap();
            assert_eq!(artifact.bytes(), b"\"\";\"current synthetic value\"\r\n");
        }
    }
}

#[cfg(not(feature = "export-check"))]
#[test]
fn registered_bitwarden_profiles_are_typed_and_write_real_json() {
    for organization in [false, true] {
        let options = export::Options::Bitwarden {
            organization,
            password: None,
        };
        assert_eq!(
            options.validate(Format::KeepassXml),
            Err(Error::InvalidOptions)
        );
        let encoded = serde_json::to_vec(&options).unwrap();
        let options = serde_json::from_slice(&encoded).unwrap();
        let writer = export::writer(Format::BitwardenJson, options, 0).unwrap();
        let plan = export::prepare(records(false, false), writer, &mut |_| true).unwrap();
        let artifact = plan.write(Consent::Lossless, &mut |_| true).unwrap();
        assert!(!artifact.file.encrypted);
        assert_eq!(artifact.file.media_type, "application/json");
        let json: serde_json::Value = serde_json::from_slice(artifact.bytes()).unwrap();
        assert_eq!(json["encrypted"], false);
        assert_eq!(
            json["items"][0]["fields"][0]["value"],
            "current synthetic value"
        );
        assert!(
            json.get(if organization {
                "collections"
            } else {
                "folders"
            })
            .is_some()
        );
        assert!(
            json.get(if organization {
                "folders"
            } else {
                "collections"
            })
            .is_none()
        );
        assert_eq!(
            artifact.file.name,
            if organization {
                "bitwarden-organization.json"
            } else {
                "bitwarden-personal.json"
            }
        );
    }
}

#[test]
fn bitwarden_profile_credentials_are_format_specific_and_bounded() {
    for organization in [false, true] {
        for password in [
            None,
            Some(String::new()),
            Some("public".into()),
            Some("x".repeat(export::MAX_PASSWORD_BYTES + 1)),
        ] {
            let options = export::Options::Bitwarden {
                organization,
                password,
            };
            let bytes = zeroize::Zeroizing::new(serde_json::to_vec(&options).unwrap());
            let decoded: export::Options = serde_json::from_slice(&bytes).unwrap();
            let export::Options::Bitwarden {
                organization: actual,
                password,
            } = &decoded
            else {
                panic!("profile");
            };
            assert_eq!(*actual, organization);
            assert_eq!(
                decoded.validate(Format::BitwardenJson).is_ok(),
                password.is_none()
            );
            assert_eq!(
                decoded.validate(Format::BitwardenEncryptedJson).is_ok(),
                password
                    .as_ref()
                    .is_some_and(|p| !p.is_empty() && p.len() <= export::MAX_PASSWORD_BYTES)
            );
            assert_eq!(decoded.validate(Format::Kdbx), Err(Error::InvalidOptions));
        }
    }
}
