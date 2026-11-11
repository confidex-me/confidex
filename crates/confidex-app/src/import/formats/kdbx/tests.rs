use super::*;
use crate::import::{Format, Limits, Options, Plan};

const PASSWORD: &str = "PUBLIC-FIXTURE-DATABASE";
const V4: &[u8] = include_bytes!("../../../../tests/import_fixtures/kdbx/password.kdbx");
const KEY: &[u8] = include_bytes!("../../../../tests/import_fixtures/kdbx/public.key");
const FILE: &[u8] = b"PUBLIC-FIXTURE-ATTACHMENT\0\xff\n";

fn plan(input: &[u8], options: &Options) -> Result<crate::import::Plan, Error> {
    let mut check = |_| true;
    let mut context = Context::new(
        Format::Kdbx,
        input.len(),
        options,
        Limits::default(),
        &mut check,
    )?;
    parse(input, &mut context)?;
    context.finish()
}

fn options(password: &str, keyfile: &[u8]) -> Options {
    Options {
        password: password.into(),
        keyfile: keyfile.into(),
        password_present: !password.is_empty(),
        keyfile_present: !keyfile.is_empty(),
        source_instance: Some("PUBLIC-KDBX-SOURCE".into()),
        include_archived: false,
        include_deleted: false,
        csv: None,
    }
}

#[test]
fn credential_presence_does_not_guess_from_empty_values_or_retained_input() {
    let expected = plan(V4, &options(PASSWORD, &[])).unwrap();
    for (input, password, keyfile) in [
        (
            include_bytes!("../../../../tests/import_fixtures/kdbx/empty-password.kdbx").as_slice(),
            "",
            None,
        ),
        (
            include_bytes!("../../../../tests/import_fixtures/kdbx/empty-password-keyfile.kdbx")
                .as_slice(),
            "",
            Some(KEY),
        ),
    ] {
        let mut opts = options(password, keyfile.unwrap_or_default());
        opts.password_present = true;
        opts.keyfile_present = keyfile.is_some();
        same_records(&expected, &plan(input, &opts).unwrap());
        if keyfile.is_some() {
            opts.keyfile_present = false;
        } else {
            opts.password_present = false;
        }
        assert!(plan(input, &opts).is_err());
    }

    let mut absent = options(PASSWORD, KEY);
    absent.password_present = false;
    absent.keyfile_present = false;
    assert_eq!(
        plan(V4, &absent).err().unwrap().kind,
        ErrorKind::InvalidOptions
    );
    absent.password_present = true;
    same_records(&expected, &plan(V4, &absent).unwrap());
    absent.keyfile.clear();
    absent.keyfile_present = true;
    assert_eq!(plan(V4, &absent).err().unwrap().kind, ErrorKind::Checksum);

    let mut file_only = options("", KEY);
    file_only.password = "PUBLIC-RETAINED-INACTIVE-PASSWORD".into();
    let file = include_bytes!("../../../../tests/import_fixtures/kdbx/keyfile.kdbx");
    same_records(&expected, &plan(file, &file_only).unwrap());
    file_only.password.clear();
    file_only.password_present = true;
    assert_eq!(
        plan(file, &file_only).err().unwrap().kind,
        ErrorKind::Checksum
    );
}

fn same_records(left: &Plan, right: &Plan) {
    fn current(mut record: Record) -> zeroize::Zeroizing<Vec<u8>> {
        record.entries.retain(|e| e.name != "Original data");
        record.entries.sort_by(|a, b| a.name.cmp(&b.name));
        record.encode_content(96 << 20).unwrap().bytes
    }
    assert_eq!(left.items.len(), right.items.len());
    for (left, right) in left.items.iter().zip(&right.items) {
        assert_eq!(left.status, right.status);
        assert!(
            current(left.record(96 << 20).unwrap()) == current(right.record(96 << 20).unwrap()),
            "Current fields differ"
        );
    }
}

#[test]
fn actual_keepassxc_password_keyfile_and_both_keep_records_and_binaries() {
    let expected = plan(V4, &options(PASSWORD, &[])).unwrap();
    assert_eq!(expected.items.len(), 3);
    let file = plan(
        include_bytes!("../../../../tests/import_fixtures/kdbx/keyfile.kdbx"),
        &options("", KEY),
    )
    .unwrap();
    let both = plan(
        include_bytes!("../../../../tests/import_fixtures/kdbx/both.kdbx"),
        &options(PASSWORD, KEY),
    )
    .unwrap();
    same_records(&expected, &file);
    same_records(&expected, &both);
    let mut files = Vec::new();
    let mut history = false;
    let mut hidden = false;
    let mut otp = false;
    let mut unresolved = false;
    for item in &expected.items {
        let record = item.record(96 << 20).unwrap();
        let attributes = Record {
            extra: item.source_attributes(96 << 20).unwrap(),
            entries: Vec::new(),
            tags: Vec::new(),
        };
        assert!(attributes.extra.contains_key("binary_pool"));
        unresolved |= item
            .diagnostics
            .iter()
            .any(|d| d.code == Code::UnresolvedFieldReference);
        for field in &record.entries {
            match field.type_name.as_str() {
                "file/v1" => files.push(field.value["data"].as_slice().unwrap().to_vec()),
                "totp/v1" => otp = true,
                "secret/v1" => {
                    hidden |= field.value["secret"].as_str() == Some("PUBLIC-FIXTURE-HIDDEN")
                }
                "secure-note/v1" if field.name == "Original data" => {
                    history |= field.value["text"]
                        .as_str()
                        .unwrap()
                        .contains("PUBLIC-FIXTURE-OLD")
                }
                _ => {}
            }
        }
    }
    assert_eq!(files.len(), 3);
    assert_eq!(
        files
            .iter()
            .filter(|bytes| bytes.as_slice() == FILE)
            .count(),
        2
    );
    assert_eq!(files.iter().filter(|bytes| bytes.is_empty()).count(), 1);
    assert!(history && hidden && otp && unresolved);
    assert_eq!(
        expected
            .items
            .iter()
            .filter(|i| i.status == Status::Excluded)
            .count(),
        1
    );
    let container = Record {
        extra: expected.container_attributes(96 << 20).unwrap(),
        entries: Vec::new(),
        tags: Vec::new(),
    };
    assert_eq!(container.extra["source_format"].as_str(), Some("kdbx"));
    assert!(
        !container.extra["outer_header"]
            .as_slice()
            .unwrap()
            .is_empty()
    );
}

#[test]
fn independently_verified_cipher_kdf_matrix_produces_the_same_plan() {
    let cases = [
        (
            include_bytes!(
                "../../../../../../vendor/keepass/tests/resources/bounded/argon2d-aes.kdbx"
            )
            .as_slice(),
            options("PUBLIC-VARIANT-DATABASE", &[]),
        ),
        (
            include_bytes!(
                "../../../../../../vendor/keepass/tests/resources/bounded/argon2d-aes-v10.kdbx"
            )
            .as_slice(),
            options("PUBLIC-VARIANT-DATABASE", &[]),
        ),
        (
            include_bytes!(
                "../../../../../../vendor/keepass/tests/resources/bounded/argon2id-chacha.kdbx"
            )
            .as_slice(),
            options(
                "PUBLIC-VARIANT-DATABASE",
                include_bytes!(
                    "../../../../../../vendor/keepass/tests/resources/bounded/public-v2.keyx"
                ),
            ),
        ),
        (
            include_bytes!(
                "../../../../../../vendor/keepass/tests/resources/bounded/aes-twofish.kdbx"
            )
            .as_slice(),
            options(
                "",
                include_bytes!(
                    "../../../../../../vendor/keepass/tests/resources/bounded/public.raw"
                ),
            ),
        ),
        (
            include_bytes!(
                "../../../../../../vendor/keepass/tests/resources/bounded/argon2id-aes-hex.kdbx"
            )
            .as_slice(),
            options(
                "",
                include_bytes!(
                    "../../../../../../vendor/keepass/tests/resources/bounded/public.hex"
                ),
            ),
        ),
    ];
    let expected = plan(cases[0].0, &cases[0].1).unwrap();
    assert_eq!(expected.items.len(), 1);
    for (input, options) in cases.iter().skip(1) {
        same_records(&expected, &plan(input, options).unwrap());
    }
    let record = expected.items[0].record(96 << 20).unwrap();
    let files = record
        .entries
        .iter()
        .filter(|e| e.type_name == "file/v1")
        .collect::<Vec<_>>();
    assert_eq!(files.len(), 2);
    assert!(
        files
            .iter()
            .any(|f| f.value["data"].as_slice() == Some(b"PUBLIC-KDBX-BINARY\0\xff\n".as_slice()))
    );
    assert!(
        files
            .iter()
            .any(|f| f.value["data"].as_slice() == Some(b"".as_slice()))
    );
}

#[test]
fn legacy_kdbx3_uses_the_same_keepass_semantics() {
    let input = include_bytes!(
        "../../../../../../vendor/keepass/tests/resources/test_db_with_password.kdbx"
    );
    let actual = plan(input, &options("demopass", &[])).unwrap();
    assert!(!actual.items.is_empty());
    assert!(actual.items.iter().any(|item| {
        item.record(96 << 20)
            .unwrap()
            .entries
            .iter()
            .any(|e| e.type_name == "password/v1")
    }));
}

#[test]
fn real_legacy_xml_pool_keeps_deduplicated_and_empty_attachments() {
    let input = include_bytes!("../../../../tests/import_fixtures/kdbx/legacy-attachments.kdbx");
    let opts = options("demopass", &[]);
    let raw = Raw::open(
        input,
        Some("demopass"),
        None,
        DecodeLimits::default(),
        &mut |_, _| true,
    )
    .unwrap();
    let mut check = |_| true;
    let mut context = Context::new(
        Format::Kdbx,
        input.len(),
        &opts,
        Limits::default(),
        &mut check,
    )
    .unwrap();
    assert_eq!(
        Document::parse(raw.xml(), &mut context)
            .unwrap()
            .pools
            .len(),
        2
    );
    let actual = plan(input, &opts).unwrap();
    let mut files = Vec::new();
    for item in &actual.items {
        let record = item.record(96 << 20).unwrap();
        for field in &record.entries {
            if field.type_name == "file/v1" {
                files.push(field.value["data"].as_slice().unwrap().to_vec());
            }
        }
    }
    assert_eq!(files.len(), 3);
    assert_eq!(
        files
            .iter()
            .filter(|b| b.as_slice() == b"PUBLIC-KDBX3-ATTACHMENT\0\xff\n")
            .count(),
        2
    );
    assert_eq!(files.iter().filter(|b| b.is_empty()).count(), 1);
}

#[test]
fn field_order_matches_each_authenticated_source_and_history_keeps_pool_links() {
    let opts = options(PASSWORD, &[]);
    let actual = plan(V4, &opts).unwrap();
    let mut raw = Raw::open(
        V4,
        Some(PASSWORD),
        None,
        DecodeLimits::default(),
        &mut |_, _| true,
    )
    .unwrap();
    let mut stream = raw.take_protected().unwrap();
    let mut check = |_| true;
    let mut context =
        Context::new(Format::Kdbx, V4.len(), &opts, Limits::default(), &mut check).unwrap();
    let values = protected::Values::read(raw.xml(), &mut stream, &mut context).unwrap();
    let doc = Document::parse(raw.xml(), &mut context).unwrap();
    for (location, item) in doc.entries.iter().zip(&actual.items) {
        let fragment = values
            .fragment(raw.xml(), location.span.clone(), &context)
            .unwrap();
        let node = keepass_xml::load(&fragment.bytes, location.span.start, &mut context).unwrap();
        let record = item.record(96 << 20).unwrap();
        let mapped = record
            .entries
            .iter()
            .filter(|e| e.name != "Original data")
            .map(|e| e.name.as_str())
            .collect::<Vec<_>>();
        let expected = node
            .children
            .iter()
            .filter(|n| matches!(n.name.as_str(), "String" | "Binary"))
            .map(|n| n.child("Key").unwrap().unwrap().leaf().unwrap())
            .filter(|name| mapped.contains(name))
            .collect::<Vec<_>>();
        assert_eq!(mapped, expected);
        let attributes = Record {
            extra: item.source_attributes(96 << 20).unwrap(),
            entries: Vec::new(),
            tags: Vec::new(),
        };
        let mut refs = BTreeSet::new();
        pool::references(&node, &mut refs);
        let stored = attributes.extra["binary_pool"].as_map().unwrap();
        assert_eq!(refs.len(), stored.len());
        for reference in refs {
            let original = raw.binary(reference.parse().unwrap()).unwrap();
            let value = stored
                .iter()
                .find(|(key, _)| key.as_str() == Some(reference))
                .unwrap()
                .1
                .as_map()
                .unwrap();
            assert!(
                value.iter().any(
                    |(k, v)| k.as_str() == Some("data") && v.as_slice() == Some(original.bytes)
                )
            );
            assert!(
                value.iter().any(|(k, v)| k.as_str() == Some("protected")
                    && v.as_bool() == Some(original.protected))
            );
        }
    }
}

#[test]
fn missing_references_orphans_repeat_limits_and_late_cancel_are_bounded() {
    let input =
        include_bytes!("../../../../../../vendor/keepass/tests/resources/bounded/argon2d-aes.kdbx");
    let opts = options("PUBLIC-VARIANT-DATABASE", &[]);
    let mut raw = Raw::open(
        input,
        Some(&opts.password),
        None,
        DecodeLimits::default(),
        &mut |_, _| true,
    )
    .unwrap();
    let mut stream = raw.take_protected().unwrap();
    let mut check = |_| true;
    let mut context = Context::new(
        Format::Kdbx,
        input.len(),
        &opts,
        Limits::default(),
        &mut check,
    )
    .unwrap();
    let values = protected::Values::read(raw.xml(), &mut stream, &mut context).unwrap();
    let doc = Document::parse(raw.xml(), &mut context).unwrap();
    let mut pool = pool::Pool::new(&raw, &values, &doc, &mut context).unwrap();
    for reference in ["missing", "99999999999999999999999999999", "999"] {
        assert!(pool.read(reference, &mut context).unwrap().is_none());
    }
    for index in 0..raw.binary_count() {
        let expected = raw.binary(index).unwrap();
        assert_eq!(
            pool.orphan(index, &context)
                .unwrap()
                .unwrap()
                .bytes
                .as_slice(),
            expected.bytes
        );
        assert_eq!(
            pool.read(&index.to_string(), &mut context)
                .unwrap()
                .unwrap()
                .bytes
                .as_slice(),
            expected.bytes
        );
        assert!(pool.orphan(index, &context).unwrap().is_none());
    }
    let limit = raw.binary(0).unwrap().bytes.len() + raw.binary(1).unwrap().bytes.len();
    context.limits.unpacked_bytes = limit;
    let before = context.memory().available();
    let index = (0..raw.binary_count())
        .find(|&i| !raw.binary(i).unwrap().bytes.is_empty())
        .unwrap();
    assert_eq!(
        pool.read(&index.to_string(), &mut context)
            .err()
            .unwrap()
            .kind,
        ErrorKind::Limit
    );
    assert_eq!(context.memory().available(), before);

    let mut check = |p: crate::import::Progress| !(p.phase == Phase::Validate && p.current > 0);
    let mut context =
        Context::new(Format::Kdbx, V4.len(), &opts, Limits::default(), &mut check).unwrap();
    let memory = context.memory().clone();
    assert_eq!(
        parse_with(V4, Some(PASSWORD), None, &mut context)
            .unwrap_err()
            .kind,
        ErrorKind::Canceled
    );
    drop(context);
    assert_eq!(memory.available(), Limits::default().memory_bytes);
}

#[test]
fn credentials_tampering_and_cancel_never_return_a_plan() {
    assert_eq!(
        plan(V4, &options("wrong", &[])).err().unwrap().kind,
        ErrorKind::Checksum
    );
    assert_eq!(
        plan(V4, &options(PASSWORD, KEY)).err().unwrap().kind,
        ErrorKind::Checksum
    );
    let mut changed = V4.to_vec();
    let last = changed.len() - 1;
    changed[last - 4] ^= 1;
    assert_eq!(
        plan(&changed, &options(PASSWORD, &[])).err().unwrap().kind,
        ErrorKind::Checksum
    );
    for input in [&V4[..10], &V4[..V4.len() - 1]] {
        assert!(plan(input, &options(PASSWORD, &[])).is_err());
    }
    let options = options(PASSWORD, &[]);
    let mut check = |p: crate::import::Progress| p.phase != Phase::Read;
    let mut context = Context::new(
        Format::Kdbx,
        V4.len(),
        &options,
        Limits::default(),
        &mut check,
    )
    .unwrap();
    let available = context.memory().available();
    assert_eq!(
        parse(V4, &mut context).unwrap_err().kind,
        ErrorKind::Canceled
    );
    assert_eq!(context.memory().available(), available);
}

#[test]
fn hostile_kdf_and_reduced_mapping_limits_fail_without_a_plan() {
    use sha2::{Digest, Sha256};
    let input =
        include_bytes!("../../../../../../vendor/keepass/tests/resources/bounded/argon2d-aes.kdbx");
    let header =
        keepass::bounded::Header::inspect(input, &DecodeLimits::default(), &mut |_| true).unwrap();
    let end = header.raw().len();
    let mut hostile = input.to_vec();
    let field = b"\x05\x01\0\0\0M\x08\0\0\0";
    let offset = hostile[..end]
        .windows(field.len())
        .position(|part| part == field)
        .unwrap()
        + field.len();
    hostile[offset..offset + 8].copy_from_slice(&(65u64 << 20).to_le_bytes());
    let digest = Sha256::digest(&hostile[..end]);
    hostile[end..end + 32].copy_from_slice(&digest);
    assert_eq!(
        plan(&hostile, &options("PUBLIC-VARIANT-DATABASE", &[]))
            .err()
            .unwrap()
            .kind,
        ErrorKind::KdfLimit
    );
    let opts = options(PASSWORD, &[]);
    for limits in [
        Limits {
            records: 1,
            ..Limits::default()
        },
        Limits {
            nodes: 8,
            ..Limits::default()
        },
        Limits {
            memory_bytes: 8 << 20,
            ..Limits::default()
        },
    ] {
        let mut check = |_| true;
        let mut context = Context::new(Format::Kdbx, V4.len(), &opts, limits, &mut check).unwrap();
        let memory = context.memory().clone();
        assert_eq!(parse(V4, &mut context).unwrap_err().kind, ErrorKind::Limit);
        drop(context);
        assert_eq!(memory.available(), limits.memory_bytes);
    }
    let mut check = |_| true;
    let mut context =
        Context::new(Format::Kdbx, V4.len(), &opts, Limits::default(), &mut check).unwrap();
    assert_eq!(
        parse_with(V4, None, None, &mut context).unwrap_err().kind,
        ErrorKind::InvalidOptions
    );
}
