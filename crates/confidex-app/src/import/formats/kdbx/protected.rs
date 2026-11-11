//! Consume the inner stream in source order, including unknown data and history.
use super::super::keepass_xml::{
    binary,
    document::xml_error,
    entry::flag,
    xml::{Node, Xml},
};
use crate::import::{Context, Error, ErrorKind, Phase, Reservation};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use keepass::bounded::Protected;
use quick_xml::events::Event;
use std::ops::Range;
use zeroize::Zeroizing;

struct Replacement {
    span: Range<usize>,
    xml: Zeroizing<Vec<u8>>,
    _memory: Reservation,
}

pub(super) struct Values {
    replacements: Vec<Replacement>,
}

pub(super) struct Fragment {
    pub bytes: Zeroizing<Vec<u8>>,
    pub(super) _memory: Reservation,
}

fn escaped(value: &str, mut emit: impl FnMut(&[u8])) {
    for character in value.chars() {
        let mut bytes = [0; 4];
        emit(match character {
            '&' => b"&amp;",
            '<' => b"&lt;",
            '>' => b"&gt;",
            '"' => b"&quot;",
            '\'' => b"&apos;",
            '\r' => b"&#13;",
            '\n' => b"&#10;",
            '\t' => b"&#9;",
            _ => character.encode_utf8(&mut bytes).as_bytes(),
        });
    }
}

fn element(node: &Node, value: &str, mut emit: impl FnMut(&[u8])) {
    emit(b"<");
    emit(node.name.as_bytes());
    for (key, value) in &node.attributes {
        if matches!(key.as_str(), "Protected" | "ProtectInMemory") {
            continue;
        }
        emit(b" ");
        emit(key.as_bytes());
        emit(b"=\"");
        escaped(value, &mut emit);
        emit(b"\"");
    }
    emit(b" ProtectInMemory=\"True\">");
    escaped(value, &mut emit);
    emit(b"</");
    emit(node.name.as_bytes());
    emit(b">");
}

fn replacement(
    node: &Node,
    binary_value: bool,
    stream: &mut Protected,
    context: &Context<'_>,
) -> Result<Replacement, Error> {
    let text = node.leaf().map_err(|e| xml_error(e, node.span.start))?;
    let sizes = binary::sizes(text, false, context.limits.unpacked_bytes)
        .map_err(|e| xml_error(e, node.span.start))?;
    let _work = context.memory().reserve(
        sizes
            .working()
            .map_err(|e| xml_error(e, node.span.start))?
            .checked_add(sizes.packed.checked_mul(3).ok_or(ErrorKind::Limit)?)
            .ok_or(ErrorKind::Limit)?,
    )?;
    let ciphertext = binary::decode(text, false, context.limits.unpacked_bytes)
        .map_err(|e| xml_error(e, node.span.start))?;
    let plaintext = stream.decrypt(&ciphertext).map_err(super::decode_error)?;
    let encoded;
    let value = if binary_value {
        encoded = Zeroizing::new(STANDARD.encode(&*plaintext));
        encoded.as_str()
    } else {
        let value = std::str::from_utf8(&plaintext).map_err(|_| ErrorKind::UnsupportedEncoding)?;
        if value.chars().any(|c| !matches!(c, '\t' | '\r' | '\n' | '\u{20}'..='\u{d7ff}' | '\u{e000}'..='\u{fffd}' | '\u{10000}'..='\u{10ffff}')) {
            return Err(ErrorKind::UnsupportedEncoding.into());
        }
        value
    };
    let mut length = 0usize;
    element(node, value, |part| {
        length = length.saturating_add(part.len())
    });
    if length > context.limits.unpacked_bytes {
        return Err(ErrorKind::Limit.into());
    }
    let memory = context
        .memory()
        .reserve(length.checked_add(256).ok_or(ErrorKind::Limit)?)?;
    let mut xml = Zeroizing::new(Vec::new());
    xml.try_reserve_exact(length)
        .map_err(|_| ErrorKind::Allocation)?;
    element(node, value, |part| xml.extend_from_slice(part));
    debug_assert_eq!(length, xml.len());
    Ok(Replacement {
        span: node.span.clone(),
        xml,
        _memory: memory,
    })
}

impl Values {
    pub fn read(
        source: &[u8],
        stream: &mut Protected,
        context: &mut Context<'_>,
    ) -> Result<Self, Error> {
        let limits = context.limits;
        let _scratch = context.reserve_work(limits.string_bytes, limits.string_bytes / 256)?;
        let mut xml = Xml::new(source, limits.depth, limits.nodes, limits.string_bytes)
            .map_err(|e| xml_error(e, 0))?;
        xml.string_limit = limits.string_bytes;
        let mut result = Self {
            replacements: Vec::new(),
        };
        let mut total = 0usize;
        let mut checkpoint = 0;
        let mut path = Vec::with_capacity(limits.depth);
        loop {
            let event = xml.next().map_err(|e| xml_error(e, xml.position))?;
            let empty = matches!(event, Event::Empty(_));
            if xml.event_count() - checkpoint >= 256 {
                context.checkpoint(Phase::Read, xml.position, source.len())?;
                checkpoint = xml.event_count();
            }
            match event {
                Event::Start(start) | Event::Empty(start) => {
                    let mut protected = false;
                    for attribute in start.attributes() {
                        let attribute = attribute.map_err(|_| ErrorKind::Malformed)?;
                        if attribute.key.as_ref() == b"Protected" {
                            let value = attribute
                                .normalized_value(quick_xml::XmlVersion::Implicit1_0)
                                .map_err(|_| ErrorKind::Malformed)?;
                            protected = flag(Some(&value))?;
                        }
                    }
                    if !protected {
                        if !empty {
                            path.push(
                                &source[xml.position + 1
                                    ..xml.position + 1 + start.name().as_ref().len()],
                            );
                        }
                        continue;
                    }
                    let binary_value = start.name().as_ref() == b"Binary"
                        || (start.name().as_ref() == b"Value"
                            && path.last() == Some(&b"Binary".as_slice()));
                    let node = xml
                        .element(start, empty, &mut |offset| {
                            context
                                .checkpoint(Phase::Read, offset, source.len())
                                .is_ok()
                        })
                        .map_err(|e| xml_error(e, xml.position))?;
                    let value = replacement(&node, binary_value, stream, context)?;
                    total = total
                        .checked_add(value.xml.len())
                        .filter(|n| *n <= limits.unpacked_bytes)
                        .ok_or(ErrorKind::Limit)?;
                    result
                        .replacements
                        .try_reserve(1)
                        .map_err(|_| ErrorKind::Allocation)?;
                    result.replacements.push(value);
                }
                Event::Eof => break,
                Event::End(_) => {
                    path.pop();
                }
                _ => {}
            }
        }
        context.checkpoint(Phase::Read, source.len(), source.len())?;
        Ok(result)
    }

    /// Materialize only the requested entry or metadata fragment, never a full XML export.
    pub fn fragment(
        &self,
        source: &[u8],
        span: Range<usize>,
        context: &Context<'_>,
    ) -> Result<Fragment, Error> {
        if span.start > span.end || span.end > source.len() {
            return Err(ErrorKind::Malformed.into());
        }
        let first = self
            .replacements
            .partition_point(|v| v.span.end <= span.start);
        let last = self
            .replacements
            .partition_point(|v| v.span.start < span.end);
        let selected = &self.replacements[first..last];
        let mut length = span.len();
        for value in selected {
            if value.span.start < span.start || value.span.end > span.end {
                return Err(ErrorKind::Malformed.into());
            }
            length = length
                .checked_sub(value.span.len())
                .and_then(|n| n.checked_add(value.xml.len()))
                .filter(|n| *n <= context.limits.unpacked_bytes)
                .ok_or(ErrorKind::Limit)?;
        }
        if length > context.limits.unpacked_bytes {
            return Err(ErrorKind::Limit.into());
        }
        let memory = context.memory().reserve(length)?;
        let mut bytes = Zeroizing::new(Vec::new());
        bytes
            .try_reserve_exact(length)
            .map_err(|_| ErrorKind::Allocation)?;
        let mut offset = span.start;
        for value in selected {
            bytes.extend_from_slice(&source[offset..value.span.start]);
            bytes.extend_from_slice(&value.xml);
            offset = value.span.end;
        }
        bytes.extend_from_slice(&source[offset..span.end]);
        debug_assert_eq!(length, bytes.len());
        Ok(Fragment {
            bytes,
            _memory: memory,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::import::{Format, Limits, Options};
    use keepass::bounded::{Limits as DecodeLimits, Raw};

    const INPUT: &[u8] =
        include_bytes!("../../../../../../vendor/keepass/tests/resources/bounded/argon2d-aes.kdbx");

    fn raw() -> Raw {
        Raw::open(
            INPUT,
            Some("PUBLIC-VARIANT-DATABASE"),
            None,
            DecodeLimits::default(),
            &mut |_, _| true,
        )
        .unwrap()
    }

    #[test]
    fn protected_values_keep_their_semantics_and_fragment_boundaries() {
        let mut raw = raw();
        let mut stream = raw.take_protected().unwrap();
        let source = raw.xml();
        let original = source.to_vec();
        let options = Options::default();
        let mut check = |_| true;
        let mut context = Context::new(
            Format::Kdbx,
            INPUT.len(),
            &options,
            Limits::default(),
            &mut check,
        )
        .unwrap();
        let before = context.memory().available();
        let values = Values::read(source, &mut stream, &mut context).unwrap();
        assert_eq!(values.replacements.len(), 2);
        let first = &values.replacements[0];
        let fragment = values
            .fragment(source, first.span.clone(), &context)
            .unwrap();
        let part = std::str::from_utf8(&fragment.bytes).unwrap();
        assert!(part.contains("PUBLIC-VARIANT-PASSWORD"));
        assert!(part.contains("ProtectInMemory=\"True\""));
        assert!(!part.contains("Protected="));
        assert!(
            values
                .fragment(source, first.span.start + 1..first.span.end, &context)
                .is_err()
        );
        let last = values
            .fragment(source, values.replacements[1].span.clone(), &context)
            .unwrap();
        assert!(
            std::str::from_utf8(&last.bytes)
                .unwrap()
                .contains("PUBLIC-VARIANT-CUSTOM")
        );
        assert_eq!(source, original);
        drop(last);
        drop(fragment);
        drop(values);
        assert_eq!(context.memory().available(), before);
    }

    #[test]
    fn real_kdbx3_and_kdbx4_history_fit_the_shared_memory_budget() {
        for (input, password, expected) in [
            (
                include_bytes!(
                    "../../../../../../vendor/keepass/tests/resources/test_db_with_password.kdbx"
                )
                .as_slice(),
                "demopass",
                "<Value ProtectInMemory=\"True\">",
            ),
            (
                include_bytes!("../../../../tests/import_fixtures/kdbx/password.kdbx").as_slice(),
                "PUBLIC-FIXTURE-DATABASE",
                "PUBLIC-FIXTURE-OLD",
            ),
        ] {
            let options = Options::default();
            let mut check = |_| true;
            let mut context = Context::new(
                Format::Kdbx,
                input.len(),
                &options,
                Limits::default(),
                &mut check,
            )
            .unwrap();
            let before = context.memory().available();
            let mut memory = context.memory().reserve(before).unwrap();
            let mut raw = Raw::open(
                input,
                Some(password),
                None,
                DecodeLimits {
                    memory_bytes: before,
                    ..DecodeLimits::default()
                },
                &mut |_, _| true,
            )
            .unwrap();
            memory.shrink_to(raw.memory_bytes()).unwrap();
            let mut stream = raw.take_protected().unwrap();
            let values = Values::read(raw.xml(), &mut stream, &mut context).unwrap();
            assert!(
                values
                    .replacements
                    .iter()
                    .any(|v| std::str::from_utf8(&v.xml).unwrap().contains(expected))
            );
            if password == "PUBLIC-FIXTURE-DATABASE" {
                for expected in [
                    "PUBLIC-FIXTURE-PASSWORD",
                    "PUBLIC-FIXTURE-HIDDEN",
                    "PUBLIC-FIXTURE-DELETED",
                ] {
                    assert!(
                        values
                            .replacements
                            .iter()
                            .any(|v| std::str::from_utf8(&v.xml).unwrap().contains(expected)),
                        "{expected}"
                    );
                }
            }
            drop(values);
            drop(stream);
            drop(raw);
            drop(memory);
            assert_eq!(context.memory().available(), before);
        }
    }

    #[test]
    fn history_unknown_nodes_and_empty_values_consume_the_same_stream() {
        let mut raw = raw();
        let options = Options::default();
        let mut check = |_| true;
        let mut context = Context::new(
            Format::Kdbx,
            INPUT.len(),
            &options,
            Limits::default(),
            &mut check,
        )
        .unwrap();
        let mut stream = raw.take_protected().unwrap();
        let values = Values::read(raw.xml(), &mut stream, &mut context).unwrap();
        let first = &raw.xml()[values.replacements[0].span.clone()];
        let last = &raw.xml()[values.replacements[1].span.clone()];
        let mut test = b"<Root><Unknown><Value Protected='True'/></Unknown><History>".to_vec();
        test.extend_from_slice(first);
        test.extend_from_slice(b"</History><Plugin>");
        test.extend_from_slice(last);
        test.extend_from_slice(b"</Plugin></Root>");
        let mut fresh = self::raw();
        let values =
            Values::read(&test, &mut fresh.take_protected().unwrap(), &mut context).unwrap();
        assert_eq!(values.replacements.len(), 3);
        assert!(
            std::str::from_utf8(&values.replacements[1].xml)
                .unwrap()
                .contains("PUBLIC-VARIANT-PASSWORD")
        );
        assert!(
            std::str::from_utf8(&values.replacements[2].xml)
                .unwrap()
                .contains("PUBLIC-VARIANT-CUSTOM")
        );
    }

    #[test]
    fn protected_binary_stays_base64_and_escaping_preserves_text() {
        let mut raw = raw();
        let options = Options::default();
        let mut check = |_| true;
        let mut context = Context::new(
            Format::Kdbx,
            INPUT.len(),
            &options,
            Limits::default(),
            &mut check,
        )
        .unwrap();
        let mut stream = raw.take_protected().unwrap();
        let values = Values::read(raw.xml(), &mut stream, &mut context).unwrap();
        let source = std::str::from_utf8(&raw.xml()[values.replacements[0].span.clone()])
            .unwrap()
            .replace("Value", "Binary");
        let mut fresh = self::raw();
        let values = Values::read(
            source.as_bytes(),
            &mut fresh.take_protected().unwrap(),
            &mut context,
        )
        .unwrap();
        let xml = &values.replacements[0].xml;
        let mut reader = Xml::new(xml, 32, 100, 4096).unwrap();
        let Event::Start(start) = reader.next().unwrap() else {
            panic!()
        };
        let node = reader.element(start, false, &mut |_| true).unwrap();
        assert_eq!(
            &*binary::decode(node.leaf().unwrap(), false, 4096).unwrap(),
            b"PUBLIC-VARIANT-PASSWORD"
        );
        let value = "<&>\"'\r\n\t東京";
        let mut serialized = Vec::new();
        element(&node, value, |part| serialized.extend_from_slice(part));
        let mut reader = Xml::new(&serialized, 32, 100, 4096).unwrap();
        let Event::Start(start) = reader.next().unwrap() else {
            panic!()
        };
        assert_eq!(
            reader
                .element(start, false, &mut |_| true)
                .unwrap()
                .leaf()
                .unwrap(),
            value
        );
    }

    #[test]
    fn invalid_xml_limits_and_cancel_return_errors_and_release_memory() {
        let options = Options::default();
        let mut check = |_| true;
        let mut context = Context::new(
            Format::Kdbx,
            INPUT.len(),
            &options,
            Limits::default(),
            &mut check,
        )
        .unwrap();
        let before = context.memory().available();
        for (source, expected) in [
            ("<Value Protected='True'>!</Value>", ErrorKind::Malformed),
            (
                "<Value Protected='True'><Child/></Value>",
                ErrorKind::Malformed,
            ),
            ("<!DOCTYPE Root><Root/>", ErrorKind::UnsupportedEncoding),
            ("<Value Protected='maybe'/>", ErrorKind::Malformed),
        ] {
            let mut raw = raw();
            assert_eq!(
                Values::read(
                    source.as_bytes(),
                    &mut raw.take_protected().unwrap(),
                    &mut context
                )
                .err()
                .unwrap()
                .kind,
                expected
            );
            assert_eq!(context.memory().available(), before);
        }
        let mut raw = raw();
        let mut stream = raw.take_protected().unwrap();
        let mut check = |progress: crate::import::Progress| progress.phase != Phase::Read;
        let mut context = Context::new(
            Format::Kdbx,
            INPUT.len(),
            &options,
            Limits::default(),
            &mut check,
        )
        .unwrap();
        assert_eq!(
            Values::read(raw.xml(), &mut stream, &mut context)
                .err()
                .unwrap()
                .kind,
            ErrorKind::Canceled
        );
        let limits = Limits {
            memory_bytes: 8 << 20,
            ..Limits::default()
        };
        let mut check = |_| true;
        let mut context =
            Context::new(Format::Kdbx, INPUT.len(), &options, limits, &mut check).unwrap();
        assert_eq!(
            Values::read(raw.xml(), &mut stream, &mut context)
                .err()
                .unwrap()
                .kind,
            ErrorKind::Limit
        );
    }

    #[test]
    fn inline_binary_values_are_encoded_as_bytes_instead_of_plain_text() {
        let mut raw = raw();
        let options = Options::default();
        let mut check = |_| true;
        let mut context = Context::new(
            Format::Kdbx,
            INPUT.len(),
            &options,
            Limits::default(),
            &mut check,
        )
        .unwrap();
        let mut stream = raw.take_protected().unwrap();
        let values = Values::read(raw.xml(), &mut stream, &mut context).unwrap();
        let original =
            std::str::from_utf8(&raw.xml()[values.replacements[0].span.clone()]).unwrap();
        let source = format!("<Binary>{original}</Binary>");
        let mut fresh = self::raw();
        let values = Values::read(
            source.as_bytes(),
            &mut fresh.take_protected().unwrap(),
            &mut context,
        )
        .unwrap();
        let fragment = values
            .fragment(source.as_bytes(), 0..source.len(), &context)
            .unwrap();
        let mut xml = Xml::new(&fragment.bytes, 32, 100, 4096).unwrap();
        let Event::Start(start) = xml.next().unwrap() else {
            panic!()
        };
        let node = xml.element(start, false, &mut |_| true).unwrap();
        let value = node.child("Value").unwrap().unwrap();
        assert_eq!(
            binary::decode(value.leaf().unwrap(), false, 4096)
                .unwrap()
                .as_slice(),
            b"PUBLIC-VARIANT-PASSWORD"
        );
    }

    #[test]
    fn ten_thousand_protected_nodes_keep_order_and_fragment_lookup() {
        let source = format!(
            "<Root>{}</Root>",
            "<Value Protected='True'/>".repeat(10_000)
        );
        let options = Options::default();
        let mut check = |_| true;
        let mut context = Context::new(
            Format::Kdbx,
            source.len(),
            &options,
            Limits::default(),
            &mut check,
        )
        .unwrap();
        let mut raw = raw();
        let mut stream = raw.take_protected().unwrap();
        let values = Values::read(source.as_bytes(), &mut stream, &mut context).unwrap();
        assert_eq!(values.replacements.len(), 10_000);
        for index in [0, 5000, 9999] {
            let span = values.replacements[index].span.clone();
            let fragment = values.fragment(source.as_bytes(), span, &context).unwrap();
            assert_eq!(
                fragment.bytes.as_slice(),
                b"<Value ProtectInMemory=\"True\"></Value>"
            );
        }
    }
}
