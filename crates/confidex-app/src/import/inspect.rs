use super::{
    Context, Error, ErrorKind, Format, Limits, Options, Phase, Progress, archive::Archive, json,
};
use quick_xml::events::Event;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Inspection {
    pub candidates: Vec<Format>,
    pub confirmation_required: bool,
}
/// Detect structure. A candidate still needs its adapter's complete validation.
pub fn inspect(
    input: &[u8],
    limits: Limits,
    callback: &mut dyn FnMut(Progress) -> bool,
) -> Result<Inspection, Error> {
    let options = Options::default();
    let mut context = Context::new(Format::Csv, input.len(), &options, limits, callback)?;
    let input = input.strip_prefix(b"\xef\xbb\xbf").unwrap_or(input);
    if input.starts_with(&[0x03, 0xd9, 0xa2, 0x9a, 0x67, 0xfb, 0x4b, 0xb5]) {
        if input.len() < 12 {
            return Err(ErrorKind::Malformed.into());
        }
        return Ok(Inspection {
            candidates: vec![Format::Kdbx],
            confirmation_required: false,
        });
    }
    if [b"PK\x03\x04", b"PK\x05\x06", b"PK\x06\x06", b"PK\x07\x08"]
        .iter()
        .any(|signature| input.starts_with(*signature))
    {
        return inspect_zip(input, &mut context);
    }
    let first = input.iter().find(|b| !b.is_ascii_whitespace()).copied();
    if first == Some(b'{') {
        let format = inspect_json(input, &mut context)?.ok_or(ErrorKind::UnsupportedFormat)?;
        return Ok(Inspection {
            candidates: vec![format],
            confirmation_required: false,
        });
    }
    if input.starts_with(b"\xff\xfe") || input.starts_with(b"\xfe\xff") {
        return Err(ErrorKind::UnsupportedEncoding.into());
    }
    if first == Some(b'<') {
        inspect_xml(input, &mut context)?;
        return Ok(Inspection {
            candidates: vec![Format::KeepassXml],
            confirmation_required: false,
        });
    }
    let text = std::str::from_utf8(input).map_err(|_| ErrorKind::UnsupportedEncoding)?;
    if text.trim().is_empty()
        || text
            .chars()
            .any(|c| c.is_control() && !matches!(c, '\n' | '\r' | '\t'))
    {
        return Err(ErrorKind::UnsupportedFormat.into());
    }
    // Plain text cannot identify a CSV profile or column meanings.
    Ok(Inspection {
        candidates: vec![Format::Csv],
        confirmation_required: true,
    })
}
fn inspect_json(input: &[u8], context: &mut Context<'_>) -> Result<Option<Format>, Error> {
    let document = json::Document::parse(input, context)?;
    let root = json::object(document.raw(), context)?;
    if root.get("encrypted").is_some_and(|v| v.get() == "true") && root.get("data").is_some() {
        return Ok(Some(Format::BitwardenEncryptedJson));
    }
    if root.get("items").is_some_and(|v| json::array(v).is_ok())
        && (root.get("folders").is_some()
            || root.get("collections").is_some()
            || root.get("encrypted").is_some_and(|v| v.get() == "false"))
    {
        return Ok(Some(Format::BitwardenJson));
    }
    Ok(None)
}
fn inspect_zip(input: &[u8], context: &mut Context<'_>) -> Result<Inspection, Error> {
    let mut archive = Archive::open(input, context)?;
    if archive
        .names()
        .any(|n| n.contains("/locks/") && n.ends_with(".sealed"))
    {
        return Err(ErrorKind::OwnBackup.into());
    }
    let mut candidates = Vec::new();
    if archive.index("export.attributes").is_some() && archive.index("export.data").is_some() {
        candidates.push(Format::Onepassword1pux);
    }
    let json_members: Vec<_> = archive
        .names()
        .enumerate()
        .filter(|(_, n)| n.ends_with(".json"))
        .map(|(i, _)| i)
        .collect();
    for index in json_members {
        let bytes = archive.read(index, context)?;
        if bytes.iter().find(|b| !b.is_ascii_whitespace()) != Some(&b'{') {
            continue;
        }
        match inspect_json(&bytes, context) {
            Ok(Some(Format::BitwardenJson)) if !candidates.contains(&Format::BitwardenZip) => {
                candidates.push(Format::BitwardenZip)
            }
            Err(e)
                if matches!(
                    e.kind,
                    ErrorKind::Canceled | ErrorKind::Limit | ErrorKind::Allocation
                ) =>
            {
                return Err(e);
            }
            _ => (),
        }
    }
    if candidates.is_empty() {
        return Err(ErrorKind::UnsupportedFormat.into());
    }
    Ok(Inspection {
        confirmation_required: candidates.len() != 1 || candidates.contains(&Format::BitwardenZip),
        candidates,
    })
}
fn inspect_xml(input: &[u8], context: &mut Context<'_>) -> Result<(), Error> {
    std::str::from_utf8(input).map_err(|_| ErrorKind::UnsupportedEncoding)?;
    let mut reader = quick_xml::Reader::from_reader(input);
    let mut depth = 0usize;
    let mut nodes = 0usize;
    let mut root = false;
    loop {
        context.checkpoint(
            Phase::Inspect,
            reader.buffer_position() as usize,
            input.len(),
        )?;
        let event = reader.read_event().map_err(|_| ErrorKind::Malformed)?;
        nodes += 1;
        if nodes > context.limits.nodes {
            return Err(ErrorKind::Limit.into());
        }
        match &event {
            Event::DocType(_) => return Err(ErrorKind::Malformed.into()),
            Event::Decl(d) => {
                if d.encoding()
                    .transpose()
                    .map_err(|_| ErrorKind::Malformed)?
                    .is_some_and(|e| !e.eq_ignore_ascii_case(b"utf-8"))
                {
                    return Err(ErrorKind::UnsupportedEncoding.into());
                }
            }
            Event::Start(e) | Event::Empty(e) => {
                if depth == 0 {
                    if root || e.name().as_ref() != b"KeePassFile" {
                        return Err(ErrorKind::Malformed.into());
                    }
                    root = true;
                }
                if depth >= context.limits.depth {
                    return Err(ErrorKind::Limit.into());
                }
                if !matches!(event, Event::Empty(_)) {
                    depth += 1;
                }
                if depth > context.limits.depth {
                    return Err(ErrorKind::Limit.into());
                }
            }
            Event::End(_) => {
                depth = depth.checked_sub(1).ok_or(ErrorKind::Malformed)?;
            }
            Event::Text(e) => {
                if e.len() > context.limits.string_bytes {
                    return Err(ErrorKind::Limit.into());
                }
                let text = e.decode().map_err(|_| ErrorKind::UnsupportedEncoding)?;
                if depth == 0 && !text.trim().is_empty() {
                    return Err(ErrorKind::Malformed.into());
                }
            }
            Event::GeneralRef(e) => {
                let name = e.decode().map_err(|_| ErrorKind::UnsupportedEncoding)?;
                if depth == 0
                    || (!matches!(name.as_ref(), "amp" | "lt" | "gt" | "quot" | "apos")
                        && !valid_reference(&name))
                {
                    return Err(ErrorKind::Malformed.into());
                }
            }
            Event::CData(e) => {
                if depth == 0 {
                    return Err(ErrorKind::Malformed.into());
                }
                if e.len() > context.limits.string_bytes {
                    return Err(ErrorKind::Limit.into());
                }
            }
            Event::Eof => break,
            _ => (),
        }
    }
    if !root || depth != 0 {
        return Err(ErrorKind::Malformed.into());
    }
    Ok(())
}

fn valid_reference(name: &str) -> bool {
    let number = if let Some(hex) = name.strip_prefix("#x") {
        u32::from_str_radix(hex, 16).ok()
    } else {
        name.strip_prefix('#').and_then(|s| s.parse::<u32>().ok())
    };
    number.is_some_and(
        |c| matches!(c, 0x9 | 0xa | 0xd | 0x20..=0xd7ff | 0xe000..=0xfffd | 0x10000..=0x10ffff),
    )
}
