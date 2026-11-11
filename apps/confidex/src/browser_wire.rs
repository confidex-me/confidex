//! Keep file bytes out of the JSON worker messages.
use confidex_app::{Command, Error, Field, Output, Request, Response};
use confidex_storage::MAX_BACKUP_BYTES;
use serde::{Deserialize, Serialize, de::DeserializeOwned};

const MAX_JSON: usize = 16 * 1024 * 1024;
pub const MAX_PACKET: usize = MAX_JSON + MAX_BACKUP_BYTES + 4;
fn pack(value: &impl Serialize, attachment: &[u8]) -> Result<Vec<u8>, Error> {
    #[derive(Serialize)]
    struct Frame<'a, T: Serialize> {
        #[serde(flatten)]
        value: &'a T,
        __attachment_bytes: usize,
    }
    let mut json = zeroize::Zeroizing::new(
        serde_json::to_vec(&Frame {
            value,
            __attachment_bytes: attachment.len(),
        })
        .map_err(|_| Error::Input)?,
    );
    if json.len() > MAX_JSON || attachment.len() > MAX_BACKUP_BYTES {
        return Err(Error::Input);
    }
    if attachment.is_empty() {
        return Ok(std::mem::take(&mut *json));
    }
    let mut bytes = Vec::with_capacity(4 + json.len() + attachment.len());
    bytes.extend_from_slice(&(json.len() as u32).to_le_bytes());
    bytes.extend_from_slice(&json);
    bytes.extend_from_slice(attachment);
    Ok(bytes)
}
fn check_length(json: &[u8], actual: usize) -> Result<(), Error> {
    #[derive(Deserialize)]
    struct Frame {
        __attachment_bytes: Option<usize>,
    }
    let frame: Frame = serde_json::from_slice(json).map_err(|_| Error::Input)?;
    if frame
        .__attachment_bytes
        .is_some_and(|expected| expected != actual)
        || (actual != 0 && frame.__attachment_bytes.is_none())
    {
        return Err(Error::Input);
    }
    Ok(())
}
fn unpack<T: DeserializeOwned>(bytes: &[u8]) -> Result<(T, &[u8]), Error> {
    if bytes.first() == Some(&b'{')
        && bytes.len() <= MAX_JSON
        && let Ok(value) = serde_json::from_slice(bytes)
    {
        check_length(bytes, 0)?;
        return Ok((value, &[]));
    }
    if bytes.len() < 4 || bytes.len() > MAX_PACKET {
        return Err(Error::Input);
    }
    let length = u32::from_le_bytes(bytes[..4].try_into().map_err(|_| Error::Input)?) as usize;
    if length > MAX_JSON || length + 4 > bytes.len() || bytes.len() - length - 4 > MAX_BACKUP_BYTES
    {
        return Err(Error::Input);
    }
    check_length(&bytes[4..length + 4], bytes.len() - length - 4)?;
    Ok((
        serde_json::from_slice(&bytes[4..length + 4]).map_err(|_| Error::Input)?,
        &bytes[length + 4..],
    ))
}
fn request_fields(
    request: &mut Request,
    mut visit: impl FnMut(&mut Field) -> Result<(), Error>,
) -> Result<(), Error> {
    if let Command::Save { draft, .. }
    | Command::SaveRevision { draft, .. }
    | Command::CheckDraft { draft } = &mut request.command
    {
        for field in &mut draft.fields {
            visit(field)?;
        }
    }
    Ok(())
}
fn response_fields(
    response: &mut Response,
    mut visit: impl FnMut(&mut Field) -> Result<(), Error>,
) -> Result<(), Error> {
    if let Ok(Output::Ssh {
        result: Ok(field), ..
    }) = &mut response.result
    {
        visit(field)?;
    }
    let drafts: Vec<_> = match &mut response.result {
        Ok(Output::Draft(draft)) => vec![draft],
        Ok(Output::Compared { local, remote, .. }) => {
            local.iter_mut().chain(remote.iter_mut()).collect()
        }
        Ok(Output::Historical { draft, .. }) => draft.iter_mut().collect(),
        _ => vec![],
    };
    for draft in drafts {
        for field in &mut draft.fields {
            visit(field)?;
        }
    }
    Ok(())
}
fn extract(field: &mut Field, bytes: &mut Vec<u8>) -> Result<(), Error> {
    if let Some(data) = field.data.take() {
        if data.len() > MAX_BACKUP_BYTES.saturating_sub(bytes.len() + 4) {
            return Err(Error::Input);
        }
        bytes.extend_from_slice(&(data.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&data);
        field.data = Some(Vec::new().into());
    }
    Ok(())
}
fn restore(field: &mut Field, bytes: &[u8], offset: &mut usize) -> Result<(), Error> {
    if let Some(data) = &field.data {
        if !data.is_empty() {
            return Err(Error::Input);
        }
        let length = bytes.get(*offset..*offset + 4).ok_or(Error::Input)?;
        let length = u32::from_le_bytes(length.try_into().map_err(|_| Error::Input)?) as usize;
        *offset += 4;
        let end = offset.checked_add(length).ok_or(Error::Input)?;
        let data = bytes.get(*offset..end).ok_or(Error::Input)?;
        field.data = Some(data.to_vec().into());
        *offset = end;
    }
    Ok(())
}
pub fn encode_request(mut request: Request) -> Result<Vec<u8>, Error> {
    let mut attachment = zeroize::Zeroizing::new(match &mut request.command {
        Command::VendorExport(confidex_app::export_flow::Command::Prepare { options, .. }) => {
            if let Some(bytes) = options.keyfile_mut() {
                if bytes.len() > confidex_app::export::MAX_KEYFILE_BYTES {
                    return Err(Error::Input);
                }
                std::mem::take(bytes)
            } else {
                vec![]
            }
        }
        Command::ImportSsh { data, .. } => {
            if data.len() > confidex_app::ssh::MAX_KEY {
                return Err(Error::Input);
            }
            std::mem::take(data)
        }
        Command::InspectBackup { archive } => std::mem::take(archive),
        Command::VendorImport(confidex_app::import_flow::Command::Prepare { bytes, .. }) => {
            std::mem::take(bytes)
        }
        Command::VendorImport(confidex_app::import_flow::Command::UnlockKdbx {
            keyfile: Some(bytes),
            ..
        }) => {
            if bytes.len() > confidex_app::import_flow::MAX_KEYFILE_BYTES {
                return Err(Error::Input);
            }
            std::mem::take(bytes)
        }
        _ => vec![],
    });
    request_fields(&mut request, |field| extract(field, &mut attachment))?;
    pack(&request, &attachment)
}
pub fn decode_request(bytes: &[u8]) -> Result<Request, Error> {
    let (mut request, attachment): (Request, _) = unpack(bytes)?;
    let destination = match &mut request.command {
        Command::VendorExport(confidex_app::export_flow::Command::Prepare { options, .. }) => {
            if attachment.len() > confidex_app::export::MAX_KEYFILE_BYTES {
                return Err(Error::Input);
            }
            options.keyfile_mut()
        }
        Command::ImportSsh { data, .. } => {
            if attachment.len() > confidex_app::ssh::MAX_KEY {
                return Err(Error::Input);
            }
            Some(data)
        }
        Command::InspectBackup { archive } => Some(archive),
        Command::VendorImport(confidex_app::import_flow::Command::Prepare { bytes, .. }) => {
            Some(bytes)
        }
        Command::VendorImport(confidex_app::import_flow::Command::UnlockKdbx {
            keyfile: Some(bytes),
            ..
        }) => {
            if attachment.len() > confidex_app::import_flow::MAX_KEYFILE_BYTES {
                return Err(Error::Input);
            }
            Some(bytes)
        }
        _ => None,
    };
    if let Some(archive) = destination {
        if !archive.is_empty() {
            return Err(Error::Input);
        }
        archive.extend_from_slice(attachment);
    } else {
        let mut offset = 0;
        request_fields(&mut request, |field| {
            restore(field, attachment, &mut offset)
        })?;
        if offset != attachment.len() {
            return Err(Error::Input);
        }
    }
    Ok(request)
}
pub fn encode_response(mut response: Response) -> Result<Vec<u8>, Error> {
    if let Ok(Output::VendorExport(Ok(confidex_app::export_flow::Reply::Chunk { chunk, .. }))) =
        &mut response.result
    {
        if chunk.bytes.len() > confidex_app::export_flow::CHUNK_BYTES {
            return Err(Error::Input);
        }
        let bytes = std::mem::take(&mut chunk.bytes);
        return pack(&response, &bytes);
    }
    let mut attachment =
        zeroize::Zeroizing::new(if let Ok(Output::Backup(archive)) = &mut response.result {
            std::mem::take(archive)
        } else {
            vec![]
        });
    response_fields(&mut response, |field| extract(field, &mut attachment))?;
    pack(&response, &attachment)
}
pub fn decode_response(bytes: &[u8]) -> Result<Response, Error> {
    let (mut response, attachment): (Response, _) = unpack(bytes)?;
    if let Ok(Output::VendorExport(Ok(confidex_app::export_flow::Reply::Chunk { chunk, .. }))) =
        &mut response.result
    {
        if !chunk.bytes.is_empty() || attachment.len() > confidex_app::export_flow::CHUNK_BYTES {
            return Err(Error::Input);
        }
        chunk.bytes = attachment.to_vec().into();
        return Ok(response);
    }
    if let Ok(Output::Backup(archive)) = &mut response.result {
        if !archive.is_empty() {
            return Err(Error::Input);
        }
        archive.extend_from_slice(attachment);
    } else {
        let mut offset = 0;
        response_fields(&mut response, |field| {
            restore(field, attachment, &mut offset)
        })?;
        if offset != attachment.len() {
            return Err(Error::Input);
        }
    }
    Ok(response)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn export_credentials_and_chunks_use_length_checked_binary_frames() {
        use confidex_app::{export, export_flow as flow};
        for (password, keyfile) in [
            (Some("public"), None),
            (None, Some(vec![197; 4096])),
            (Some("public"), Some(vec![197; 4096])),
            (Some(""), None),
            (Some(""), Some(vec![])),
        ] {
            let request = Request {
                generation: 9,
                command: Command::VendorExport(flow::Command::Prepare {
                    operation: 7,
                    created_at: 1_735_689_600,
                    format: export::Format::Kdbx,
                    options: export::Options::Password {
                        password: password.map(str::to_owned),
                        keyfile: keyfile.clone(),
                    },
                    selection: flow::Selection::All,
                }),
            };
            let packet = encode_request(request).unwrap();
            let request = decode_request(&packet).unwrap();
            let Command::VendorExport(flow::Command::Prepare {
                options:
                    export::Options::Password {
                        password: decoded,
                        keyfile: decoded_file,
                    },
                ..
            }) = &request.command
            else {
                panic!("credentials");
            };
            assert_eq!(decoded.as_deref(), password);
            assert_eq!(*decoded_file, keyfile);
            assert!(decode_request(&packet[..packet.len() - 1]).is_err());
            let inline = serde_json::to_vec(&request).unwrap();
            if decoded_file.as_ref().is_some_and(|bytes| !bytes.is_empty()) {
                assert!(decode_request(&inline).is_err());
            }
        }
        let mut chunk: flow::Chunk =
            serde_json::from_str(r#"{"offset":0,"bytes":[],"next":null}"#).unwrap();
        chunk.bytes = vec![197; flow::CHUNK_BYTES].into();
        let response = Response {
            generation: 9,
            result: Ok(Output::VendorExport(Ok(flow::Reply::Chunk {
                token: [3; 16],
                chunk,
            }))),
        };
        let packet = encode_response(response).unwrap();
        assert!(packet.len() < flow::CHUNK_BYTES + 1024);
        assert!(decode_response(&packet[..packet.len() - 1]).is_err());
        let response = decode_response(&packet).unwrap();
        let Ok(Output::VendorExport(Ok(flow::Reply::Chunk { ref chunk, .. }))) = response.result
        else {
            panic!("chunk");
        };
        assert_eq!(chunk.bytes.len(), flow::CHUNK_BYTES);
        assert!(chunk.bytes.iter().all(|&byte| byte == 197));
        assert!(decode_response(&serde_json::to_vec(&response).unwrap()).is_err());
        let mut oversized: flow::Chunk =
            serde_json::from_str(r#"{"offset":0,"bytes":[],"next":null}"#).unwrap();
        oversized.bytes = vec![0; flow::CHUNK_BYTES + 1].into();
        assert!(
            encode_response(Response {
                generation: 9,
                result: Ok(Output::VendorExport(Ok(flow::Reply::Chunk {
                    token: [3; 16],
                    chunk: oversized
                })))
            })
            .is_err()
        );
    }
    #[test]
    fn ssh_import_and_projection_use_bounded_binary_packets() {
        const PEM: &[u8] =
            include_bytes!("../../../crates/confidex-ui/tests/fixtures/public-ssh-key.pem");
        for password in [None, Some(""), Some("public-fixture-passphrase")] {
            let packet = encode_request(Request {
                generation: 7,
                command: Command::ImportSsh {
                    token: 42,
                    data: PEM.to_vec(),
                    password: password.map(str::to_owned),
                },
            })
            .unwrap();
            assert!(packet.len() < PEM.len() + 256);
            let request = decode_request(&packet).unwrap();
            let Command::ImportSsh {
                token,
                data,
                password: actual,
            } = &request.command
            else {
                panic!("ssh command");
            };
            assert_eq!(*token, 42);
            assert_eq!(data.as_slice(), PEM);
            assert_eq!(actual.as_deref(), password);
        }
        let field = confidex_app::ssh::import(PEM, Some("public-fixture-passphrase")).unwrap();
        let data = field.data.clone().unwrap();
        let encoded = encode_response(Response {
            generation: 7,
            result: Ok(Output::Ssh {
                token: 42,
                result: Ok(field),
            }),
        })
        .unwrap();
        let response = decode_response(&encoded).unwrap();
        let Ok(Output::Ssh {
            token,
            result: Ok(field),
        }) = response.result
        else {
            panic!("ssh projection");
        };
        assert_eq!(token, 42);
        assert_eq!(&**field.data.as_ref().unwrap(), &*data);
        assert_eq!(field.values["key_type"], "Ed25519");
        assert!(decode_response(&encoded[..encoded.len() - 1]).is_err());
        let oversized = Request {
            generation: 0,
            command: Command::ImportSsh {
                token: 1,
                data: vec![0; confidex_app::ssh::MAX_KEY + 1],
                password: None,
            },
        };
        assert!(encode_request(oversized).is_err());
        let empty = Request {
            generation: 0,
            command: Command::ImportSsh {
                token: 1,
                data: vec![],
                password: None,
            },
        };
        assert!(
            decode_request(&pack(&empty, &vec![0; confidex_app::ssh::MAX_KEY + 1]).unwrap())
                .is_err()
        );
    }
    #[test]
    fn draft_attachments_use_binary_frames_and_reject_truncation_and_inline_bytes() {
        for (kind, size) in [("photo/v1", 5 * 1024 * 1024), ("ssh/v1", 64 * 1024)] {
            let mut draft = confidex_app::new_record().unwrap();
            let mut file = confidex_app::field(kind).unwrap();
            let expected = vec![197; size];
            file.data = Some(expected.clone().into());
            draft.fields.push(file);
            let packet = encode_request(Request {
                generation: 3,
                command: Command::CheckDraft {
                    draft: draft.clone(),
                },
            })
            .unwrap();
            assert!(packet.len() < expected.len() + 1024);
            let request = decode_request(&packet).unwrap();
            let Command::CheckDraft { draft: decoded } = &request.command else {
                panic!("draft");
            };
            assert_eq!(
                &**decoded.fields[0].data.as_ref().unwrap(),
                expected.as_slice()
            );
            let response = encode_response(Response {
                generation: 3,
                result: Ok(Output::Draft(draft.clone())),
            })
            .unwrap();
            let Ok(Output::Draft(decoded)) = decode_response(&response).unwrap().result else {
                panic!("response");
            };
            assert_eq!(
                &**decoded.fields[0].data.as_ref().unwrap(),
                expected.as_slice()
            );
            assert!(decode_request(&packet[..packet.len() - 1]).is_err());
            let mut invalid = packet.clone();
            let offset = u32::from_le_bytes(invalid[..4].try_into().unwrap()) as usize + 4;
            invalid[offset..offset + 4].copy_from_slice(&u32::MAX.to_le_bytes());
            assert!(decode_request(&invalid).is_err());
            let json = serde_json::to_vec(&Request {
                generation: 0,
                command: Command::Save { draft, epoch: 0 },
            })
            .unwrap();
            assert!(decode_request(&json).is_err());
        }
    }
    #[test]
    fn attachments_round_trip_without_json_expansion() {
        let bytes = vec![193; 17 * 1024 * 1024];
        let packet = encode_request(Request {
            generation: 7,
            command: Command::InspectBackup {
                archive: bytes.clone(),
            },
        })
        .unwrap();
        assert!(packet.len() < bytes.len() + 100);
        let request = decode_request(&packet).unwrap();
        assert_eq!(request.generation, 7);
        assert!(
            matches!(&request.command, Command::InspectBackup { archive } if *archive == bytes)
        );
        let response = decode_response(
            &encode_response(Response {
                generation: 7,
                result: Ok(Output::Backup(bytes.clone())),
            })
            .unwrap(),
        )
        .unwrap();
        assert!(matches!(response.result, Ok(Output::Backup(archive)) if archive == bytes));
        for packet in [&[][..], &[255; 4][..], &[2, 0, 0, 0, 123][..]] {
            assert!(decode_request(packet).is_err());
        }
        let mut packet = encode_request(Request {
            generation: 0,
            command: Command::Lock,
        })
        .unwrap();
        assert_eq!(packet.first(), Some(&b'{'));
        packet.push(1);
        assert!(decode_request(&packet).is_err());
    }
    #[test]
    fn keyfile_packets_preserve_absent_and_empty_credentials_and_enforce_the_limit() {
        use confidex_app::import_flow as flow;
        for password in [None, Some(""), Some(" PUBLIC Unicode 密码 ")] {
            for keyfile in [None, Some(&[][..]), Some(&[0, 255, 32, 1][..])] {
                let packet = zeroize::Zeroizing::new(
                    encode_request(Request {
                        generation: 8,
                        command: Command::VendorImport(flow::Command::UnlockKdbx {
                            operation: 3,
                            token: [1; 16],
                            password: password.map(str::to_owned),
                            keyfile: keyfile.map(<[u8]>::to_vec),
                        }),
                    })
                    .unwrap(),
                );
                let request = decode_request(&packet).unwrap();
                let Command::VendorImport(flow::Command::UnlockKdbx {
                    password: decoded_password,
                    keyfile: decoded_keyfile,
                    ..
                }) = &request.command
                else {
                    panic!("credential packet")
                };
                assert_eq!(decoded_password.as_deref(), password);
                assert_eq!(decoded_keyfile.as_deref(), keyfile);
            }
        }
        let request = |keyfile| Request {
            generation: 8,
            command: Command::VendorImport(flow::Command::UnlockKdbx {
                operation: 3,
                token: [1; 16],
                password: None,
                keyfile: Some(keyfile),
            }),
        };
        let packet = encode_request(request(vec![193; flow::MAX_KEYFILE_BYTES])).unwrap();
        assert!(packet.len() < flow::MAX_KEYFILE_BYTES + 256);
        assert!(decode_request(&packet).is_ok());
        assert!(encode_request(request(vec![193; flow::MAX_KEYFILE_BYTES + 1])).is_err());
        let packet = pack(&request(vec![]), &vec![193; flow::MAX_KEYFILE_BYTES + 1]).unwrap();
        assert!(decode_request(&packet).is_err());
    }
    #[test]
    fn plaintext_import_uses_the_bounded_attachment_channel() {
        use confidex_app::{import, import_flow as flow};
        let source = vec![b'x'; 17 * 1024 * 1024];
        let packet = zeroize::Zeroizing::new(
            encode_request(Request {
                generation: 9,
                command: Command::VendorImport(flow::Command::Prepare {
                    operation: 1,
                    file_name: "public.json".into(),
                    format: None,
                    options: import::Options::default(),
                    bytes: source.clone(),
                }),
            })
            .unwrap(),
        );
        assert!(packet.len() < source.len() + 512);
        let request = decode_request(&packet).unwrap();
        assert_eq!(request.generation, 9);
        assert!(
            matches!(&request.command,Command::VendorImport(flow::Command::Prepare { bytes,.. }) if *bytes==source)
        );
    }
    #[test]
    fn binary_lengths_that_start_with_a_json_brace_are_not_json() {
        use confidex_app::{import, import_flow as flow};
        for length in 0..256 {
            let packet = encode_request(Request {
                generation: 1,
                command: Command::VendorImport(flow::Command::Prepare {
                    operation: 1,
                    file_name: "x".repeat(length),
                    format: None,
                    options: import::Options::default(),
                    bytes: vec![1, 2, 3],
                }),
            })
            .unwrap();
            if packet[0] == b'{' {
                assert!(decode_request(&packet).is_ok());
                return;
            }
        }
        panic!("missing boundary fixture");
    }
}
