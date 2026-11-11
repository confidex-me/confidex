use confidex_app::{Summary, local_sync, sync};
use confidex_storage::{Head, RecordId, RevisionId, VaultId, VaultInfo};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::io::{self, Read, Write};
use zeroize::{Zeroize, Zeroizing};

pub const VERSION: u16 = 1;
pub const MAX_REQUEST: usize = 64 * 1024;
pub const MAX_HEADER: usize = confidex_vault::resources::MAX_DECOMPRESSED;
pub const MAX_PAYLOAD: usize = confidex_vault::resources::MAX_DECOMPRESSED;
pub const MAX_SECRET: usize = 4096;

pub struct Secret(pub String);
impl Serialize for Secret {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        if self.0.len() > MAX_SECRET {
            return Err(serde::ser::Error::custom("credential exceeds limit"));
        }
        serializer.serialize_bytes(self.0.as_bytes())
    }
}
impl<'de> Deserialize<'de> for Secret {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Visitor;
        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = Secret;
            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("a bounded UTF-8 byte array")
            }
            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                mut sequence: A,
            ) -> Result<Secret, A::Error> {
                let mut bytes = Zeroizing::new(Vec::new());
                bytes
                    .try_reserve_exact(MAX_SECRET)
                    .map_err(|_| serde::de::Error::custom("credential allocation failed"))?;
                while let Some(byte) = sequence.next_element::<u8>()? {
                    if bytes.len() == MAX_SECRET {
                        return Err(serde::de::Error::custom("credential exceeds limit"));
                    }
                    bytes.push(byte);
                }
                match String::from_utf8(std::mem::take(&mut *bytes)) {
                    Ok(text) => Ok(Secret(text)),
                    Err(error) => {
                        error.into_bytes().zeroize();
                        Err(serde::de::Error::custom("credential is not UTF-8"))
                    }
                }
            }
        }
        // Byte arrays avoid a parser scratch string for escaped secret characters.
        deserializer.deserialize_seq(Visitor)
    }
}
impl Drop for Secret {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Credentials {
    pub password: Secret,
    pub secret_key: Option<Secret>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Record {
    pub selector: String,
    pub revision: Option<RevisionId>,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Field {
    Name(String),
    Index(usize),
}

#[derive(Serialize, Deserialize)]
// External tags avoid an intermediate unprotected credentials map during parsing.
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum Operation {
    Stop {},
    Vaults {},
    Status {},
    Unlock {
        credentials: Credentials,
    },
    Lock {},
    Create {
        name: String,
        credentials: Credentials,
        key_output: std::path::PathBuf,
    },
    Connect {
        name: String,
        server: String,
        credentials: Credentials,
    },
    List {
        query: Option<String>,
        tag: Option<String>,
        after: Option<Head>,
        refresh: bool,
    },
    Fields {
        record: Record,
    },
    Get {
        record: Record,
        field: Field,
        value: Option<String>,
    },
    Sync {
        folder: bool,
    },
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub version: u16,
    pub id: u64,
    pub vault: Option<VaultId>,
    pub command: Operation,
}
impl Request {
    fn validate(&self) -> io::Result<()> {
        let global = matches!(
            self.command,
            Operation::Stop { .. }
                | Operation::Vaults { .. }
                | Operation::Create { .. }
                | Operation::Connect { .. }
        );
        if self.version != VERSION || global == self.vault.is_some() {
            return Err(invalid());
        }
        Ok(())
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FieldInfo {
    pub index: usize,
    pub name: String,
    pub type_name: String,
    pub keys: Vec<String>,
    pub binary: bool,
    pub opaque: usize,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Reply {
    Stopped {},
    Vaults {
        vaults: Vec<VaultInfo>,
    },
    Status {
        unlocked: bool,
    },
    Opened {
        vault: VaultInfo,
    },
    Locked {},
    Created {
        vault: VaultInfo,
        remembered: bool,
        length: usize,
    },
    Indexing {},
    Rows {
        rows: Vec<Summary>,
        more: bool,
        next: Option<Head>,
    },
    Fields {
        fields: Vec<FieldInfo>,
    },
    Value {
        binary: bool,
        length: usize,
    },
    Synced {
        report: Option<sync::Report>,
        conflict: Option<RecordId>,
    },
    FolderSynced {
        report: Option<local_sync::Report>,
        conflict: Option<RecordId>,
    },
}
impl Reply {
    fn matches(&self, operation: &Operation) -> bool {
        matches!(
            (self, operation),
            (Self::Stopped { .. }, Operation::Stop { .. })
                | (Self::Vaults { .. }, Operation::Vaults { .. })
                | (Self::Status { .. }, Operation::Status { .. })
                | (
                    Self::Opened { .. },
                    Operation::Unlock { .. } | Operation::Connect { .. }
                )
                | (Self::Locked { .. }, Operation::Lock { .. })
                | (Self::Created { .. }, Operation::Create { .. })
                | (Self::Rows { .. }, Operation::List { .. })
                | (Self::Indexing { .. }, Operation::List { .. })
                | (Self::Fields { .. }, Operation::Fields { .. })
                | (Self::Value { .. }, Operation::Get { .. })
                | (Self::Synced { .. }, Operation::Sync { folder: false })
                | (Self::FolderSynced { .. }, Operation::Sync { folder: true })
        )
    }
    fn payload_length(&self) -> usize {
        match self {
            Self::Value { length, .. } | Self::Created { length, .. } => *length,
            _ => 0,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Code {
    Io,
    Input,
    Locked,
    NotFound,
    Ambiguous,
    Auth,
    Network,
    Protocol,
    Cancelled,
}
impl Code {
    pub fn exit(self) -> i32 {
        match self {
            Self::Io => 1,
            Self::Input => 2,
            Self::Locked => 3,
            Self::NotFound => 4,
            Self::Ambiguous => 5,
            Self::Auth => 6,
            Self::Network => 7,
            Self::Protocol => 8,
            Self::Cancelled => 130,
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Failure {
    pub code: Code,
    pub message: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Response {
    pub version: u16,
    pub id: u64,
    pub vault: Option<VaultId>,
    pub result: Result<Reply, Failure>,
}
impl Response {
    fn payload_length(&self) -> usize {
        self.result.as_ref().map_or(0, Reply::payload_length)
    }
    fn validate(&self, expected_id: u64) -> io::Result<()> {
        if self.version != VERSION || self.id != expected_id || self.payload_length() > MAX_PAYLOAD
        {
            return Err(invalid());
        }
        Ok(())
    }
}

fn invalid() -> io::Error {
    io::ErrorKind::InvalidData.into()
}

fn read_bytes(reader: &mut impl Read, length: usize) -> io::Result<Zeroizing<Vec<u8>>> {
    let mut bytes = Zeroizing::new(Vec::new());
    bytes
        .try_reserve_exact(length)
        .map_err(|_| io::ErrorKind::OutOfMemory)?;
    bytes.resize(length, 0);
    reader.read_exact(&mut bytes)?;
    Ok(bytes)
}

fn read_json<T: DeserializeOwned>(reader: &mut impl Read, limit: usize) -> io::Result<T> {
    let mut prefix = [0; 4];
    reader.read_exact(&mut prefix)?;
    let length = u32::from_be_bytes(prefix) as usize;
    if length == 0 || length > limit {
        return Err(invalid());
    }
    serde_json::from_slice(&read_bytes(reader, length)?).map_err(|_| invalid())
}

struct Count {
    length: usize,
    limit: usize,
}
impl Write for Count {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.length = self
            .length
            .checked_add(bytes.len())
            .filter(|n| *n <= self.limit)
            .ok_or_else(invalid)?;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn write_json(writer: &mut impl Write, value: &impl Serialize, limit: usize) -> io::Result<()> {
    let mut count = Count { length: 0, limit };
    serde_json::to_writer(&mut count, value).map_err(|_| invalid())?;
    let mut bytes = Zeroizing::new(Vec::new());
    // Measure first so serialization does not leave plaintext in old allocations.
    bytes
        .try_reserve_exact(count.length)
        .map_err(|_| io::ErrorKind::OutOfMemory)?;
    serde_json::to_writer(&mut *bytes, value).map_err(|_| invalid())?;
    writer.write_all(&(bytes.len() as u32).to_be_bytes())?;
    writer.write_all(&bytes)
}

pub fn read_request(reader: &mut impl Read) -> io::Result<Request> {
    let request: Request = read_json(reader, MAX_REQUEST)?;
    request.validate()?;
    Ok(request)
}

pub fn write_request(writer: &mut impl Write, request: &Request) -> io::Result<()> {
    request.validate()?;
    write_json(writer, request, MAX_REQUEST)?;
    writer.flush()
}

pub fn read_response(
    reader: &mut impl Read,
    request: &Request,
) -> io::Result<(Response, Zeroizing<Vec<u8>>)> {
    let response: Response = read_json(reader, MAX_HEADER)?;
    response.validate(request.id)?;
    if response.vault != request.vault
        || response
            .result
            .as_ref()
            .is_ok_and(|reply| !reply.matches(&request.command))
    {
        return Err(invalid());
    }
    let payload = read_bytes(reader, response.payload_length())?;
    if matches!(
        response.result,
        Ok(Reply::Value { binary: false, .. } | Reply::Created { .. })
    ) && std::str::from_utf8(&payload).is_err()
    {
        return Err(invalid());
    }
    Ok((response, payload))
}

pub fn write_response(
    writer: &mut impl Write,
    response: &Response,
    payload: &[u8],
) -> io::Result<()> {
    response.validate(response.id)?;
    if response.payload_length() != payload.len() {
        return Err(invalid());
    }
    write_json(writer, response, MAX_HEADER)?;
    writer.write_all(payload)?;
    writer.flush()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn frame(json: &[u8]) -> Vec<u8> {
        let mut bytes = (json.len() as u32).to_be_bytes().to_vec();
        bytes.extend_from_slice(json);
        bytes
    }

    fn get_request(id: u64) -> Request {
        Request {
            version: VERSION,
            id,
            vault: Some([1; 16]),
            command: Operation::Get {
                record: Record {
                    selector: "fixture".into(),
                    revision: None,
                },
                field: Field::Index(0),
                value: None,
            },
        }
    }

    #[test]
    fn request_roundtrip_and_scope() {
        let request = Request {
            version: VERSION,
            id: 19,
            vault: Some([1; 16]),
            command: Operation::Unlock {
                credentials: Credentials {
                    password: Secret("public fixture".into()),
                    secret_key: None,
                },
            },
        };
        let mut wire = Zeroizing::new(Vec::new());
        write_request(&mut *wire, &request).unwrap();
        let decoded = read_request(&mut Cursor::new(&*wire)).unwrap();
        assert!(
            !wire
                .windows(b"public fixture".len())
                .any(|bytes| bytes == b"public fixture")
        );
        assert_eq!(decoded.id, 19);
        assert_eq!(decoded.vault, Some([1; 16]));
        assert!(matches!(decoded.command, Operation::Unlock { .. }));
        let invalid = Request {
            vault: None,
            ..request
        };
        assert!(write_request(&mut Vec::new(), &invalid).is_err());
    }

    #[test]
    fn rejects_unknown_versions_commands_fields_and_bad_frames() {
        for json in [
            br#"{"version":2,"id":1,"vault":null,"command":{"vaults":{}}}"#.as_slice(),
            br#"{"version":1,"id":1,"vault":null,"command":{"execute":{"command":"ExportKey"}}}"#,
            br#"{"version":1,"id":1,"vault":null,"command":{"vaults":{"extra":"secret"}}}"#,
            br#"{"version":1,"version":1,"id":1,"vault":null,"command":{"vaults":{}}}"#,
            b"{",
        ] {
            assert!(read_request(&mut Cursor::new(frame(json))).is_err());
        }
        for bytes in [
            vec![],
            vec![0, 0],
            0u32.to_be_bytes().to_vec(),
            ((MAX_REQUEST + 1) as u32).to_be_bytes().to_vec(),
            vec![0, 0, 0, 9, b'{'],
        ] {
            assert!(read_request(&mut Cursor::new(bytes)).is_err());
        }
        let mut output = Vec::new();
        assert!(write_json(&mut output, &"too large", 2).is_err());
        assert!(output.is_empty());
    }

    #[test]
    fn credentials_reject_invalid_utf8_and_lengths() {
        assert!(serde_json::from_slice::<Secret>(b"[255]").is_err());
        assert!(serde_json::from_slice::<Secret>(b"[0,256]").is_err());
        let oversized = serde_json::to_vec(&vec![b'x'; MAX_SECRET + 1]).unwrap();
        assert!(serde_json::from_slice::<Secret>(&oversized).is_err());
        let secret = Secret("test\\\"\n\u{263a}".into());
        let mut encoded = Zeroizing::new(Vec::new());
        serde_json::to_writer(&mut *encoded, &secret).unwrap();
        let decoded: Secret = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(decoded.0, secret.0);
    }

    #[test]
    fn selected_payload_is_raw_bounded_and_fully_received_before_use() {
        let response = Response {
            version: VERSION,
            id: 41,
            vault: Some([1; 16]),
            result: Ok(Reply::Value {
                binary: true,
                length: 4,
            }),
        };
        let mut wire = Vec::new();
        write_response(&mut wire, &response, &[0, 255, 1, 2]).unwrap();
        let (_, payload) = read_response(&mut Cursor::new(&wire), &get_request(41)).unwrap();
        assert_eq!(payload.as_slice(), &[0, 255, 1, 2]);
        assert!(read_response(&mut Cursor::new(&wire), &get_request(42)).is_err());
        let mut wrong_vault = get_request(41);
        wrong_vault.vault = Some([2; 16]);
        assert!(read_response(&mut Cursor::new(&wire), &wrong_vault).is_err());
        assert!(
            read_response(&mut Cursor::new(&wire[..wire.len() - 1]), &get_request(41)).is_err()
        );
        let mut output = Vec::new();
        assert!(write_response(&mut output, &response, b"bad").is_err());
        assert!(output.is_empty());
        let oversized = Response {
            result: Ok(Reply::Value {
                binary: true,
                length: MAX_PAYLOAD + 1,
            }),
            ..response
        };
        let mut header = Vec::new();
        write_json(&mut header, &oversized, MAX_HEADER).unwrap();
        assert!(read_response(&mut Cursor::new(header), &get_request(41)).is_err());
        let text = Response {
            result: Ok(Reply::Value {
                binary: false,
                length: 1,
            }),
            ..response
        };
        let mut invalid_text = Vec::new();
        write_response(&mut invalid_text, &text, &[255]).unwrap();
        assert!(read_response(&mut Cursor::new(invalid_text), &get_request(41)).is_err());
    }

    #[test]
    fn metadata_cannot_carry_an_unrequested_payload() {
        let response = Response {
            version: VERSION,
            id: 1,
            vault: Some([1; 16]),
            result: Ok(Reply::Fields {
                fields: vec![FieldInfo {
                    index: 0,
                    name: "Password".into(),
                    type_name: "password/v1".into(),
                    keys: vec!["password".into()],
                    binary: false,
                    opaque: 0,
                }],
            }),
        };
        let mut output = Vec::new();
        assert!(write_response(&mut output, &response, b"not requested").is_err());
        assert!(output.is_empty());
        write_response(&mut output, &response, b"").unwrap();
        let request = Request {
            version: VERSION,
            id: 1,
            vault: Some([1; 16]),
            command: Operation::Fields {
                record: Record {
                    selector: "fixture".into(),
                    revision: None,
                },
            },
        };
        assert!(read_response(&mut Cursor::new(&output), &get_request(1)).is_err());
        let (received, payload) = read_response(&mut Cursor::new(output), &request).unwrap();
        assert!(matches!(received.result, Ok(Reply::Fields { .. })));
        assert!(payload.is_empty());
    }
}
