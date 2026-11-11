use super::*;

fn number(input: &mut &[u8]) -> io::Result<u32> {
    let (value, rest) = input.split_at_checked(4).ok_or_else(invalid)?;
    *input = rest;
    Ok(u32::from_be_bytes(value.try_into().unwrap()))
}
fn field<'a>(input: &mut &'a [u8], cap: usize) -> io::Result<&'a [u8]> {
    let length = number(input)? as usize;
    if length > cap {
        return Err(invalid());
    }
    let (value, rest) = input.split_at_checked(length).ok_or_else(invalid)?;
    *input = rest;
    Ok(value)
}
fn append(out: &mut Vec<u8>, bytes: &[u8]) -> io::Result<()> {
    if out.len() + 4 + bytes.len() > MAX_RESPONSE {
        return Err(invalid());
    }
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
    Ok(())
}
fn identities(source: &mut impl KeySource) -> io::Result<Vec<Identity>> {
    let ids = source.identities()?;
    if ids.len() > MAX_IDENTITIES
        || ids
            .iter()
            .any(|i| i.public_key.len() > 4096 || i.comment.len() > 256)
    {
        return Err(invalid());
    }
    Ok(ids)
}
pub(super) fn dispatch(
    bytes: &[u8],
    peer: Peer,
    source: &mut impl KeySource,
    approve: &mut impl FnMut(&SignRequest<'_>) -> bool,
) -> io::Result<Zeroizing<Vec<u8>>> {
    let (&opcode, mut input) = bytes.split_first().ok_or_else(invalid)?;
    let mut out = Zeroizing::new(Vec::new());
    out.try_reserve_exact(MAX_RESPONSE)
        .map_err(|_| io::ErrorKind::OutOfMemory)?;
    match opcode {
        11 if input.is_empty() => {
            let ids = identities(source)?;
            out.push(12);
            out.extend_from_slice(&(ids.len() as u32).to_be_bytes());
            for id in ids {
                append(&mut out, &id.public_key)?;
                append(&mut out, id.comment.as_bytes())?;
            }
        }
        13 => {
            let public_key = field(&mut input, 4096)?;
            let data = field(&mut input, confidex_vault::ssh::MAX_MESSAGE)?;
            let flags = number(&mut input)?;
            if flags != 0 || !input.is_empty() {
                return Err(invalid());
            }
            if !identities(source)?
                .iter()
                .any(|id| id.public_key == public_key)
                || !approve(&SignRequest {
                    peer,
                    public_key,
                    data,
                })
            {
                return Err(denied());
            }
            let key = source.load(public_key)?;
            if key.public_blob().map_err(|_| invalid())? != public_key {
                return Err(invalid());
            }
            let signature = key.sign(data).map_err(|_| invalid())?;
            out.push(14);
            append(&mut out, &signature)?;
        }
        _ => return Err(invalid()),
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Source {
        value: confidex_vault::record::Mapping,
        public: Vec<u8>,
        loads: usize,
        locked: bool,
    }
    impl KeySource for Source {
        fn identities(&mut self) -> io::Result<Vec<Identity>> {
            Ok(if self.locked {
                vec![]
            } else {
                vec![Identity {
                    public_key: self.public.clone(),
                    comment: "fixture".into(),
                }]
            })
        }
        fn load(&mut self, _: &[u8]) -> io::Result<Key> {
            self.loads += 1;
            Key::from_value(&self.value, confidex_vault::ssh::REQUIRED_MEMORY)
                .map_err(|_| invalid())
        }
    }
    fn source() -> Source {
        let private = ssh_key::PrivateKey::new(
            ssh_key::private::Ed25519Keypair::from_seed(&[42; 32]).into(),
            "fixture",
        )
        .unwrap();
        let pem = private.to_openssh(ssh_key::LineEnding::LF).unwrap();
        let key = Key::import(pem.as_bytes(), None, confidex_vault::ssh::REQUIRED_MEMORY).unwrap();
        Source {
            value: key.to_value().unwrap(),
            public: key.public_blob().unwrap(),
            loads: 0,
            locked: false,
        }
    }
    fn peer() -> Peer {
        Peer {
            pid: None,
            #[cfg(unix)]
            uid: 123,
        }
    }
    fn request(public: &[u8], data: &[u8], flags: u32) -> Vec<u8> {
        let mut out = vec![13];
        append(&mut out, public).unwrap();
        append(&mut out, data).unwrap();
        out.extend_from_slice(&flags.to_be_bytes());
        out
    }
    #[test]
    fn confirmation_precedes_private_key_loading_and_each_signature_is_checked() {
        let mut source = source();
        let request = request(&source.public, b"authentication challenge", 0);
        let mut confirmations = 0;
        assert_eq!(
            dispatch(&[11], peer(), &mut source, &mut |_| panic!(
                "listing needs no signing approval"
            ))
            .unwrap()[0],
            12
        );
        assert!(
            dispatch(&request, peer(), &mut source, &mut |_| {
                confirmations += 1;
                false
            })
            .is_err()
        );
        assert_eq!(source.loads, 0);
        let response = dispatch(&request, peer(), &mut source, &mut |r| {
            confirmations += 1;
            assert_eq!(r.data, b"authentication challenge");
            true
        })
        .unwrap();
        assert_eq!(source.loads, 1);
        assert_eq!(confirmations, 2);
        assert_eq!(response[0], 14);
        let mut data = &response[1..];
        let signature = field(&mut data, 1024).unwrap();
        assert!(data.is_empty());
        confidex_vault::ssh::verify(&source.public, b"authentication challenge", signature)
            .unwrap();
        source.locked = true;
        assert_eq!(
            &dispatch(&[11], peer(), &mut source, &mut |_| false).unwrap()[..],
            &[12, 0, 0, 0, 0]
        );
        assert!(
            dispatch(&request, peer(), &mut source, &mut |_| panic!(
                "locked vault"
            ))
            .is_err()
        );
        assert_eq!(source.loads, 1);
    }
    #[test]
    fn malformed_or_unsupported_requests_cannot_reach_approval_or_private_keys() {
        let mut source = source();
        let mut bad = vec![
            vec![],
            vec![11, 0],
            vec![13],
            request(&[0; 32], b"x", 0),
            request(&source.public, b"x", 2),
            request(&source.public, &vec![0; 32769], 0),
        ];
        let mut trailing = request(&source.public, b"x", 0);
        trailing.push(0);
        bad.push(trailing);
        for opcode in 0..=255 {
            if opcode != 11 && opcode != 13 {
                bad.push(vec![opcode]);
            }
        }
        for request in bad {
            assert!(
                dispatch(&request, peer(), &mut source, &mut |_| panic!(
                    "bad request"
                ))
                .is_err()
            );
        }
        assert_eq!(source.loads, 0);
    }
}
