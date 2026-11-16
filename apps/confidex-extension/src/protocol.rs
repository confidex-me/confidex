use confidex_app::Error;
use confidex_storage::Head;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

pub const VERSION: u8 = 1;
#[cfg(any(test, feature = "session"))]
pub const MAX_REQUEST: usize = 32 * 1024;
pub const MAX_RESPONSE: usize = 1024 * 1024;

#[derive(Deserialize, Serialize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
pub struct Credentials {
    pub password: String,
    pub key: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub version: u8,
    pub action: Action,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub enum Action {
    Status,
    Connect {
        name: String,
        server: String,
        credentials: Credentials,
    },
    Unlock(Credentials),
    Lock,
    Sync,
    Logins {
        after: Option<Head>,
    },
}

#[cfg(any(test, feature = "session"))]
impl Request {
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() > MAX_REQUEST {
            return Err(Error::Input);
        }
        let request: Self = serde_json::from_slice(bytes).map_err(|_| Error::Input)?;
        if request.version != VERSION {
            return Err(Error::Input);
        }
        Ok(request)
    }
}

#[derive(Deserialize, Serialize)]
pub enum Reply {
    Disconnected,
    Locked {
        name: String,
    },
    Opened {
        name: String,
        can_sync: bool,
    },
    Synced {
        conflicts: bool,
        more: bool,
    },
    Logins {
        rows: Vec<Login>,
        next: Option<Head>,
    },
}

#[derive(Deserialize, Serialize)]
pub struct Login {
    pub title: String,
    pub username: String,
}
impl Drop for Login {
    fn drop(&mut self) {
        self.title.zeroize();
        self.username.zeroize();
    }
}

pub type Response = Result<Reply, Error>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn worker_rejects_unknown_and_oversized_messages() {
        assert!(matches!(
            Request::decode(br#"{"version":1,"action":"Status"}"#)
                .unwrap()
                .action,
            Action::Status
        ));
        for bytes in [
            &br#"{"version":0,"action":"Status"}"#[..],
            br#"{"version":1,"action":"Open"}"#,
            br#"{"version":1,"action":"Status","origin":"https://example.test"}"#,
            br#"{"version":1,"action":{"Unlock":{"password":"p","key":"k","remember":true}}}"#,
            &[b' '; MAX_REQUEST + 1],
        ] {
            assert!(matches!(Request::decode(bytes), Err(Error::Input)));
        }
    }

    #[test]
    fn login_reply_contains_only_preview_metadata() {
        let result: Response = Ok(Reply::Logins {
            rows: vec![Login {
                title: "Test".into(),
                username: "public fixture".into(),
            }],
            next: None,
        });
        let bytes = serde_json::to_vec(&result).unwrap();
        assert!(bytes.len() < MAX_RESPONSE);
        let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            value["Ok"]["Logins"]["rows"][0].as_object().unwrap().len(),
            2
        );
    }
}
