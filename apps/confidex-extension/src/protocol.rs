use confidex_app::{
    Error,
    browser_logins::{Change, Cursor, EditLogin, NewLogin, Page, Selection},
};
use confidex_storage::{Head, RecordId};
use serde::{Deserialize, Serialize};
use zeroize::ZeroizeOnDrop;

pub const VERSION: u8 = 3;
// A full tag list and five login fields can each expand sixfold in JSON.
#[cfg(any(test, feature = "session"))]
pub const MAX_REQUEST: usize = 512 * 1024;
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
        after: Option<Cursor>,
    },
    LoginChoices {
        record: RecordId,
        after: Option<Cursor>,
    },
    LoginEditor {
        target: Selection,
    },
    CreateLogin {
        record: RecordId,
        login: NewLogin,
    },
    UpdateLogin {
        target: Selection,
        change: Change,
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
        sync: SyncStatus,
    },
    Synced {
        sync: SyncStatus,
        more: bool,
    },
    Logins {
        page: Page,
        sync: SyncStatus,
    },
    LoginChoices(Page),
    LoginEditor {
        target: Selection,
        fields: EditLogin,
    },
    Saved(Head),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub enum SyncStatus {
    Disabled,
    Pending,
    Current,
    Offline,
    Failed(Error),
}

pub type Response = Result<Reply, Error>;

// The browser adapter supplies this context separately from the form report.
#[cfg(any(test, feature = "session"))]
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SenderContext {
    tab_id: u32,
    frame_id: u32,
    document_id: String,
    origin: String,
}

#[cfg(any(test, feature = "session"))]
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FormReport {
    version: u8,
    kind: FormKind,
    has_password: bool,
}

#[cfg(any(test, feature = "session"))]
#[derive(Deserialize)]
enum FormKind {
    FormPresence,
}

#[cfg(any(test, feature = "session"))]
impl FormReport {
    pub fn valid(context: &str, report: &str) -> bool {
        if context.len() > 1024 || report.len() > 128 {
            return false;
        }
        let (Ok(context), Ok(report)) = (
            serde_json::from_str::<SenderContext>(context),
            serde_json::from_str::<Self>(report),
        ) else {
            return false;
        };
        let Ok(origin) = confidex_app::sync::server_url(&context.origin) else {
            return false;
        };
        context.tab_id <= i32::MAX as u32
            && context.frame_id == 0
            && context.document_id.len() <= 64
            && !context.document_id.is_empty()
            && context
                .document_id
                .bytes()
                .all(|b| b.is_ascii_hexdigit() || b == b'-')
            && origin.starts_with("https://")
            && origin.strip_suffix('/') == Some(context.origin.as_str())
            && matches!(report.kind, FormKind::FormPresence)
            && report.version == 1
            && report.has_password
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn worker_rejects_unknown_and_oversized_messages() {
        assert!(matches!(
            Request::decode(br#"{"version":3,"action":"Status"}"#)
                .unwrap()
                .action,
            Action::Status
        ));
        for bytes in [
            &br#"{"version":1,"action":"Status"}"#[..],
            br#"{"version":3,"action":"Open"}"#,
            br#"{"version":3,"action":"Status","origin":"https://example.test"}"#,
            br#"{"version":3,"action":{"Unlock":{"password":"p","key":"k","remember":true}}}"#,
        ] {
            assert!(matches!(Request::decode(bytes), Err(Error::Input)));
        }
        assert!(matches!(
            Request::decode(&vec![b' '; MAX_REQUEST + 1]),
            Err(Error::Input)
        ));
    }

    #[test]
    fn only_a_versioned_form_report_with_separate_top_frame_context_is_accepted() {
        let context =
            r#"{"tabId":2,"frameId":0,"documentId":"a0b1","origin":"https://example.test:8443"}"#;
        let report = r#"{"version":1,"kind":"FormPresence","hasPassword":true}"#;
        assert!(FormReport::valid(context, report));
        for invalid in [
            report.replace("true", "1"),
            report.replace("true", "false"),
            report.replace("Presence", "Fill"),
            report.replace("1", "2"),
            report.replace(r#""hasPassword""#, r#""origin""#),
            report.replace("true", r#"true,"tabId":2"#),
            " ".repeat(129),
        ] {
            assert!(!FormReport::valid(context, &invalid));
        }
        for invalid in [
            context.replace(r#""frameId":0"#, r#""frameId":1"#),
            context.replace("https:", "http:"),
            context.replace(":8443", "/login"),
            context.replace("a0b1", "opaque"),
        ] {
            assert!(!FormReport::valid(&invalid, report));
        }
    }

    #[test]
    fn login_reply_serializes_only_selection_metadata() {
        use confidex_app::browser_logins::{Issues, Login};

        let reply: Response = Ok(Reply::Logins {
            page: Page {
                rows: vec![Login {
                    target: Selection {
                        head: Head {
                            record: [1; 16],
                            revision: [2; 32],
                        },
                        field: 1,
                    },
                    title: "Test".into(),
                    username: "fixture".into(),
                    fields: 4,
                }],
                next: None,
                issues: Issues::default(),
            },
            sync: SyncStatus::Current,
        });
        let bytes = serde_json::to_vec(&reply).unwrap();
        assert!(bytes.len() < MAX_RESPONSE);
        let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        let row = value["Ok"]["Logins"]["page"]["rows"][0]
            .as_object()
            .unwrap();
        assert_eq!(
            row.keys().map(String::as_str).collect::<Vec<_>>(),
            ["fields", "target", "title", "username"]
        );
    }
}
