use confidex_app::browser_logins::{Cursor, Page, Selection};
use confidex_extension_content::Choice;
use serde::{Deserialize, Serialize};

use crate::{
    autosave::{SaveReply, SitePolicy},
    protocol::SyncStatus,
};

#[cfg(feature = "ui")]
use crate::autosave::SaveAction;

#[cfg(feature = "ui")]
#[derive(Serialize)]
pub struct PopupRequest {
    pub version: u8,
    pub action: PopupAction,
}

#[cfg(feature = "ui")]
#[derive(Serialize)]
pub enum PopupAction {
    CurrentSite,
    Discover {
        after: Option<Cursor>,
        #[serde(skip_serializing_if = "Option::is_none")]
        previous: Option<String>,
    },
    Fill {
        operation: String,
        form: u32,
        target: Selection,
    },
    Save(SaveAction),
    VaultSave(SaveAction),
    SetPolicy {
        origin: String,
        policy: SitePolicy,
    },
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub enum PopupReply {
    Locked,
    Unavailable,
    Changed,
    Busy,
    Error,
    Filled,
    Live,
    Save(SaveReply),
    PolicyChanged,
    CurrentSite {
        origin: String,
        policy: SitePolicy,
    },
    SiteDisabled {
        origin: String,
    },
    Site {
        operation: String,
        origin: String,
        forms: Vec<Choice>,
        matches: Page,
        sync: SyncStatus,
        preferred: Option<Selection>,
        policy: SitePolicy,
    },
}

#[cfg(all(feature = "session", target_arch = "wasm32", target_os = "unknown"))]
pub use worker::*;

#[cfg(any(
    test,
    all(feature = "session", target_arch = "wasm32", target_os = "unknown")
))]
mod worker {
    use std::{cell::RefCell, rc::Rc};

    use confidex_app::browser_logins::FillLogin;
    use confidex_extension_content::{Snapshot, Target};

    use super::*;
    use crate::protocol::{SenderContext, valid_id};

    const OPERATION_MS: u64 = 90_000;
    const CONTINUATION_MS: u64 = 120_000;
    const MAX_CONTINUATIONS: usize = 10;

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct SiteRequest {
        pub version: u8,
        pub context: SenderContext,
        pub action: SiteAction,
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    pub enum SiteAction {
        Find {
            operation: String,
            snapshot: Snapshot,
            after: Option<Cursor>,
            previous: Option<String>,
            recent: Option<(confidex_storage::RecordId, usize)>,
            inline_field: Option<u32>,
            #[serde(default)]
            automatic: bool,
        },
        Fill {
            operation: String,
            form: u32,
            target: Selection,
            snapshot: Snapshot,
        },
        Complete {
            operation: String,
        },
    }

    impl SiteRequest {
        pub fn valid(&self) -> bool {
            let valid = match &self.action {
                SiteAction::Find {
                    operation,
                    snapshot,
                    previous,
                    ..
                } => {
                    valid_id(operation)
                        && snapshot.valid()
                        && previous.as_deref().is_none_or(valid_id)
                }
                SiteAction::Fill {
                    operation,
                    snapshot,
                    ..
                } => valid_id(operation) && snapshot.valid(),
                SiteAction::Complete { operation } => valid_id(operation),
            };
            self.version == 1 && self.context.valid() && valid
        }
    }

    #[derive(Serialize)]
    pub enum SiteReply {
        Popup(PopupReply),
        Fill { fields: Target, login: FillLogin },
    }

    struct Operation {
        id: String,
        start: u64,
        context: SenderContext,
        snapshot: Snapshot,
        logins: Vec<Selection>,
    }

    struct Continuation {
        operation: String,
        context: SenderContext,
        target: Selection,
        start: u64,
        delivered: bool,
    }

    #[derive(Default)]
    struct State {
        operation: Option<Operation>,
        continuations: Vec<Continuation>,
    }

    #[derive(Clone, Default)]
    pub struct Autofill(Rc<RefCell<State>>);

    impl Autofill {
        pub fn live(&self, now: u64, operation: &str) -> bool {
            self.0
                .borrow()
                .operation
                .as_ref()
                .is_some_and(|op| op.id == operation && fresh(now, op.start, OPERATION_MS))
        }

        pub fn clear(&self) {
            *self.0.borrow_mut() = State::default();
        }

        pub fn invalidate_waiting_for_form(&self) {
            let mut state = self.0.borrow_mut();
            if state
                .operation
                .as_ref()
                .is_some_and(|op| op.snapshot.choices(&op.context.origin).is_empty())
            {
                state.operation = None;
            }
        }

        pub fn same_snapshot(
            &self,
            now: u64,
            id: &str,
            context: &SenderContext,
            snapshot: &Snapshot,
        ) -> bool {
            self.0.borrow().operation.as_ref().is_some_and(|op| {
                op.id == id
                    && fresh(now, op.start, OPERATION_MS)
                    && &op.context == context
                    && &op.snapshot == snapshot
            })
        }

        pub fn navigate(&self, tab: u32, origin: Option<&str>) {
            let mut state = self.0.borrow_mut();
            if state
                .operation
                .as_ref()
                .is_some_and(|op| op.context.tab_id == tab)
            {
                state.operation = None;
            }
            state
                .continuations
                .retain(|c| c.context.tab_id != tab || (Some(c.context.origin.as_str()) == origin));
        }

        pub fn issue(
            &self,
            now: u64,
            id: String,
            context: SenderContext,
            snapshot: Snapshot,
            logins: &Page,
        ) -> Option<Selection> {
            let mut state = self.0.borrow_mut();
            state.continuations.retain(|c| {
                fresh(now, c.start, CONTINUATION_MS)
                    && (c.context.tab_id != context.tab_id || c.context.origin == context.origin)
            });
            let preferred = state
                .continuations
                .iter()
                .find(|c| {
                    c.delivered
                        && c.context.tab_id == context.tab_id
                        && c.context.origin == context.origin
                })
                .map(|c| c.target.clone());
            state.operation = Some(Operation {
                id,
                start: now,
                context,
                snapshot,
                logins: logins.rows.iter().map(|row| row.target.clone()).collect(),
            });
            preferred
        }

        pub fn consume(
            &self,
            now: u64,
            id: &str,
            context: &SenderContext,
            fresh_snapshot: &Snapshot,
            form: u32,
            login: &Selection,
        ) -> Option<Target> {
            if !self.live(now, id) {
                return None;
            }
            let op = self.0.borrow_mut().operation.take()?;
            if &op.context != context
                || !op.logins.contains(login)
                || !op.snapshot.same_form(fresh_snapshot, form)
            {
                return None;
            }
            fresh_snapshot
                .choices(&context.origin)
                .into_iter()
                .find(|choice| choice.target.form == form)
                .map(|choice| choice.target)
        }

        pub fn begin_continuation(
            &self,
            now: u64,
            operation: String,
            context: SenderContext,
            target: Selection,
        ) {
            let mut state = self.0.borrow_mut();
            state.continuations.retain(|c| {
                c.context.tab_id != context.tab_id && fresh(now, c.start, CONTINUATION_MS)
            });
            if state.continuations.len() == MAX_CONTINUATIONS {
                state.continuations.remove(0);
            }
            state.continuations.push(Continuation {
                operation,
                context,
                target,
                start: now,
                delivered: false,
            });
        }

        pub fn complete(&self, operation: &str, context: &SenderContext) {
            if let Some(c) = self
                .0
                .borrow_mut()
                .continuations
                .iter_mut()
                .find(|c| !c.delivered && c.operation == operation && &c.context == context)
            {
                c.delivered = true;
            }
        }
    }

    fn fresh(now: u64, start: u64, ttl: u64) -> bool {
        now.checked_sub(start).is_some_and(|age| age < ttl)
    }
}

#[cfg(test)]
mod tests {
    use super::{PopupReply, worker::*};
    use crate::protocol::SenderContext;
    use confidex_app::browser_logins::{Issues, Login, Page, Selection};
    use confidex_extension_content::Snapshot;
    use confidex_storage::Head;

    fn request() -> SiteRequest {
        serde_json::from_str(
            r#"{
            "version":1,
            "context":{"tabId":2,"frameId":0,"documentId":"a001","origin":"https://example.test"},
            "action":{"Find":{"operation":"aa","after":null,"snapshot":{"page":1,"forms":[{
              "id":1,"stamp":0,"label":"Login","destinations":["https://example.test"],"submitsWithGet":false,
              "fields":[{"id":2,"kind":"password","autocomplete":"current-password","hint":""}]
            }]}}}
        }"#,
        )
        .unwrap()
    }

    fn issue(state: &Autofill, start: u64) -> (SenderContext, Snapshot, Selection) {
        let request = request();
        assert!(request.valid());
        let SiteAction::Find {
            operation,
            snapshot,
            after,
            previous,
            ..
        } = request.action
        else {
            unreachable!();
        };
        assert!(after.is_none());
        assert!(previous.is_none());
        let target = Selection {
            head: Head {
                record: [1; 16],
                revision: [2; 32],
            },
            field: 1,
        };
        let page = Page {
            rows: vec![Login {
                target: target.clone(),
                title: "Fixture".into(),
                username: "user".into(),
                fields: 3,
            }],
            next: None,
            issues: Issues::default(),
        };
        let fresh = serde_json::from_value(serde_json::to_value(&snapshot).unwrap()).unwrap();
        state.issue(start, operation, request.context.clone(), snapshot, &page);
        (request.context, fresh, target)
    }

    #[test]
    fn only_the_selected_login_and_live_document_can_consume_a_fill() {
        let state = Autofill::default();
        let (mut context, snapshot, target) = issue(&state, 1);
        context.document_id = "a002".into();
        assert!(
            state
                .consume(2, "aa", &context, &snapshot, 1, &target)
                .is_none()
        );
        assert!(!state.live(2, "aa"));

        let (context, mut snapshot, target) = issue(&state, 1);
        snapshot.page += 1;
        assert!(
            state
                .consume(2, "aa", &context, &snapshot, 1, &target)
                .is_none()
        );

        let (context, snapshot, target) = issue(&state, 1);
        assert!(
            state
                .consume(90_001, "aa", &context, &snapshot, 1, &target)
                .is_none()
        );

        let (context, snapshot, target) = issue(&state, 2);
        assert!(
            state
                .consume(2, "aa", &context, &snapshot, 1, &target)
                .unwrap()
                .password
                == Some(2)
        );
        assert!(
            state
                .consume(2, "aa", &context, &snapshot, 1, &target)
                .is_none()
        );
    }

    #[test]
    fn login_previews_while_waiting_for_a_form_follow_the_live_document() {
        let state = Autofill::default();
        let (mut context, mut snapshot, _) = issue(&state, 1);
        assert!(state.same_snapshot(2, "aa", &context, &snapshot));
        snapshot.forms.clear();
        assert!(!state.same_snapshot(2, "aa", &context, &snapshot));
        let page = Page {
            rows: vec![],
            next: None,
            issues: Issues::default(),
        };
        state.issue(
            2,
            "bb".into(),
            context.clone(),
            Snapshot {
                page: snapshot.page,
                forms: vec![],
            },
            &page,
        );
        assert!(state.same_snapshot(3, "bb", &context, &snapshot));
        context.document_id = "a002".into();
        assert!(!state.same_snapshot(3, "bb", &context, &snapshot));
        context.document_id = "a001".into();
        assert!(!state.same_snapshot(90_002, "bb", &context, &snapshot));
        state.invalidate_waiting_for_form();
        assert!(!state.same_snapshot(3, "bb", &context, &snapshot));
    }

    #[test]
    fn versions_and_field_metadata_are_validated() {
        let mut request = request();
        request.version = 0;
        assert!(!request.valid());
        request.version = 1;
        request.context.frame_id = 1;
        assert!(!request.valid());
        request.context.frame_id = 0;
        request.context.origin = "https://example.test/other".into();
        assert!(!request.valid());
        let (mut context, _, _) = issue(&Autofill::default(), 1);
        context.origin = "http://example.test".into();
        assert!(!context.valid());
    }

    #[test]
    fn the_fill_reply_is_distinct_from_any_popup_reply() {
        let (context, snapshot, target) = issue(&Autofill::default(), 1);
        let fill: SiteRequest = serde_json::from_value(serde_json::json!({
            "version": 1, "context": context, "action": {"Fill": {
                "operation": "aa", "snapshot": snapshot, "form": 1, "target": target,
            }},
        }))
        .unwrap();
        assert!(fill.valid());
        let SiteAction::Fill {
            form,
            target: selection,
            snapshot,
            ..
        } = fill.action
        else {
            unreachable!()
        };
        assert_eq!(form, 1);
        assert!(selection == target);

        let reply = SiteReply::Fill {
            fields: snapshot.choices(&fill.context.origin).remove(0).target,
            login: confidex_app::browser_logins::FillLogin {
                username: None,
                password: Some("fixture-secret".into()),
            },
        };
        assert_eq!(
            serde_json::to_value(reply).unwrap()["Fill"]["login"]["password"],
            "fixture-secret"
        );
        assert_eq!(
            serde_json::to_value(SiteReply::Popup(PopupReply::Filled)).unwrap(),
            serde_json::json!({"Popup": "Filled"})
        );
    }

    #[test]
    fn username_first_context_is_short_lived_and_drops_on_origin_change() {
        let state = Autofill::default();
        let (context, snapshot, target) = issue(&state, 1);
        state.begin_continuation(1, "aa".into(), context.clone(), target.clone());
        state.complete("aa", &context);
        state.navigate(context.tab_id, Some(&context.origin));
        let page = Page {
            rows: vec![],
            next: None,
            issues: Issues::default(),
        };
        let preferred = state.issue(2, "ab".into(), context.clone(), snapshot, &page);
        assert!(preferred == Some(target.clone()));
        state.navigate(context.tab_id, None);
        let (_, snapshot, _) = issue(&state, 2);
        assert!(
            state
                .issue(3, "ab".into(), context.clone(), snapshot, &page)
                .is_none()
        );
        state.begin_continuation(4, "aa".into(), context.clone(), target);
        state.complete("aa", &context);
        let (_, snapshot, _) = issue(&state, 4);
        assert!(
            state
                .issue(120_004, "ab".into(), context, snapshot, &page)
                .is_none()
        );
        state.clear();
        assert!(!state.live(120_004, "ab"));
    }
}
