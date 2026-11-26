use confidex_app::browser_logins::{Issues, Login, Selection};
use serde::{Deserialize, Serialize};
use zeroize::ZeroizeOnDrop;

use crate::protocol::SyncStatus;

#[derive(Clone, Copy, Default, Deserialize, Serialize, PartialEq, Eq)]
pub enum SitePolicy {
    #[default]
    Allow,
    NoSave,
    Disabled,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub enum SaveAction {
    List,
    Confirm {
        id: String,
        target: Option<Selection>,
    },
    Dismiss {
        id: String,
    },
}

#[derive(Clone, Deserialize, Serialize, ZeroizeOnDrop)]
pub struct Offer {
    pub id: String,
    pub origin: String,
    pub remaining: u32,
    #[zeroize(skip)]
    pub kind: OfferKind,
}

#[derive(Clone, Deserialize, Serialize)]
pub enum OfferKind {
    New { username: String },
    Update(Vec<Login>),
    Blocked(Issues),
}

impl Drop for OfferKind {
    fn drop(&mut self) {
        if let Self::New { username } = self {
            zeroize::Zeroize::zeroize(username);
        }
    }
}

#[derive(Deserialize, Serialize)]
pub enum SaveReply {
    Offers {
        offers: Vec<Offer>,
        sync: SyncStatus,
    },
    Saved(SyncStatus),
    Dismissed,
    Duplicate,
    Changed,
    Busy,
    Locked,
    Error,
}

#[cfg(any(
    test,
    all(feature = "session", target_arch = "wasm32", target_os = "unknown")
))]
pub use worker::*;

#[cfg(any(
    test,
    all(feature = "session", target_arch = "wasm32", target_os = "unknown")
))]
mod worker {
    use std::{cell::RefCell, collections::HashMap, rc::Rc};

    use confidex_app::browser_logins::{CaptureMatches, MAX_LOGIN_TEXT, login_origin};
    use confidex_extension_content::{CaptureFields, Snapshot};
    use zeroize::Zeroizing;

    use super::*;
    use crate::protocol::{SenderContext, valid_id};

    pub const TTL: u64 = 120_000;
    const LIMIT: usize = 10;
    const MAX_CAPTURE_MESSAGE: usize = 96 * 1024;

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct SaveRequest {
        pub version: u8,
        pub tab: Option<u32>,
        pub action: SaveAction,
    }

    impl SaveRequest {
        pub fn valid(&self) -> bool {
            self.version == 1
                && self.tab.is_none_or(|tab| tab <= i32::MAX as u32)
                && match &self.action {
                    SaveAction::List => true,
                    SaveAction::Confirm { id, .. } | SaveAction::Dismiss { id } => valid_id(id),
                }
        }
    }

    #[derive(Serialize)]
    pub struct CapturePlan {
        revision: u32,
        remaining: i32,
        fields: Vec<CaptureFields>,
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Capture {
        version: u8,
        id: String,
        revision: u32,
        snapshot: Snapshot,
        values: Values,
    }

    #[derive(Deserialize, ZeroizeOnDrop)]
    #[serde(deny_unknown_fields)]
    struct Values {
        username: Option<String>,
        password: Option<String>,
        confirmation: Option<String>,
    }

    #[derive(ZeroizeOnDrop)]
    pub struct Candidate {
        pub id: String,
        pub origin: String,
        pub username: Option<String>,
        pub password: String,
        pub update_only: bool,
        pub tab: u32,
        start: u64,
    }

    impl Candidate {
        fn remaining(&self, now: u64) -> Option<u32> {
            remaining(now, self.start)
        }

        pub fn offer(&self, matches: CaptureMatches) -> Option<OfferKind> {
            if matches.duplicate {
                None
            } else if matches.issues.ambiguous || matches.issues.conflicts {
                Some(OfferKind::Blocked(matches.issues))
            } else if !matches.rows.is_empty() {
                Some(OfferKind::Update(matches.rows))
            } else if self.update_only {
                None
            } else {
                Some(OfferKind::New {
                    username: self
                        .username
                        .as_deref()
                        .unwrap_or("")
                        .chars()
                        .take(128)
                        .collect(),
                })
            }
        }
    }

    #[derive(ZeroizeOnDrop)]
    struct Username {
        tab: u32,
        origin: String,
        start: u64,
        value: String,
    }

    struct Entry {
        capture: Rc<Candidate>,
        offer: Option<OfferKind>,
    }

    #[derive(Default)]
    struct State {
        entries: Vec<Entry>,
        usernames: Vec<Username>,
        enabled: bool,
        revision: u32,
        exceptions: HashMap<String, SitePolicy>,
    }

    #[derive(Clone, Default)]
    pub struct Autosave(Rc<RefCell<State>>);

    impl Autosave {
        pub fn policy(&self, origin: &str) -> SitePolicy {
            self.0.borrow().policy(origin)
        }

        pub fn set_policy(&self, allowed: bool, json: &str) -> bool {
            let exceptions = (json.len() <= 600_000)
                .then(|| serde_json::from_str::<HashMap<String, SitePolicy>>(json).ok())
                .flatten()
                .filter(|entries| {
                    entries.len() <= 512
                        && entries.iter().all(|(origin, policy)| {
                            *policy != SitePolicy::Allow
                                && origin.len() <= 1024
                                && login_origin(origin).ok().as_ref() == Some(origin)
                        })
                });
            let enabled = allowed && exceptions.is_some();
            let exceptions = exceptions.unwrap_or_default();
            let mut state = self.0.borrow_mut();
            if state.enabled == enabled && state.exceptions == exceptions {
                return false;
            }
            state.enabled = enabled;
            state.revision = state.revision.wrapping_add(1);
            state
                .entries
                .retain(|entry| enabled && !exceptions.contains_key(&entry.capture.origin));
            state
                .usernames
                .retain(|entry| enabled && !exceptions.contains_key(&entry.origin));
            state.exceptions = exceptions;
            true
        }

        pub fn navigate(&self, tab: u32, origin: Option<&str>) {
            self.0
                .borrow_mut()
                .usernames
                .retain(|entry| entry.tab != tab || origin == Some(entry.origin.as_str()));
        }

        pub fn close_tab(&self, tab: u32) {
            self.navigate(tab, None);
            self.0.borrow_mut().entries.retain(|e| e.capture.tab != tab);
        }

        pub fn plan(&self, remaining: i32, context: &str, snapshot: &str) -> Option<CapturePlan> {
            if remaining <= 0 || snapshot.len() > crate::protocol::MAX_REQUEST {
                return None;
            }
            let context = decode_context(context)?;
            let state = self.0.borrow();
            if state.policy(&context.origin) != SitePolicy::Allow {
                return None;
            }
            let snapshot: Snapshot = serde_json::from_str(snapshot).ok()?;
            snapshot.valid().then(|| CapturePlan {
                revision: state.revision,
                remaining,
                fields: snapshot
                    .forms
                    .iter()
                    .filter_map(|form| form.capture_fields(&context.origin))
                    .collect(),
            })
        }

        pub fn capture(&self, now: u64, context: &str, json: &str) -> Option<()> {
            if json.len() > MAX_CAPTURE_MESSAGE {
                return None;
            }
            let context = decode_context(context)?;
            let mut state = self.0.borrow_mut();
            if state.policy(&context.origin) != SitePolicy::Allow {
                return None;
            }
            let mut report: Capture = serde_json::from_str(json).ok()?;
            if report.version != 1
                || !valid_id(&report.id)
                || state.revision != report.revision
                || report.snapshot.forms.len() != 1
                || !report.snapshot.valid()
            {
                return None;
            }
            let fields = report.snapshot.forms[0].capture_fields(&context.origin)?;
            if !report.values.valid(&fields) {
                return None;
            }
            state.expire(now);
            let tab = context.tab_id;
            let origin = context.origin;
            let mut username = report.values.username.take().map(Zeroizing::new);
            let Some(password) = report.values.password.take().map(Zeroizing::new) else {
                let mut value = username.take()?;
                if value.is_empty() {
                    return None;
                }
                state.usernames.retain(|entry| entry.tab != tab);
                if state.usernames.len() == LIMIT {
                    state.usernames.remove(0);
                }
                state.usernames.push(Username {
                    tab,
                    origin,
                    start: now,
                    value: std::mem::take(&mut value),
                });
                return Some(());
            };
            let update_only = fields.update_only
                || (fields.new_password && username.as_ref().is_none_or(|name| name.is_empty()));
            if !update_only
                && username.is_none()
                && let Some(index) = state
                    .usernames
                    .iter()
                    .position(|entry| entry.tab == tab && entry.origin == origin)
            {
                // Keep the username briefly for retries and a click followed by submit.
                username = Some(Zeroizing::new(state.usernames[index].value.clone()));
            }
            let mut username = username.or_else(|| (!update_only).then(Zeroizing::default));
            if update_only && username.as_ref().is_some_and(|name| name.is_empty()) {
                username = None;
            }
            if state.entries.iter().any(|entry| {
                let capture = &entry.capture;
                capture.id == report.id
                    || (capture.tab == tab
                        && capture.origin == origin
                        && capture.username.as_deref()
                            == username.as_ref().map(|value| value.as_str())
                        && capture.password == *password
                        && capture.update_only == update_only)
            }) {
                return Some(());
            }
            state.entries.retain(|entry| entry.capture.tab != tab);
            if state.entries.len() == LIMIT {
                state.entries.remove(0);
            }
            let mut password = password;
            state.entries.push(Entry {
                capture: Rc::new(Candidate {
                    id: report.id,
                    origin,
                    tab,
                    update_only,
                    start: now,
                    username: username.as_mut().map(|name| std::mem::take(&mut **name)),
                    password: std::mem::take(&mut *password),
                }),
                offer: None,
            });
            Some(())
        }

        pub fn next(&self, now: u64) -> Option<Rc<Candidate>> {
            let mut state = self.0.borrow_mut();
            state.expire(now);
            state
                .entries
                .iter()
                .find(|entry| entry.offer.is_none())
                .map(|entry| entry.capture.clone())
        }

        pub fn present(&self, now: u64, candidate: &Rc<Candidate>) -> bool {
            candidate.remaining(now).is_some()
                && self
                    .0
                    .borrow()
                    .entries
                    .iter()
                    .any(|entry| Rc::ptr_eq(&entry.capture, candidate))
        }

        pub fn review(&self, candidate: &Rc<Candidate>, offer: Option<OfferKind>) {
            let mut state = self.0.borrow_mut();
            if let Some(index) = state
                .entries
                .iter()
                .position(|e| Rc::ptr_eq(&e.capture, candidate))
            {
                if let Some(offer) = offer {
                    state.entries[index].offer = Some(offer);
                } else {
                    state.entries.remove(index);
                }
            }
        }

        pub fn find(
            &self,
            now: u64,
            tab: Option<u32>,
            id: &str,
        ) -> Option<(Rc<Candidate>, OfferKind)> {
            let mut state = self.0.borrow_mut();
            state.expire(now);
            let entry = state.entries.iter().find(|e| e.matches(tab, id))?;
            Some((entry.capture.clone(), entry.offer.clone()?))
        }

        pub fn dismiss(&self, now: u64, tab: Option<u32>, id: &str) -> bool {
            let mut state = self.0.borrow_mut();
            state.expire(now);
            let Some(index) = state.entries.iter().position(|e| e.matches(tab, id)) else {
                return false;
            };
            state.entries.remove(index);
            true
        }

        pub fn offers(&self, now: u64, tab: Option<u32>) -> Vec<Offer> {
            let mut state = self.0.borrow_mut();
            state.expire(now);
            state
                .entries
                .iter()
                .rev()
                .filter_map(|entry| {
                    let capture = &entry.capture;
                    if tab.is_some_and(|tab| tab != capture.tab) {
                        return None;
                    }
                    Some(Offer {
                        id: capture.id.clone(),
                        origin: capture.origin.clone(),
                        remaining: capture.remaining(now)?,
                        kind: entry.offer.clone()?,
                    })
                })
                .collect()
        }

        pub fn badges(&self, now: u64) -> Vec<u32> {
            let mut state = self.0.borrow_mut();
            state.expire(now);
            state
                .entries
                .iter()
                .filter(|e| e.offer.is_some())
                .map(|e| e.capture.tab)
                .collect()
        }

        pub fn next_expiry(&self, now: u64) -> i32 {
            let mut state = self.0.borrow_mut();
            state.expire(now);
            state
                .entries
                .iter()
                .filter_map(|e| e.capture.remaining(now))
                .chain(
                    state
                        .usernames
                        .iter()
                        .filter_map(|e| remaining(now, e.start)),
                )
                .min()
                .map_or(-1, |ms| ms as i32)
        }
    }

    impl Entry {
        fn matches(&self, tab: Option<u32>, id: &str) -> bool {
            self.capture.id == id && tab.is_none_or(|tab| self.capture.tab == tab)
        }
    }

    impl State {
        fn expire(&mut self, now: u64) {
            self.entries.retain(|e| e.capture.remaining(now).is_some());
            self.usernames.retain(|e| remaining(now, e.start).is_some());
        }

        fn policy(&self, origin: &str) -> SitePolicy {
            if self.enabled {
                self.exceptions.get(origin).copied().unwrap_or_default()
            } else {
                SitePolicy::Disabled
            }
        }
    }

    impl Values {
        fn valid(&self, fields: &CaptureFields) -> bool {
            [
                (fields.username, &self.username),
                (fields.password, &self.password),
                (fields.confirmation, &self.confirmation),
            ]
            .into_iter()
            .all(|(field, value)| match value {
                Some(value) => field.is_some() && value.len() <= MAX_LOGIN_TEXT,
                None => field.is_none(),
            }) && self
                .password
                .as_ref()
                .is_none_or(|password| !password.is_empty())
                && self
                    .confirmation
                    .as_ref()
                    .is_none_or(|confirmation| self.password.as_ref() == Some(confirmation))
        }
    }

    fn remaining(now: u64, start: u64) -> Option<u32> {
        let age = now.checked_sub(start)?;
        (age < TTL).then(|| (TTL - age) as u32)
    }

    fn decode_context(context: &str) -> Option<SenderContext> {
        if context.len() > 2048 {
            return None;
        }
        let context: SenderContext = serde_json::from_str(context).ok()?;
        context.valid().then_some(context)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use confidex_app::browser_logins::CaptureMatches;
    use serde_json::{Value, json};

    const ORIGIN: &str = "https://example.test";

    fn context(tab: u32, origin: &str) -> String {
        json!({"tabId": tab, "frameId": 0, "documentId": "abc", "origin": origin}).to_string()
    }

    fn snapshot(username: bool, roles: &[&str]) -> Value {
        let mut fields = vec![];
        if username {
            fields.push(json!({"id": 2, "kind": "text", "autocomplete": "username", "hint": ""}));
        }
        fields.extend(roles.iter().enumerate().map(
            |(i, role)| json!({"id": i + 3, "kind": "password", "autocomplete": role, "hint": ""}),
        ));
        json!({"page": 1, "forms": [{
            "id": 1, "stamp": 0, "label": "", "destinations": [ORIGIN],
            "submitsWithGet": false, "fields": fields,
        }]})
    }

    fn capture(id: &str) -> Value {
        json!({"version": 1, "id": id, "revision": 1,
            "snapshot": snapshot(true, &["current-password"]),
            "values": {"username": "fixture-user", "password": "fixture-pass", "confirmation": null},
        })
    }

    #[test]
    fn consent_and_live_session_are_required_to_read_fields() {
        let state = Autosave::default();
        let context = context(1, ORIGIN);
        let snapshot = snapshot(true, &["current-password"]).to_string();
        assert!(state.plan(1000, &context, &snapshot).is_none());
        assert!(
            state
                .capture(1, &context, &capture("a").to_string())
                .is_none()
        );
        assert!(state.set_policy(true, "{}"));
        assert!(state.plan(0, &context, &snapshot).is_none());
        let plan = serde_json::to_value(state.plan(1000, &context, &snapshot).unwrap()).unwrap();
        assert_eq!(
            plan,
            json!({"remaining":1000,"revision":1,"fields":[{
                "form":1,"username":2,"password":3,"confirmation":null
            }]})
        );
        let exclusions = json!({ORIGIN: "NoSave"}).to_string();
        assert!(state.set_policy(true, &exclusions));
        assert!(state.policy(ORIGIN) == SitePolicy::NoSave);
        assert!(state.plan(1000, &context, &snapshot).is_none());
        assert!(state.set_policy(true, "{}"));
        assert!(
            state
                .capture(1, &context, &capture("a").to_string())
                .is_none(),
            "stale permit"
        );
    }

    #[test]
    fn candidates_expire_replace_and_disappear_on_tab_close() {
        let state = Autosave::default();
        state.set_policy(true, "{}");
        for tab in 1..=11 {
            let id = format!("{tab:x}");
            assert!(
                state
                    .capture(10, &context(tab, ORIGIN), &capture(&id).to_string())
                    .is_some()
            );
        }
        assert_eq!(state.next(10).unwrap().id, "2");
        let mut replacement = capture("c");
        replacement["values"]["password"] = json!("replaced");
        let context = context(2, ORIGIN);
        state
            .capture(20, &context, &replacement.to_string())
            .unwrap();
        assert_eq!(state.next(20).unwrap().id, "3");
        state.close_tab(3);
        assert_eq!(state.next(20).unwrap().id, "4");
        state.navigate(2, Some("https://different.test"));
        assert_eq!(state.next_expiry(20), TTL as i32 - 10);
        let last = state.next(10 + TTL).unwrap();
        assert_eq!(last.id, "c");
        assert!(state.present(19 + TTL, &last));
        assert!(!state.present(20 + TTL, &last));
        assert!(state.next(20 + TTL).is_none());
        assert_eq!(state.next_expiry(20 + TTL), -1);
    }

    #[test]
    fn username_first_and_deduplication_use_the_original_tab_and_origin() {
        let state = Autosave::default();
        state.set_policy(true, "{}");
        let context = context(3, ORIGIN);
        let mut first = capture("a");
        first["snapshot"] = snapshot(true, &[]);
        first["values"]["password"] = Value::Null;
        state.capture(1, &context, &first.to_string()).unwrap();
        let mut second = capture("b");
        second["snapshot"] = snapshot(false, &["current-password"]);
        second["values"]["username"] = Value::Null;
        state.capture(2, &context, &second.to_string()).unwrap();
        let candidate = state.next(2).unwrap();
        assert_eq!(candidate.username.as_deref(), Some("fixture-user"));
        let offer = candidate.offer(CaptureMatches::default()).unwrap();
        state.review(&candidate, Some(offer));
        assert_eq!(state.badges(2), [3]);
        second["id"] = json!("c");
        state.capture(3, &context, &second.to_string()).unwrap();
        assert!(state.find(3, Some(4), "b").is_none());
        assert_eq!(state.offers(3, Some(3))[0].remaining, TTL as u32 - 1);
        assert!(!state.dismiss(3, Some(4), "b"));
        assert!(state.dismiss(3, Some(3), "b"));
        assert!(!state.dismiss(3, Some(3), "b"));

        state.navigate(3, Some("https://different.test"));
        state.capture(4, &context, &second.to_string()).unwrap();
        assert_eq!(state.next(4).unwrap().username.as_deref(), Some(""));
    }

    #[test]
    fn offered_metadata_omits_passwords_and_confirmation_is_mandatory() {
        let state = Autosave::default();
        state.set_policy(true, "{}");
        let context = context(4, ORIGIN);
        let mut packet = capture("ab");
        packet["snapshot"] = snapshot(true, &["new-password", "new-password"]);
        for confirmation in [Value::Null, json!("mismatch")] {
            packet["values"]["confirmation"] = confirmation;
            assert!(state.capture(1, &context, &packet.to_string()).is_none());
        }
        packet["values"]["confirmation"] = packet["values"]["password"].clone();
        let mut forged = packet.clone();
        forged["origin"] = json!("https://wrong.test");
        assert!(state.capture(1, &context, &forged.to_string()).is_none());
        forged = packet.clone();
        forged["values"]["password"] = json!("ß".repeat(3000));
        assert!(state.capture(1, &context, &forged.to_string()).is_none());
        let subframe = context.replace(r#""frameId":0"#, r#""frameId":1"#);
        assert!(state.capture(1, &subframe, &packet.to_string()).is_none());
        state.capture(1, &context, &packet.to_string()).unwrap();
        let candidate = state.next(1).unwrap();
        let mut matches = CaptureMatches {
            duplicate: true,
            ..Default::default()
        };
        assert!(candidate.offer(matches).is_none());
        matches = CaptureMatches::default();
        state.review(&candidate, candidate.offer(matches));
        let offer = serde_json::to_string(&state.offers(1, None)).unwrap();
        assert!(offer.contains("fixture-user"));
        assert!(!offer.contains("fixture-pass"));
        assert!(state.set_policy(false, "{}"));
        assert!(state.offers(1, None).is_empty());

        let request: SaveRequest = serde_json::from_value(json!({
            "version": 2, "tab": null, "action": {"Dismiss": {"id": "ab"}},
        }))
        .unwrap();
        assert!(!request.valid());
    }
}
