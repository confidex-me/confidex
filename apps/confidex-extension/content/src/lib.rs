#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
use wasm_bindgen::prelude::*;

// The bootstrap smoke test supplies the isolated world's document.
#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
#[wasm_bindgen]
pub fn has_password_field(document: &web_sys::Document) -> Result<bool, JsValue> {
    document
        .query_selector("input[type=password]")
        .map(|input| input.is_some())
}

use serde::{Deserialize, Serialize};
use std::collections::HashSet;

pub const MAX_FORMS: usize = 24;
pub const MAX_FIELDS: usize = 32;

#[derive(Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Snapshot {
    pub page: u32,
    pub forms: Vec<Form>,
}

#[derive(Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Form {
    pub id: u32,
    stamp: u32,
    label: String,
    destinations: Vec<String>,
    submits_with_get: bool,
    fields: Vec<Field>,
}

#[derive(Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Field {
    id: u32,
    kind: Kind,
    autocomplete: String,
    hint: String,
}

#[derive(Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
enum Kind {
    Text,
    Email,
    Tel,
    Password,
}

#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct Target {
    pub form: u32,
    pub username: Option<u32>,
    pub password: Option<u32>,
}

#[derive(Deserialize, Serialize)]
pub struct Choice {
    pub target: Target,
    pub label: String,
}

#[derive(Serialize)]
pub struct CaptureFields {
    pub form: u32,
    pub username: Option<u32>,
    pub password: Option<u32>,
    pub confirmation: Option<u32>,
    #[serde(skip)]
    pub update_only: bool,
    #[serde(skip)]
    pub new_password: bool,
}

impl Snapshot {
    pub fn valid(&self) -> bool {
        let mut groups = HashSet::new();
        let mut inputs = HashSet::new();
        self.page > 0
            && self.forms.len() <= MAX_FORMS
            && self.forms.iter().all(|form| {
                form.id > 0
                    && groups.insert(form.id)
                    && form.label.len() <= 512
                    && !form.destinations.is_empty()
                    && form.destinations.len() <= 16
                    && form.destinations.iter().all(|origin| origin.len() <= 1024)
                    && form.fields.len() <= MAX_FIELDS
                    && form.fields.iter().all(|field| {
                        field.id > 0
                            && inputs.insert(field.id)
                            && field.autocomplete.len() <= 128
                            && field.hint.len() <= 512
                    })
            })
    }

    pub fn choices(&self, origin: &str) -> Vec<Choice> {
        self.forms
            .iter()
            .filter_map(|form| form.choice(origin))
            .collect()
    }

    pub fn same_form(&self, fresh: &Self, form: u32) -> bool {
        self.page == fresh.page
            && self
                .forms
                .iter()
                .find(|f| f.id == form)
                .is_some_and(|previous| fresh.forms.contains(previous))
    }
}

impl Form {
    pub fn capture_fields(&self, origin: &str) -> Option<CaptureFields> {
        if !self
            .destinations
            .iter()
            .all(|destination| destination == origin)
        {
            return None;
        }
        let username = self.username().ok()?;
        let (mut current, mut new, mut confirmation) = (None, None, None);
        for field in self
            .fields
            .iter()
            .filter(|field| field.kind == Kind::Password)
        {
            match field.token() {
                "new-password" | "" | "on" | "off" if field.confirmation_hint() => {
                    if confirmation.replace(field.id).is_some() {
                        return None;
                    }
                }
                "new-password" | "" | "on" | "off"
                    if field.token() == "new-password" || field.new_password_hint() =>
                {
                    if new.is_none() {
                        new = Some(field.id);
                    } else if confirmation.replace(field.id).is_some() {
                        return None;
                    }
                }
                "current-password" | "" | "on" | "off" => {
                    if current.replace(field).is_some() {
                        return None;
                    }
                }
                _ => return None,
            }
        }
        // A generic password followed by a field explicitly labeled as confirmation
        // represents a new password. An explicitly current password never does.
        if new.is_none() && confirmation.is_some() {
            let field = current.take()?;
            if field.token() == "current-password" || field.current_password_hint() {
                return None;
            }
            new = Some(field.id);
        }
        if new.is_some()
            && current.is_some_and(|field| {
                field.token() != "current-password" && !field.current_password_hint()
            })
        {
            return None;
        }
        let password = new.or_else(|| current.map(|field| field.id));
        if password.is_some() && self.submits_with_get
            || password.is_none() && username.is_none_or(|field| field.username_rank() < 2)
        {
            return None;
        }
        Some(CaptureFields {
            form: self.id,
            username: username.map(|field| field.id),
            password,
            confirmation,
            update_only: new.is_some() && (current.is_some() || username.is_none()),
            new_password: new.is_some(),
        })
    }

    fn username(&self) -> Result<Option<&Field>, ()> {
        let (mut selected, mut rank, mut ambiguous) = (None, 0, false);
        for field in self
            .fields
            .iter()
            .filter(|field| field.kind != Kind::Password)
        {
            let score = field.username_rank();
            if score > rank {
                (selected, rank, ambiguous) = (Some(field), score, false);
            } else if score > 0 && score == rank {
                ambiguous = true;
            }
        }
        if ambiguous { Err(()) } else { Ok(selected) }
    }

    fn choice(&self, origin: &str) -> Option<Choice> {
        if !self
            .destinations
            .iter()
            .all(|destination| destination == origin)
        {
            return None;
        }
        let mut password = None;
        let mut has_masked_field = false;
        for field in &self.fields {
            if field.kind == Kind::Password {
                has_masked_field = true;
                match field.token() {
                    "new-password" => return None,
                    "current-password" | "" | "on" | "off" => {
                        if field.new_password_hint() || password.replace(field.id).is_some() {
                            return None;
                        }
                    }
                    _ => (),
                }
            }
        }
        let username = self.username().ok()?;
        // A username-first form must have no visible masked field.
        if match password {
            Some(_) => self.submits_with_get,
            None => has_masked_field || username.is_none_or(|field| field.username_rank() < 2),
        } {
            return None;
        }
        Some(Choice {
            target: Target {
                form: self.id,
                username: username.map(|field| field.id),
                password,
            },
            label: self
                .label
                .chars()
                .filter(|c| !c.is_control())
                .take(80)
                .collect(),
        })
    }
}

impl Field {
    fn token(&self) -> &str {
        let mut tokens = self.autocomplete.split_ascii_whitespace();
        match tokens.next_back() {
            Some("webauthn") => tokens.next_back().unwrap_or("webauthn"),
            Some(token) => token,
            None => "",
        }
    }

    fn hint_contains(&self, patterns: &[&str]) -> bool {
        let hint: String = self
            .hint
            .chars()
            .filter(|c| c.is_alphanumeric())
            .flat_map(char::to_lowercase)
            .collect();
        patterns.iter().any(|pattern| hint.contains(pattern))
    }

    fn new_password_hint(&self) -> bool {
        self.confirmation_hint() || self.hint_contains(&["newpass", "passwordnew", "новыйпароль"])
    }

    fn confirmation_hint(&self) -> bool {
        self.hint
            .split(|character: char| !character.is_alphanumeric())
            .any(|word| {
                ["confirm", "repeat", "retype", "подтвердите", "повторите"]
                    .iter()
                    .any(|hint| word.eq_ignore_ascii_case(hint))
            })
            || self.hint_contains(&[
                "confirmpass",
                "passwordconfirm",
                "repeatpass",
                "passwordrepeat",
                "verifypass",
                "retypepass",
                "повторитепароль",
            ])
    }

    fn current_password_hint(&self) -> bool {
        self.hint_contains(&["oldpass", "currentpass", "старыйпароль", "текущийпароль"])
    }

    fn username_rank(&self) -> u8 {
        match self.token() {
            "username" => return 3,
            "email" => return 2,
            "" | "on" | "off" => (),
            _ => return 0,
        }
        let hint = self.hint.to_lowercase();
        if self.kind == Kind::Email
            || [
                "user",
                "login",
                "email",
                "e-mail",
                "identifier",
                "логин",
                "почта",
            ]
            .iter()
            .any(|pattern| hint.contains(pattern))
        {
            2
        } else if self.kind == Kind::Text && hint.trim().is_empty() {
            1
        } else {
            0
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ORIGIN: &str = "https://example.test";

    fn form(method_is_get: bool, fields: &[(Kind, &str)]) -> Form {
        Form {
            id: 1,
            stamp: 0,
            label: String::new(),
            destinations: vec![ORIGIN.into()],
            submits_with_get: method_is_get,
            fields: fields
                .iter()
                .enumerate()
                .map(|(index, (kind, autocomplete))| Field {
                    id: index as u32 + 2,
                    kind: *kind,
                    autocomplete: (*autocomplete).into(),
                    hint: String::new(),
                })
                .collect(),
        }
    }

    #[test]
    fn masked_explicit_non_login_roles_are_never_password_candidates() {
        for role in [
            "cc-csc",
            "section-checkout billing cc-csc",
            "one-time-code",
            "webauthn",
            "unknown",
        ] {
            assert!(
                form(false, &[(Kind::Password, role)])
                    .choice(ORIGIN)
                    .is_none()
            );
            assert!(
                form(false, &[(Kind::Email, "username"), (Kind::Password, role)])
                    .choice(ORIGIN)
                    .is_none()
            );
        }
        let mixed = form(
            false,
            &[
                (Kind::Password, "cc-csc"),
                (Kind::Password, "section-login current-password webauthn"),
            ],
        );
        assert_eq!(mixed.choice(ORIGIN).unwrap().target.password, Some(3));
        for role in ["", "on", "off"] {
            assert_eq!(
                form(false, &[(Kind::Password, role)])
                    .choice(ORIGIN)
                    .unwrap()
                    .target
                    .password,
                Some(2)
            );
        }
    }

    #[test]
    fn get_blocks_password_fill_but_preserves_a_username_only_first_step() {
        let login = [
            (Kind::Email, "username"),
            (Kind::Password, "current-password"),
        ];
        assert!(form(true, &login).choice(ORIGIN).is_none());
        assert_eq!(
            form(false, &login).choice(ORIGIN).unwrap().target.password,
            Some(3)
        );
        let first_step = form(true, &login[..1]).choice(ORIGIN).unwrap().target;
        assert_eq!(first_step.username, Some(2));
        assert_eq!(first_step.password, None);
    }
    #[test]
    fn capture_identifies_registration_and_change_without_reading_the_old_password() {
        let fields = [
            (Kind::Email, "username"),
            (Kind::Password, "current-password"),
            (Kind::Password, "new-password"),
            (Kind::Password, "new-password"),
        ];
        let change = form(false, &fields).capture_fields(ORIGIN).unwrap();
        assert!(change.update_only);
        assert_eq!(
            (change.username, change.password, change.confirmation),
            (Some(2), Some(4), Some(5))
        );
        let registration = form(false, &[fields[0], fields[2], fields[3]]);
        let plan = registration.capture_fields(ORIGIN).unwrap();
        assert!(!plan.update_only);
        assert!(plan.new_password);
        assert_eq!((plan.password, plan.confirmation), (Some(3), Some(4)));
        assert!(
            registration
                .capture_fields("https://foreign.test")
                .is_none()
        );
        assert!(form(true, &fields).capture_fields(ORIGIN).is_none());
        assert!(
            form(false, &[fields[0], fields[2], fields[2], fields[2]])
                .capture_fields(ORIGIN)
                .is_none()
        );
        assert!(
            form(false, &[fields[1], fields[1]])
                .capture_fields(ORIGIN)
                .is_none()
        );
        assert!(
            form(false, &[(Kind::Password, "one-time-code")])
                .capture_fields(ORIGIN)
                .is_none()
        );
        assert!(
            form(false, &[fields[0], fields[0], fields[1]])
                .capture_fields(ORIGIN)
                .is_none()
        );
    }
}
