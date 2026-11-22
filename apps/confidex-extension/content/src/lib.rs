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
        let mut username = None;
        let mut score = 0;
        let mut ambiguous = false;
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
            } else {
                let rank = field.username_rank();
                if rank > score {
                    username = Some(field.id);
                    score = rank;
                    ambiguous = false;
                } else if rank > 0 && rank == score {
                    ambiguous = true;
                }
            }
        }
        // A username-first form must have no visible masked field.
        if ambiguous
            || match password {
                Some(_) => self.submits_with_get,
                None => has_masked_field || score < 2,
            }
        {
            return None;
        }
        Some(Choice {
            target: Target {
                form: self.id,
                username,
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

    fn new_password_hint(&self) -> bool {
        let hint: String = self
            .hint
            .chars()
            .filter(|c| c.is_alphanumeric())
            .flat_map(char::to_lowercase)
            .collect();
        [
            "newpass",
            "confirmpass",
            "passwordconfirm",
            "repeatpass",
            "passwordrepeat",
            "passwordnew",
            "verifypass",
            "retypepass",
            "новыйпароль",
            "повторитепароль",
        ]
        .iter()
        .any(|pattern| hint.contains(pattern))
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
}
