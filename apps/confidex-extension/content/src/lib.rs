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
#[serde(deny_unknown_fields)]
pub struct Form {
    pub id: u32,
    stamp: u32,
    label: String,
    destinations: Vec<String>,
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
        let mut new_password = false;
        let mut username = None;
        let mut score = 0;
        let mut ambiguous = false;
        for field in &self.fields {
            if field.kind == Kind::Password {
                if field.token() == "new-password" || field.new_password_hint() {
                    new_password = true;
                } else if field.token() == "one-time-code" || password.replace(field.id).is_some() {
                    return None;
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
        // A sign-up or password-change form is outside the login flow.
        if new_password || ambiguous || (password.is_none() && score < 2) {
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
        self.autocomplete
            .split_ascii_whitespace()
            .filter(|part| *part != "webauthn")
            .next_back()
            .unwrap_or("")
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
