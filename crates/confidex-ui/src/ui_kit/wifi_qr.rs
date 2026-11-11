//! A Wi-Fi QR field resolves values from the current record.
use super::Metrics as M;
use crate::theme::Palette;
use confidex_vault::{
    record::ValueError,
    wifi::{Auth, Credentials, QUIET_ZONE, Qr},
};
use eframe::egui::{self, Id, Rect, Response, Vec2};
use zeroize::Zeroizing;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Text,
    Password,
    Other,
}
pub struct Source<'a> {
    pub id: u64,
    pub name: &'a str,
    pub kind: Kind,
    pub value: &'a str,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Links {
    pub ssid: Option<u64>,
    pub password: Option<u64>,
    pub auth: Auth,
}
impl Default for Links {
    fn default() -> Self {
        Self {
            ssid: None,
            password: None,
            auth: Auth::Wpa,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    MissingSsid,
    MissingPassword,
    Ssid,
    ShortPassword,
    Password,
    Encoding,
}
impl Error {
    pub fn key(self) -> &'static str {
        match self {
            Self::MissingSsid => "missing-ssid",
            Self::MissingPassword => "missing-password",
            Self::Ssid => "ssid",
            Self::ShortPassword => "short-password",
            Self::Password => "password",
            Self::Encoding => "encoding",
        }
    }
    fn index(self) -> usize {
        self as usize
    }
}
pub struct Labels<'a> {
    pub ssid: &'a str,
    pub password: &'a str,
    pub auth: &'a str,
    pub auths: [&'a str; 3],
    pub choose_text: &'a str,
    pub choose_password: &'a str,
    pub unnamed: &'a str,
    pub errors: [&'a str; 6],
}
pub struct Field<'a> {
    pub id: Id,
    pub links: &'a mut Links,
    pub sources: &'a [Source<'a>],
    pub editing: bool,
    pub labels: Labels<'a>,
}
#[derive(Default)]
pub struct State {
    qr: Option<Qr>,
    ssid: Zeroizing<String>,
    password: Zeroizing<String>,
    auth: Option<Auth>,
}
pub struct Output {
    pub controls: Vec<(String, Response)>,
    pub qr: Option<Rect>,
    pub error: Option<(Error, Rect)>,
}
struct Values<'a> {
    ssid: &'a str,
    password: &'a str,
}
pub fn validate(links: &Links, sources: &[Source<'_>]) -> Result<(), Error> {
    resolve(links, sources).map(|_| ())
}
fn resolve<'a>(links: &Links, sources: &'a [Source<'a>]) -> Result<Option<Values<'a>>, Error> {
    let find = |id, kind| {
        sources
            .iter()
            .find(|s| Some(s.id) == id && s.kind == kind)
            .map(|s| s.value)
    };
    let ssid = find(links.ssid, Kind::Text);
    let password = if links.auth == Auth::Open {
        Some("")
    } else {
        find(links.password, Kind::Password)
    };
    // Empty starter fields are optional; partially entered credentials still need validation.
    if links.ssid.is_none() && links.password.is_none() || ssid == Some("") && password == Some("")
    {
        return Ok(None);
    }
    let ssid = ssid.ok_or(Error::MissingSsid)?;
    let password = password.ok_or(Error::MissingPassword)?;
    if links.auth == Auth::Wpa && password.len() < 8 {
        return Err(Error::ShortPassword);
    }
    Credentials::new(ssid, links.auth, Some(password), false).map_err(|error| match error {
        ValueError::InvalidValue("ssid") => Error::Ssid,
        _ => Error::Password,
    })?;
    Ok(Some(Values { ssid, password }))
}
impl State {
    fn clear(&mut self) {
        *self = Self::default();
    }
    pub fn show(&mut self, ui: &mut egui::Ui, p: Palette, mut field: Field<'_>) -> Output {
        let mut output = Output {
            controls: Vec::new(),
            qr: None,
            error: None,
        };
        if field.editing {
            self.clear();
            select(ui, &mut field, Kind::Text, &mut output.controls);
            ui.add_space(M::SM);
            select(ui, &mut field, Kind::Password, &mut output.controls);
            ui.add_space(M::SM);
            ui.label(field.labels.auth);
            let mut index = match field.links.auth {
                Auth::Open => 0,
                Auth::Wep => 1,
                Auth::Wpa => 2,
            };
            let response = super::Select::from_id_salt(field.id.with("auth"))
                .selected_text(field.labels.auths[index])
                .width(ui.available_width())
                .show_ui(ui, |ui| {
                    for (i, name) in field.labels.auths.iter().enumerate() {
                        let response = ui.selectable_value(&mut index, i, *name);
                        output.controls.push((format!("auth-{i}"), response));
                    }
                });
            output.controls.push(("auth".into(), response.response));
            field.links.auth = [Auth::Open, Auth::Wep, Auth::Wpa][index];
        }
        let result = resolve(field.links, field.sources).and_then(|values| {
            let Some(values) = values else {
                self.clear();
                return Ok(());
            };
            if field.editing {
                return Ok(());
            }
            if self.qr.is_none()
                || self.ssid.as_str() != values.ssid
                || self.password.as_str() != values.password
                || self.auth != Some(field.links.auth)
            {
                self.clear();
                let credentials =
                    Credentials::new(values.ssid, field.links.auth, Some(values.password), false)
                        .map_err(|_| Error::Password)?;
                self.qr = Some(credentials.qr().map_err(|_| Error::Encoding)?);
                self.ssid.push_str(values.ssid);
                self.password.push_str(values.password);
                self.auth = Some(field.links.auth);
            }
            Ok(())
        });
        if let Err(error) = result {
            self.clear();
            let response =
                ui.label(egui::RichText::new(field.labels.errors[error.index()]).color(p.error));
            output.error = Some((error, response.rect));
        } else if let Some(qr) = &self.qr {
            output.qr = Some(paint(ui, qr));
        }
        output
    }
}
fn select(
    ui: &mut egui::Ui,
    field: &mut Field<'_>,
    kind: Kind,
    controls: &mut Vec<(String, Response)>,
) {
    let sources = field.sources;
    let unnamed = field.labels.unnamed;
    let enabled = kind != Kind::Password || field.links.auth != Auth::Open;
    let (selected, label, placeholder, key) = match kind {
        Kind::Text => (
            &mut field.links.ssid,
            field.labels.ssid,
            field.labels.choose_text,
            "ssid",
        ),
        Kind::Password => (
            &mut field.links.password,
            field.labels.password,
            field.labels.choose_password,
            "password",
        ),
        Kind::Other => return,
    };
    let id = field.id.with(key);
    ui.label(label);
    let name = |source: &Source<'_>, position| {
        let name = if source.name.is_empty() {
            unnamed
        } else {
            source.name
        };
        if source.name.is_empty()
            || sources
                .iter()
                .filter(|s| s.kind == kind && s.name == source.name)
                .count()
                > 1
        {
            format!("{name} · {}", position + 1)
        } else {
            name.into()
        }
    };
    let current = sources
        .iter()
        .enumerate()
        .find(|(_, s)| Some(s.id) == *selected && s.kind == kind)
        .map(|(i, s)| name(s, i))
        .unwrap_or_else(|| placeholder.into());
    let response = ui
        .add_enabled_ui(enabled, |ui| {
            super::Select::from_id_salt(id)
                .selected_text(current)
                .width(ui.available_width())
                .show_ui(ui, |ui| {
                    for (position, source) in
                        sources.iter().enumerate().filter(|(_, s)| s.kind == kind)
                    {
                        let response =
                            ui.selectable_value(selected, Some(source.id), name(source, position));
                        controls.push((format!("{key}-{}", source.id), response));
                    }
                })
        })
        .inner;
    controls.push((key.into(), response.response));
}
fn paint(ui: &mut egui::Ui, qr: &Qr) -> Rect {
    let cells = qr.size() + 2 * QUIET_ZONE;
    let ppp = ui.ctx().pixels_per_point();
    let unit = ((ui.available_width().clamp(1., 320.) * ppp / cells as f32)
        .floor()
        .max(1.))
        / ppp;
    ui.vertical_centered(|ui| {
        let (rect, _) =
            ui.allocate_exact_size(Vec2::splat(unit * cells as f32), egui::Sense::hover());
        let origin = egui::pos2(
            (rect.left() * ppp).round() / ppp,
            (rect.top() * ppp).round() / ppp,
        );
        let rect = Rect::from_min_size(origin, rect.size());
        ui.painter().rect_filled(rect, 0., egui::Color32::WHITE);
        for y in 0..qr.size() {
            for x in 0..qr.size() {
                if qr.dark(x, y) {
                    let min = origin
                        + egui::vec2(
                            (x + QUIET_ZONE) as f32 * unit,
                            (y + QUIET_ZONE) as f32 * unit,
                        );
                    ui.painter().rect_filled(
                        Rect::from_min_size(min, Vec2::splat(unit)),
                        0.,
                        egui::Color32::BLACK,
                    );
                }
            }
        }
        rect
    })
    .inner
}

#[cfg(test)]
mod tests {
    use super::*;
    fn sources() -> [Source<'static>; 4] {
        [
            Source {
                id: 10,
                name: "Network",
                kind: Kind::Text,
                value: "Guest; café",
            },
            Source {
                id: 20,
                name: "Password",
                kind: Kind::Password,
                value: "public-demo-password",
            },
            Source {
                id: 30,
                name: "Password",
                kind: Kind::Text,
                value: "not-a-password-source",
            },
            Source {
                id: 40,
                name: "Network",
                kind: Kind::Text,
                value: "Other network",
            },
        ]
    }
    #[test]
    fn an_empty_optional_starter_has_no_qr_but_partial_credentials_need_correction() {
        let mut sources = sources();
        let links = Links {
            ssid: Some(10),
            password: Some(20),
            auth: Auth::Wpa,
        };
        sources[0].value = "";
        sources[1].value = "";
        assert!(resolve(&links, &sources).unwrap().is_none());
        assert!(validate(&Links::default(), &[]).is_ok());
        sources[1].value = "public-password";
        assert!(matches!(validate(&links, &sources), Err(Error::Ssid)));
        sources[0].value = "Public network";
        sources[1].value = "";
        assert!(matches!(
            validate(&links, &sources),
            Err(Error::ShortPassword)
        ));
    }
    #[test]
    fn references_follow_the_selected_fields_not_their_names_or_positions() {
        let mut sources = sources();
        let links = Links {
            ssid: Some(10),
            password: Some(20),
            auth: Auth::Wpa,
        };
        sources.swap(0, 3);
        sources[3].name = "Renamed";
        let values = resolve(&links, &sources).unwrap().unwrap();
        assert_eq!(values.ssid, "Guest; café");
        assert_eq!(values.password, "public-demo-password");
        let payload = Credentials::new(values.ssid, links.auth, Some(values.password), false)
            .unwrap()
            .payload()
            .unwrap();
        assert!(payload.contains("S:Guest\\; café;"));
        assert!(payload.contains("P:public-demo-password;"));
        assert!(matches!(
            resolve(&links, &sources[..1]),
            Err(Error::MissingSsid)
        ));
        let wrong_type = Links {
            password: Some(30),
            ..links
        };
        assert!(matches!(
            resolve(&wrong_type, &sources),
            Err(Error::MissingPassword)
        ));
    }
    #[test]
    fn short_password_is_an_error_and_open_network_does_not_use_a_password() {
        let mut sources = sources();
        sources[1].value = "short";
        let mut links = Links {
            ssid: Some(10),
            password: Some(20),
            auth: Auth::Wpa,
        };
        assert!(matches!(
            resolve(&links, &sources),
            Err(Error::ShortPassword)
        ));
        links.auth = Auth::Open;
        links.password = None;
        assert_eq!(resolve(&links, &sources).unwrap().unwrap().password, "");
        links.ssid = Some(20);
        assert!(matches!(resolve(&links, &sources), Err(Error::MissingSsid)));
    }
    fn labels() -> Labels<'static> {
        Labels {
            ssid: "SSID field",
            password: "Password field",
            auth: "Security",
            auths: ["Open", "WEP", "WPA2"],
            choose_text: "Choose text",
            choose_password: "Choose password",
            unnamed: "Unnamed",
            errors: [
                "ssid reference",
                "password reference",
                "ssid",
                "short password",
                "password",
                "encoding",
            ],
        }
    }
    #[test]
    fn inline_qr_is_bounded_and_invalid_inputs_drop_the_old_qr() {
        for width in [180., 390., 720.] {
            let ctx = egui::Context::default();
            super::super::setup(&ctx);
            let mut state = State::default();
            let mut sources = sources();
            let mut links = Links {
                ssid: Some(10),
                password: Some(20),
                auth: Auth::Wpa,
            };
            for _ in 0..2 {
                let mut output = ctx.run_ui(
                    egui::RawInput {
                        screen_rect: Some(Rect::from_min_size(
                            egui::Pos2::ZERO,
                            Vec2::new(width, 700.),
                        )),
                        ..Default::default()
                    },
                    |root| {
                        egui::CentralPanel::default().show(root, |ui| {
                            let output = state.show(
                                ui,
                                crate::theme::THEMES[0].colors,
                                Field {
                                    id: Id::unique("test-qr"),
                                    links: &mut links,
                                    sources: &sources,
                                    editing: false,
                                    labels: labels(),
                                },
                            );
                            assert!(output.error.is_none());
                            assert!(ui.max_rect().expand(1.).contains_rect(output.qr.unwrap()));
                        });
                    },
                );
                output.textures_delta.clear();
            }
            assert!(state.qr.is_some());
            sources[1].value = "short";
            let mut output = ctx.run_ui(Default::default(), |root| {
                egui::CentralPanel::default().show(root, |ui| {
                    let output = state.show(
                        ui,
                        crate::theme::THEMES[0].colors,
                        Field {
                            id: Id::unique("test-qr"),
                            links: &mut links,
                            sources: &sources,
                            editing: false,
                            labels: labels(),
                        },
                    );
                    assert_eq!(output.error.unwrap().0, Error::ShortPassword);
                    assert!(output.qr.is_none());
                });
            });
            output.textures_delta.clear();
            assert!(state.qr.is_none());
            assert!(state.password.is_empty());
        }
    }
}
