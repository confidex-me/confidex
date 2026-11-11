use super::*;
use confidex_vault::wifi::Auth;
use design::wifi_qr;

fn links(values: &BTreeMap<String, String>, keys: &[u64]) -> wifi_qr::Links {
    let target = |key| {
        values
            .get(key)
            .and_then(|v| v.parse::<usize>().ok())
            .and_then(|i| keys.get(i))
            .copied()
    };
    wifi_qr::Links {
        ssid: target("ssid"),
        password: target("password"),
        auth: match values.get("auth").map(String::as_str) {
            Some("nopass") => Auth::Open,
            Some("WEP") => Auth::Wep,
            _ => Auth::Wpa,
        },
    }
}
fn sources<'a>(fields: &'a [app::Field], keys: &[u64]) -> Vec<wifi_qr::Source<'a>> {
    fields
        .iter()
        .zip(keys)
        .map(|(field, key)| {
            let (kind, value_key) = match field.type_name.as_str() {
                "text/v1" => (wifi_qr::Kind::Text, "text"),
                "password/v1" => (wifi_qr::Kind::Password, "password"),
                _ => (wifi_qr::Kind::Other, ""),
            };
            wifi_qr::Source {
                id: *key,
                name: &field.name,
                kind,
                value: field
                    .values
                    .get(value_key)
                    .map(String::as_str)
                    .unwrap_or(""),
            }
        })
        .collect()
}
pub(super) fn problem(
    field: &app::Field,
    fields: &[app::Field],
    keys: &[u64],
) -> Option<&'static str> {
    if field.type_name != "wifi-qr/v1" {
        return None;
    }
    wifi_qr::validate(&links(&field.values, keys), &sources(fields, keys))
        .err()
        .map(|error| match error {
            wifi_qr::Error::MissingSsid => "gallery-wifi-missing-ssid",
            wifi_qr::Error::MissingPassword => "gallery-wifi-missing-password",
            wifi_qr::Error::Ssid => "gallery-wifi-invalid-ssid",
            wifi_qr::Error::ShortPassword => "gallery-wifi-short-password",
            wifi_qr::Error::Password => "gallery-wifi-invalid-password",
            wifi_qr::Error::Encoding => "gallery-wifi-failed",
        })
}

impl VaultApp {
    pub(super) fn wifi_field(
        &mut self,
        ui: &mut egui::Ui,
        id: egui::Id,
        values: &mut BTreeMap<String, String>,
        fields: &[app::Field],
        keys: &[u64],
        editing: bool,
    ) {
        let labels = [
            "gallery-wifi-ssid-field",
            "gallery-wifi-password-field",
            "gallery-wifi-auth",
            "gallery-wifi-open",
            "gallery-wifi-wep",
            "gallery-wifi-wpa",
            "gallery-wifi-choose-text",
            "gallery-wifi-choose-password",
            "gallery-wifi-unnamed",
            "gallery-wifi-missing-ssid",
            "gallery-wifi-missing-password",
            "gallery-wifi-invalid-ssid",
            "gallery-wifi-short-password",
            "gallery-wifi-invalid-password",
            "gallery-wifi-failed",
        ]
        .map(|key| self.locale.text(key));
        let mut links = links(values, keys);
        let sources = sources(fields, keys);
        let output = self.wifi_fields.entry(id.value()).or_default().show(
            ui,
            THEMES[self.theme].colors,
            wifi_qr::Field {
                id,
                links: &mut links,
                sources: &sources,
                editing,
                labels: wifi_qr::Labels {
                    ssid: &labels[0],
                    password: &labels[1],
                    auth: &labels[2],
                    auths: [&labels[3], &labels[4], &labels[5]],
                    choose_text: &labels[6],
                    choose_password: &labels[7],
                    unnamed: &labels[8],
                    errors: std::array::from_fn(|i| labels[i + 9].as_str()),
                },
            },
        );
        if editing {
            for (name, key) in [("ssid", links.ssid), ("password", links.password)] {
                let position = key.and_then(|key| keys.iter().position(|id| *id == key));
                values.insert(
                    name.into(),
                    position.map(|i| i.to_string()).unwrap_or_default(),
                );
            }
            values.insert(
                "auth".into(),
                match links.auth {
                    Auth::Open => "nopass",
                    Auth::Wep => "WEP",
                    Auth::Wpa => "WPA",
                }
                .into(),
            );
        }
        for (name, response) in output.controls {
            self.hits
                .insert(format!("wifi-{}-{name}", id.value()), response.rect);
        }
        if let Some(rect) = output.qr {
            self.bounds
                .insert(format!("wifi-{}-code", id.value()), rect);
        }
        if let Some((error, rect)) = output.error {
            self.bounds
                .insert(format!("wifi-{}-error-{}", id.value(), error.key()), rect);
        }
    }
}
