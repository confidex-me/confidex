//! Location entry is local and does not use a map or device position.
use super::value;
use crate::theme::Palette;
use eframe::egui::{self, Id, Rect};
use std::collections::BTreeMap;
use zeroize::Zeroize;

#[derive(Clone, Default, PartialEq)]
pub struct Editor {
    pub name: String,
    pub latitude: String,
    pub longitude: String,
}
pub use confidex_vault::location::Invalid;
impl Drop for Editor {
    fn drop(&mut self) {
        self.name.zeroize();
        self.latitude.zeroize();
        self.longitude.zeroize();
    }
}
impl Editor {
    pub fn coordinates(&self) -> Result<Option<(f64, f64)>, Invalid> {
        confidex_vault::location::parse(&self.latitude, &self.longitude)
    }
    pub fn show(
        &mut self,
        ui: &mut egui::Ui,
        p: Palette,
        id: Id,
        editing: bool,
        labels: Labels<'_>,
    ) -> Output {
        let mut hits = BTreeMap::new();
        let mut changed = false;
        let mut copied = None;
        for (key, name, value) in [
            ("name", labels.name, &mut self.name),
            ("latitude", labels.latitude, &mut self.latitude),
            ("longitude", labels.longitude, &mut self.longitude),
        ] {
            let label = ui.label(name);
            let mut revealed = false;
            let field = value::ValueField {
                id: id.with(key),
                value,
                kind: value::Kind::Text,
                protected: false,
                editing,
                enabled: ui.is_enabled(),
                revealed: &mut revealed,
                feedback: value::CopyState::Idle,
                labels: labels.value,
            }
            .show(ui, p);
            let input = field.input.labelled_by(label.id);
            changed |= input.changed();
            if field.copy.clicked() {
                copied = Some((key, value.clone()));
            }
            hits.insert(key.into(), input.rect);
            hits.insert(format!("copy-{key}"), field.copy.rect);
        }
        let valid = self.coordinates().is_ok();
        if !valid {
            ui.colored_label(p.error, labels.invalid);
        }
        Output {
            valid,
            changed,
            copy: copied,
            hits,
        }
    }
    pub fn text(&self) -> String {
        if self.latitude.is_empty() && self.longitude.is_empty() {
            return self.name.clone();
        }
        let coordinates = format!("{}, {}", self.latitude, self.longitude);
        if self.name.is_empty() {
            coordinates
        } else {
            format!("{}\n{coordinates}", self.name)
        }
    }
}
pub struct Labels<'a> {
    pub name: &'a str,
    pub latitude: &'a str,
    pub longitude: &'a str,
    pub invalid: &'a str,
    pub value: value::Labels<'a>,
}
pub struct Output {
    pub valid: bool,
    pub changed: bool,
    pub copy: Option<(&'static str, String)>,
    pub hits: BTreeMap<String, Rect>,
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn coordinate_pairs_are_optional_finite_and_bounded() {
        let mut point = Editor::default();
        assert_eq!(point.coordinates(), Ok(None));
        for (lat, lon) in [
            ("90", "-180"),
            ("-90", "180"),
            ("52,37", "4.90"),
            ("-0", "0"),
        ] {
            point.latitude = lat.into();
            point.longitude = lon.into();
            assert!(point.coordinates().is_ok());
            assert_eq!(point.latitude, lat);
        }
        for (lat, lon) in [
            ("90.01", "0"),
            ("0", "180.01"),
            ("NaN", "0"),
            ("0", "inf"),
            ("", "1"),
            ("1", ""),
            ("north", "east"),
        ] {
            point.latitude = lat.into();
            point.longitude = lon.into();
            assert!(point.coordinates().is_err(), "{lat}/{lon}");
        }
    }
}
