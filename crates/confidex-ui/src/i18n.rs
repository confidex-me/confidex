//! Message resources and fallback are shared by both hosts.
use fluent_bundle::{FluentArgs, FluentBundle, FluentResource};

const LOCALES: &[(&str, &str)] = &[
    ("en-US", include_str!("../locales/en-US.ftl")),
    ("ru", include_str!("../locales/ru.ftl")),
    ("zh-Hans", include_str!("../locales/zh-Hans.ftl")),
    ("zh-Hant", include_str!("../locales/zh-Hant.ftl")),
    ("cs", include_str!("../locales/cs.ftl")),
    ("nl", include_str!("../locales/nl.ftl")),
    ("fil", include_str!("../locales/fil.ftl")),
    ("fr", include_str!("../locales/fr.ftl")),
    ("de", include_str!("../locales/de.ftl")),
    ("el", include_str!("../locales/el.ftl")),
    ("id", include_str!("../locales/id.ftl")),
    ("it", include_str!("../locales/it.ftl")),
    ("ja", include_str!("../locales/ja.ftl")),
    ("ko", include_str!("../locales/ko.ftl")),
    ("ms", include_str!("../locales/ms.ftl")),
    ("pl", include_str!("../locales/pl.ftl")),
    ("pt-BR", include_str!("../locales/pt-BR.ftl")),
    ("pt-PT", include_str!("../locales/pt-PT.ftl")),
    ("ro", include_str!("../locales/ro.ftl")),
    ("es", include_str!("../locales/es.ftl")),
    ("sw", include_str!("../locales/sw.ftl")),
    ("sv", include_str!("../locales/sv.ftl")),
    ("te", include_str!("../locales/te.ftl")),
    ("tr", include_str!("../locales/tr.ftl")),
    ("uk", include_str!("../locales/uk.ftl")),
    ("vi", include_str!("../locales/vi.ftl")),
];

#[cfg(any(test, feature = "export-check"))]
// shortcut: Check cursor mapping before these scripts are enabled.
const DEFERRED: &[(&str, &str)] = &[
    ("bn", include_str!("../locales/bn.ftl")),
    ("hi", include_str!("../locales/hi.ftl")),
    ("mr", include_str!("../locales/mr.ftl")),
    ("ta", include_str!("../locales/ta.ftl")),
    ("th", include_str!("../locales/th.ftl")),
];
pub struct Localizer {
    pub index: usize,
    primary: FluentBundle<FluentResource>,
    fallback: FluentBundle<FluentResource>,
}
#[cfg(any(test, feature = "export-check"))]
mod export_check;
#[cfg(any(test, feature = "export-check"))]
pub use export_check::check_export_catalogues;
fn bundle(index: usize) -> Result<FluentBundle<FluentResource>, String> {
    let (id, source) = LOCALES[index];
    let locale: unic_langid::LanguageIdentifier =
        id.parse().map_err(|error| format!("{error:?}"))?;
    let resource =
        FluentResource::try_new(source.to_owned()).map_err(|(_, errors)| format!("{errors:?}"))?;
    let mut bundle = FluentBundle::new(vec![locale]);
    bundle
        .add_resource(resource)
        .map_err(|errors| format!("{errors:?}"))?;
    let gallery = [
        include_str!("../locales/gallery.en-US.ftl"),
        include_str!("../locales/gallery.ru.ftl"),
    ];
    if let Some(source) = gallery.get(index) {
        let resource = FluentResource::try_new((*source).to_owned())
            .map_err(|(_, errors)| format!("{errors:?}"))?;
        bundle
            .add_resource(resource)
            .map_err(|errors| format!("{errors:?}"))?;
    }
    Ok(bundle)
}
impl Localizer {
    pub fn generator_labels(&self) -> [String; 18] {
        [
            "generate",
            "symbols",
            "words",
            "length",
            "count",
            "lower",
            "upper",
            "digits",
            "punctuation",
            "exclude-similar",
            "again",
            "use",
            "close",
            "entropy",
            "parameters",
            "random",
            "separators",
            "other-punctuation",
        ]
        .map(|key| self.text(&format!("gallery-generator-{key}")))
    }
    pub fn new(index: usize) -> Result<Self, String> {
        if index >= LOCALES.len() {
            return Err("unsupported locale".into());
        }
        Ok(Self {
            index,
            primary: bundle(index)?,
            fallback: bundle(0)?,
        })
    }
    pub fn from_preferences(
        preferences: impl IntoIterator<Item = impl AsRef<str>>,
    ) -> Result<Self, String> {
        let requested: Vec<unic_langid::LanguageIdentifier> = preferences
            .into_iter()
            .filter_map(|tag| tag.as_ref().replace('_', "-").parse().ok())
            .collect();
        let available: Vec<unic_langid::LanguageIdentifier> = LOCALES
            .iter()
            .map(|(id, _)| id.parse().expect("invalid locale identifier"))
            .collect();
        let selected = fluent_langneg::negotiate_languages(
            &requested,
            &available,
            Some(&available[0]),
            fluent_langneg::NegotiationStrategy::Lookup,
        );
        let index = available
            .iter()
            .position(|id| id == selected[0])
            .unwrap_or(0);
        Self::new(index)
    }
    pub fn id(&self) -> &'static str {
        LOCALES[self.index].0
    }
    pub fn languages() -> &'static [(usize, String)] {
        static NAMES: std::sync::OnceLock<Vec<(usize, String)>> = std::sync::OnceLock::new();
        NAMES.get_or_init(|| {
            let mut names: Vec<_> = (0..LOCALES.len())
                .map(|index| {
                    let locale = Self::new(index).expect("invalid embedded catalogue");
                    (
                        index,
                        locale.text("language-english-name"),
                        locale.text("language-name"),
                    )
                })
                .collect();
            names.sort_by(|a, b| a.1.cmp(&b.1));
            names
                .into_iter()
                .map(|(index, _, name)| (index, name))
                .collect()
        })
    }
    pub fn next(&self) -> Result<Self, String> {
        Self::new((self.index + 1) % LOCALES.len())
    }
    pub fn password_strength(&self) -> [String; 18] {
        [
            "0",
            "1",
            "2",
            "3",
            "4",
            "bits",
            "limit",
            "hint",
            "checking",
            "unavailable",
            "common",
            "keyboard",
            "repeat",
            "sequence",
            "date",
            "word",
            "name",
            "uncommon",
        ]
        .map(|key| self.text(&format!("vault-password-strength-{key}")))
    }
    pub fn text(&self, id: &str) -> String {
        self.format(id, &FluentArgs::new())
    }
    pub fn format(&self, id: &str, args: &FluentArgs<'_>) -> String {
        for bundle in [&self.primary, &self.fallback] {
            if let Some(pattern) = bundle.get_message(id).and_then(|message| message.value()) {
                let mut errors = Vec::new();
                let result = bundle.format_pattern(pattern, Some(args), &mut errors);
                if errors.is_empty() {
                    return result.into_owned();
                }
            }
        }
        id.to_owned()
    }
    pub fn title(&self) -> String {
        let mut args = FluentArgs::new();
        args.set(
            "build",
            if cfg!(debug_assertions) {
                "debug"
            } else {
                "release"
            },
        );
        self.format("window-title", &args)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;
    #[test]
    fn preferred_locale_uses_the_available_catalogue_and_order() {
        for &(id, _) in LOCALES {
            assert_eq!(Localizer::from_preferences([id]).unwrap().id(), id);
        }
        assert_eq!(
            Localizer::from_preferences(["ru-RU", "en-US"])
                .unwrap()
                .id(),
            "ru"
        );
        assert_eq!(
            Localizer::from_preferences(["en-GB", "ru"]).unwrap().id(),
            "en-US"
        );
        assert_eq!(
            Localizer::from_preferences(["invalid!", "ru_RU"])
                .unwrap()
                .id(),
            "ru"
        );
        assert_eq!(
            Localizer::from_preferences(["zz-ZZ"]).unwrap().id(),
            "en-US"
        );
        assert_eq!(
            Localizer::from_preferences(Vec::<String>::new())
                .unwrap()
                .id(),
            "en-US"
        );
    }
    #[test]
    fn catalogues_format_all_messages_and_russian_plurals() {
        let keys = |source: &str| {
            source
                .lines()
                .filter(|line| !line.starts_with(char::is_whitespace))
                .filter_map(|line| line.split_once('=').map(|(key, _)| key.trim().to_owned()))
                .collect::<BTreeSet<_>>()
        };
        assert_eq!(keys(LOCALES[0].1), keys(LOCALES[1].1));
        let app_keys = |source: &str| {
            keys(source)
                .into_iter()
                .filter(|key| {
                    key.starts_with("vault-")
                        || key.starts_with("field-")
                        || key.starts_with("ssh-")
                        || key.starts_with("template-")
                        || key.starts_with("starter-")
                        || key.starts_with("gallery-extra-fields")
                        || key.starts_with("import-")
                        || key.starts_with("export-")
                        || key.starts_with("settings-")
                        || key.starts_with("history-")
                        || key.starts_with("remove-vault")
                        || key.starts_with("rename-vault")
                        || key.starts_with("sync-new-vaults")
                        || key == "language-name"
                        || key == "language-english-name"
                })
                .collect::<BTreeSet<_>>()
        };
        for &(id, source) in LOCALES.iter().chain(DEFERRED) {
            assert_eq!(app_keys(source), app_keys(LOCALES[0].1), "{id}");
            let mut primary = FluentBundle::new(vec![id.parse().unwrap()]);
            primary
                .add_resource(FluentResource::try_new(source.to_owned()).unwrap())
                .unwrap();
            for key in [
                "settings-app",
                "settings-vaults",
                "settings-vault",
                "settings-appearance",
            ] {
                assert!(primary.get_message(key).is_some(), "{id}: {key}");
            }
            let mut args = FluentArgs::new();
            for name in ["name", "detail", "build", "field", "fields", "shortcut"] {
                args.set(name, "fixture");
            }
            args.set("count", 2);
            args.set("limit", 64);
            args.set("value", 36);
            for key in keys(source) {
                let pattern = primary.get_message(&key).unwrap().value().unwrap();
                let mut errors = vec![];
                let _ = primary.format_pattern(pattern, Some(&args), &mut errors);
                assert!(errors.is_empty(), "{key}: {errors:?}");
            }
            let weekdays = primary
                .get_message("field-weekdays")
                .unwrap()
                .value()
                .unwrap();
            let weekdays = primary.format_pattern(weekdays, None, &mut vec![]);
            assert_eq!(
                weekdays
                    .split(',')
                    .filter(|name| !name.trim().is_empty())
                    .count(),
                7,
                "{id}"
            );
        }
        let ru = Localizer::new(1).unwrap();
        for (count, ending) in [
            (1, "результат"),
            (2, "результата"),
            (5, "результатов"),
            (21, "результат"),
        ] {
            let mut args = FluentArgs::new();
            args.set("count", count);
            assert!(ru.format("result-count", &args).ends_with(ending));
        }
        assert_eq!(ru.text("missing-message"), "missing-message");
        let mut missing = Localizer::new(1).unwrap();
        missing.primary = FluentBundle::new(vec!["ru".parse().unwrap()]);
        assert_eq!(missing.text("run"), "Run Argon2");
    }
    #[test]
    fn language_menu_is_sorted_by_english_names_and_preserves_native_names() {
        let mut previous = String::new();
        for (index, name) in Localizer::languages() {
            let locale = Localizer::new(*index).unwrap();
            let english = locale.text("language-english-name");
            assert!(english.is_ascii());
            assert!(previous < english, "{previous} / {english}");
            assert_eq!(*name, locale.text("language-name"));
            previous = english;
        }
        assert_eq!(Localizer::languages().len(), LOCALES.len());
        for (tag, expected) in [
            ("fr-CA", "fr"),
            ("pt-PT", "pt-PT"),
            ("zh-TW", "zh-Hant"),
            ("zh-CN", "zh-Hans"),
        ] {
            assert_eq!(Localizer::from_preferences([tag]).unwrap().id(), expected);
        }
    }
    #[test]
    fn application_translations_have_glyphs_and_keep_text_cursor_positions() {
        use crate::ui_kit::fonts;
        use eframe::egui;
        let ctx = egui::Context::default();
        fonts::install(&ctx);
        let mut output = ctx.run_ui(egui::RawInput::default(), |ui| {
            ui.fonts_mut(|fonts| {
                for (index, (id, source)) in LOCALES.iter().enumerate() {
                    let locale = Localizer::new(index).unwrap();
                    let mut args = FluentArgs::new();
                    args.set("count", 2);
                    args.set("fields", "fixture");
                    args.set("limit", 64);
                    for line in source.lines() {
                        let Some((key, _)) = line.split_once(" = ") else {
                            continue;
                        };
                        if !key.starts_with("vault-")
                            && !key.starts_with("field-")
                            && !key.starts_with("ssh-")
                            && !key.starts_with("template-")
                            && !key.starts_with("starter-")
                            && !key.starts_with("gallery-extra-fields")
                            && !key.starts_with("settings-")
                            && !key.starts_with("export-")
                            && !key.starts_with("history-")
                            && !key.starts_with("folder-")
                            && key != "language-name"
                        {
                            continue;
                        }
                        let text: String = locale
                            .format(key, &args)
                            .chars()
                            .filter(|c| !matches!(c, '\u{2068}' | '\u{2069}'))
                            .collect();
                        for font in [
                            crate::ui_kit::fonts::regular(18.),
                            crate::ui_kit::fonts::medium(18.),
                            crate::ui_kit::fonts::semibold(18.),
                        ] {
                            for chr in text.chars().filter(|c| !c.is_control()) {
                                assert!(fonts.has_glyph(&font, chr), "{id} {key}: missing {chr:?}");
                            }
                            let galley =
                                fonts.layout_no_wrap(text.clone(), font, egui::Color32::WHITE);
                            let glyphs: usize =
                                galley.rows.iter().map(|row| row.glyphs.len()).sum();
                            assert_eq!(
                                glyphs,
                                text.chars().count(),
                                "{id} {key}: egui cursor mapping"
                            );
                        }
                    }
                }
            });
        });
        output.textures_delta.clear();
    }
}

#[cfg(test)]
mod gallery_tests {
    use super::*;
    #[test]
    fn gallery_resources_match_and_format() {
        let sources = [
            include_str!("../locales/gallery.en-US.ftl"),
            include_str!("../locales/gallery.ru.ftl"),
        ];
        let keys = |source: &str| {
            source
                .lines()
                .filter_map(|line| line.split_once(" = ").map(|(key, _)| key.to_owned()))
                .collect::<std::collections::BTreeSet<_>>()
        };
        assert_eq!(keys(sources[0]), keys(sources[1]));
        for (index, source) in sources.iter().enumerate() {
            let l = Localizer::new(index).unwrap();
            let mut args = FluentArgs::new();
            args.set("value", 3);
            for key in keys(source) {
                assert_ne!(l.format(&key, &args), key);
            }
        }
    }
}

#[cfg(test)]
mod folder_tests {
    use super::*;
    #[test]
    fn folder_messages_cover_every_catalogue() {
        let keys = |source: &str| {
            source
                .lines()
                .filter_map(|line| line.split_once(" = "))
                .filter(|(key, _)| key.starts_with("folder-"))
                .map(|(key, _)| key.to_owned())
                .collect::<std::collections::BTreeSet<_>>()
        };
        let expected = keys(LOCALES[0].1);
        assert_eq!(expected.len(), 9);
        for &(id, source) in LOCALES.iter().chain(DEFERRED) {
            assert_eq!(keys(source), expected, "{id}");
            let resource = FluentResource::try_new(source.to_owned()).unwrap();
            let mut bundle = FluentBundle::new(vec![id.parse().unwrap()]);
            bundle.add_resource(resource).unwrap();
            for key in &expected {
                let value = bundle.get_message(key).unwrap().value().unwrap();
                let mut errors = Vec::new();
                let text = bundle.format_pattern(value, None, &mut errors);
                assert!(!text.is_empty() && errors.is_empty(), "{id} {key}");
            }
        }
    }
}
