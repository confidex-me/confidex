# Application translations

The production vault screens use the same Fluent resources in native and WASM.
Language names are shown in their own language. The menu is ordered by their
English names, stored as `language-english-name` in each catalogue.

The 26 available locales are Chinese (Simplified), Chinese (Traditional), Czech,
Dutch, English, Filipino, French, German, Greek, Indonesian, Italian, Japanese,
Korean, Malay, Polish, Portuguese (Brazil), Portuguese (Portugal), Romanian,
Russian, Spanish, Swahili, Swedish, Telugu, Turkish, Ukrainian and Vietnamese.

Named themes keep their existing names. User data is never translated.

Initial selection uses browser or operating-system preferences and the current
catalogue. The CLDR feature distinguishes scripts such as zh-TW and zh-CN.
Manual selection preserves the session, form values and record drafts.

Bengali, Hindi, Marathi, Tamil and Thai catalogues are translated and checked,
but not enabled. Tests reproduced glyph/character-count mismatches in egui 0.35,
which cause incorrect text cursor positions. Arabic, Hebrew, Persian and Urdu
also wait for the upstream bidirectional-text fixes. Do not enable these merely
because a font contains their characters. See egui issues 8576 and 8818.

Tests check production message coverage, Fluent formatting, language order,
preference matching, glyph coverage and text cursor mapping in every enabled
catalogue. Translations have not had an independent native-speaker review.
