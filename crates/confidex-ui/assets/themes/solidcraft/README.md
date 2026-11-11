# SolidCraft colour schemes

The 25 JSON files are unchanged copies from
[tangency-labs/solidcraft](https://github.com/tangency-labs/solidcraft/tree/82660d4ee22a38936c81366273ed81f418c32c86/assets/styles/ui/themes),
revision `82660d4ee22a38936c81366273ed81f418c32c86`. Their original names,
provenance, options and non-UI colours remain available here. See
[ATTRIBUTION.md](ATTRIBUTION.md), [LICENSE-MIT](LICENSE-MIT) and
[LICENSE-APACHE](LICENSE-APACHE). We use the MIT license option.

`generate.py` maps the authored default colours to Confidex's smaller semantic
palette. Run it with Python 3 from any directory; no packages or network are
needed. It writes `src/theme/solidcraft.rs`, which is compiled on native and
WASM without a JSON parser or a dependency on SolidCraft. The two original
Confidex themes remain first, preserving their existing IDs and defaults.

| Confidex role | SolidCraft token |
| --- | --- |
| background | field |
| surface | panel |
| control | control_fill |
| hover | hover |
| pressed | selected_bg |
| border | control_border |
| text / text_muted | text / text_dim |
| accent / on_accent | accent / on_accent |
| error / success / warning | error / form_success (or agent_ok) / warning |

The adapter preserves readable authored colours. Confidex uses body text over
control fills, whereas CAD hover/selection fills can be graphical highlights:
when an authored highlight cannot carry body text, the adapter uses control_fill.
Foreground shades then move towards black or white only as needed to reach
4.5:1 contrast across our text surfaces. Each changed shade is annotated next
to its generated value. Source JSON files remain unchanged.

This imports **colour schemes**, not SolidCraft's shape metrics, 3D colours,
blur, opacity, option controls, theme-file import or per-tab overlays. The
defaults of its theme files are used; Confidex keeps its own shared layout.
