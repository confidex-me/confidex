# Bundled interface fonts

Inter Regular, Medium and SemiBold (Rasmus Andersson) and JetBrains Mono Regular
(JetBrains) are distributed unchanged under SIL OFL 1.1; license texts are adjacent.
Source: https://github.com/storytold/photocraft/tree/6ab99157189f2b9ea79e2404967151d0ba5eb2db/assets/fonts

Native builds and the UI gallery embed these files. The web app loads the
same fonts from its own origin at startup and caches them for offline use.
Font weights are explicit families;
`RichText::strong` alone does not select a bold face in egui.

Both hosts use the same fallback files. Font requests are independent of
the contents of a field.

- `DroidSansFallback.ttf`, Android Open Source Project, Apache 2.0 (adjacent
  `DroidSansFallback-NOTICE.txt` includes the license).
  [Pinned source](https://android.googlesource.com/platform/frameworks/base/+/1cdfff555f4a21f71ccc978290e2e212e2f8b168/data/fonts/).
  SHA-256: `21b96a0377f067833a93af3082eb28d4ffab7a8cd46bfd513286f1d64b7b0949`.
- `NotoEmoji.ttf`, Google, SIL OFL 1.1 (`NotoEmoji-OFL.txt`), renamed locally from
  `NotoEmoji[wght].ttf` without changing its bytes.
  [Pinned source](https://github.com/google/fonts/tree/8b0a1d0f5983c89bc2b93f1b5fb55f9e252744b5/ofl/notoemoji).
  SHA-256: `de6c18832938afc99caf132b39d6a30a19bac7f2e812e28db2535b4608d27551`.

The fallback files add 5,434,496 uncompressed bytes. Inter and JetBrains Mono
remain the primary faces. The emoji face precedes egui's older emoji fallback
so modern sequences can shape together. Tests cover common Chinese, Japanese,
Korean, combining accents, and composed emoji in every UI font family. This is
not a guarantee of coverage for every Unicode script or historical character.

`NotoSansTelugu.ttf` is an unchanged copy of `NotoSansTelugu[wdth,wght].ttf`
from Google Fonts commit `5bb28733cec313b63fbd415b574b5ae35c8aa8b8`, directory
`ofl/notosanstelugu`, under the adjacent `NotoSansTelugu-OFL.txt` license.
SHA-256: `e618af7bf999df192ed4f388eba2e563f2b5015034e9cbb317b5bd793bd7334d`.
The font file is 888,808 bytes.
