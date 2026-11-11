use confidex_vault::entropy::fill_random;
use std::sync::OnceLock;
use zeroize::Zeroizing;

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(default)]
pub struct Config {
    pub words: bool,
    pub length: usize,
    pub count: usize,
    #[serde(deserialize_with = "deserialize_classes")]
    pub classes: [bool; 5],
    pub exclude_similar: bool,
}
fn deserialize_classes<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<[bool; 5], D::Error> {
    #[derive(serde::Deserialize)]
    #[serde(untagged)]
    enum Classes {
        Current([bool; 5]),
        Legacy([bool; 4]),
    }
    Ok(match serde::Deserialize::deserialize(deserializer)? {
        Classes::Current(flags) => flags,
        Classes::Legacy([lower, upper, digits, punctuation]) => {
            [lower, upper, digits, punctuation, punctuation]
        }
    })
}
impl Default for Config {
    fn default() -> Self {
        Self {
            words: false,
            length: 20,
            count: 6,
            classes: [true; 5],
            exclude_similar: true,
        }
    }
}
impl Config {
    pub fn restore(storage: Option<&dyn eframe::Storage>) -> Self {
        storage
            .and_then(|storage| eframe::get_value::<Self>(storage, "password-generator"))
            .filter(|config| (8..=64).contains(&config.length) && (1..=10).contains(&config.count))
            .unwrap_or_default()
    }
    pub fn save(&self, storage: &mut dyn eframe::Storage) {
        eframe::set_value(storage, "password-generator", self);
    }
}
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) enum Error {
    Parameters,
    Random,
}
#[derive(Clone, Default)]
pub(super) struct State {
    pub config: Config,
    pub candidate: Zeroizing<String>,
    pub bits: f64,
    pub error: Option<Error>,
}
impl State {
    pub fn regenerate(&mut self) {
        self.candidate = Zeroizing::new(String::new());
        self.bits = 0.;
        self.error = None;
        match generate(self.config, |bytes| {
            fill_random(bytes).map_err(|_| Error::Random)
        }) {
            Ok((candidate, bits)) => {
                self.candidate = candidate;
                self.bits = bits;
            }
            Err(error) => self.error = Some(error),
        }
    }
    pub fn clear(&mut self) {
        self.candidate = Zeroizing::new(String::new());
        self.bits = 0.;
        self.error = None;
    }
}
fn words() -> &'static [&'static str] {
    static WORDS: OnceLock<Vec<&str>> = OnceLock::new();
    WORDS.get_or_init(|| {
        include_str!("../../../assets/wordlists/eff-large.txt")
            .lines()
            .filter_map(|line| line.split_once('\t').map(|(_, word)| word))
            .collect()
    })
}
fn alphabet(config: Config) -> Vec<u8> {
    const SETS: [&[u8]; 5] = [
        b"abcdefghijklmnopqrstuvwxyz",
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZ",
        b"0123456789",
        b".-_@#$!",
        b"\"%&'()*+,/:;<=>?[\\]^`{|}~",
    ];
    SETS.into_iter()
        .zip(config.classes)
        .filter(|(_, enabled)| *enabled)
        .flat_map(|(set, _)| set.iter().copied())
        .filter(|c| !config.exclude_similar || !b"iIlLoO01|".contains(c))
        .collect()
}
fn accepted(draw: u16, size: usize) -> Option<usize> {
    let draw = usize::from(draw);
    (draw < 65_536 / size * size).then_some(draw % size)
}
fn sample(
    size: usize,
    fill: &mut impl FnMut(&mut [u8]) -> Result<(), Error>,
) -> Result<usize, Error> {
    let mut bytes = Zeroizing::new([0; 2]);
    for _ in 0..128 {
        fill(&mut bytes[..])?;
        if let Some(index) = accepted(u16::from_le_bytes(*bytes), size) {
            return Ok(index);
        }
    }
    Err(Error::Random)
}
fn generate(
    config: Config,
    mut fill: impl FnMut(&mut [u8]) -> Result<(), Error>,
) -> Result<(Zeroizing<String>, f64), Error> {
    let alphabet = alphabet(config);
    let (count, size) = if config.words {
        if !(1..=10).contains(&config.count) || (config.count > 1 && alphabet.is_empty()) {
            return Err(Error::Parameters);
        }
        (config.count, words().len())
    } else {
        if !(8..=64).contains(&config.length) || alphabet.is_empty() {
            return Err(Error::Parameters);
        }
        (config.length, alphabet.len())
    };
    let mut output = Zeroizing::new(String::new());
    for i in 0..count {
        if config.words {
            if i > 0 {
                output.push(char::from(alphabet[sample(alphabet.len(), &mut fill)?]));
            }
            let word = words()[sample(size, &mut fill)?];
            let case = sample(3, &mut fill)?;
            for (index, letter) in word.chars().enumerate() {
                output.push(if case == 2 || (case == 1 && index == 0) {
                    letter.to_ascii_uppercase()
                } else {
                    letter
                });
            }
        } else {
            output.push(char::from(alphabet[sample(size, &mut fill)?]));
        }
    }
    let mut bits = count as f64 * (size as f64).log2();
    if config.words {
        bits += count as f64 * 3f64.log2();
        if count > 1 {
            bits += (count - 1) as f64 * (alphabet.len() as f64).log2();
        }
    }
    Ok((output, bits))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn dictionary_and_uniform_sampling_match_entropy() {
        let words = words();
        assert_eq!(words.len(), 7776);
        let unique: std::collections::BTreeSet<_> = words.iter().collect();
        assert_eq!(unique.len(), words.len());
        assert!(
            words
                .iter()
                .all(|w| !w.is_empty() && w.bytes().all(|b| b.is_ascii_lowercase() || b == b'-'))
        );
        assert!(
            words
                .iter()
                .all(|w| w.starts_with(|c: char| c.is_ascii_lowercase())
                    && w.bytes().filter(u8::is_ascii_lowercase).count() >= 2)
        );
        for size in [3, 6, 85, 94, 7776] {
            let mut counts = vec![0; size];
            for draw in 0..=u16::MAX {
                if let Some(i) = accepted(draw, size) {
                    counts[i] += 1;
                }
            }
            assert!(counts.iter().all(|n| *n == 65_536 / size));
        }
        let config = Config {
            words: true,
            ..Default::default()
        };
        let (text, bits) = generate(config, |bytes| {
            bytes.fill(0);
            Ok(())
        })
        .unwrap();
        assert_eq!(text.as_str(), [words[0]; 6].join("a"));
        let expected =
            6. * (7776f64).log2() + 6. * 3f64.log2() + 5. * (alphabet(config).len() as f64).log2();
        assert!((bits - expected).abs() < 1e-9);
    }
    #[test]
    fn words_choose_each_case_and_separator_independently() {
        let config = Config {
            words: true,
            count: 3,
            classes: [false, false, true, false, false],
            ..Default::default()
        };
        let mut draws = [0u16, 0, 0, 0, 1, 0, 0, 2].into_iter();
        let (text, bits) = generate(config, |bytes| {
            bytes.copy_from_slice(&draws.next().unwrap().to_le_bytes());
            Ok(())
        })
        .unwrap();
        let word = words()[0];
        assert_eq!(
            text.as_str(),
            format!(
                "{word}2{}{}2{}",
                word[..1].to_ascii_uppercase(),
                &word[1..],
                word.to_ascii_uppercase()
            )
        );
        assert_eq!(draws.next(), None);
        assert!(
            (bits - (3. * ((words().len() as f64).log2() + 3f64.log2()) + 2. * 3.)).abs() < 1e-9
        );
        for index in 0..5 {
            let mut config = config;
            config.classes = [false; 5];
            config.classes[index] = true;
            let (text, _) = generate(config, |bytes| {
                bytes.fill(0);
                Ok(())
            })
            .unwrap();
            assert_eq!(
                text.as_str(),
                [word; 3].join(&char::from(alphabet(config)[0]).to_string())
            );
        }
        let mut empty = Config {
            words: true,
            classes: [false; 5],
            ..Default::default()
        };
        assert_eq!(
            generate(empty, |_| panic!(
                "invalid separators must not request random"
            )),
            Err(Error::Parameters)
        );
        empty.count = 1;
        let (text, bits) = generate(empty, |bytes| {
            bytes.fill(0);
            Ok(())
        })
        .unwrap();
        assert_eq!(text.as_str(), word);
        assert!(bits.is_finite());
        let mut calls = 0;
        assert_eq!(
            generate(config, |bytes| {
                calls += 1;
                if calls == 3 {
                    Err(Error::Random)
                } else {
                    bytes.fill(0);
                    Ok(())
                }
            }),
            Err(Error::Random)
        );
    }
    #[test]
    fn punctuation_groups_are_disjoint_and_preserve_the_complete_set() {
        let config = Config {
            classes: [false, false, false, true, false],
            exclude_similar: false,
            length: 14,
            ..Default::default()
        };
        let simple = alphabet(config);
        assert_eq!(simple, b".-_@#$!");
        let other = alphabet(Config {
            classes: [false, false, false, false, true],
            ..config
        });
        assert!(other.iter().all(|c| !simple.contains(c)));
        let mut complete = simple.clone();
        complete.extend(other);
        complete.sort_unstable();
        assert_eq!(
            complete,
            (0..=127u8)
                .filter(u8::is_ascii_punctuation)
                .collect::<Vec<_>>()
        );
        let mut draw = 0u16;
        let (text, bits) = generate(config, |bytes| {
            bytes.copy_from_slice(&(draw % 7).to_le_bytes());
            draw += 1;
            Ok(())
        })
        .unwrap();
        assert_eq!(text.as_str(), ".-_@#$!.-_@#$!");
        assert_eq!(bits, 14. * 7f64.log2());
    }
    #[test]
    fn parameters_random_failure_and_rejection_fail_closed() {
        let invalid = Config {
            classes: [false; 5],
            ..Default::default()
        };
        assert_eq!(
            generate(invalid, |_| panic!("must not request random")),
            Err(Error::Parameters)
        );
        assert_eq!(
            generate(Config::default(), |_| Err(Error::Random)),
            Err(Error::Random)
        );
        assert_eq!(
            generate(Config::default(), |bytes| {
                bytes.fill(255);
                Ok(())
            }),
            Err(Error::Random)
        );
        let mut config = Config {
            classes: [false, false, true, false, false],
            ..Default::default()
        };
        config.exclude_similar = true;
        let (text, bits) = generate(config, |bytes| {
            bytes.fill(0);
            Ok(())
        })
        .unwrap();
        assert_eq!(text.as_str(), "2".repeat(config.length));
        assert_eq!(bits, config.length as f64 * 3.);
        let mut state = State::default();
        state.regenerate();
        assert!(!state.candidate.is_empty());
        state.config = invalid;
        state.regenerate();
        assert!(state.candidate.is_empty());
        assert_eq!(state.error, Some(Error::Parameters));
    }
}
