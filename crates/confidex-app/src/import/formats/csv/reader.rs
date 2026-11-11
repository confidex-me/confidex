//! Read strict CSV spans before allocating decoded values.
use crate::import::{Error, ErrorKind, Limits, Location};
use std::ops::Range;
use zeroize::Zeroizing;

pub(super) struct Cell {
    pub span: Range<usize>,
    pub bytes: usize,
    pub quoted: bool,
}
impl Cell {
    pub fn decode(&self, source: &str) -> Zeroizing<String> {
        let raw = &source[self.span.clone()];
        if !self.quoted {
            return Zeroizing::new(raw.to_owned());
        }
        let mut value = Zeroizing::new(String::with_capacity(self.bytes));
        for (index, part) in raw[1..raw.len() - 1].split("\"\"").enumerate() {
            if index != 0 {
                value.push('"');
            }
            value.push_str(part);
        }
        value
    }
}
pub(super) struct Row {
    pub cells: Vec<Cell>,
    pub span: Range<usize>,
    pub bytes: usize,
}
pub(super) struct Reader<'a> {
    pub source: &'a str,
    offset: usize,
    delimiter: u8,
    limits: Limits,
    rows: usize,
    nodes: usize,
    next_checkpoint: usize,
}
fn error(kind: ErrorKind, offset: usize) -> Error {
    Error::from(kind).at(Location {
        offset: Some(offset),
        ..Location::default()
    })
}
impl<'a> Reader<'a> {
    pub fn new(input: &'a [u8], delimiter: u8, limits: Limits) -> Result<Self, Error> {
        let mut limits = limits.validate()?;
        limits.string_bytes = limits
            .string_bytes
            .min(confidex_vault::encoding::CONTENT_LIMITS.string);
        if input.len() > limits.input_bytes {
            return Err(ErrorKind::Limit.into());
        }
        if !matches!(delimiter, b',' | b';' | b'\t' | b'|') {
            return Err(ErrorKind::InvalidOptions.into());
        }
        let source = std::str::from_utf8(input)
            .map_err(|e| error(ErrorKind::UnsupportedEncoding, e.valid_up_to()))?;
        if let Some(offset) = input.iter().position(|&b| b == 0) {
            return Err(error(ErrorKind::UnsupportedEncoding, offset));
        }
        Ok(Self {
            source,
            offset: if input.starts_with(&[0xef, 0xbb, 0xbf]) {
                3
            } else {
                0
            },
            delimiter,
            limits,
            rows: 0,
            nodes: 0,
            next_checkpoint: 0,
        })
    }
    pub fn offset(&self) -> usize {
        self.offset
    }
    fn checkpoint(&mut self, callback: &mut dyn FnMut(usize) -> bool) -> Result<(), Error> {
        if self.offset >= self.next_checkpoint {
            if !callback(self.offset) {
                return Err(error(ErrorKind::Canceled, self.offset));
            }
            self.next_checkpoint = self.offset.saturating_add(65_536);
        }
        Ok(())
    }
    pub fn next(&mut self, callback: &mut dyn FnMut(usize) -> bool) -> Result<Option<Row>, Error> {
        self.checkpoint(callback)?;
        if self.offset == self.source.len() {
            return Ok(None);
        }
        self.rows += 1;
        self.nodes += 1;
        if self.rows > self.limits.records + 1 || self.nodes > self.limits.nodes {
            return Err(error(ErrorKind::Limit, self.offset));
        }
        let start = self.offset;
        let mut cells = Vec::new();
        cells
            .try_reserve_exact(self.limits.fields)
            .map_err(|_| ErrorKind::Allocation)?;
        let mut bytes = 0usize;
        let input = self.source.as_bytes();
        loop {
            if cells.len() >= self.limits.fields || self.nodes >= self.limits.nodes {
                return Err(error(ErrorKind::Limit, self.offset));
            }
            self.nodes += 1;
            let begin = self.offset;
            let quoted = input.get(begin) == Some(&b'"');
            let mut closed = !quoted;
            let mut decoded = 0usize;
            if quoted {
                self.offset += 1;
            }
            while let Some(&byte) = input.get(self.offset) {
                self.checkpoint(callback)?;
                if quoted {
                    if byte == b'"' {
                        self.offset += 1;
                        if input.get(self.offset) == Some(&b'"') {
                            self.offset += 1;
                            decoded += 1;
                        } else {
                            closed = true;
                            break;
                        }
                    } else {
                        self.offset += 1;
                        decoded += 1;
                    }
                } else if byte == self.delimiter || matches!(byte, b'\r' | b'\n') {
                    break;
                } else if byte == b'"' {
                    return Err(error(ErrorKind::Malformed, self.offset));
                } else {
                    self.offset += 1;
                    decoded += 1;
                }
                if decoded > self.limits.string_bytes {
                    return Err(error(ErrorKind::Limit, self.offset));
                }
            }
            if !closed {
                return Err(error(ErrorKind::Malformed, self.offset));
            }
            bytes = bytes.checked_add(decoded).ok_or(ErrorKind::Limit)?;
            cells.push(Cell {
                span: begin..self.offset,
                bytes: decoded,
                quoted,
            });
            match input.get(self.offset) {
                Some(&byte) if byte == self.delimiter => self.offset += 1,
                Some(b'\r' | b'\n') => {
                    let end = self.offset;
                    let carriage_return = input[self.offset] == b'\r';
                    self.offset += 1;
                    if carriage_return && input.get(self.offset) == Some(&b'\n') {
                        self.offset += 1;
                    }
                    return Ok(Some(Row {
                        cells,
                        span: start..end,
                        bytes,
                    }));
                }
                None => {
                    return Ok(Some(Row {
                        cells,
                        span: start..self.offset,
                        bytes,
                    }));
                }
                _ => return Err(error(ErrorKind::Malformed, self.offset)),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn rows(input: &[u8], delimiter: u8) -> Result<Vec<Vec<Zeroizing<String>>>, Error> {
        let mut reader = Reader::new(input, delimiter, Limits::default())?;
        let mut result = Vec::new();
        while let Some(row) = reader.next(&mut |_| true)? {
            assert!(row.span.end <= reader.offset());
            let values = row
                .cells
                .iter()
                .map(|c| c.decode(reader.source))
                .collect::<Vec<_>>();
            assert_eq!(row.bytes, values.iter().map(|v| v.len()).sum::<usize>());
            result.push(values);
        }
        Ok(result)
    }
    #[test]
    fn quotes_empty_cells_multiline_bom_and_all_line_endings_keep_values() {
        let source = b"\xef\xbb\xbfname,extra,extra,,password\r\n\"\xd0\x9f\xd0\xbe\xd1\x87\xd1\x82\xd0\xb0\",\"a\r\nb\",\"He said \"\"hello\"\"\",,\r\n,,\"\",last,\r";
        let parsed = rows(source, b',').unwrap();
        assert_eq!(parsed.len(), 3);
        assert_eq!(
            parsed[0].iter().map(|s| s.as_str()).collect::<Vec<_>>(),
            ["name", "extra", "extra", "", "password"]
        );
        assert_eq!(
            parsed[1].iter().map(|s| s.as_str()).collect::<Vec<_>>(),
            ["Почта", "a\r\nb", "He said \"hello\"", "", ""]
        );
        assert_eq!(
            parsed[2].iter().map(|s| s.as_str()).collect::<Vec<_>>(),
            ["", "", "", "last", ""]
        );
        assert_eq!(rows(b"a\nb\rc\r\n", b',').unwrap().len(), 3);
        assert_eq!(rows(b",", b',').unwrap()[0].len(), 2);
        assert_eq!(rows(b"\n", b',').unwrap()[0].len(), 1);
        assert!(rows(b"", b',').unwrap().is_empty());
        for delimiter in *b";|\t" {
            let source = [b'a', delimiter, b'b'];
            assert_eq!(rows(&source, delimiter).unwrap()[0].len(), 2);
        }
    }
    #[test]
    fn malformed_quotes_and_unsupported_encoding_are_rejected() {
        for source in [
            b"\"unclosed".as_slice(),
            b"plain\"quote",
            b"\"closed\" tail",
            b"\"one\"\"",
            b"\"\"x",
        ] {
            assert_eq!(rows(source, b',').err().unwrap().kind, ErrorKind::Malformed);
        }
        for source in [b"\xff\xfea\0".as_slice(), b"a,\xff", b"a\0b"] {
            assert_eq!(
                rows(source, b',').err().unwrap().kind,
                ErrorKind::UnsupportedEncoding
            );
        }
        assert_eq!(
            rows(b"a,b", b':').err().unwrap().kind,
            ErrorKind::InvalidOptions
        );
    }
    #[test]
    fn limits_precede_value_allocation_and_long_fields_can_be_canceled() {
        let cases = [
            (
                b"long".as_slice(),
                Limits {
                    string_bytes: 3,
                    ..Limits::default()
                },
            ),
            (
                b"\"\"\"\"\"\"\"\"".as_slice(),
                Limits {
                    string_bytes: 2,
                    ..Limits::default()
                },
            ),
            (
                b"a,b,c".as_slice(),
                Limits {
                    fields: 2,
                    ..Limits::default()
                },
            ),
            (
                b"a,b,c".as_slice(),
                Limits {
                    nodes: 3,
                    ..Limits::default()
                },
            ),
            (
                b"a\nb\nc".as_slice(),
                Limits {
                    records: 1,
                    ..Limits::default()
                },
            ),
        ];
        for (source, limits) in cases {
            let mut reader = Reader::new(source, b',', limits).unwrap();
            let error = loop {
                match reader.next(&mut |_| true) {
                    Err(error) => break error,
                    Ok(Some(_)) => {}
                    Ok(None) => panic!("expected admission failure"),
                }
            };
            assert_eq!(error.kind, ErrorKind::Limit);
        }
        let input = "x".repeat(200_000);
        let mut reader = Reader::new(input.as_bytes(), b',', Limits::default()).unwrap();
        let error = reader.next(&mut |offset| offset < 65_536).err().unwrap();
        assert_eq!(error.kind, ErrorKind::Canceled);
        assert_eq!(error.location.offset, Some(65_536));
    }
}
