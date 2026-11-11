//! Read one XML element at a time. Owned source text is cleared on drop.
use quick_xml::{
    Reader, XmlVersion,
    events::{BytesStart, Event},
};
use std::ops::Range;
use zeroize::Zeroizing;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::import::formats) enum Error {
    Invalid,
    Limit,
    Unsupported,
    Canceled,
}
pub(in crate::import::formats) type Result<T> = std::result::Result<T, Error>;

pub(in crate::import::formats) struct Node {
    pub name: Zeroizing<String>,
    pub attributes: Vec<(Zeroizing<String>, Zeroizing<String>)>,
    pub text: Zeroizing<String>,
    pub children: Vec<Node>,
    pub span: Range<usize>,
}
pub(in crate::import::formats) fn append_text(target: &mut Zeroizing<String>, value: &str) {
    let needed = target.len() + value.len();
    if needed > target.capacity() {
        let mut next = Zeroizing::new(String::with_capacity(
            needed.checked_next_power_of_two().unwrap_or(needed),
        ));
        next.push_str(target);
        std::mem::swap(target, &mut next);
    }
    target.push_str(value);
}
impl Node {
    pub fn attribute(&self, name: &str) -> Option<&str> {
        self.attributes
            .iter()
            .find(|(key, _)| key.as_str() == name)
            .map(|(_, value)| value.as_str())
    }
    pub fn child(&self, name: &str) -> Result<Option<&Node>> {
        let mut matches = self
            .children
            .iter()
            .filter(|node| node.name.as_str() == name);
        let first = matches.next();
        if matches.next().is_some() {
            return Err(Error::Invalid);
        }
        Ok(first)
    }
    pub fn leaf(&self) -> Result<&str> {
        if !self.children.is_empty() {
            return Err(Error::Invalid);
        }
        Ok(&self.text)
    }
}
pub(in crate::import::formats) struct Xml<'a> {
    reader: Reader<&'a [u8]>,
    source: &'a str,
    depth: usize,
    roots: usize,
    nodes: usize,
    events: usize,
    before_event: usize,
    checkpoint_events: usize,
    max_depth: usize,
    max_nodes: usize,
    max_element: usize,
    pub string_limit: usize,
    text_lengths: Vec<usize>,
    declaration: bool,
    pub position: usize,
}
fn valid_char(c: char) -> bool {
    matches!(c, '\t' | '\r' | '\n' | '\u{20}'..='\u{d7ff}' | '\u{e000}'..='\u{fffd}' | '\u{10000}'..='\u{10ffff}')
}
fn supported_name(name: &[u8]) -> bool {
    !name.is_empty()
        && (name[0].is_ascii_alphabetic() || name[0] == b'_')
        && name
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(b))
}
impl<'a> Xml<'a> {
    pub fn new(
        source: &'a [u8],
        max_depth: usize,
        max_nodes: usize,
        max_element: usize,
    ) -> Result<Self> {
        let text = std::str::from_utf8(source).map_err(|_| Error::Unsupported)?;
        if !text.chars().all(valid_char) {
            return Err(Error::Invalid);
        }
        let mut reader = Reader::from_reader(source);
        reader.config_mut().check_comments = true;
        Ok(Self {
            reader,
            source: text,
            depth: 0,
            roots: 0,
            nodes: 0,
            events: 0,
            before_event: 0,
            checkpoint_events: 0,
            max_depth,
            max_nodes,
            max_element,
            string_limit: max_element,
            text_lengths: Vec::with_capacity(max_depth),
            declaration: false,
            position: 0,
        })
    }
    pub fn next(&mut self) -> Result<Event<'a>> {
        self.position = self.reader.buffer_position() as usize;
        self.before_event = self.nodes;
        let event = self.reader.read_event().map_err(|_| Error::Invalid)?;
        match &event {
            Event::Start(start) => {
                self.position = self.reader.buffer_position() as usize - start.len() - 2
            }
            Event::Empty(start) => {
                self.position = self.reader.buffer_position() as usize - start.len() - 3
            }
            _ => {}
        }
        if event.len() > self.max_element {
            return Err(Error::Limit);
        }
        self.events = self.events.checked_add(1).ok_or(Error::Limit)?;
        if self.events > self.max_nodes.saturating_mul(4) {
            return Err(Error::Limit);
        }
        let meaningful = match &event {
            Event::Start(_) | Event::Empty(_) | Event::CData(_) | Event::GeneralRef(_) => true,
            Event::Text(text) => !text
                .iter()
                .all(|b| matches!(b, b' ' | b'\t' | b'\r' | b'\n')),
            _ => false,
        };
        if meaningful {
            self.nodes = self.nodes.checked_add(1).ok_or(Error::Limit)?;
        }
        if self.nodes > self.max_nodes {
            return Err(Error::Limit);
        }
        match &event {
            Event::Start(start) | Event::Empty(start) => {
                if self.depth == 0 {
                    self.roots += 1;
                }
                if self.roots > 1 {
                    return Err(Error::Invalid);
                }
                if self.depth >= self.max_depth {
                    return Err(Error::Limit);
                }
                self.validate_start(start)?;
                if matches!(event, Event::Start(_)) {
                    self.depth += 1;
                    self.text_lengths.push(0);
                }
            }
            Event::End(_) => {
                self.depth = self.depth.checked_sub(1).ok_or(Error::Invalid)?;
                self.text_lengths.pop();
            }
            Event::DocType(_) | Event::PI(_) => return Err(Error::Unsupported),
            Event::Decl(declaration) => {
                if self.declaration
                    || self.roots != 0
                    || (self.position != 0
                        && !(self.position == 3 && self.source.starts_with('\u{feff}')))
                {
                    return Err(Error::Invalid);
                }
                if declaration.version().map_err(|_| Error::Invalid)?.as_ref() != b"1.0" {
                    return Err(Error::Unsupported);
                }
                if let Some(encoding) = declaration.encoding() {
                    let encoding = encoding.map_err(|_| Error::Invalid)?;
                    if !encoding.eq_ignore_ascii_case(b"utf-8")
                        && !encoding.eq_ignore_ascii_case(b"us-ascii")
                    {
                        return Err(Error::Unsupported);
                    }
                    if encoding.eq_ignore_ascii_case(b"us-ascii") && !self.source.is_ascii() {
                        return Err(Error::Invalid);
                    }
                }
                self.declaration = true;
            }
            Event::GeneralRef(reference) => {
                if self.depth == 0 {
                    return Err(Error::Invalid);
                }
                Self::reference(reference)?;
            }
            Event::Text(text) if self.depth == 0 => {
                if !text
                    .iter()
                    .all(|b| matches!(b, b' ' | b'\t' | b'\r' | b'\n'))
                {
                    return Err(Error::Invalid);
                }
            }
            Event::CData(_) if self.depth == 0 => return Err(Error::Invalid),
            Event::Eof if self.depth != 0 || self.roots != 1 => return Err(Error::Invalid),
            _ => {}
        }
        let text_bytes = match &event {
            Event::Text(text) => {
                if text.windows(3).any(|s| s == b"]]>") {
                    return Err(Error::Invalid);
                }
                text.len()
            }
            Event::CData(text) => text.len(),
            Event::GeneralRef(reference) => Self::reference(reference)?.len_utf8(),
            _ => 0,
        };
        if let Some(length) = self.text_lengths.last_mut() {
            *length = length.checked_add(text_bytes).ok_or(Error::Limit)?;
            if *length > self.string_limit {
                return Err(Error::Limit);
            }
        }
        Ok(event)
    }
    fn validate_start(&mut self, start: &BytesStart<'_>) -> Result<()> {
        if start.name().as_ref().len() > 4096 {
            return Err(Error::Limit);
        }
        if !supported_name(start.name().as_ref()) {
            return Err(Error::Unsupported);
        }
        for (index, attribute) in start.attributes().enumerate() {
            // Bound the XML library's duplicate-attribute comparisons.
            if index >= 512 {
                return Err(Error::Limit);
            }
            let attribute = attribute.map_err(|_| Error::Invalid)?;
            self.nodes = self.nodes.checked_add(1).ok_or(Error::Limit)?;
            if self.nodes > self.max_nodes {
                return Err(Error::Limit);
            }
            if attribute.key.as_ref().len() > 4096 {
                return Err(Error::Limit);
            }
            if attribute.key.as_ref() == b"xmlns" || !supported_name(attribute.key.as_ref()) {
                return Err(Error::Unsupported);
            }
            if attribute.value.len() > self.string_limit {
                return Err(Error::Limit);
            }
            let value = Zeroizing::new(
                attribute
                    .decoded_and_normalized_value(XmlVersion::Implicit1_0, self.reader.decoder())
                    .map_err(|_| Error::Invalid)?
                    .into_owned(),
            );
            if !value.chars().all(valid_char) {
                return Err(Error::Invalid);
            }
        }
        Ok(())
    }
    pub(in crate::import::formats) fn reference(
        reference: &quick_xml::events::BytesRef<'_>,
    ) -> Result<char> {
        if reference.len() > 16 {
            return Err(Error::Limit);
        }
        let character =
            if let Some(value) = reference.resolve_char_ref().map_err(|_| Error::Invalid)? {
                value
            } else {
                match &**reference {
                    b"amp" => '&',
                    b"lt" => '<',
                    b"gt" => '>',
                    b"quot" => '"',
                    b"apos" => '\'',
                    _ => return Err(Error::Unsupported),
                }
            };
        if !valid_char(character) {
            return Err(Error::Invalid);
        }
        Ok(character)
    }
    pub fn element(
        &mut self,
        start: BytesStart<'a>,
        empty: bool,
        checkpoint: &mut dyn FnMut(usize) -> bool,
    ) -> Result<Node> {
        if !checkpoint(self.position) {
            return Err(Error::Canceled);
        }
        self.checkpoint_events = self.events;
        let node = self.element_inner(start, empty, checkpoint)?;
        if !checkpoint(self.position) {
            return Err(Error::Canceled);
        }
        Ok(node)
    }
    fn element_inner(
        &mut self,
        start: BytesStart<'a>,
        empty: bool,
        checkpoint: &mut dyn FnMut(usize) -> bool,
    ) -> Result<Node> {
        let begin = self.position;
        let before = self.before_event;
        self.element_nodes(before)?;
        let name = std::str::from_utf8(start.name().as_ref())
            .map_err(|_| Error::Invalid)?
            .to_owned();
        let mut node = Node {
            name: Zeroizing::new(name),
            attributes: Vec::new(),
            text: Zeroizing::new(String::new()),
            children: Vec::new(),
            span: begin..self.reader.buffer_position() as usize,
        };
        for attribute in start.attributes() {
            let attribute = attribute.map_err(|_| Error::Invalid)?;
            node.attributes.push((
                Zeroizing::new(
                    std::str::from_utf8(attribute.key.as_ref())
                        .map_err(|_| Error::Invalid)?
                        .to_owned(),
                ),
                Zeroizing::new(
                    attribute
                        .decoded_and_normalized_value(
                            XmlVersion::Implicit1_0,
                            self.reader.decoder(),
                        )
                        .map_err(|_| Error::Invalid)?
                        .into_owned(),
                ),
            ));
        }
        if !empty {
            loop {
                if self.reader.buffer_position() as usize - begin > self.max_element {
                    return Err(Error::Limit);
                }
                let event = self.next()?;
                self.element_nodes(before)?;
                if self.events - self.checkpoint_events >= 256 {
                    if !checkpoint(self.position) {
                        return Err(Error::Canceled);
                    }
                    self.checkpoint_events = self.events;
                }
                if self.reader.buffer_position() as usize - begin > self.max_element {
                    return Err(Error::Limit);
                }
                match event {
                    Event::Start(child) => node
                        .children
                        .push(self.element_inner(child, false, checkpoint)?),
                    Event::Empty(child) => node
                        .children
                        .push(self.element_inner(child, true, checkpoint)?),
                    Event::Text(text) => {
                        let value = Zeroizing::new(
                            text.xml10_content()
                                .map_err(|_| Error::Invalid)?
                                .into_owned(),
                        );
                        if text.windows(3).any(|s| s == b"]]>") {
                            return Err(Error::Invalid);
                        }
                        append_text(&mut node.text, &value);
                    }
                    Event::CData(text) => {
                        let value = Zeroizing::new(
                            text.xml10_content()
                                .map_err(|_| Error::Invalid)?
                                .into_owned(),
                        );
                        append_text(&mut node.text, &value);
                    }
                    Event::GeneralRef(reference) => {
                        let mut bytes = [0; 4];
                        let character = Self::reference(&reference)?;
                        append_text(&mut node.text, character.encode_utf8(&mut bytes));
                    }
                    Event::Comment(_) => {}
                    Event::End(_) => break,
                    _ => return Err(Error::Invalid),
                }
            }
        }
        node.span.end = self.reader.buffer_position() as usize;
        if node.span.len() > self.max_element {
            return Err(Error::Limit);
        }
        Ok(node)
    }
    fn element_nodes(&self, before: usize) -> Result<()> {
        // Node storage is bounded as well as source text.
        if self.nodes - before > (self.max_element / 256).max(1) {
            return Err(Error::Limit);
        }
        Ok(())
    }
    pub fn event_count(&self) -> usize {
        self.events
    }
    pub fn event_nodes(&self) -> usize {
        self.before_event
    }
    pub fn decoder(&self) -> quick_xml::encoding::Decoder {
        self.reader.decoder()
    }
    pub fn offset(&self) -> usize {
        self.reader.buffer_position() as usize
    }
    pub fn node_count(&self) -> usize {
        self.nodes
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn document(source: &[u8], depth: usize, nodes: usize, bytes: usize) -> Result<Node> {
        let mut xml = Xml::new(source, depth, nodes, bytes)?;
        let root = loop {
            match xml.next()? {
                Event::Start(start) => break xml.element(start, false, &mut |_| true)?,
                Event::Empty(start) => break xml.element(start, true, &mut |_| true)?,
                Event::Decl(_) | Event::Comment(_) | Event::Text(_) => {}
                _ => return Err(Error::Invalid),
            }
        };
        loop {
            if matches!(xml.next()?, Event::Eof) {
                break;
            }
        }
        Ok(root)
    }
    #[test]
    fn text_entities_cdata_crlf_and_empty_values_keep_their_meaning() {
        let input=b"<?xml version='1.0'?><Entry><Value ProtectInMemory='True'>A&amp;&lt;&gt;&quot;&apos;&#x1F600;\r\n<![CDATA[B<C]]></Value><Empty /></Entry>";
        let root = document(input, 64, 1000, 4096).unwrap();
        let value = root.child("Value").unwrap().unwrap();
        assert_eq!(value.attribute("ProtectInMemory"), Some("True"));
        assert_eq!(value.leaf().unwrap(), "A&<>\"'😀\nB<C");
        assert_eq!(root.child("Empty").unwrap().unwrap().leaf().unwrap(), "");
        let mut xml = Xml::new(input, 64, 1000, 4096).unwrap();
        while let Event::Decl(_) = xml.next().unwrap() {}
        assert!(
            std::str::from_utf8(&input[root.span.clone()])
                .unwrap()
                .starts_with("<Entry>")
        );
    }
    #[test]
    fn admission_rejects_dtd_entities_malformed_xml_and_wrong_encoding() {
        for input in [
            "<!DOCTYPE Entry [<!ENTITY secret SYSTEM 'file:///private/secret'>]><Entry>&secret;</Entry>",
            "<Entry>&unknown;</Entry>",
            "<Entry>]]></Entry>",
            "<1Entry/>",
            "<Entry>bad & bare</Entry>",
            "<!--prelude--><?xml version='1.0'?><Entry/>",
            "<Entry>&#0;</Entry>",
            "<Entry attr='&#0;' />",
            "<Entry a='one' a='two' />",
            "<Entry><Value></Entry>",
            "<Entry>",
            "<Entry/><Other/>",
            "junk<Entry/>",
            "<Entry/><!-- a--b -->",
            "<Entry/><?xml version='1.0'?>",
            "<?xml version='1.0' encoding='utf-16'?><Entry/>",
            "<Entry xmlns='unexpected'/>",
        ] {
            assert!(document(input.as_bytes(), 64, 1000, 4096).is_err());
        }
        assert!(document(&[b'<', b'E', b'>', 0xff], 64, 1000, 4096).is_err());
    }
    #[test]
    fn depth_nodes_and_element_bytes_are_admitted() {
        assert!(matches!(
            document(b"<Entry><Value>data</Value></Entry>", 1, 100, 4096),
            Err(Error::Limit)
        ));
        assert!(matches!(
            document(b"<Entry a='one'><Value/></Entry>", 64, 2, 4096),
            Err(Error::Limit)
        ));
        assert!(matches!(
            document(b"<Entry><A/><A/><A/><A/></Entry>", 64, 100, 1024),
            Err(Error::Limit)
        ));
        assert!(matches!(
            document(b"<Entry>oversized</Entry>", 64, 100, 8),
            Err(Error::Limit)
        ));
        assert!(
            document(b"<Entry><Value/><Value/></Entry>", 64, 100, 4096)
                .unwrap()
                .child("Value")
                .is_err()
        );
    }
    #[test]
    fn cancellation_stops_an_element_before_it_is_returned() {
        let mut xml = Xml::new(
            b"<Entry><Value>public fixture</Value></Entry>",
            64,
            1000,
            4096,
        )
        .unwrap();
        let Event::Start(start) = xml.next().unwrap() else {
            panic!("missing root")
        };
        assert!(matches!(
            xml.element(start, false, &mut |_| false),
            Err(Error::Canceled)
        ));
        let source = format!(
            "<Entry>{}</Entry>",
            "<Value>public fixture</Value>".repeat(1000)
        );
        let mut xml = Xml::new(source.as_bytes(), 64, 100_000, 1_000_000).unwrap();
        let Event::Start(start) = xml.next().unwrap() else {
            panic!("missing root")
        };
        let mut calls = 0;
        assert!(matches!(
            xml.element(start, false, &mut |_| {
                calls += 1;
                calls == 1
            }),
            Err(Error::Canceled)
        ));
        assert_eq!(calls, 2);
        assert!(xml.position < source.len());
    }
}
