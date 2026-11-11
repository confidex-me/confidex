//! Keep CSV setup data independent of translated form labels.
use confidex_app::{export, export_flow as flow, import::formats::csv::Profile};
use confidex_storage::Head;
use std::collections::BTreeSet;

pub struct State {
    pub manual: export::Csv,
    profile: Option<Profile>,
    sample: Option<Head>,
    fields: usize,
    page: Option<flow::FieldSources>,
    start: usize,
    expected: Option<(u32, Head, usize)>,
}
impl Default for State {
    fn default() -> Self {
        Self {
            manual: export::Csv {
                profile: None,
                delimiter: b',',
                header: true,
                columns: Vec::new(),
            },
            profile: None,
            sample: None,
            fields: 0,
            page: None,
            start: 0,
            expected: None,
        }
    }
}
impl State {
    pub fn profile(&self) -> Option<Profile> {
        self.profile
    }
    pub fn set_profile(&mut self, profile: Option<Profile>) {
        self.profile = profile;
        self.clear_sources();
    }
    pub fn valid(&self) -> bool {
        if self.waiting() {
            return false;
        }
        if self.profile.is_some() {
            return true;
        }
        let mut sources = BTreeSet::new();
        self.manual.profile.is_none()
            && self.manual.validate().is_ok()
            && self
                .manual
                .columns
                .iter()
                .all(|column| !column.heading.contains('\0') && sources.insert(&column.source))
    }
    pub fn add(&mut self, heading: String, source: export::Source) -> Result<(), export::Error> {
        if self.profile.is_some()
            || self.manual.columns.len() >= confidex_vault::record::MAX_ENTRIES
        {
            return Err(export::Error::InvalidOptions);
        }
        self.manual.columns.push(export::Column { heading, source });
        if !self.valid() {
            self.manual.columns.pop();
            return Err(export::Error::InvalidOptions);
        }
        Ok(())
    }
    pub fn set_source(
        &mut self,
        index: usize,
        source: export::Source,
    ) -> Result<(), export::Error> {
        if self.profile.is_some() {
            return Err(export::Error::InvalidOptions);
        }
        let column = self
            .manual
            .columns
            .get_mut(index)
            .ok_or(export::Error::InvalidOptions)?;
        let previous = std::mem::replace(&mut column.source, source);
        if !self.valid() {
            self.manual.columns[index].source = previous;
            return Err(export::Error::InvalidOptions);
        }
        Ok(())
    }
    pub fn remove(&mut self, index: usize) -> bool {
        if self.profile.is_some() || index >= self.manual.columns.len() {
            return false;
        }
        self.manual.columns.remove(index);
        true
    }
    pub fn reorder(&mut self, from: usize, to: usize) -> bool {
        if self.profile.is_some()
            || from >= self.manual.columns.len()
            || to >= self.manual.columns.len()
            || from == to
        {
            return false;
        }
        let column = self.manual.columns.remove(from);
        self.manual.columns.insert(to, column);
        true
    }
    pub fn take_config(&mut self) -> Result<export::Csv, export::Error> {
        if !self.valid() {
            return Err(export::Error::InvalidOptions);
        }
        let config = if let Some(profile) = self.profile {
            export::Csv {
                profile: Some(profile.id().into()),
                delimiter: b',',
                header: true,
                columns: Vec::new(),
            }
        } else {
            std::mem::replace(&mut self.manual, Self::default().manual)
        };
        self.clear_sources();
        Ok(config)
    }
    pub fn sample(&self) -> Option<&Head> {
        self.sample.as_ref()
    }
    pub fn sources(&self) -> &[flow::FieldSource] {
        self.page.as_ref().map_or(&[], |page| page.items.as_slice())
    }
    pub fn start(&self) -> usize {
        self.start
    }
    pub fn next(&self) -> Option<usize> {
        self.page.as_ref().and_then(|page| page.next)
    }
    pub fn previous(&self) -> Option<usize> {
        self.start.checked_sub(flow::SOURCE_PAGE_SIZE)
    }
    pub fn waiting(&self) -> bool {
        self.expected.is_some()
    }
    pub fn clear_sources(&mut self) {
        self.sample = None;
        self.fields = 0;
        self.page = None;
        self.start = 0;
        self.expected = None;
    }
    pub fn begin_fields(&mut self, operation: u32, head: Head, start: usize, fields: usize) {
        if self.sample.as_ref() != Some(&head) {
            self.clear_sources();
        }
        self.sample = Some(head.clone());
        self.fields = fields;
        self.expected = Some((operation, head, start));
    }
    pub fn accept(
        &mut self,
        operation: u32,
        head: Head,
        start: usize,
        fields: flow::FieldSources,
    ) -> Result<bool, flow::Error> {
        let Some((expected, expected_head, expected_start)) = &self.expected else {
            return Ok(false);
        };
        if operation != *expected {
            return Ok(false);
        }
        let invalid = || flow::Error::App(confidex_app::Error::Integrity);
        if &head != expected_head
            || start != *expected_start
            || fields.items.len() > flow::SOURCE_PAGE_SIZE
            || (start > 0 && fields.items.is_empty())
            || fields.next.is_some_and(|next| {
                fields.items.len() != flow::SOURCE_PAGE_SIZE
                    || next.checked_sub(start) != Some(fields.items.len())
            })
            || fields.items.iter().any(|field| {
                field.index >= self.fields
                    || field.index >= confidex_vault::record::MAX_ENTRIES
                    || field.name.len() > 4096
                    || field.type_name.is_empty()
                    || field.type_name.len() > 64
                    || field.key.is_empty()
                    || field.key.len() > 4096
            })
            || fields.items.windows(2).any(|pair| {
                pair[0].index > pair[1].index
                    || pair[0].index == pair[1].index
                        && (pair[0].key >= pair[1].key
                            || pair[0].name != pair[1].name
                            || pair[0].type_name != pair[1].type_name)
            })
        {
            return Err(invalid());
        }
        self.page = Some(fields);
        self.start = start;
        self.expected = None;
        Ok(true)
    }
}

#[cfg(any(test, feature = "export-check"))]
pub fn check() {
    let mut state = State::default();
    assert!(!state.valid());
    state.manual.delimiter = b'|';
    state.manual.header = false;
    state.add("Same".into(), export::Source::Title).unwrap();
    state.add("Same".into(), export::Source::Tags).unwrap();
    assert!(
        state
            .add("Duplicate".into(), export::Source::Title)
            .is_err()
    );
    assert_eq!(state.manual.columns.len(), 2);
    assert!(state.set_source(1, export::Source::Title).is_err());
    assert!(matches!(
        state.manual.columns[1].source,
        export::Source::Tags
    ));
    assert!(state.reorder(0, 1));
    assert!(matches!(
        state.manual.columns[0].source,
        export::Source::Tags
    ));
    assert!(!state.reorder(0, 2));
    for profile in [Profile::Chromium, Profile::Firefox, Profile::ApplePasswords] {
        state.set_profile(Some(profile));
        let config = state.take_config().unwrap();
        assert_eq!(config.profile.as_deref(), Some(profile.id()));
        assert!(config.header && config.delimiter == b',' && config.columns.is_empty());
        confidex_app::import::formats::csv::Writer::new(config).unwrap();
        state.set_profile(None);
        assert_eq!(state.manual.delimiter, b'|');
        assert!(!state.manual.header);
        assert_eq!(state.manual.columns.len(), 2);
        assert!(
            state
                .manual
                .columns
                .iter()
                .all(|column| column.heading == "Same")
        );
    }
    state.manual.columns[0].heading = "\0".into();
    assert!(!state.valid());
    state.manual.columns[0].heading = "公開,\r\nHeader".into();
    assert!(state.remove(1));
    assert!(state.valid());
    let config = state.take_config().unwrap();
    assert_eq!(config.columns[0].heading, "公開,\r\nHeader");
    assert!(matches!(config.columns[0].source, export::Source::Tags));
    assert!(config.profile.is_none() && !config.header && config.delimiter == b'|');
    confidex_app::import::formats::csv::Writer::new(config).unwrap();
    assert!(!state.valid() && state.manual.columns.is_empty());
}

#[cfg(test)]
mod tests {
    use super::*;
    fn head() -> Head {
        Head {
            record: [1; 16],
            revision: [2; 32],
        }
    }
    fn page(start: usize, length: usize, next: Option<usize>) -> flow::FieldSources {
        serde_json::from_value(serde_json::json!({
            "items": (start..start+length).map(|index| serde_json::json!({"index":index,"name":"","type_name":"text/v1","key":"text"})).collect::<Vec<_>>(), "next":next,
        })).unwrap()
    }
    #[test]
    fn csv_configuration_preserves_manual_drafts_and_uses_the_real_writer() {
        check();
    }
    #[test]
    fn csv_sources_replace_one_page_and_keep_columns_unchanged() {
        let mut state = State::default();
        state
            .add("User heading".into(), export::Source::Title)
            .unwrap();
        state.begin_fields(1, head(), 0, 40);
        assert!(!state.valid());
        assert!(state.accept(1, head(), 0, page(0, 16, Some(16))).unwrap());
        assert!(state.valid());
        assert_eq!(state.sources().len(), 16);
        assert_eq!(state.next(), Some(16));
        assert_eq!(state.previous(), None);
        state.begin_fields(2, head(), 16, 40);
        assert!(state.accept(2, head(), 16, page(16, 16, Some(32))).unwrap());
        assert_eq!(state.sources()[0].index, 16);
        assert_eq!(state.previous(), Some(0));
        assert_eq!(state.next(), Some(32));
        assert_eq!(state.manual.columns[0].heading, "User heading");
        state.set_profile(Some(Profile::Firefox));
        assert!(state.sources().is_empty() && state.sample().is_none());
        assert!(!state.accept(2, head(), 16, page(16, 16, Some(32))).unwrap());
        state.set_profile(None);
        assert_eq!(state.manual.columns[0].heading, "User heading");
    }
    #[test]
    fn csv_sources_reject_bad_scope_bounds_order_and_cursors() {
        for case in 0..13 {
            let mut state = State::default();
            state.begin_fields(3, head(), 0, 40);
            let mut fields = page(0, 16, Some(16));
            let mut reply_head = head();
            let mut start = 0;
            match case {
                0 => reply_head.revision = [9; 32],
                1 => start = 1,
                2 => fields = page(0, 17, None),
                3 => fields.items[0].index = 40,
                4 => fields.items[0].name = "n".repeat(4097),
                5 => fields.items[0].type_name = "x".repeat(65),
                6 => fields.items[0].key = String::new(),
                7 => fields.next = Some(17),
                8 => fields.items[1].index = 0,
                9 => fields.items[1].index = 39,
                10 => fields.items[0].key = "k".repeat(4097),
                11 => fields.items[0].type_name.clear(),
                12 => {
                    state.fields = usize::MAX;
                    fields.items[0].index = confidex_vault::record::MAX_ENTRIES;
                }
                _ => unreachable!(),
            }
            assert!(
                state.accept(3, reply_head, start, fields).is_err(),
                "case {case}"
            );
            assert!(state.sources().is_empty());
        }
        let mut state = State::default();
        state.begin_fields(3, head(), 0, 40);
        assert!(!state.accept(2, head(), 0, page(0, 16, Some(16))).unwrap());
        assert!(state.waiting());
        state.clear_sources();
        assert!(!state.accept(3, head(), 0, page(0, 16, Some(16))).unwrap());
        assert!(state.sources().is_empty() && state.sample().is_none());
    }
}
