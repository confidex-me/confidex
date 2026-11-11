//! CSV setup receives field bindings, never field values.
use super::*;

// Names and component keys can expand sixfold in JSON.
pub const SOURCE_PAGE_SIZE: usize = 16;

#[derive(Serialize, Deserialize)]
pub struct FieldSource {
    pub index: usize,
    pub name: String,
    pub type_name: String,
    pub key: String,
}
impl Drop for FieldSource {
    fn drop(&mut self) {
        self.name.zeroize();
        self.type_name.zeroize();
        self.key.zeroize();
    }
}
#[derive(Serialize, Deserialize)]
pub struct FieldSources {
    pub items: Vec<FieldSource>,
    pub next: Option<usize>,
    #[serde(skip)]
    _memory: Option<crate::import::Reservation>,
}

impl Engine {
    pub async fn export_fields(
        &mut self,
        store: &mut impl Store,
        head: &Head,
        start: usize,
        control: &mut impl Control,
    ) -> Result<FieldSources, Error> {
        self.begin_export()?;
        let vault = self.vault.as_ref().ok_or(AppError::Locked)?;
        check_heads(
            store,
            vault.vault_id(),
            false,
            std::slice::from_ref(head),
            control,
        )
        .await?;
        let memory = crate::import::Memory::new(export::Limits::default().memory_bytes);
        let labels = memory.reserve(1 << 20).map_err(|_| export::Error::Limit)?;
        let _wire = memory
            .reserve(confidex_storage::MAX_OBJECT)
            .map_err(|_| export::Error::Limit)?;
        let wire = store.object(vault.vault_id(), head.revision).await?;
        if wire.len() > confidex_storage::MAX_OBJECT {
            return Err(export::Error::Limit.into());
        }
        let verified = envelope::verify(
            &wire,
            vault.anchor(),
            Some(&head.revision),
            memory.available(),
        )
        .map_err(envelope_error)?;
        if verified.header().record_id != head.record {
            return Err(AppError::Integrity.into());
        }
        if verified.header().kind == envelope::EventKind::Deletion {
            return Err(Error::InvalidSelection);
        }
        let record = verified
            .open(vault.keys(), memory.available())
            .map_err(envelope_error)?;
        let mut sources = record
            .entries
            .iter()
            .enumerate()
            .flat_map(|(index, entry)| {
                entry.value.keys().filter_map(move |key| {
                    (!entry.type_name.is_empty()
                        && entry.type_name.len() <= 64
                        && !key.is_empty()
                        && key.len() <= 4096)
                        .then_some((index, entry, key))
                })
            });
        for _ in 0..start {
            if sources.next().is_none() {
                return Err(Error::InvalidSelection);
            }
        }
        let mut items = Vec::new();
        items
            .try_reserve_exact(SOURCE_PAGE_SIZE)
            .map_err(|_| export::Error::Allocation)?;
        for (index, entry, key) in sources.by_ref().take(SOURCE_PAGE_SIZE) {
            let mut end = entry.name.len().min(4096);
            while !entry.name.is_char_boundary(end) {
                end -= 1;
            }
            items.push(FieldSource {
                index,
                name: entry.name[..end].into(),
                type_name: entry.type_name.clone(),
                key: key.clone(),
            });
        }
        let next = sources.next().is_some().then_some(start + items.len());
        check_heads(
            store,
            vault.vault_id(),
            false,
            std::slice::from_ref(head),
            control,
        )
        .await?;
        Ok(FieldSources {
            items,
            next,
            _memory: Some(labels),
        })
    }
}
