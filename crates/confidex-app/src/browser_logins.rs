//! Narrow access to browser logins without projecting or rewriting other fields.
use super::*;
use zeroize::ZeroizeOnDrop;

const PAGE_SIZE: usize = 128;
const CONFLICT: Error = Error::Storage(confidex_storage::Error::Conflict);
pub const MAX_LOGIN_TEXT: usize = 4096;

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Selection {
    pub head: Head,
    // Index of the password's source entry in this exact revision.
    pub field: usize,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Cursor {
    pub head: Head,
    // Zero advances past the head. A positive offset resumes within its revision.
    pub offset: usize,
}

#[derive(Deserialize, Serialize)]
pub struct Login {
    pub target: Selection,
    pub title: String,
    pub username: String,
    pub fields: usize,
}

impl Drop for Login {
    fn drop(&mut self) {
        self.title.zeroize();
        self.username.zeroize();
    }
}

#[derive(Default, Deserialize, Serialize)]
pub struct Issues {
    pub ambiguous: bool,
    pub conflicts: bool,
}

#[derive(Deserialize, Serialize)]
pub struct Page {
    pub rows: Vec<Login>,
    pub next: Option<Cursor>,
    pub issues: Issues,
}

#[derive(Default, Deserialize, Serialize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
pub struct NewLogin {
    pub title: String,
    pub url: String,
    pub username: String,
    pub password: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub notes: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
}

impl NewLogin {
    pub fn has_valid_lengths(&self) -> bool {
        !self.title.trim().is_empty()
            && self.title.len() <= MAX_LOGIN_TEXT
            && !self.url.trim().is_empty()
            && self.url.len() <= MAX_LOGIN_TEXT
            && self.username.len() <= MAX_LOGIN_TEXT
            && valid_password(&self.password)
            && self.notes.len() <= MAX_LOGIN_TEXT
    }
}

/// The saved values the session editor can display. Passwords stay in the worker.
#[derive(Deserialize, Serialize, ZeroizeOnDrop)]
pub struct EditLogin {
    pub title: String,
    pub username: Option<String>,
    pub url: Option<String>,
    pub notes: Option<String>,
    pub tags: Vec<String>,
}

#[derive(Default, Deserialize, Serialize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
pub struct Change {
    pub title: Option<String>,
    pub username: Option<String>,
    pub password: Option<String>,
    pub url: Option<String>,
    pub notes: Option<String>,
    pub tags: Option<Vec<String>>,
}

struct Pair {
    username: usize,
    password: usize,
    url: usize,
}

fn text<'a>(entry: &'a Entry, key: &str) -> Option<&'a str> {
    entry.value.get(key).map_or(Some(""), Value::as_str)
}

fn pairs(record: &Record) -> (impl Iterator<Item = Pair> + '_, bool) {
    let mut separate = [None; 3];
    let mut repeated = false;
    for (index, entry) in record.entries.iter().enumerate() {
        let slot = match entry.type_name.as_str() {
            "username/v1" => &mut separate[0],
            "password/v1" => &mut separate[1],
            "url/v1" => &mut separate[2],
            _ => continue,
        };
        repeated |= slot.replace(index).is_some();
    }
    let [username, password, url] = separate;
    let ambiguous = repeated && separate.iter().all(Option::is_some);
    let separate = match (repeated, username, password, url) {
        (false, Some(username), Some(password), Some(url))
            if text(&record.entries[username], "username").is_some()
                && nonempty(&record.entries[password], "password")
                && nonempty(&record.entries[url], "url") =>
        {
            Some(Pair {
                username,
                password,
                url,
            })
        }
        _ => None,
    };
    let compound = record
        .entries
        .iter()
        .enumerate()
        .filter_map(|(index, entry)| {
            (entry.type_name == "login/v1"
                && text(entry, "username").is_some()
                && nonempty(entry, "password")
                && nonempty(entry, "url"))
            .then_some(Pair {
                username: index,
                password: index,
                url: index,
            })
        });
    (compound.chain(separate), ambiguous)
}

fn nonempty(entry: &Entry, key: &str) -> bool {
    text(entry, key).is_some_and(|value| !value.is_empty())
}

fn replace(record: &mut Record, field: usize, key: &str, value: &str, retired: &mut Record) {
    if let Some(old) = record.entries[field]
        .value
        .insert(key.into(), Value::from(value))
    {
        // Record wipes displaced values, including the old password.
        retired.extra.insert(key.into(), old);
    }
}

fn new_content(login: &NewLogin) -> Result<Record, Error> {
    if !login.has_valid_lengths() {
        return Err(Error::Input);
    }
    let origin = login_origin(&login.url)?;
    let template = templates::get("login").ok_or(Error::Integrity)?;
    let mut fields = template.fields()?;
    for field in &mut fields {
        let (key, value) = match field.type_name.as_str() {
            "username/v1" => ("username", login.username.as_str()),
            "password/v1" => ("password", login.password.as_str()),
            "url/v1" => ("url", origin.as_str()),
            "note/v1" => ("text", login.notes.as_str()),
            _ => continue,
        };
        field.values.insert(key.into(), value.into());
    }
    let mut record = Record::default();
    set_tags(&mut record, &login.tags)?;
    sections::apply(&mut record, Some(&template.sections()), fields.len())?;
    fields::apply(&mut record, &fields)?;
    record
        .extra
        .insert(TITLE_KEY.into(), Value::from(login.title.trim()));
    Ok(record)
}

fn login_origin(input: &str) -> Result<String, Error> {
    let url = url::Url::parse(input.trim()).map_err(|_| Error::Input)?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return Err(Error::Input);
    }
    Ok(url.origin().ascii_serialization())
}

fn valid_password(password: &str) -> bool {
    !password.is_empty() && password.len() <= MAX_LOGIN_TEXT
}

fn set_tags(record: &mut Record, tags: &[String]) -> Result<(), Error> {
    let mut sorted = Zeroizing::new(tags.to_vec());
    sorted.sort_unstable();
    if !confidex_storage::valid_tags(&sorted) {
        return Err(Error::Input);
    }
    std::mem::swap(&mut record.tags, &mut sorted);
    Ok(())
}

fn login_pair(record: &Record, field: usize) -> Result<Pair, Error> {
    pairs(record)
        .0
        .find(|pair| pair.password == field)
        .ok_or(Error::Input)
}

fn unprotected_text<'a>(entry: &'a Entry, key: &str) -> Option<&'a str> {
    if field_protected(entry) {
        return None;
    }
    text(entry, key)
}

fn editable_text<'a>(entry: &'a Entry, key: &str) -> Option<&'a str> {
    unprotected_text(entry, key).filter(|value| value.len() <= MAX_LOGIN_TEXT)
}

// An unambiguous ordinary note is record-wide, even for a compound login.
fn note_field(record: &Record) -> Result<Option<usize>, Error> {
    let mut notes = record
        .entries
        .iter()
        .enumerate()
        .filter(|(_, entry)| entry.type_name == "note/v1");
    match notes.next() {
        Some((index, entry))
            if notes.next().is_none() && editable_text(entry, "text").is_some() =>
        {
            Ok(Some(index))
        }
        None if record.entries.len() < confidex_vault::record::MAX_ENTRIES => Ok(None),
        _ => Err(Error::Input),
    }
}

fn editor_content(mut record: Record, field: usize) -> Result<EditLogin, Error> {
    let pair = login_pair(&record, field)?;
    let username = editable_text(&record.entries[pair.username], "username").map(str::to_owned);
    let url = editable_text(&record.entries[pair.url], "url").map(str::to_owned);
    let notes = note_field(&record).ok().map(|index| {
        index
            .and_then(|i| text(&record.entries[i], "text"))
            .unwrap_or("")
            .to_owned()
    });
    Ok(EditLogin {
        title: title(&record)?,
        username,
        url,
        notes,
        tags: std::mem::take(&mut record.tags),
    })
}

fn update_content(record: &mut Record, field: usize, change: &Change) -> Result<(), Error> {
    let pair = login_pair(record, field)?;
    if change
        .title
        .as_ref()
        .is_some_and(|title| title.trim().is_empty() || title.len() > MAX_LOGIN_TEXT)
        || change
            .password
            .as_deref()
            .is_some_and(|password| !valid_password(password))
        || change.username.as_ref().is_some_and(|name| {
            name.len() > MAX_LOGIN_TEXT
                || editable_text(&record.entries[pair.username], "username").is_none()
        })
        || change.url.as_ref().is_some_and(|url| {
            url.len() > MAX_LOGIN_TEXT || editable_text(&record.entries[pair.url], "url").is_none()
        })
        || change
            .notes
            .as_ref()
            .is_some_and(|notes| notes.len() > MAX_LOGIN_TEXT)
        || (change.title.is_none()
            && change.username.is_none()
            && change.password.is_none()
            && change.url.is_none()
            && change.notes.is_none()
            && change.tags.is_none())
    {
        return Err(Error::Input);
    }
    let origin = change.url.as_deref().map(login_origin).transpose()?;
    let note = change
        .notes
        .as_ref()
        .map(|_| note_field(record))
        .transpose()?
        .flatten();
    let mut retired = Record::default();
    if let Some(tags) = &change.tags {
        set_tags(record, tags)?;
    }
    if let Some(title) = &change.title
        && let Some(old) = record
            .extra
            .insert(TITLE_KEY.into(), Value::from(title.trim()))
    {
        retired.extra.insert(TITLE_KEY.into(), old);
    }
    if let Some(username) = &change.username {
        replace(record, pair.username, "username", username, &mut retired);
    }
    if let Some(password) = &change.password {
        replace(record, pair.password, "password", password, &mut retired);
    }
    if let Some(origin) = origin {
        replace(record, pair.url, "url", &origin, &mut retired);
    }
    if let Some(notes) = &change.notes {
        if let Some(index) = note {
            replace(record, index, "text", notes, &mut retired);
        } else {
            let mut note = template("login")?
                .into_iter()
                .find(|field| field.type_name == "note/v1")
                .ok_or(Error::Integrity)?;
            note.values.insert("text".into(), notes.clone());
            record.entries.append(&mut field_record(&note)?.entries);
        }
    }
    Ok(())
}

async fn read_current_login(
    store: &mut impl Store,
    vault: &lock::OpenedVault,
    head: &Head,
) -> Result<Record, Error> {
    if record_head(store, vault.vault_id(), head.record)
        .await?
        .as_ref()
        != Some(head)
    {
        return Err(CONFLICT);
    }
    read_record(store, vault, head.record, head.revision)
        .await?
        .ok_or(CONFLICT)
}

impl Engine {
    pub async fn browser_logins(
        &self,
        store: &mut impl Store,
        cursor: Option<Cursor>,
    ) -> Result<Page, Error> {
        let vault = self.vault.as_ref().ok_or(Error::Locked)?;
        let heads = store
            .branch_heads(vault.vault_id(), cursor.as_ref().map(|c| &c.head), None)
            .await?;
        let mut page = Page {
            rows: Vec::new(),
            next: None,
            issues: Issues::default(),
        };
        let resume = cursor.filter(|cursor| cursor.offset > 0);
        let mut last = None;
        for (head, offset) in resume
            .into_iter()
            .map(|cursor| (cursor.head, cursor.offset))
            .chain(heads.iter().cloned().map(|head| (head, 0)))
        {
            if page.rows.len() == PAGE_SIZE {
                page.next = last;
                return Ok(page);
            }
            match record_head(store, vault.vault_id(), head.record).await {
                Err(CONFLICT) => page.issues.conflicts = true,
                Err(error) => return Err(error),
                Ok(Some(current)) if current == head => {
                    if let Some(record) =
                        read_record(store, vault, head.record, head.revision).await?
                        && let Some(offset) = append_previews(&record, &head, offset, &mut page)
                    {
                        page.next = Some(Cursor { head, offset });
                        return Ok(page);
                    }
                }
                Ok(_) => {}
            }
            last = Some(Cursor { head, offset: 0 });
        }
        if heads.len() == confidex_storage::PAGE_SIZE {
            page.next = last;
        }
        Ok(page)
    }

    pub async fn browser_login_choices(
        &self,
        store: &mut impl Store,
        record: RecordId,
        after: Option<Cursor>,
    ) -> Result<Page, Error> {
        let vault = self.vault.as_ref().ok_or(Error::Locked)?;
        let mut page = Page {
            rows: Vec::new(),
            next: None,
            issues: Issues::default(),
        };
        let head = match record_head(store, vault.vault_id(), record).await {
            Ok(Some(head)) => head,
            Ok(None) => return Ok(page),
            Err(CONFLICT) => {
                page.issues.conflicts = true;
                return Ok(page);
            }
            Err(error) => return Err(error),
        };
        let offset = after
            .filter(|cursor| cursor.head == head)
            .map_or(0, |cursor| cursor.offset);
        if let Some(content) = read_record(store, vault, record, head.revision).await?
            && let Some(offset) = append_previews(&content, &head, offset, &mut page)
        {
            page.next = Some(Cursor { head, offset });
        }
        Ok(page)
    }

    pub async fn browser_login_editor(
        &self,
        store: &mut impl Store,
        target: &Selection,
    ) -> Result<EditLogin, Error> {
        let vault = self.vault.as_ref().ok_or(Error::Locked)?;
        let content = read_current_login(store, vault, &target.head).await?;
        editor_content(content, target.field)
    }

    pub async fn create_browser_login(
        &mut self,
        store: &mut impl Store,
        record: RecordId,
        login: &NewLogin,
        epoch: u64,
    ) -> Result<Head, Error> {
        let vault = self.vault.as_ref().ok_or(Error::Locked)?;
        let content = new_content(login)?;
        let revision = append(
            store,
            vault,
            &content,
            Options {
                vault_id: vault.vault_id(),
                record_id: record,
                parents: &[],
                epoch,
                kind: EventKind::Content,
            },
            ParentCheck::OnlyCurrent,
        )
        .await?;
        self.search = None;
        self.export_session = None;
        Ok(Head { record, revision })
    }

    pub async fn update_browser_login(
        &mut self,
        store: &mut impl Store,
        target: &Selection,
        change: &Change,
        epoch: u64,
    ) -> Result<Head, Error> {
        let vault = self.vault.as_ref().ok_or(Error::Locked)?;
        let Head { record, revision } = target.head;
        let mut content = read_current_login(store, vault, &target.head).await?;
        update_content(&mut content, target.field, change)?;
        let revision = append(
            store,
            vault,
            &content,
            Options {
                vault_id: vault.vault_id(),
                record_id: record,
                parents: &[revision],
                epoch,
                kind: EventKind::Content,
            },
            ParentCheck::OnlyCurrent,
        )
        .await?;
        self.search = None;
        self.export_session = None;
        Ok(Head { record, revision })
    }
}

fn append_previews(record: &Record, head: &Head, offset: usize, page: &mut Page) -> Option<usize> {
    let (pairs, ambiguous) = pairs(record);
    page.issues.ambiguous |= ambiguous;
    let title = record
        .extra
        .get(TITLE_KEY)
        .and_then(Value::as_str)
        .unwrap_or("");
    let fields = fields::count(record);
    for (index, pair) in pairs.enumerate().skip(offset) {
        if page.rows.len() == PAGE_SIZE {
            return Some(index);
        }
        page.rows.push(Login {
            target: Selection {
                head: head.clone(),
                field: pair.password,
            },
            fields,
            title: title.chars().take(128).collect(),
            username: unprotected_text(&record.entries[pair.username], "username")
                .unwrap_or("")
                .chars()
                .take(128)
                .collect(),
        });
    }
    None
}

#[cfg(test)]
mod tests;
