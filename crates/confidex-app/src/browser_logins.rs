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

#[derive(Clone, Deserialize, Serialize)]
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

#[derive(Clone, Default, Deserialize, Serialize)]
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

#[derive(Default)]
pub struct CaptureMatches {
    pub rows: Vec<Login>,
    pub issues: Issues,
    pub duplicate: bool,
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

#[derive(Serialize, ZeroizeOnDrop)]
pub struct FillLogin {
    pub username: Option<String>,
    pub password: Option<String>,
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

pub fn login_origin(input: &str) -> Result<String, Error> {
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
        self.browser_login_page(store, cursor, None).await
    }

    pub async fn find_browser_logins(
        &self,
        store: &mut impl Store,
        cursor: Option<Cursor>,
        origin: &str,
    ) -> Result<Page, Error> {
        let origin = login_origin(origin)?;
        self.browser_login_page(store, cursor, Some(&origin)).await
    }

    /// Resolve a remembered field against the current revision and exact origin.
    pub async fn recent_browser_login(
        &self,
        store: &mut impl Store,
        record: RecordId,
        field: usize,
        origin: &str,
    ) -> Result<Option<Login>, Error> {
        let vault = self.vault.as_ref().ok_or(Error::Locked)?;
        let head = match record_head(store, vault.vault_id(), record).await {
            Ok(Some(head)) => head,
            Ok(None) | Err(CONFLICT) => return Ok(None),
            Err(error) => return Err(error),
        };
        let Some(content) = read_record(store, vault, record, head.revision).await? else {
            return Ok(None);
        };
        let (mut candidates, _) = pairs(&content);
        Ok(candidates
            .find(|pair| pair.password == field && fill_values(&content, pair, origin).is_some())
            .map(|pair| preview(&content, &head, &pair, fields::count(&content))))
    }

    async fn browser_login_page(
        &self,
        store: &mut impl Store,
        cursor: Option<Cursor>,
        origin: Option<&str>,
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
                        && let Some(offset) =
                            append_previews(&record, &head, offset, &mut page, origin)
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
            && let Some(offset) = append_previews(&content, &head, offset, &mut page, None)
        {
            page.next = Some(Cursor { head, offset });
        }
        Ok(page)
    }

    pub async fn prepare_browser_fill(
        &self,
        store: &mut impl Store,
        target: &Selection,
        origin: &str,
        fill_username: bool,
        fill_password: bool,
    ) -> Result<FillLogin, Error> {
        let vault = self.vault.as_ref().ok_or(Error::Locked)?;
        let content = read_current_login(store, vault, &target.head).await?;
        let pair = login_pair(&content, target.field)?;
        let (username, password) = fill_values(&content, &pair, origin).ok_or(Error::Input)?;
        let username = fill_username
            .then(|| username.to_owned())
            .filter(|name| !name.is_empty());
        let password = fill_password.then(|| password.to_owned());
        if username.is_none() && password.is_none() {
            return Err(Error::Input);
        }
        Ok(FillLogin { username, password })
    }

    /// Compare full credentials in the vault. Only redacted previews leave this method.
    /// Without a username (a password change), consider every account on this origin.
    pub async fn match_browser_capture(
        &self,
        store: &mut impl Store,
        origin: &str,
        username: Option<&str>,
        password: &str,
        live: impl Fn() -> bool,
    ) -> Result<CaptureMatches, Error> {
        let vault = self.vault.as_ref().ok_or(Error::Locked)?;
        let mut result = CaptureMatches::default();
        let mut after = None;
        loop {
            if !live() {
                return Err(Error::Input);
            }
            let heads = store
                .branch_heads(vault.vault_id(), after.as_ref(), None)
                .await?;
            for head in &heads {
                if !live() {
                    return Err(Error::Input);
                }
                let Some(record) = read_record(store, vault, head.record, head.revision).await?
                else {
                    continue;
                };
                let (pairs, ambiguous) = pairs(&record);
                result.issues.ambiguous |= ambiguous && has_separate_origin(&record, origin);
                let fields = std::cell::LazyCell::new(|| fields::count(&record));
                let mut current = None;
                for pair in pairs {
                    if !matches_origin(&record, &pair, origin) {
                        continue;
                    }
                    let saved_password = text(&record.entries[pair.password], "password");
                    let saved_username = text(&record.entries[pair.username], "username");
                    if username.is_some() && saved_username != username {
                        continue;
                    }
                    if current.is_none() {
                        current = Some(
                            match record_head(store, vault.vault_id(), head.record).await {
                                Ok(Some(current)) => current == *head,
                                Ok(None) => false,
                                Err(CONFLICT) => {
                                    result.issues.conflicts = true;
                                    false
                                }
                                Err(error) => return Err(error),
                            },
                        );
                    }
                    if current == Some(false) {
                        break;
                    }
                    if saved_password == Some(password) {
                        if username.is_some() {
                            result.duplicate = true;
                            return Ok(result);
                        }
                        continue;
                    }
                    if result.rows.len() == PAGE_SIZE {
                        result.issues.ambiguous = true;
                        return Ok(result);
                    }
                    let mut row = preview(&record, head, &pair, *fields);
                    // Up to ten offers can share one session reply. Bound the
                    // display strings independently of the full comparisons.
                    for value in [&mut row.title, &mut row.username] {
                        let short = value.chars().filter(|c| !c.is_control()).take(60).collect();
                        value.zeroize();
                        *value = short;
                    }
                    result.rows.push(row);
                }
            }
            if heads.len() < confidex_storage::PAGE_SIZE {
                return Ok(result);
            }
            after = heads.into_iter().last();
        }
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
        self.create_browser_login_if(store, record, login, epoch, || true)
            .await
    }

    pub async fn create_browser_login_if(
        &mut self,
        store: &mut impl Store,
        record: RecordId,
        login: &NewLogin,
        epoch: u64,
        live: impl Fn() -> bool,
    ) -> Result<Head, Error> {
        let vault = self.vault.as_ref().ok_or(Error::Locked)?;
        let content = new_content(login)?;
        let revision = append_if(
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
            live,
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
        self.update_browser_login_if(store, target, change, epoch, || true)
            .await
    }

    pub async fn update_browser_login_if(
        &mut self,
        store: &mut impl Store,
        target: &Selection,
        change: &Change,
        epoch: u64,
        live: impl Fn() -> bool,
    ) -> Result<Head, Error> {
        let vault = self.vault.as_ref().ok_or(Error::Locked)?;
        let Head { record, revision } = target.head;
        let mut content = read_current_login(store, vault, &target.head).await?;
        update_content(&mut content, target.field, change)?;
        let revision = append_if(
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
            live,
        )
        .await?;
        self.search = None;
        self.export_session = None;
        Ok(Head { record, revision })
    }
}

fn fill_values<'a>(record: &'a Record, pair: &Pair, origin: &str) -> Option<(&'a str, &'a str)> {
    if !matches_origin(record, pair, origin) {
        return None;
    }
    let password =
        text(&record.entries[pair.password], "password").filter(|p| valid_password(p))?;
    // A protected username is never copied into preview metadata or filled.
    let username = editable_text(&record.entries[pair.username], "username").unwrap_or("");
    Some((username, password))
}

fn matches_origin(record: &Record, pair: &Pair, origin: &str) -> bool {
    text(&record.entries[pair.url], "url")
        .and_then(|url| login_origin(url).ok())
        .as_deref()
        == Some(origin)
}

fn append_previews(
    record: &Record,
    head: &Head,
    offset: usize,
    page: &mut Page,
    origin: Option<&str>,
) -> Option<usize> {
    let (pairs, ambiguous) = pairs(record);
    page.issues.ambiguous |=
        ambiguous && origin.is_none_or(|origin| has_separate_origin(record, origin));
    let fields = fields::count(record);
    for (index, pair) in pairs.enumerate().skip(offset) {
        if origin.is_some_and(|origin| fill_values(record, &pair, origin).is_none()) {
            continue;
        }
        if page.rows.len() == PAGE_SIZE {
            return Some(index);
        }
        page.rows.push(preview(record, head, &pair, fields));
    }
    None
}

fn has_separate_origin(record: &Record, origin: &str) -> bool {
    record.entries.iter().any(|entry| {
        entry.type_name == "url/v1"
            && text(entry, "url")
                .and_then(|url| login_origin(url).ok())
                .as_deref()
                == Some(origin)
    })
}

fn preview(record: &Record, head: &Head, pair: &Pair, fields: usize) -> Login {
    Login {
        target: Selection {
            head: head.clone(),
            field: pair.password,
        },
        fields,
        title: record
            .extra
            .get(TITLE_KEY)
            .and_then(Value::as_str)
            .unwrap_or("")
            .chars()
            .take(128)
            .collect(),
        username: unprotected_text(&record.entries[pair.username], "username")
            .unwrap_or("")
            .chars()
            .take(128)
            .collect(),
    }
}

#[cfg(test)]
mod tests;
