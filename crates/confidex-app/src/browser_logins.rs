//! Narrow access to browser logins without projecting or rewriting other fields.
use super::*;
use zeroize::ZeroizeOnDrop;

const PAGE_SIZE: usize = 128;
const CONFLICT: Error = Error::Storage(confidex_storage::Error::Conflict);
pub const MAX_LOGIN_TEXT: usize = 4096;

#[derive(Clone, Deserialize, Serialize)]
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
}

#[derive(Deserialize, Serialize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
pub struct Change {
    pub username: Option<String>,
    pub password: String,
}

struct Pair {
    username: usize,
    password: usize,
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
            Some(Pair { username, password })
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
    let title = login.title.trim();
    if title.is_empty()
        || title.len() > MAX_LOGIN_TEXT
        || login.username.len() > MAX_LOGIN_TEXT
        || login.url.len() > MAX_LOGIN_TEXT
        || !valid_password(&login.password)
    {
        return Err(Error::Input);
    }
    let url = url::Url::parse(login.url.trim()).map_err(|_| Error::Input)?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return Err(Error::Input);
    }
    let origin = url.origin().ascii_serialization();
    let template = templates::get("login").ok_or(Error::Integrity)?;
    let mut fields = template.fields()?;
    for field in &mut fields {
        let (key, value) = match field.type_name.as_str() {
            "username/v1" => ("username", login.username.as_str()),
            "password/v1" => ("password", login.password.as_str()),
            "url/v1" => ("url", origin.as_str()),
            _ => continue,
        };
        field.values.insert(key.into(), value.into());
    }
    let mut record = Record::default();
    sections::apply(&mut record, Some(&template.sections()), fields.len())?;
    fields::apply(&mut record, &fields)?;
    record.extra.insert(TITLE_KEY.into(), Value::from(title));
    Ok(record)
}

fn valid_password(password: &str) -> bool {
    !password.is_empty() && password.len() <= MAX_LOGIN_TEXT
}

fn update_content(record: &mut Record, field: usize, change: &Change) -> Result<(), Error> {
    if !valid_password(&change.password)
        || change
            .username
            .as_ref()
            .is_some_and(|name| name.len() > MAX_LOGIN_TEXT)
    {
        return Err(Error::Input);
    }
    let pair = pairs(record)
        .0
        .find(|pair| pair.password == field)
        .ok_or(Error::Input)?;
    let mut retired = Record::default();
    if let Some(username) = &change.username {
        replace(record, pair.username, "username", username, &mut retired);
    }
    replace(
        record,
        pair.password,
        "password",
        &change.password,
        &mut retired,
    );
    Ok(())
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
        if record_head(store, vault.vault_id(), record).await?.as_ref() != Some(&target.head) {
            return Err(CONFLICT);
        }
        let mut content = read_record(store, vault, record, revision)
            .await?
            .ok_or(CONFLICT)?;
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
    for (index, pair) in pairs.enumerate().skip(offset) {
        if page.rows.len() == PAGE_SIZE {
            return Some(index);
        }
        page.rows.push(Login {
            target: Selection {
                head: head.clone(),
                field: pair.password,
            },
            title: title.chars().take(128).collect(),
            username: text(&record.entries[pair.username], "username")
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
