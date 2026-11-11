use super::{Error, Id};
use rusqlite::{Connection, OptionalExtension, params};
use zeroize::Zeroizing;

pub(super) struct Backend(Connection);
fn error(_: rusqlite::Error) -> Error {
    Error::Storage(confidex_storage::Error::Storage)
}
// Encode UTF-8 terms to keep SQLite Unicode tables out of tokenization.
fn token(word: &str) -> String {
    std::iter::once('u')
        .chain(word.bytes().flat_map(|byte| {
            [
                char::from(b'a' + (byte >> 4)),
                char::from(b'a' + (byte & 15)),
            ]
        }))
        .collect()
}
impl Backend {
    pub fn new() -> Result<Self, Error> {
        let conn = Connection::open_in_memory().map_err(error)?;
        conn.execute_batch(
            "PRAGMA temp_store=MEMORY;
            PRAGMA max_page_count=16384;
            CREATE TABLE documents(id INTEGER PRIMARY KEY, record BLOB NOT NULL UNIQUE);
            CREATE VIRTUAL TABLE search USING fts5(terms, content='', contentless_delete=1,
                detail=none, tokenize='ascii', prefix='3 5 7');",
        )
        .map_err(error)?;
        Ok(Self(conn))
    }
    pub fn remove(&mut self, record: Id) -> Result<(), Error> {
        let tx = self.0.transaction().map_err(error)?;
        tx.execute(
            "DELETE FROM search WHERE rowid=(SELECT id FROM documents WHERE record=?1)",
            [record.as_slice()],
        )
        .map_err(error)?;
        tx.execute("DELETE FROM documents WHERE record=?1", [record.as_slice()])
            .map_err(error)?;
        tx.commit().map_err(error)
    }
    pub fn replace(&mut self, record: Id, terms: &[String]) -> Result<(), Error> {
        let text = Zeroizing::new(
            terms
                .iter()
                .map(|word| token(word))
                .collect::<Vec<_>>()
                .join(" "),
        );
        let tx = self.0.transaction().map_err(error)?;
        let existing: Option<i64> = tx
            .query_row(
                "SELECT id FROM documents WHERE record=?1",
                [record.as_slice()],
                |r| r.get(0),
            )
            .optional()
            .map_err(error)?;
        let id = if let Some(id) = existing {
            id
        } else {
            tx.execute(
                "INSERT INTO documents(record) VALUES(?1)",
                [record.as_slice()],
            )
            .map_err(error)?;
            tx.last_insert_rowid()
        };
        tx.execute(
            "INSERT OR REPLACE INTO search(rowid,terms) VALUES(?1,?2)",
            params![id, text.as_str()],
        )
        .map_err(error)?;
        tx.commit().map_err(error)
    }
    pub fn search(&self, terms: &[String]) -> Result<Vec<Id>, Error> {
        let query = Zeroizing::new(
            terms
                .iter()
                .enumerate()
                .map(|(i, term)| {
                    format!(
                        "\"{}\"{}",
                        token(term),
                        if i + 1 == terms.len() { "*" } else { "" }
                    )
                })
                .collect::<Vec<_>>()
                .join(" AND "),
        );
        let mut stmt = self.0.prepare("SELECT documents.record FROM search
            JOIN documents ON documents.id=search.rowid WHERE search MATCH ?1 ORDER BY documents.record")
            .map_err(error)?;
        let rows = stmt
            .query_map([query.as_str()], |row| {
                let bytes: Vec<u8> = row.get(0)?;
                bytes.try_into().map_err(|_| rusqlite::Error::InvalidQuery)
            })
            .map_err(error)?;
        rows.collect::<Result<Vec<Id>, _>>().map_err(error)
    }
}
