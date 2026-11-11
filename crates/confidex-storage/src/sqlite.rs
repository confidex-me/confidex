use crate::*;
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use std::{path::Path, time::Duration};

pub struct SqliteStore(Connection);
fn sql(_: rusqlite::Error) -> Error {
    Error::Storage
}
fn fixed<const N: usize>(value: Vec<u8>) -> rusqlite::Result<[u8; N]> {
    value.try_into().map_err(|_| rusqlite::Error::InvalidQuery)
}
impl SqliteStore {
    pub fn open(path: &Path) -> Result<Self, Error> {
        // SQLite 3.51.3 fixes the WAL-reset race between independent writers.
        if rusqlite::version_number() < 3_051_003 {
            return Err(Error::Version);
        }
        let mut db = Connection::open(path).map_err(sql)?;
        db.busy_timeout(Duration::from_secs(5)).map_err(sql)?;
        db.pragma_update(None, "journal_mode", "WAL").map_err(sql)?;
        db.pragma_update(None, "synchronous", "FULL").map_err(sql)?;
        db.pragma_update(None, "foreign_keys", true).map_err(sql)?;
        let tx = db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sql)?;
        let version: u32 = tx
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .map_err(sql)?;
        if version > 5 {
            return Err(Error::Version);
        }
        tx.execute_batch("CREATE TABLE IF NOT EXISTS vaults (
            id BLOB PRIMARY KEY CHECK(length(id)=16), name TEXT NOT NULL,
            lock BLOB NOT NULL CHECK(length(lock)<=344));
            CREATE TABLE IF NOT EXISTS objects (
            vault BLOB NOT NULL REFERENCES vaults(id), record BLOB NOT NULL,
            revision BLOB NOT NULL CHECK(length(revision)=32), wire BLOB NOT NULL,
            PRIMARY KEY(vault,revision));
            CREATE TABLE IF NOT EXISTS heads (
            vault BLOB NOT NULL REFERENCES vaults(id), record BLOB NOT NULL CHECK(length(record)=16),
            revision BLOB NOT NULL, PRIMARY KEY(vault,record),
            FOREIGN KEY(vault,revision) REFERENCES objects(vault,revision));
            CREATE TABLE IF NOT EXISTS sync_state (
            vault BLOB PRIMARY KEY REFERENCES vaults(id), checkpoint BLOB NOT NULL);
            CREATE TABLE IF NOT EXISTS record_tags (
            vault BLOB NOT NULL, record BLOB NOT NULL, revision BLOB NOT NULL,
            tag TEXT NOT NULL CHECK(length(CAST(tag AS BLOB))<=256),
            PRIMARY KEY(vault,revision,tag),
            FOREIGN KEY(vault,revision) REFERENCES objects(vault,revision));
            CREATE INDEX IF NOT EXISTS tags_search ON record_tags(vault,tag,record,revision);").map_err(sql)?;
        if version < 4 {
            tx.execute_batch("ALTER TABLE vaults ADD COLUMN removing INTEGER NOT NULL DEFAULT 0 CHECK(removing IN (0,1));").map_err(sql)?;
        }
        if version < 5 {
            tx.execute_batch("CREATE TABLE heads_v5 (
                vault BLOB NOT NULL REFERENCES vaults(id), record BLOB NOT NULL CHECK(length(record)=16),
                revision BLOB NOT NULL, PRIMARY KEY(vault,record,revision),
                FOREIGN KEY(vault,revision) REFERENCES objects(vault,revision));
                INSERT INTO heads_v5 SELECT vault,record,revision FROM heads;
                DROP TABLE heads;
                ALTER TABLE heads_v5 RENAME TO heads;").map_err(sql)?;
        }
        tx.pragma_update(None, "user_version", 5).map_err(sql)?;
        for table in ["objects", "heads", "record_tags", "sync_state"] {
            for action in ["INSERT", "UPDATE"] {
                tx.execute_batch(&format!("CREATE TRIGGER IF NOT EXISTS {table}_removing_{action} BEFORE {action} ON {table} WHEN EXISTS(SELECT 1 FROM vaults WHERE id=NEW.vault AND removing=1) BEGIN SELECT RAISE(ABORT,'vault removal in progress'); END;")).map_err(sql)?;
            }
        }
        tx.commit().map_err(sql)?;
        Ok(Self(db))
    }
    pub fn sqlite_version(&self) -> &'static str {
        rusqlite::version()
    }

    /// Read branch tips in record and revision order.
    pub async fn branch_heads(
        &mut self,
        vault: VaultId,
        after: Option<&Head>,
        tag: Option<&str>,
    ) -> Result<Vec<Head>, Error> {
        if tag.is_some_and(|tag| tag.len() > 256) {
            return Err(Error::Limit);
        }
        let mut statement = self
            .0
            .prepare(
                "SELECT h.record,h.revision FROM heads h
            WHERE h.vault=?1 AND (?2 IS NULL OR (h.record,h.revision)>(?2,?3))
            AND (?4 IS NULL OR EXISTS(SELECT 1 FROM record_tags t WHERE t.vault=h.vault
                AND t.record=h.record AND t.revision=h.revision AND t.tag=?4))
            ORDER BY h.record,h.revision LIMIT 128",
            )
            .map_err(sql)?;
        statement
            .query_map(
                params![
                    vault.as_slice(),
                    after.map(|h| h.record.as_slice()),
                    after.map(|h| h.revision.as_slice()),
                    tag
                ],
                |row| {
                    Ok(Head {
                        record: fixed(row.get(0)?)?,
                        revision: fixed(row.get(1)?)?,
                    })
                },
            )
            .map_err(sql)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(sql)
    }

    /// Publish verified objects and replace only the expected branch tips.
    pub async fn publish_branches(
        &mut self,
        vault: VaultId,
        commit: &SyncCommit,
    ) -> Result<(), Error> {
        self.commit_sync(vault, commit, true)
    }

    fn commit_sync(
        &mut self,
        vault: VaultId,
        commit: &SyncCommit,
        branched: bool,
    ) -> Result<(), Error> {
        commit.validate()?;
        let tx = self
            .0
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sql)?;
        available(&tx, vault)?;
        let previous: Option<Vec<u8>> = tx
            .query_row(
                "SELECT checkpoint FROM sync_state WHERE vault=?1",
                [vault.as_slice()],
                |r| r.get(0),
            )
            .optional()
            .map_err(sql)?;
        if previous != commit.previous {
            return Err(Error::Conflict);
        }
        put_objects(&tx, vault, &commit.objects)?;
        move_heads(&tx, vault, &commit.heads, branched)?;
        tx.execute("INSERT INTO sync_state(vault,checkpoint) VALUES(?1,?2) ON CONFLICT(vault) DO UPDATE SET checkpoint=excluded.checkpoint",
            params![vault.as_slice(),commit.current]).map_err(sql)?;
        tx.commit().map_err(sql)
    }
}

fn single_heads(db: &Connection, vault: VaultId) -> Result<(), Error> {
    let ambiguous: bool = db
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM heads WHERE vault=?1
        GROUP BY record HAVING count(*)>1)",
            [vault.as_slice()],
            |r| r.get(0),
        )
        .map_err(sql)?;
    if ambiguous {
        Err(Error::Conflict)
    } else {
        Ok(())
    }
}
fn available(db: &Connection, vault: VaultId) -> Result<(), Error> {
    match db
        .query_row(
            "SELECT removing FROM vaults WHERE id=?1",
            [vault.as_slice()],
            |r| r.get::<_, bool>(0),
        )
        .optional()
        .map_err(sql)?
    {
        Some(false) => Ok(()),
        Some(true) => Err(Error::Removing),
        None => Err(Error::NotFound),
    }
}
fn clear_records(tx: &rusqlite::Transaction<'_>, vault: VaultId) -> Result<(), Error> {
    for table in ["record_tags", "heads", "objects", "sync_state"] {
        tx.execute(
            &format!("DELETE FROM {table} WHERE vault=?1"),
            [vault.as_slice()],
        )
        .map_err(sql)?;
    }
    Ok(())
}
fn put_objects(
    tx: &rusqlite::Transaction<'_>,
    vault: VaultId,
    objects: &[StoredObject],
) -> Result<(), Error> {
    for object in objects {
        tx.execute("INSERT INTO objects(vault,record,revision,wire) VALUES(?1,?2,?3,?4) ON CONFLICT DO NOTHING",
                params![vault.as_slice(),object.head.record.as_slice(),object.head.revision.as_slice(),object.wire]).map_err(sql)?;
        let same: bool = tx
            .query_row(
                "SELECT record=?3 AND wire=?4 FROM objects WHERE vault=?1 AND revision=?2",
                params![
                    vault.as_slice(),
                    object.head.revision.as_slice(),
                    object.head.record.as_slice(),
                    object.wire
                ],
                |r| r.get(0),
            )
            .map_err(sql)?;
        if !same {
            return Err(Error::Conflict);
        }
        for tag in &object.tags {
            tx.execute("INSERT INTO record_tags(vault,record,revision,tag) VALUES(?1,?2,?3,?4) ON CONFLICT DO NOTHING",
                    params![vault.as_slice(),object.head.record.as_slice(),object.head.revision.as_slice(),tag]).map_err(sql)?;
        }
    }
    Ok(())
}
fn move_heads(
    tx: &rusqlite::Transaction<'_>,
    vault: VaultId,
    heads: &[HeadChange],
    branched: bool,
) -> Result<(), Error> {
    if !branched {
        single_heads(tx, vault)?;
        let records: std::collections::BTreeSet<_> = heads.iter().map(|h| h.head.record).collect();
        if records.len() != heads.len() {
            return Err(Error::Invalid);
        }
    }
    for change in heads {
        let current: Option<Vec<u8>> = tx
            .query_row(
                "SELECT revision FROM heads WHERE vault=?1 AND record=?2 AND (?3=0 OR revision=?4)",
                params![
                    vault.as_slice(),
                    change.head.record.as_slice(),
                    branched,
                    change.expected.as_ref().map(|id| id.as_slice())
                ],
                |r| r.get(0),
            )
            .optional()
            .map_err(sql)?;
        if current.as_deref() != change.expected.as_ref().map(|r| r.as_slice()) {
            return Err(Error::Conflict);
        }
        let exists: bool = tx
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM objects WHERE vault=?1 AND record=?2 AND revision=?3)",
                params![
                    vault.as_slice(),
                    change.head.record.as_slice(),
                    change.head.revision.as_slice()
                ],
                |r| r.get(0),
            )
            .map_err(sql)?;
        if !exists {
            return Err(Error::NotFound);
        }
    }
    for change in heads {
        if let Some(expected) = change.expected {
            tx.execute(
                "DELETE FROM heads WHERE vault=?1 AND record=?2 AND revision=?3",
                params![
                    vault.as_slice(),
                    change.head.record.as_slice(),
                    expected.as_slice()
                ],
            )
            .map_err(sql)?;
        }
    }
    for change in heads {
        let count = tx
            .execute(
                "INSERT INTO heads(vault,record,revision) VALUES(?1,?2,?3) ON CONFLICT DO NOTHING",
                params![
                    vault.as_slice(),
                    change.head.record.as_slice(),
                    change.head.revision.as_slice()
                ],
            )
            .map_err(sql)?;
        if count != 1 && !branched {
            return Err(Error::Conflict);
        }
    }
    Ok(())
}
impl Store for SqliteStore {
    async fn branch_heads(
        &mut self,
        vault: VaultId,
        after: Option<&Head>,
        tag: Option<&str>,
    ) -> Result<Vec<Head>, Error> {
        SqliteStore::branch_heads(self, vault, after, tag).await
    }
    async fn publish_branches(&mut self, vault: VaultId, commit: &SyncCommit) -> Result<(), Error> {
        SqliteStore::publish_branches(self, vault, commit).await
    }
    async fn batch_commit(&mut self, vault: VaultId, commit: &BatchCommit) -> Result<(), Error> {
        commit.validate()?;
        let tx = self
            .0
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sql)?;
        available(&tx, vault)?;
        let current = {
            let mut statement = tx
                .prepare(
                    "SELECT record,revision FROM heads WHERE vault=?1 ORDER BY record,revision LIMIT ?2",
                )
                .map_err(sql)?;
            statement
                .query_map(
                    params![vault.as_slice(), (MAX_BATCH_BASE_HEADS + 1) as i64],
                    |row| {
                        Ok(Head {
                            record: fixed(row.get(0)?)?,
                            revision: fixed(row.get(1)?)?,
                        })
                    },
                )
                .map_err(sql)?
                .collect::<Result<Vec<_>, _>>()
                .map_err(sql)?
        };
        if current.len() > MAX_BATCH_BASE_HEADS {
            return Err(Error::Limit);
        }
        if current != commit.previous {
            return Err(Error::Conflict);
        }
        put_objects(&tx, vault, &commit.objects)?;
        move_heads(&tx, vault, &commit.heads, true)?;
        tx.commit().map_err(sql)
    }

    async fn rename(&mut self, vault: VaultId, expected: &str, name: &str) -> Result<(), Error> {
        if name.is_empty() || name.len() > 128 || expected.len() > 128 {
            return Err(Error::Invalid);
        }
        let tx = self
            .0
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sql)?;
        available(&tx, vault)?;
        if tx
            .execute(
                "UPDATE vaults SET name=?1 WHERE id=?2 AND name=?3",
                params![name, vault.as_slice(), expected],
            )
            .map_err(sql)?
            != 1
        {
            return Err(Error::Conflict);
        }
        tx.commit().map_err(sql)
    }

    async fn clear_records(&mut self, vault: VaultId) -> Result<(), Error> {
        let tx = self
            .0
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sql)?;
        tx.execute(
            "UPDATE vaults SET removing=1 WHERE id=?1",
            [vault.as_slice()],
        )
        .map_err(sql)?;
        clear_records(&tx, vault)?;
        tx.commit().map_err(sql)
    }
    async fn remove(&mut self, vault: VaultId) -> Result<(), Error> {
        let tx = self
            .0
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sql)?;
        clear_records(&tx, vault)?;
        tx.execute("DELETE FROM vaults WHERE id=?1", [vault.as_slice()])
            .map_err(sql)?;
        tx.commit().map_err(sql)
    }
    async fn snapshot(&mut self, vault: VaultId) -> Result<Snapshot, Error> {
        let tx = self.0.transaction().map_err(sql)?;
        available(&tx, vault)?;
        let vault = tx
            .query_row(
                "SELECT name,lock FROM vaults WHERE id=?1",
                [vault.as_slice()],
                |r| {
                    Ok(StoredVault {
                        info: VaultInfo {
                            id: vault,
                            name: r.get(0)?,
                        },
                        lock: r.get(1)?,
                    })
                },
            )
            .optional()
            .map_err(sql)?
            .ok_or(Error::NotFound)?;
        let mut objects = Vec::new();
        let mut bytes = 0;
        {
            let mut statement = tx
                .prepare(
                    "SELECT record,revision,wire,length(wire) FROM objects WHERE vault=?1 ORDER BY revision",
                )
                .map_err(sql)?;
            let mut rows = statement.query([vault.info.id.as_slice()]).map_err(sql)?;
            while let Some(row) = rows.next().map_err(sql)? {
                let length: i64 = row.get(3).map_err(sql)?;
                if !(1..=MAX_OBJECT as i64).contains(&length) {
                    return Err(Error::Limit);
                }
                bytes += length as usize;
                if bytes > MAX_BACKUP_BYTES * 3 / 4 || objects.len() == MAX_BACKUP_OBJECTS {
                    return Err(Error::Limit);
                }
                let wire: Vec<u8> = row.get(2).map_err(sql)?;
                objects.push(StoredObject {
                    head: Head {
                        record: fixed(row.get(0).map_err(sql)?).map_err(sql)?,
                        revision: fixed(row.get(1).map_err(sql)?).map_err(sql)?,
                    },
                    wire,
                    tags: vec![],
                });
            }
        }
        let heads = {
            let mut statement = tx
                .prepare(
                    "SELECT record,revision FROM heads WHERE vault=?1 ORDER BY record,revision LIMIT 10001",
                )
                .map_err(sql)?;
            statement
                .query_map([vault.info.id.as_slice()], |r| {
                    Ok(Head {
                        record: fixed(r.get(0)?)?,
                        revision: fixed(r.get(1)?)?,
                    })
                })
                .map_err(sql)?
                .collect::<Result<Vec<_>, _>>()
                .map_err(sql)?
        };
        let snapshot = Snapshot {
            vault,
            objects,
            heads,
        };
        snapshot.validate()?;
        tx.commit().map_err(sql)?;
        Ok(snapshot)
    }
    async fn restore(&mut self, snapshot: &Snapshot) -> Result<(), Error> {
        snapshot.validate()?;
        let tx = self
            .0
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sql)?;
        let vault = snapshot.vault.info.id;
        let added = tx
            .execute(
                "INSERT INTO vaults(id,name,lock) VALUES(?1,?2,?3) ON CONFLICT DO NOTHING",
                params![
                    vault.as_slice(),
                    snapshot.vault.info.name,
                    snapshot.vault.lock
                ],
            )
            .map_err(sql)?;
        if added != 1 {
            return Err(Error::Conflict);
        }
        for object in &snapshot.objects {
            tx.execute(
                "INSERT INTO objects(vault,record,revision,wire) VALUES(?1,?2,?3,?4)",
                params![
                    vault.as_slice(),
                    object.head.record.as_slice(),
                    object.head.revision.as_slice(),
                    object.wire
                ],
            )
            .map_err(sql)?;
            for tag in &object.tags {
                tx.execute(
                    "INSERT INTO record_tags(vault,record,revision,tag) VALUES(?1,?2,?3,?4)",
                    params![
                        vault.as_slice(),
                        object.head.record.as_slice(),
                        object.head.revision.as_slice(),
                        tag
                    ],
                )
                .map_err(sql)?;
            }
        }
        for head in &snapshot.heads {
            tx.execute(
                "INSERT INTO heads(vault,record,revision) VALUES(?1,?2,?3)",
                params![
                    vault.as_slice(),
                    head.record.as_slice(),
                    head.revision.as_slice()
                ],
            )
            .map_err(sql)?;
        }
        tx.commit().map_err(sql)
    }
    async fn sync_state(&mut self, vault: VaultId) -> Result<Option<Vec<u8>>, Error> {
        let bytes: Option<Vec<u8>> = self
            .0
            .query_row(
                "SELECT checkpoint FROM sync_state WHERE vault=?1",
                [vault.as_slice()],
                |r| r.get(0),
            )
            .optional()
            .map_err(sql)?;
        if bytes.as_ref().is_some_and(|b| b.len() > MAX_SYNC_STATE) {
            return Err(Error::Limit);
        }
        Ok(bytes)
    }
    async fn sync_commit(&mut self, vault: VaultId, commit: &SyncCommit) -> Result<(), Error> {
        self.commit_sync(vault, commit, false)
    }
    async fn vaults(&mut self) -> Result<Vec<VaultInfo>, Error> {
        let mut statement = self
            .0
            .prepare("SELECT id,name FROM vaults ORDER BY name,id LIMIT 129")
            .map_err(sql)?;
        let values = statement
            .query_map([], |row| {
                Ok(VaultInfo {
                    id: fixed(row.get(0)?)?,
                    name: row.get(1)?,
                })
            })
            .map_err(sql)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(sql)?;
        if values.len() > 128 || values.iter().any(|v| v.name.len() > 128) {
            return Err(Error::Limit);
        }
        Ok(values)
    }
    async fn vault(&mut self, id: VaultId) -> Result<StoredVault, Error> {
        available(&self.0, id)?;
        self.0
            .query_row(
                "SELECT name,lock FROM vaults WHERE id=?1 AND length(lock)<=344",
                [id.as_slice()],
                |row| {
                    Ok(StoredVault {
                        info: VaultInfo {
                            id,
                            name: row.get(0)?,
                        },
                        lock: row.get(1)?,
                    })
                },
            )
            .optional()
            .map_err(sql)?
            .ok_or(Error::NotFound)
    }
    async fn create(&mut self, vault: &StoredVault) -> Result<(), Error> {
        if vault.info.name.is_empty() || vault.info.name.len() > 128 || vault.lock.len() > 344 {
            return Err(Error::Invalid);
        }
        let count = self
            .0
            .execute(
                "INSERT INTO vaults(id,name,lock) VALUES(?1,?2,?3) ON CONFLICT DO NOTHING",
                params![vault.info.id.as_slice(), vault.info.name, vault.lock],
            )
            .map_err(sql)?;
        if count == 1 {
            Ok(())
        } else {
            Err(Error::Conflict)
        }
    }
    async fn heads(&mut self, vault: VaultId, after: Option<RecordId>) -> Result<Vec<Head>, Error> {
        let tx = self.0.transaction().map_err(sql)?;
        single_heads(&tx, vault)?;
        let mut statement = tx.prepare("SELECT record,revision FROM heads WHERE vault=?1 AND (?2 IS NULL OR record>?2) ORDER BY record,revision LIMIT 128").map_err(sql)?;
        statement
            .query_map(
                params![vault.as_slice(), after.as_ref().map(|id| id.as_slice())],
                |row| {
                    Ok(Head {
                        record: fixed(row.get(0)?)?,
                        revision: fixed(row.get(1)?)?,
                    })
                },
            )
            .map_err(sql)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(sql)
    }
    async fn head(&mut self, vault: VaultId, record: RecordId) -> Result<Option<Head>, Error> {
        let tx = self.0.transaction().map_err(sql)?;
        single_heads(&tx, vault)?;
        tx.query_row(
            "SELECT revision FROM heads WHERE vault=?1 AND record=?2",
            params![vault.as_slice(), record.as_slice()],
            |row| {
                Ok(Head {
                    record,
                    revision: fixed(row.get(0)?)?,
                })
            },
        )
        .optional()
        .map_err(sql)
    }
    async fn tagged_heads(
        &mut self,
        vault: VaultId,
        tag: &str,
        after: Option<RecordId>,
    ) -> Result<Vec<Head>, Error> {
        let tx = self.0.transaction().map_err(sql)?;
        single_heads(&tx, vault)?;
        if tag.len() > 256 {
            return Err(Error::Limit);
        }
        let mut statement = tx.prepare("SELECT h.record,h.revision FROM record_tags t JOIN heads h ON h.vault=t.vault AND h.record=t.record AND h.revision=t.revision WHERE t.vault=?1 AND t.tag=?2 AND (?3 IS NULL OR t.record>?3) ORDER BY t.record,t.revision LIMIT 128").map_err(sql)?;
        statement
            .query_map(
                params![
                    vault.as_slice(),
                    tag,
                    after.as_ref().map(|id| id.as_slice())
                ],
                |row| {
                    Ok(Head {
                        record: fixed(row.get(0)?)?,
                        revision: fixed(row.get(1)?)?,
                    })
                },
            )
            .map_err(sql)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(sql)
    }
    async fn object(&mut self, vault: VaultId, revision: RevisionId) -> Result<Vec<u8>, Error> {
        self.0
            .query_row(
                "SELECT wire FROM objects WHERE vault=?1 AND revision=?2 AND length(wire)<=?3",
                params![vault.as_slice(), revision.as_slice(), MAX_OBJECT as i64],
                |row| row.get(0),
            )
            .optional()
            .map_err(sql)?
            .ok_or(Error::NotFound)
    }
    async fn append(
        &mut self,
        vault: VaultId,
        head: &Head,
        expected: Option<RevisionId>,
        wire: &[u8],
        tags: &[String],
    ) -> Result<(), Error> {
        if wire.is_empty() || wire.len() > MAX_OBJECT || !valid_tags(tags) {
            return Err(Error::Limit);
        }
        let tx = self
            .0
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sql)?;
        available(&tx, vault)?;
        single_heads(&tx, vault)?;
        let current: Option<Vec<u8>> = tx
            .query_row(
                "SELECT revision FROM heads WHERE vault=?1 AND record=?2",
                params![vault.as_slice(), head.record.as_slice()],
                |row| row.get(0),
            )
            .optional()
            .map_err(sql)?;
        if current.as_deref() == Some(head.revision.as_slice()) {
            let same: bool = tx
                .query_row(
                    "SELECT wire=?3 AND record=?4 FROM objects WHERE vault=?1 AND revision=?2",
                    params![
                        vault.as_slice(),
                        head.revision.as_slice(),
                        wire,
                        head.record.as_slice()
                    ],
                    |row| row.get(0),
                )
                .map_err(sql)?;
            return if same { Ok(()) } else { Err(Error::Conflict) };
        }
        if current.as_deref() != expected.as_ref().map(|id| id.as_slice()) {
            return Err(Error::Conflict);
        }
        let added = tx.execute("INSERT INTO objects(vault,record,revision,wire) VALUES(?1,?2,?3,?4) ON CONFLICT DO NOTHING",
            params![vault.as_slice(),head.record.as_slice(),head.revision.as_slice(),wire]).map_err(sql)?;
        if added != 1 {
            return Err(Error::Conflict);
        }
        for tag in tags {
            tx.execute(
                "INSERT INTO record_tags(vault,record,revision,tag) VALUES(?1,?2,?3,?4)",
                params![
                    vault.as_slice(),
                    head.record.as_slice(),
                    head.revision.as_slice(),
                    tag
                ],
            )
            .map_err(sql)?;
        }
        move_heads(
            &tx,
            vault,
            &[HeadChange {
                head: head.clone(),
                expected,
            }],
            false,
        )?;
        tx.commit().map_err(sql)
    }
}
