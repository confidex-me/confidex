use crate::*;

pub struct Statement {
    pub sql: String,
    pub values: Vec<String>,
}
impl Statement {
    pub fn new(sql: &str, values: Vec<String>) -> Self {
        Self {
            sql: sql.to_owned(),
            values,
        }
    }
}

#[allow(async_fn_in_trait)]
pub trait Index {
    async fn query(
        &self,
        expression: &str,
        suffix: &str,
        values: &[String],
    ) -> Result<Vec<serde_json::Value>>;
    async fn batch(&self, statements: Vec<Statement>) -> Result<Vec<u64>>;
}
#[allow(async_fn_in_trait)]
pub trait Blobs {
    async fn get(&self, blob: BlobRef<'_>) -> Result<Bytes>;
    async fn put(&self, blob: BlobRef<'_>, bytes: &[u8]) -> Result<()>;
}
#[derive(Clone, Copy)]
pub struct BlobRef<'a> {
    pub vault: &'a str,
    pub digest: &'a str,
    pub lock: bool,
}
impl<'a> BlobRef<'a> {
    pub fn lock(vault: &'a str, digest: &'a str) -> Self {
        Self {
            vault,
            digest,
            lock: true,
        }
    }
    pub fn record(vault: &'a str, digest: &'a str) -> Self {
        Self {
            vault,
            digest,
            lock: false,
        }
    }
}

pub struct Mirrors<B>(pub Vec<B>);
impl<B: Blobs> Blobs for Mirrors<B> {
    async fn get(&self, blob: BlobRef<'_>) -> Result<Bytes> {
        for destination in &self.0 {
            if let Ok(bytes) = destination.get(blob).await
                && digest(&bytes) == blob.digest
            {
                return Ok(bytes);
            }
        }
        Err(Error::Storage)
    }
    async fn put(&self, blob: BlobRef<'_>, bytes: &[u8]) -> Result<()> {
        if self.0.is_empty() {
            return Err(Error::Storage);
        }
        for destination in &self.0 {
            destination.put(blob, bytes).await?;
        }
        Ok(())
    }
}

pub struct Store<'a, I, B> {
    pub index: &'a I,
    pub blobs: &'a B,
}
const LOCK_JSON: &str = "json_object('id',id,'vault_id',vault_id,'public_key',public_key,'blob',blob,'signature',signature,'previous',previous,'cursor',cursor)";

impl<I: Index, B: Blobs> Store<'_, I, B> {
    pub async fn lock(&self, id: &str) -> Result<Lock> {
        rows(
            self.index,
            LOCK_JSON,
            "FROM sync_locks WHERE id=$1",
            &[id.to_owned()],
        )
        .await?
        .into_iter()
        .next()
        .ok_or(Error::NotFound)
    }
    pub async fn create(&self, lock: &Lock, wire: &[u8]) -> Result<bool> {
        match self.lock(&lock.id).await {
            Ok(old) => {
                return if old.public_key == lock.public_key
                    && old.vault_id == lock.vault_id
                    && old.blob == lock.blob
                {
                    Ok(false)
                } else {
                    Err(Error::Conflict)
                };
            }
            Err(Error::NotFound) => {}
            Err(e) => return Err(e),
        }
        // shortcut: Failed commits can leave unused objects; add collection when space must be recovered.
        self.blobs
            .put(BlobRef::lock(&lock.id, &lock.blob), wire)
            .await?;
        let changes = self.index.batch(vec![Statement::new(
            "INSERT INTO sync_locks(id,vault_id,public_key,blob,signature,previous) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT DO NOTHING",
            vec![lock.id.clone(),lock.vault_id.clone(),lock.public_key.clone(),lock.blob.clone(),lock.signature.clone(),lock.previous.clone()])]).await?;
        if changes[0] == 1 {
            return Ok(true);
        }
        let old = self.lock(&lock.id).await?;
        if old.public_key == lock.public_key
            && old.vault_id == lock.vault_id
            && old.blob == lock.blob
        {
            Ok(false)
        } else {
            Err(Error::Conflict)
        }
    }
    pub async fn replace(&self, lock: &Lock, wire: &[u8], expected: &str) -> Result<()> {
        self.blobs
            .put(BlobRef::lock(&lock.id, &lock.blob), wire)
            .await?;
        let changes = self.index.batch(vec![Statement::new(
            "UPDATE sync_locks SET blob=$1,signature=$2,previous=$3 WHERE id=$4 AND blob=$5 AND public_key=$6 AND vault_id=$7",
            vec![lock.blob.clone(),lock.signature.clone(),lock.previous.clone(),lock.id.clone(),expected.to_owned(),lock.public_key.clone(),lock.vault_id.clone()])]).await?;
        if changes[0] == 1 {
            Ok(())
        } else {
            Err(Error::Precondition)
        }
    }
    pub async fn record(&self, id: &str, revision: &str) -> Result<Option<String>> {
        let records: Vec<String> = rows(
            self.index,
            "json_quote(record_id)",
            "FROM sync_records WHERE lock_id=$1 AND revision=$2",
            &[id.to_owned(), revision.to_owned()],
        )
        .await?;
        Ok(records.into_iter().next())
    }
    pub async fn append(&self, id: &str, base: i64, records: &[Record]) -> Result<i64> {
        let next = base
            .checked_add(records.len() as i64)
            .ok_or(Error::Conflict)?;
        let token = digest(&serde_json::to_vec(&(id, base, records)).map_err(|_| Error::Storage)?);
        let mut statements = vec![Statement::new(
            "UPDATE sync_locks SET cursor=CAST($1 AS BIGINT),commit_token=$2 WHERE id=$3 AND cursor=CAST($4 AS BIGINT)",
            vec![
                next.to_string(),
                token.clone(),
                id.to_owned(),
                base.to_string(),
            ],
        )];
        for (offset, record) in records.iter().enumerate() {
            // The token prevents a failed CAS from publishing another writer's rows.
            statements.push(Statement::new(
                "INSERT INTO sync_records(lock_id,sequence,revision,record_id,blob,size) SELECT $1,CAST($2 AS BIGINT),$3,$4,$5,CAST($6 AS BIGINT) FROM sync_locks WHERE id=$1 AND commit_token=$7 AND cursor=CAST($8 AS BIGINT)",
                vec![id.to_owned(),(base+offset as i64+1).to_string(),record.revision.clone(),record.record_id.clone(),record.blob.clone(),record.size.to_string(),token.clone(),next.to_string()]));
        }
        let changes = self.index.batch(statements).await?;
        if changes.first() != Some(&1) {
            return Err(Error::Conflict);
        }
        Ok(next)
    }
    pub async fn page(&self, id: &str, after: i64, head: i64) -> Result<(i64, bool, Vec<Bytes>)> {
        #[derive(Deserialize)]
        struct Row {
            sequence: i64,
            blob: String,
            size: i64,
        }
        let refs: Vec<Row> = rows(self.index,"json_object('sequence',sequence,'blob',blob,'size',size)",
            "FROM sync_records WHERE lock_id=$1 AND sequence>CAST($2 AS BIGINT) AND sequence<=CAST($3 AS BIGINT) ORDER BY sequence LIMIT 16",
            &[id.to_owned(),after.to_string(),head.to_string()]).await?;
        let mut objects = Vec::new();
        let mut total = 0;
        let mut cursor = after;
        for reference in refs {
            let size = usize::try_from(reference.size).map_err(|_| Error::Storage)?;
            if total + size > MAX_PAGE_BYTES {
                break;
            }
            let bytes = self.blobs.get(BlobRef::record(id, &reference.blob)).await?;
            if bytes.len() != size || digest(&bytes) != reference.blob {
                return Err(Error::Storage);
            }
            total += size;
            cursor = reference.sequence;
            objects.push(bytes);
        }
        if cursor == after && after < head {
            return Err(Error::Storage);
        }
        Ok((cursor, cursor < head, objects))
    }
}
